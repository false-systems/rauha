//! Linux isolation backend: cgroups v2 + namespaces + current eBPF LSM support.
//!
//! Orchestrates the Linux pieces behind Rauha zones:
//! - cgroup v2 hierarchy provides resource limits and process grouping
//! - Network namespaces + veth pairs isolate network stacks
//! - current in-repo eBPF LSM programs enforce zone boundaries at syscall level
//!
//! Architecturally, the kernel enforcement piece belongs behind the Syva
//! boundary: Rauha creates zones; Syva makes the Linux kernel respect them.

mod cgroup;
mod ebpf;
pub mod events;
mod maps;
mod namespace;
mod network;
pub(crate) mod nftables;

/// Clean up Linux network state (nftables table + bridge).
/// Called during daemon shutdown.
pub fn cleanup_network() {
    if let Err(e) = nftables::cleanup_nat() {
        tracing::warn!(%e, "failed to clean up nftables table");
    }
    if let Err(e) = network::destroy_bridge() {
        tracing::warn!(%e, "failed to destroy network bridge");
    }
}

use std::collections::HashMap;
use std::io::{Read, Write};
use std::os::unix::net::UnixStream;
use std::path::PathBuf;
use std::process::Command;
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::{Mutex, MutexGuard};
use std::time::Duration;

use rauha_common::backend::IsolationBackend;
use rauha_common::container::{ContainerHandle, ContainerSpec};
use rauha_common::error::{RauhaError, Result};
use rauha_common::shim::{self, ShimRequest, ShimResponse};
use rauha_common::zone::*;
use uuid::Uuid;

use self::cgroup::CgroupManager;
use self::ebpf::EbpfManager;
use self::maps::MapManager;
use crate::network::allocator::IpAllocator;

/// Connection to a zone's shim process via Unix socket.
struct ShimConnection {
    socket_path: PathBuf,
}

impl ShimConnection {
    fn new(socket_path: PathBuf) -> Self {
        Self { socket_path }
    }

    /// Send a request to the shim and receive a response.
    fn send_request(&self, request: &ShimRequest) -> Result<ShimResponse> {
        let mut stream = UnixStream::connect(&self.socket_path).map_err(|e| {
            RauhaError::ShimError {
                zone: self.socket_path.display().to_string(),
                message: format!("failed to connect to shim: {e}"),
            }
        })?;

        stream
            .set_read_timeout(Some(Duration::from_secs(30)))
            .ok();
        stream
            .set_write_timeout(Some(Duration::from_secs(10)))
            .ok();

        shim::encode_to(&mut stream, request).map_err(|e| RauhaError::ShimError {
            zone: self.socket_path.display().to_string(),
            message: format!("failed to send request: {e}"),
        })?;

        shim::decode_from::<ShimResponse>(&mut stream).map_err(|e| RauhaError::ShimError {
            zone: self.socket_path.display().to_string(),
            message: format!("failed to read response: {e}"),
        })
    }
}

/// Lock a mutex, aborting the process if poisoned.
///
/// Mutex poisoning means a thread panicked while holding the lock — the
/// protected data is in an undefined state. Process abort (not just task
/// panic) ensures the process actually terminates so systemd can restart it.
fn lock_or_abort<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    mutex.lock().unwrap_or_else(|_| {
        tracing::error!("mutex poisoned — daemon state corrupt, aborting for restart");
        std::process::abort();
    })
}

/// Linux isolation backend using eBPF LSM + namespaces + cgroups.
pub struct LinuxBackend {
    root: String,
    /// eBPF program manager (None if eBPF is not available / not loaded yet).
    ebpf: Mutex<Option<EbpfManager>>,
    /// cgroup v2 manager.
    cgroup: CgroupManager,
    /// Monotonic zone ID counter for compact BPF map keys.
    next_zone_id: AtomicU32,
    /// Maps Uuid → compact u32 zone_id used in BPF maps.
    zone_id_map: Mutex<HashMap<Uuid, u32>>,
    /// Maps zone name → Uuid for reverse lookups.
    zone_name_map: Mutex<HashMap<String, Uuid>>,
    /// Shim connections per zone.
    shim_connections: Mutex<HashMap<String, ShimConnection>>,
    /// Registered inodes per zone, for correct cleanup without re-walking.
    /// Key is zone name, value is the inode list registered in INODE_ZONE_MAP.
    registered_inodes: Mutex<HashMap<String, Vec<u64>>>,
    /// Cancellation token for the enforcement event reader task.
    event_reader_cancel: Option<tokio_util::sync::CancellationToken>,
    /// Broadcast sender for enforcement events (gRPC WatchEvents subscribes here).
    event_tx: Option<tokio::sync::broadcast::Sender<events::DecodedEvent>>,
    /// IP address allocator for zone networking.
    ip_allocator: Mutex<IpAllocator>,
}

impl LinuxBackend {
    pub fn new(root: &str) -> Result<Self> {
        let cgroup = CgroupManager::new()?;
        let ip_allocator = IpAllocator::default_subnet();

        // Try to load eBPF programs. If it fails, log a warning and continue
        // in degraded mode (no kernel enforcement).
        let (ebpf, event_reader_cancel, event_tx) = match Self::try_load_ebpf(root) {
            Ok(mut mgr) => {
                tracing::info!("eBPF programs loaded — kernel enforcement active");

                // Start the enforcement event reader (ring buffer → tracing logs).
                let (cancel, event_tx) = match mgr.take_event_ring_buf() {
                    Ok(ring_buf) => {
                        let token = tokio_util::sync::CancellationToken::new();
                        let tx = events::spawn_event_reader(ring_buf, token.clone());
                        (Some(token), Some(tx))
                    }
                    Err(e) => {
                        tracing::warn!(%e, "enforcement event ring buffer not available");
                        (None, None)
                    }
                };

                (Some(mgr), cancel, event_tx)
            }
            Err(e) => {
                tracing::warn!(%e, "eBPF programs not loaded — running without kernel enforcement");
                (None, None, None)
            }
        };

        // Ensure the network bridge exists with a gateway IP.
        if let Err(e) = network::ensure_bridge(ip_allocator.gateway(), ip_allocator.prefix_len()) {
            tracing::warn!(%e, "failed to create network bridge — zones will have no networking");
        }

        // Set up NAT masquerade for zone traffic.
        let subnet_cidr = {
            let s = ip_allocator.subnet();
            format!("{}.{}.{}.{}/{}", s[0], s[1], s[2], s[3], ip_allocator.prefix_len())
        };
        if let Err(e) = nftables::ensure_nat(&subnet_cidr) {
            tracing::warn!(%e, "failed to set up NAT — zones won't have internet access");
        }

        Ok(Self {
            root: root.into(),
            ebpf: Mutex::new(ebpf),
            cgroup,
            next_zone_id: AtomicU32::new(1), // 0 is reserved for "no zone".
            zone_id_map: Mutex::new(HashMap::new()),
            zone_name_map: Mutex::new(HashMap::new()),
            shim_connections: Mutex::new(HashMap::new()),
            registered_inodes: Mutex::new(HashMap::new()),
            event_reader_cancel,
            event_tx,
            ip_allocator: Mutex::new(ip_allocator),
        })
    }

    fn try_load_ebpf(root: &str) -> Result<EbpfManager> {
        // Look for the eBPF object in well-known locations.
        let candidates = [
            PathBuf::from(root).join("rauha-ebpf"),
            PathBuf::from("/usr/lib/rauha/rauha-ebpf"),
            // Development build path.
            PathBuf::from(env!("CARGO_MANIFEST_DIR"))
                .parent()
                .unwrap_or_else(|| std::path::Path::new("."))
                .join("rauha-ebpf/target/bpfel-unknown-none/debug/rauha-ebpf"),
            PathBuf::from(env!("CARGO_MANIFEST_DIR"))
                .parent()
                .unwrap_or_else(|| std::path::Path::new("."))
                .join("rauha-ebpf/target/bpfel-unknown-none/release/rauha-ebpf"),
        ];

        for path in &candidates {
            if path.exists() {
                return EbpfManager::load(path);
            }
        }

        Err(RauhaError::EbpfError {
            message: "eBPF object not found in any known location".into(),
            hint: "run `cargo xtask build-ebpf` to compile eBPF programs".into(),
        })
    }

    /// Get a clone of the enforcement event broadcast sender, if available.
    pub fn event_sender(&self) -> Option<tokio::sync::broadcast::Sender<events::DecodedEvent>> {
        self.event_tx.clone()
    }

    /// Allocate a new compact zone_id for BPF maps.
    fn allocate_zone_id(&self, uuid: Uuid) -> u32 {
        let id = self.next_zone_id.fetch_add(1, Ordering::Relaxed);
        self.zone_id_map.lock().unwrap_or_else(|_| { tracing::error!("mutex poisoned"); std::process::abort() }).insert(uuid, id);
        id
    }

    /// Look up the compact zone_id for a Uuid.
    fn get_zone_id(&self, uuid: &Uuid) -> Option<u32> {
        self.zone_id_map.lock().unwrap_or_else(|_| { tracing::error!("mutex poisoned"); std::process::abort() }).get(uuid).copied()
    }

    /// Remove zone_id mapping.
    fn remove_zone_id(&self, uuid: &Uuid) -> Option<u32> {
        self.zone_id_map.lock().unwrap_or_else(|_| { tracing::error!("mutex poisoned"); std::process::abort() }).remove(uuid)
    }

    /// Get the socket path for a zone's shim.
    fn shim_socket_path(zone_name: &str) -> PathBuf {
        PathBuf::from(format!("/run/rauha/shim-{zone_name}.sock"))
    }

    /// Ensure a shim process is running for a zone, spawning one if needed.
    fn ensure_shim(&self, zone_name: &str) -> Result<()> {
        let socket_path = Self::shim_socket_path(zone_name);

        // Check if shim is already connected and responsive.
        {
            let conns = self.shim_connections.lock().unwrap_or_else(|_| { tracing::error!("mutex poisoned"); std::process::abort() });
            if let Some(conn) = conns.get(zone_name) {
                // Try a quick health check.
                if conn
                    .send_request(&ShimRequest::GetState {
                        id: "__ping__".into(),
                    })
                    .is_ok()
                {
                    return Ok(());
                }
            }
        }

        // If socket exists but shim is dead, remove the stale socket.
        if socket_path.exists() {
            let _ = std::fs::remove_file(&socket_path);
        }

        // Spawn shim process.
        let rootfs_root = PathBuf::from(&self.root).join("zones").join(zone_name);
        std::fs::create_dir_all(&rootfs_root).map_err(|e| RauhaError::ShimError {
            zone: zone_name.into(),
            message: format!("failed to create zone dir: {e}"),
        })?;

        // Ensure /run/rauha exists.
        std::fs::create_dir_all("/run/rauha").ok();

        let shim_bin = find_shim_binary()?;

        Command::new(&shim_bin)
            .arg("--zone-name")
            .arg(zone_name)
            .arg("--socket")
            .arg(&socket_path)
            .arg("--rootfs-root")
            .arg(&rootfs_root)
            .spawn()
            .map_err(|e| RauhaError::ShimError {
                zone: zone_name.into(),
                message: format!("failed to spawn shim: {e}"),
            })?;

        // Wait for socket to appear.
        for _ in 0..50 {
            if socket_path.exists() {
                break;
            }
            std::thread::sleep(Duration::from_millis(100));
        }

        if !socket_path.exists() {
            return Err(RauhaError::ShimError {
                zone: zone_name.into(),
                message: "shim socket did not appear after spawn".into(),
            });
        }

        // Register connection.
        let conn = ShimConnection::new(socket_path);
        self.shim_connections
            .lock()
            .unwrap_or_else(|_| { tracing::error!("mutex poisoned"); std::process::abort() })
            .insert(zone_name.to_string(), conn);

        tracing::info!(zone = zone_name, "shim spawned");
        Ok(())
    }

    /// Send a request to a zone's shim.
    fn shim_request(&self, zone_name: &str, request: &ShimRequest) -> Result<ShimResponse> {
        let conns = self.shim_connections.lock().unwrap_or_else(|_| { tracing::error!("mutex poisoned"); std::process::abort() });
        let conn = conns.get(zone_name).ok_or_else(|| RauhaError::ShimError {
            zone: zone_name.into(),
            message: "no shim connection".into(),
        })?;
        conn.send_request(request)
    }

    /// Apply nftables forward rules for a zone based on its network policy.
    fn apply_nftables_for_zone(&self, zone: &ZoneHandle, net_policy: &NetworkPolicy) -> Result<()> {
        let veth_name = network::veth_host_name_for(&zone.name);

        if let Err(e) = nftables::apply_zone_rules(&zone.name, &veth_name, net_policy) {
            tracing::warn!(%e, zone = zone.name, "failed to apply nftables rules — network filtering inactive");
        }
        Ok(())
    }

    /// Sync the ZONE_ALLOWED_COMMS BPF map for defense-in-depth.
    ///
    /// Revokes any previously allowed comms for this zone that are no longer
    /// in the policy, then adds the current allowed set. This ensures
    /// hot-reload actually revokes permissions when zones are removed from
    /// `allowed_zones`.
    fn sync_bpf_allowed_comms(
        &self,
        bpf: &mut aya::Bpf,
        zone_id: u32,
        net_policy: &NetworkPolicy,
    ) -> Result<()> {
        let zone_names = self.zone_name_map.lock().unwrap_or_else(|_| { tracing::error!("mutex poisoned"); std::process::abort() });
        let zone_ids = self.zone_id_map.lock().unwrap_or_else(|_| { tracing::error!("mutex poisoned"); std::process::abort() });

        // Collect the set of peer zone_ids that should be allowed.
        let mut allowed_peer_ids: std::collections::HashSet<u32> = std::collections::HashSet::new();
        for allowed_zone_name in &net_policy.allowed_zones {
            if let Some(peer_uuid) = zone_names.get(allowed_zone_name) {
                if let Some(&peer_zone_id) = zone_ids.get(peer_uuid) {
                    allowed_peer_ids.insert(peer_zone_id);
                }
            }
        }

        // Revoke comms for all known zones that are NOT in the allowed set.
        // This handles the hot-reload case where a zone is removed from allowed_zones.
        for &peer_zone_id in zone_ids.values() {
            if peer_zone_id == zone_id {
                continue;
            }
            if !allowed_peer_ids.contains(&peer_zone_id) {
                if let Err(e) = MapManager::deny_zone_comm(bpf, zone_id, peer_zone_id) {
                    tracing::warn!(%e, zone_id, peer_zone_id, "failed to revoke zone comm");
                }
                if let Err(e) = MapManager::deny_zone_comm(bpf, peer_zone_id, zone_id) {
                    tracing::warn!(%e, zone_id, peer_zone_id, "failed to revoke reverse zone comm");
                }
            }
        }

        // Add the currently allowed comms.
        for &peer_zone_id in &allowed_peer_ids {
            if let Err(e) = MapManager::allow_zone_comm(bpf, zone_id, peer_zone_id) {
                tracing::warn!(%e, zone_id, peer_zone_id, "failed to allow zone comm in BPF map");
            }
            if let Err(e) = MapManager::allow_zone_comm(bpf, peer_zone_id, zone_id) {
                tracing::warn!(%e, zone_id, peer_zone_id, "failed to allow reverse zone comm in BPF map");
            }
        }

        Ok(())
    }
}

/// Find the rauha-shim binary.
fn find_shim_binary() -> Result<PathBuf> {
    let project_root = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap_or_else(|| std::path::Path::new("."))
        .to_path_buf();

    let candidates = [
        // Same directory as the running binary.
        std::env::current_exe()
            .ok()
            .and_then(|p| p.parent().map(|d| d.join("rauha-shim"))),
        // Development build paths (debug + release).
        Some(project_root.join("target/debug/rauha-shim")),
        Some(project_root.join("target/release/rauha-shim")),
        // System paths.
        Some(PathBuf::from("/usr/local/bin/rauha-shim")),
        Some(PathBuf::from("/usr/bin/rauha-shim")),
    ];

    for candidate in candidates.iter().flatten() {
        if candidate.exists() {
            return Ok(candidate.clone());
        }
    }

    Err(RauhaError::ShimError {
        zone: String::new(),
        message: "rauha-shim binary not found".into(),
    })
}

impl IsolationBackend for LinuxBackend {
    fn recover_zone(&self, zone: &ZoneHandle, zone_type: ZoneType, policy: &ZonePolicy) -> Result<()> {
        tracing::info!(zone = zone.name, "recovering zone state from metadata");

        // Allocate a compact zone_id (these are ephemeral, not persisted).
        let zone_id = self.allocate_zone_id(zone.id);
        self.zone_name_map
            .lock()
            .unwrap_or_else(|_| { tracing::error!("mutex poisoned"); std::process::abort() })
            .insert(zone.name.clone(), zone.id);

        // Re-create cgroup if missing (idempotent).
        let cgroup_id = if self.cgroup.zone_cgroup_exists(&zone.name) {
            self.cgroup.cgroup_id_for_zone(&zone.name)?
        } else {
            self.cgroup.create_zone_cgroup(&zone.name)?
        };

        // Re-apply resource limits.
        if let Err(e) = self.cgroup.apply_resources(&zone.name, &policy.resources) {
            tracing::warn!(%e, zone = zone.name, "failed to re-apply resource limits during recovery");
        }

        // Re-register IP in allocator if zone has network state.
        if let Some(ref net_state) = zone.network_state {
            self.ip_allocator.lock().unwrap_or_else(|_| { tracing::error!("mutex poisoned"); std::process::abort() }).mark_allocated(net_state.ip());
        }

        // Re-create netns if missing (idempotent).
        if !namespace::netns_exists(&zone.name) {
            if let Err(e) = namespace::create_netns(&zone.name) {
                tracing::warn!(%e, zone = zone.name, "failed to re-create netns during recovery");
            }
            // Re-create veth pair with IP if we had to recreate the namespace.
            if let Err(e) = network::create_veth_pair(&zone.name, zone.network_state.as_ref()) {
                tracing::warn!(%e, zone = zone.name, "failed to re-create veth pair during recovery");
            }
        }

        // Re-populate BPF maps.
        if let Ok(ref mut ebpf_guard) = self.ebpf.lock() {
            if let Some(ref mut ebpf) = **ebpf_guard {
                let bpf = ebpf.bpf_mut();
                if let Err(e) = MapManager::add_zone_member(bpf, cgroup_id, zone_id, zone_type) {
                    tracing::warn!(%e, zone = zone.name, "failed to re-add zone to BPF map during recovery");
                }
                if let Err(e) = MapManager::set_zone_policy(bpf, zone_id, policy) {
                    tracing::warn!(%e, zone = zone.name, "failed to re-set zone policy during recovery");
                }
            }
        }

        tracing::info!(zone = zone.name, zone_id, cgroup_id, "zone recovered");
        Ok(())
    }

    fn cleanup_orphans(&self, known_zones: &[ZoneHandle]) -> Result<()> {
        let known_names: std::collections::HashSet<&str> =
            known_zones.iter().map(|z| z.name.as_str()).collect();

        // Clean up orphaned cgroups under rauha.slice/.
        let slice_path = std::path::Path::new("/sys/fs/cgroup/rauha.slice");
        if slice_path.exists() {
            if let Ok(entries) = std::fs::read_dir(slice_path) {
                for entry in entries.flatten() {
                    let name = entry.file_name();
                    let name_str = name.to_string_lossy();
                    if let Some(zone_name) = name_str.strip_prefix("zone-") {
                        if !known_names.contains(zone_name) {
                            tracing::warn!(cgroup = %name_str, "cleaning up orphaned cgroup");
                            let _ = self.cgroup.destroy_zone_cgroup(zone_name);
                        }
                    }
                }
            }
        }

        // Clean up orphaned network namespaces.
        let netns_dir = std::path::Path::new("/var/run/netns");
        if netns_dir.exists() {
            if let Ok(entries) = std::fs::read_dir(netns_dir) {
                for entry in entries.flatten() {
                    let name = entry.file_name();
                    let name_str = name.to_string_lossy();
                    if let Some(zone_name) = name_str.strip_prefix("rauha-") {
                        if !known_names.contains(zone_name) {
                            tracing::warn!(netns = %name_str, "cleaning up orphaned netns");
                            let _ = namespace::destroy_netns(zone_name);
                        }
                    }
                }
            }
        }

        Ok(())
    }

    fn create_zone(&self, config: &ZoneConfig) -> Result<ZoneHandle> {
        tracing::info!(zone = config.name, backend = "linux-ebpf", "creating zone");

        let zone_uuid = Uuid::new_v4();
        let zone_id = self.allocate_zone_id(zone_uuid);

        // Track zone name → uuid mapping.
        self.zone_name_map
            .lock()
            .unwrap_or_else(|_| { tracing::error!("mutex poisoned"); std::process::abort() })
            .insert(config.name.clone(), zone_uuid);

        // Step 1: Create cgroup.
        let cgroup_id = match self.cgroup.create_zone_cgroup(&config.name) {
            Ok(id) => id,
            Err(e) => {
                self.remove_zone_id(&zone_uuid);
                return Err(e);
            }
        };

        // Step 2: Create network namespace + veth with IP assignment.
        let net_state = if config.policy.network.mode != NetworkMode::Host {
            // Allocate an IP for this zone.
            let ip_state = {
                let mut alloc = self.ip_allocator.lock().unwrap_or_else(|_| { tracing::error!("mutex poisoned"); std::process::abort() });
                let ip = alloc.allocate()?;
                ZoneNetworkState {
                    ip: ip.octets(),
                    gateway: alloc.gateway().octets(),
                    prefix_len: alloc.prefix_len(),
                }
            };

            namespace::create_netns(&config.name).map_err(|e| {
                tracing::error!(%e, zone = config.name, "failed to create netns for bridged zone");
                e
            })?;
            if let Err(e) = network::create_veth_pair(&config.name, Some(&ip_state)) {
                tracing::warn!(%e, zone = config.name, "failed to create veth pair — zone will have limited networking");
            }

            Some(ip_state)
        } else {
            // Host mode: zone shares the host's network stack.
            // No network namespace or veth pair — the zone's processes use
            // the host interfaces directly.
            None
        };

        // Step 3: Populate BPF maps.
        if let Ok(ref mut ebpf_guard) = self.ebpf.lock() {
            if let Some(ref mut ebpf) = **ebpf_guard {
                let bpf = ebpf.bpf_mut();

                if let Err(e) =
                    MapManager::add_zone_member(bpf, cgroup_id, zone_id, config.zone_type)
                {
                    tracing::warn!(%e, "failed to add zone to BPF membership map");
                }

                if let Err(e) = MapManager::set_zone_policy(bpf, zone_id, &config.policy) {
                    tracing::warn!(%e, "failed to set zone policy in BPF map");
                }
            }
        }

        // Step 4: Apply cgroup resource limits.
        if let Err(e) = self.cgroup.apply_resources(&config.name, &config.policy.resources) {
            tracing::warn!(%e, zone = config.name, "failed to apply resource limits");
        }

        tracing::info!(
            zone = config.name,
            zone_id,
            cgroup_id,
            "zone created"
        );

        Ok(ZoneHandle {
            id: zone_uuid,
            name: config.name.clone(),
            platform_id: cgroup_id,
            network_state: net_state,
        })
    }

    fn destroy_zone(&self, zone: &ZoneHandle) -> Result<()> {
        tracing::info!(zone = zone.name, "destroying zone");

        // Shut down shim if running.
        {
            let mut conns = self.shim_connections.lock().unwrap_or_else(|_| { tracing::error!("mutex poisoned"); std::process::abort() });
            if let Some(conn) = conns.remove(&zone.name) {
                let _ = conn.send_request(&ShimRequest::Shutdown);
            }
        }

        // Remove from BPF maps first.
        let zone_id = self.remove_zone_id(&zone.id);
        // Remove stored inodes from BPF map (uses stored list, no re-walk).
        let stored_inodes = self
            .registered_inodes
            .lock()
            .unwrap_or_else(|_| { tracing::error!("mutex poisoned"); std::process::abort() })
            .remove(&zone.name)
            .unwrap_or_default();

        if let (Some(zone_id), Ok(ref mut ebpf_guard)) = (zone_id, self.ebpf.lock()) {
            if let Some(ref mut ebpf) = **ebpf_guard {
                let bpf = ebpf.bpf_mut();

                if !stored_inodes.is_empty() {
                    if let Err(e) = MapManager::remove_inodes(bpf, &stored_inodes) {
                        tracing::warn!(%e, zone = zone.name, "failed to unregister rootfs inodes");
                    }
                }

                let _ = MapManager::remove_zone_member(bpf, zone.platform_id);
                let _ = MapManager::remove_zone_policy(bpf, zone_id);
            }
        }

        // Release IP back to allocator.
        if let Some(ref net_state) = zone.network_state {
            let mut alloc = self.ip_allocator.lock().unwrap_or_else(|_| { tracing::error!("mutex poisoned"); std::process::abort() });
            alloc.release(net_state.ip());
        }

        // Remove nftables rules for this zone.
        if let Err(e) = nftables::remove_zone_rules(&zone.name) {
            tracing::warn!(%e, zone = zone.name, "failed to remove nftables rules");
        }

        // Tear down network.
        let _ = network::destroy_veth_pair(&zone.name);
        let _ = namespace::destroy_netns(&zone.name);

        // Destroy cgroup last (must be empty).
        self.cgroup.destroy_zone_cgroup(&zone.name)?;

        self.zone_name_map.lock().unwrap_or_else(|_| { tracing::error!("mutex poisoned"); std::process::abort() }).remove(&zone.name);

        // Clean up shim socket.
        let socket_path = Self::shim_socket_path(&zone.name);
        let _ = std::fs::remove_file(&socket_path);

        tracing::info!(zone = zone.name, "zone destroyed");
        Ok(())
    }

    fn enforce_policy(&self, zone: &ZoneHandle, policy: &ZonePolicy) -> Result<()> {
        tracing::info!(zone = zone.name, "enforcing policy");

        // Update BPF policy map.
        if let Some(zone_id) = self.get_zone_id(&zone.id) {
            if let Ok(ref mut ebpf_guard) = self.ebpf.lock() {
                if let Some(ref mut ebpf) = **ebpf_guard {
                    MapManager::set_zone_policy(ebpf.bpf_mut(), zone_id, policy)?;

                    // Wire up ZONE_ALLOWED_COMMS BPF map for defense-in-depth.
                    self.sync_bpf_allowed_comms(ebpf.bpf_mut(), zone_id, &policy.network)?;
                }
            }
        }

        // Apply nftables forward rules for this zone.
        self.apply_nftables_for_zone(zone, &policy.network)?;

        // Update cgroup resource limits.
        self.cgroup.apply_resources(&zone.name, &policy.resources)?;

        Ok(())
    }

    fn hot_reload_policy(&self, zone: &ZoneHandle, policy: &ZonePolicy) -> Result<()> {
        tracing::info!(zone = zone.name, "hot-reloading policy");

        // BPF HashMap insert is atomic — kernel sees old or new, never partial.
        if let Some(zone_id) = self.get_zone_id(&zone.id) {
            if let Ok(ref mut ebpf_guard) = self.ebpf.lock() {
                if let Some(ref mut ebpf) = **ebpf_guard {
                    MapManager::hot_reload_policy(ebpf.bpf_mut(), zone_id, policy)?;

                    // Re-sync allowed comms on hot reload.
                    self.sync_bpf_allowed_comms(ebpf.bpf_mut(), zone_id, &policy.network)?;
                }
            }
        }

        // Re-apply nftables rules.
        self.apply_nftables_for_zone(zone, &policy.network)?;

        // Update cgroup limits.
        self.cgroup.apply_resources(&zone.name, &policy.resources)?;

        Ok(())
    }

    fn create_container(&self, zone: &ZoneHandle, spec: &ContainerSpec) -> Result<ContainerHandle> {
        tracing::info!(
            zone = zone.name,
            container = spec.name,
            "creating container"
        );

        // Ensure shim is running for this zone.
        self.ensure_shim(&zone.name)?;

        let container_id = Uuid::new_v4();

        // Prepare rootfs for this container.
        // If overlay_layers is available, mount overlayfs (O(1) creation).
        // Otherwise, fall back to copying the base rootfs.
        let container_dir = PathBuf::from(&self.root)
            .join("zones")
            .join(&zone.name)
            .join("containers")
            .join(container_id.to_string());

        let rootfs_dir = if let Some(ref overlay_layers) = spec.overlay_layers {
            let snapshotter = rauha_oci::snapshotter::OverlayfsSnapshotter::new(
                &PathBuf::from(&self.root).join("zones").join(&zone.name),
            );
            snapshotter.mount_overlay(
                &container_id.to_string(),
                overlay_layers,
                &container_dir,
            )?
        } else if let Some(ref base_rootfs) = spec.rootfs_path {
            let rootfs_dir = container_dir.join("rootfs");
            copy_dir_recursive(base_rootfs, &rootfs_dir)?;
            rootfs_dir
        } else {
            let rootfs_dir = container_dir.join("rootfs");
            std::fs::create_dir_all(&rootfs_dir).map_err(|e| RauhaError::RootfsError {
                message: format!("failed to create rootfs dir: {e}"),
            })?;
            rootfs_dir
        };

        // Write resolv.conf for DNS resolution inside the container.
        let resolv_conf_path = rootfs_dir.join("etc").join("resolv.conf");
        if let Some(parent) = resolv_conf_path.parent() {
            let _ = std::fs::create_dir_all(parent);
        }
        let resolv_content = crate::network::dns::generate_resolv_conf();
        if let Err(e) = std::fs::write(&resolv_conf_path, &resolv_content) {
            tracing::warn!(%e, "failed to write resolv.conf — DNS may not work inside container");
        }

        // Generate OCI runtime spec.
        let spec_json = serde_json::to_string(
            &oci_spec::runtime::SpecBuilder::default()
                .version("1.0.2")
                .root(
                    oci_spec::runtime::RootBuilder::default()
                        .path(rootfs_dir.to_string_lossy().as_ref())
                        .readonly(false)
                        .build()
                        .unwrap(),
                )
                .process(
                    oci_spec::runtime::ProcessBuilder::default()
                        .args(if spec.command.is_empty() {
                            vec!["/bin/sh".to_string()]
                        } else {
                            spec.command.clone()
                        })
                        .env(
                            spec.env
                                .iter()
                                .map(|(k, v)| format!("{k}={v}"))
                                .chain(std::iter::once(
                                    "PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin".into(),
                                ))
                                .collect::<Vec<_>>(),
                        )
                        .cwd(spec.working_dir.as_deref().unwrap_or("/"))
                        .terminal(false)
                        .build()
                        .unwrap(),
                )
                .hostname(spec.name.clone())
                .build()
                .unwrap(),
        )
        .map_err(|e| RauhaError::BackendError(format!("failed to serialize spec: {e}")))?;

        // Register rootfs inodes in BPF map for file isolation.
        // Phase 1: Collect inodes from filesystem (no lock, may be slow for large rootfs).
        // Phase 2: Insert into BPF map (short lock hold).
        if let Some(zone_id) = self.get_zone_id(&zone.id) {
            let is_overlay = rootfs_dir.ends_with("merged");
            tracing::debug!(
                zone = zone.name,
                path = %rootfs_dir.display(),
                overlay = is_overlay,
                "collecting rootfs inodes for BPF file isolation"
            );

            let inodes = maps::collect_rootfs_inodes(
                &rootfs_dir,
                rauha_ebpf_common::MAX_INODES,
            );

            if !inodes.is_empty() {
                if let Ok(ref mut ebpf_guard) = self.ebpf.lock() {
                    if let Some(ref mut ebpf) = **ebpf_guard {
                        match MapManager::insert_inodes(ebpf.bpf_mut(), &inodes, zone_id) {
                            Ok(inserted) => {
                                // Store only successfully inserted inodes for cleanup.
                                // This prevents removing entries that were never in the map.
                                lock_or_abort(&self.registered_inodes)
                                    .entry(zone.name.clone())
                                    .or_default()
                                    .extend_from_slice(&inserted);
                                tracing::info!(
                                    zone = zone.name,
                                    container = %container_id,
                                    count = inserted.len(),
                                    collected = inodes.len(),
                                    "registered container rootfs inodes in BPF map"
                                );
                            }
                            Err(e) => {
                                tracing::warn!(
                                    %e,
                                    zone = zone.name,
                                    container = %container_id,
                                    "failed to register rootfs inodes — file isolation incomplete"
                                );
                            }
                        }
                    }
                }
            }
        }

        // Send CreateContainer to shim.
        let response = self.shim_request(
            &zone.name,
            &ShimRequest::CreateContainer {
                id: container_id.to_string(),
                spec_json,
            },
        )?;

        match response {
            ShimResponse::Created { pid } => Ok(ContainerHandle {
                id: container_id,
                zone_id: zone.id,
                pid,
                platform_id: 0,
            }),
            ShimResponse::Ok => Ok(ContainerHandle {
                id: container_id,
                zone_id: zone.id,
                pid: 0,
                platform_id: 0,
            }),
            ShimResponse::Error { message } => Err(RauhaError::ShimError {
                zone: zone.name.clone(),
                message,
            }),
            _ => Err(RauhaError::ShimError {
                zone: zone.name.clone(),
                message: "unexpected shim response".into(),
            }),
        }
    }

    fn start_container(&self, container: &ContainerHandle) -> Result<u32> {
        tracing::info!(container = %container.id, "starting container");

        // Look up zone name for this container.
        let zone_name = self
            .zone_name_map
            .lock()
            .unwrap_or_else(|_| { tracing::error!("mutex poisoned"); std::process::abort() })
            .iter()
            .find(|(_, uuid)| **uuid == container.zone_id)
            .map(|(name, _)| name.clone())
            .ok_or_else(|| RauhaError::ShimError {
                zone: container.zone_id.to_string(),
                message: "zone not found for container".into(),
            })?;

        let response = self.shim_request(
            &zone_name,
            &ShimRequest::StartContainer {
                id: container.id.to_string(),
            },
        )?;

        match response {
            ShimResponse::Created { pid } => Ok(pid),
            ShimResponse::Error { message } => Err(RauhaError::ContainerExecError {
                container: container.id.to_string(),
                message,
            }),
            other => Err(RauhaError::ShimError {
                zone: zone_name,
                message: format!("unexpected response to StartContainer: {other:?}"),
            }),
        }
    }

    fn stop_container(&self, container: &ContainerHandle) -> Result<()> {
        tracing::info!(container = %container.id, "stopping container");

        let zone_name = self
            .zone_name_map
            .lock()
            .unwrap_or_else(|_| { tracing::error!("mutex poisoned"); std::process::abort() })
            .iter()
            .find(|(_, uuid)| **uuid == container.zone_id)
            .map(|(name, _)| name.clone())
            .ok_or_else(|| RauhaError::ShimError {
                zone: container.zone_id.to_string(),
                message: "zone not found for container".into(),
            })?;

        // Send SIGTERM first.
        let response = self.shim_request(
            &zone_name,
            &ShimRequest::StopContainer {
                id: container.id.to_string(),
                signal: 15, // SIGTERM
            },
        )?;

        match response {
            ShimResponse::Ok => Ok(()),
            ShimResponse::Error { message } => {
                tracing::warn!(container = %container.id, %message, "SIGTERM failed, trying SIGKILL");
                // Try SIGKILL as fallback.
                let _ = self.shim_request(
                    &zone_name,
                    &ShimRequest::Signal {
                        id: container.id.to_string(),
                        signal: 9, // SIGKILL
                    },
                );
                Ok(())
            }
            _ => Ok(()),
        }
    }

    fn zone_stats(&self, zone: &ZoneHandle) -> Result<ZoneStats> {
        self.cgroup.read_stats(&zone.name, zone.id)
    }

    fn verify_isolation(&self, zone: &ZoneHandle) -> Result<IsolationReport> {
        let mut checks = Vec::new();

        // Check 1: cgroup exists.
        let cgroup_ok = self.cgroup.zone_cgroup_exists(&zone.name);
        checks.push(IsolationCheck {
            name: "cgroup".into(),
            passed: cgroup_ok,
            detail: if cgroup_ok {
                "zone cgroup exists".into()
            } else {
                "zone cgroup missing — zone is not resource-limited".into()
            },
        });

        // Check 2: eBPF programs loaded.
        let ebpf_ok = if let Ok(ref ebpf_guard) = self.ebpf.lock() {
            if let Some(ref ebpf) = **ebpf_guard {
                match ebpf.health_check() {
                    Ok(statuses) => {
                        let all_ok = statuses.iter().all(|s| s.loaded && s.attached);
                        for status in &statuses {
                            let passed = status.loaded && status.attached;
                            let detail = if status.loaded && status.attached {
                                "program loaded and attached".into()
                            } else if status.loaded {
                                "program loaded but detached from hook — restart rauhad to re-attach".into()
                            } else {
                                "program not loaded — zone boundary not enforced".into()
                            };
                            checks.push(IsolationCheck {
                                name: format!("ebpf:{}", status.name),
                                passed,
                                detail,
                            });
                        }
                        all_ok
                    }
                    Err(e) => {
                        checks.push(IsolationCheck {
                            name: "ebpf:health".into(),
                            passed: false,
                            detail: format!("health check failed: {e}"),
                        });
                        false
                    }
                }
            } else {
                checks.push(IsolationCheck {
                    name: "ebpf".into(),
                    passed: false,
                    detail: "eBPF not loaded — no kernel enforcement".into(),
                });
                false
            }
        } else {
            false
        };

        // Check 3: zone membership in BPF map.
        let membership_ok = self.get_zone_id(&zone.id).is_some();
        checks.push(IsolationCheck {
            name: "bpf_membership".into(),
            passed: membership_ok,
            detail: if membership_ok {
                "zone registered in BPF membership map".into()
            } else {
                "zone not in BPF map — kernel cannot identify zone processes".into()
            },
        });

        // Check 4: network namespace.
        let netns_ok = namespace::netns_exists(&zone.name);
        checks.push(IsolationCheck {
            name: "netns".into(),
            passed: netns_ok,
            detail: if netns_ok {
                "network namespace exists".into()
            } else {
                "network namespace missing — network not isolated".into()
            },
        });

        // Check 5: enforcement counters — detect silent enforcement failure.
        if let Ok(ref ebpf_guard) = self.ebpf.lock() {
            if let Some(ref ebpf) = **ebpf_guard {
                if let Ok(counters) = ebpf.read_enforcement_counters() {
                    for (name, c) in &counters {
                        if c.error > 0 && c.deny == 0 {
                            checks.push(IsolationCheck {
                                name: format!("enforcement:{name}"),
                                passed: false,
                                detail: format!(
                                    "hook has {} errors and 0 denials — enforcement may be silently failing",
                                    c.error
                                ),
                            });
                        } else if c.allow > 0 || c.deny > 0 {
                            checks.push(IsolationCheck {
                                name: format!("enforcement:{name}"),
                                passed: true,
                                detail: format!(
                                    "allow={}, deny={}, error={}",
                                    c.allow, c.deny, c.error
                                ),
                            });
                        }
                    }
                }
            }
        }

        let is_isolated = cgroup_ok && ebpf_ok && membership_ok && netns_ok;

        Ok(IsolationReport {
            zone_id: zone.id,
            model: IsolationModel::SyscallPolicy,
            is_isolated,
            checks,
        })
    }

    fn isolation_model(&self) -> IsolationModel {
        IsolationModel::SyscallPolicy
    }

    fn name(&self) -> &str {
        "linux-ebpf"
    }
}

/// Recursively copy a directory tree, preserving symlinks and file permissions.
///
/// Uses `symlink_metadata` to avoid following symlinks (OCI rootfs trees
/// commonly contain symlinks that must be preserved as-is).
fn copy_dir_recursive(src: &std::path::Path, dst: &std::path::Path) -> Result<()> {
    std::fs::create_dir_all(dst).map_err(|e| RauhaError::RootfsError {
        message: format!("failed to create dir {}: {e}", dst.display()),
    })?;

    for entry in std::fs::read_dir(src).map_err(|e| RauhaError::RootfsError {
        message: format!("failed to read dir {}: {e}", src.display()),
    })? {
        let entry = entry.map_err(|e| RauhaError::RootfsError {
            message: format!("failed to read entry: {e}"),
        })?;
        let src_path = entry.path();
        let dst_path = dst.join(entry.file_name());

        // Use symlink_metadata to detect symlinks without following them.
        let meta = std::fs::symlink_metadata(&src_path).map_err(|e| RauhaError::RootfsError {
            message: format!("failed to stat {}: {e}", src_path.display()),
        })?;

        if meta.is_symlink() {
            let link_target =
                std::fs::read_link(&src_path).map_err(|e| RauhaError::RootfsError {
                    message: format!("failed to read symlink {}: {e}", src_path.display()),
                })?;
            std::os::unix::fs::symlink(&link_target, &dst_path).map_err(|e| {
                RauhaError::RootfsError {
                    message: format!(
                        "failed to create symlink {} → {}: {e}",
                        dst_path.display(),
                        link_target.display()
                    ),
                }
            })?;
        } else if meta.is_dir() {
            copy_dir_recursive(&src_path, &dst_path)?;
        } else {
            std::fs::copy(&src_path, &dst_path).map_err(|e| RauhaError::RootfsError {
                message: format!(
                    "failed to copy {} → {}: {e}",
                    src_path.display(),
                    dst_path.display()
                ),
            })?;
        }
    }

    // Preserve directory permissions.
    if let Ok(metadata) = std::fs::symlink_metadata(src) {
        let _ = std::fs::set_permissions(dst, metadata.permissions());
    }

    Ok(())
}
