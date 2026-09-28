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
mod enforcer;
pub mod events;
mod maps;
mod namespace;
mod network;
pub(crate) mod nftables;

/// Clean up Linux network state (nftables table + bridge).
/// Called during daemon shutdown.
pub fn cleanup_network(bridge: &str) {
    if let Err(e) = nftables::cleanup_nat() {
        tracing::warn!(%e, "failed to clean up nftables table");
    }
    if let Err(e) = network::destroy_bridge(bridge) {
        tracing::warn!(%e, "failed to destroy network bridge");
    }
}

use std::collections::{BTreeSet, HashMap};
use std::os::unix::fs::MetadataExt;
use std::os::unix::net::UnixStream;
use std::path::{Component, Path, PathBuf};
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
use self::enforcer::LinuxEnforcer;
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
        let mut stream =
            UnixStream::connect(&self.socket_path).map_err(|e| RauhaError::ShimError {
                zone: self.socket_path.display().to_string(),
                message: format!("failed to connect to shim: {e}"),
            })?;

        stream.set_read_timeout(Some(Duration::from_secs(30))).ok();
        stream.set_write_timeout(Some(Duration::from_secs(10))).ok();

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

/// Lock backend state, failing closed if the protected data may be corrupt.
fn lock_backend<'a, T>(mutex: &'a Mutex<T>, name: &str) -> Result<MutexGuard<'a, T>> {
    mutex.lock().map_err(|_| {
        tracing::error!(state = name, "mutex poisoned — refusing backend operation");
        RauhaError::BackendError(format!("linux backend state poisoned: {name}"))
    })
}

/// Linux isolation backend using eBPF LSM + namespaces + cgroups.
pub struct LinuxBackend {
    root: String,
    /// Linux kernel enforcement adapter.
    enforcer: LinuxEnforcer,
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
    /// Last admitted policy per zone. Container construction must use the same
    /// capability allow-list that was installed in the kernel policy map.
    zone_policies: Mutex<HashMap<String, ZonePolicy>>,
    /// Runtime controls that audit admission allowed to degrade.
    zone_degradations: Mutex<HashMap<String, BTreeSet<String>>>,
    /// IP address allocator for zone networking.
    ip_allocator: Mutex<IpAllocator>,
    /// Daemon configuration (never hardcode: paths, subnet, DNS, capacities
    /// all come from here).
    config: std::sync::Arc<crate::config::DaemonConfig>,
}

impl LinuxBackend {
    pub fn new(root: &str, config: std::sync::Arc<crate::config::DaemonConfig>) -> Result<Self> {
        let cgroup = CgroupManager::new()?;
        let (subnet_octets, prefix_len) = config.subnet_octets()?;
        let ip_allocator = IpAllocator::new(subnet_octets, prefix_len);
        let bridge = config.network.bridge.as_str();

        let enforcer = LinuxEnforcer::new(root, &config.paths.bpf_pin_dir)?;

        // Ensure the network bridge exists with a gateway IP.
        if let Err(e) =
            network::ensure_bridge(ip_allocator.gateway(), ip_allocator.prefix_len(), bridge)
        {
            tracing::warn!(%e, "failed to create network bridge — zones will have no networking");
        }

        // Set up NAT masquerade for zone traffic.
        let subnet_cidr = {
            let s = ip_allocator.subnet();
            format!(
                "{}.{}.{}.{}/{}",
                s[0],
                s[1],
                s[2],
                s[3],
                ip_allocator.prefix_len()
            )
        };
        nftables::ensure_nat(&subnet_cidr, bridge)?;

        Ok(Self {
            root: root.into(),
            enforcer,
            cgroup,
            next_zone_id: AtomicU32::new(1), // 0 is reserved for "no zone".
            zone_id_map: Mutex::new(HashMap::new()),
            zone_name_map: Mutex::new(HashMap::new()),
            shim_connections: Mutex::new(HashMap::new()),
            registered_inodes: Mutex::new(HashMap::new()),
            zone_policies: Mutex::new(HashMap::new()),
            zone_degradations: Mutex::new(HashMap::new()),
            ip_allocator: Mutex::new(ip_allocator),
            config,
        })
    }

    /// Get a clone of the enforcement event broadcast sender, if available.
    pub fn event_sender(
        &self,
    ) -> Option<tokio::sync::broadcast::Sender<rauha_evidence::FalseEvent>> {
        self.enforcer.event_sender()
    }

    /// Allocate a new compact zone_id for BPF maps.
    fn allocate_zone_id(&self, uuid: Uuid) -> Result<u32> {
        let id = self.next_zone_id.fetch_add(1, Ordering::Relaxed);
        lock_backend(&self.zone_id_map, "zone_id_map")?.insert(uuid, id);
        Ok(id)
    }

    /// Look up the compact zone_id for a Uuid.
    fn get_zone_id(&self, uuid: &Uuid) -> Result<Option<u32>> {
        Ok(lock_backend(&self.zone_id_map, "zone_id_map")?
            .get(uuid)
            .copied())
    }

    /// Remove zone_id mapping.
    fn remove_zone_id(&self, uuid: &Uuid) -> Result<Option<u32>> {
        Ok(lock_backend(&self.zone_id_map, "zone_id_map")?.remove(uuid))
    }

    /// Get the socket path for a zone's shim.
    fn shim_socket_path(&self, zone_name: &str) -> PathBuf {
        PathBuf::from(&self.config.paths.run_dir).join(format!("shim-{zone_name}.sock"))
    }

    /// Ensure a shim process is running for a zone, spawning one if needed.
    fn ensure_shim(&self, zone_name: &str) -> Result<()> {
        let socket_path = self.shim_socket_path(zone_name);

        // Check if shim is already connected and responsive.
        {
            let conns = lock_backend(&self.shim_connections, "shim_connections")?;
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

        // Ensure the runtime dir exists.
        std::fs::create_dir_all(&self.config.paths.run_dir).ok();

        let shim_bin = find_shim_binary()?;

        Command::new(&shim_bin)
            .env("RAUHA_RUN_DIR", &self.config.paths.run_dir)
            .env("RAUHA_CRUN", &self.config.executor.crun)
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
        lock_backend(&self.shim_connections, "shim_connections")?
            .insert(zone_name.to_string(), conn);

        tracing::info!(zone = zone_name, "shim spawned");
        Ok(())
    }

    /// Send a request to a zone's shim.
    fn shim_request(&self, zone_name: &str, request: &ShimRequest) -> Result<ShimResponse> {
        let conns = lock_backend(&self.shim_connections, "shim_connections")?;
        let conn = conns.get(zone_name).ok_or_else(|| RauhaError::ShimError {
            zone: zone_name.into(),
            message: "no shim connection".into(),
        })?;
        conn.send_request(request)
    }

    /// Apply nftables forward rules for a zone based on its network policy.
    fn apply_nftables_for_zone(&self, zone: &ZoneHandle, policy: &ZonePolicy) -> Result<()> {
        let veth_name = network::veth_host_name_for(&zone.name);

        match nftables::apply_zone_rules(&zone.name, &veth_name, &policy.network) {
            Ok(()) => self.clear_degradation(&zone.name, "network:nftables")?,
            Err(e) if policy.admission == PolicyAdmission::Strict => return Err(e),
            Err(e) => {
                self.record_degradation(&zone.name, "network:nftables")?;
                tracing::warn!(%e, zone = zone.name, admission = "audit", status = "unsupported", "network filtering inactive");
            }
        }
        Ok(())
    }

    fn record_degradation(&self, zone_name: &str, control: &str) -> Result<()> {
        lock_backend(&self.zone_degradations, "zone_degradations")?
            .entry(zone_name.to_string())
            .or_default()
            .insert(control.to_string());
        Ok(())
    }

    fn clear_degradation(&self, zone_name: &str, control: &str) -> Result<()> {
        if let Some(controls) =
            lock_backend(&self.zone_degradations, "zone_degradations")?.get_mut(zone_name)
        {
            controls.remove(control);
        }
        Ok(())
    }

    fn restore_rootfs_inodes(&self, zone_name: &str, zone_id: u32) -> Result<()> {
        let expected = collect_zone_rootfs_inodes(&self.root, zone_name)?;
        if expected.is_empty() && self.cgroup.zone_has_processes(zone_name)? {
            return Err(RauhaError::BackendError(
                "live recovered zone has no discoverable rootfs inodes".into(),
            ));
        }
        let inserted = self.enforcer.insert_inodes(&expected, zone_id)?;
        lock_backend(&self.registered_inodes, "registered_inodes")?
            .insert(zone_name.to_string(), inserted.clone());
        if inserted.len() != expected.len() {
            return Err(RauhaError::BackendError(format!(
                "rootfs inode recovery incomplete: registered {} of {}",
                inserted.len(),
                expected.len()
            )));
        }
        Ok(())
    }

    /// Sync the ZONE_ALLOWED_COMMS BPF map for defense-in-depth.
    ///
    /// Revokes any previously allowed comms for this zone that are no longer
    /// in the policy, then adds the current allowed set. This ensures
    /// hot-reload actually revokes permissions when zones are removed from
    /// `allowed_zones`.
    fn sync_bpf_allowed_comms(&self, zone_id: u32, net_policy: &NetworkPolicy) -> Result<()> {
        let zone_names = lock_backend(&self.zone_name_map, "zone_name_map")?;
        let zone_ids = lock_backend(&self.zone_id_map, "zone_id_map")?;

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
                self.enforcer.deny_zone_comm(zone_id, peer_zone_id)?;
                self.enforcer.deny_zone_comm(peer_zone_id, zone_id)?;
            }
        }

        // Add the currently allowed comms.
        for &peer_zone_id in &allowed_peer_ids {
            self.enforcer.allow_zone_comm(zone_id, peer_zone_id)?;
            self.enforcer.allow_zone_comm(peer_zone_id, zone_id)?;
        }

        Ok(())
    }
}

fn unsupported_linux_controls(policy: &ZonePolicy, safe_writable_roots: &[String]) -> Vec<String> {
    let mut unsupported = Vec::new();
    if policy
        .filesystem
        .writable_paths
        .iter()
        .any(|path| !safe_writable_path(path, safe_writable_roots))
    {
        unsupported.push("filesystem.writable_paths".to_string());
    }
    if policy
        .devices
        .allowed
        .iter()
        .any(|path| device_numbers(path).is_none())
    {
        unsupported.push("devices.allowed".to_string());
    }
    unsupported
}

fn safe_writable_path(path: &str, safe_writable_roots: &[String]) -> bool {
    let path = Path::new(path);
    path.is_absolute()
        && path != Path::new("/")
        && !safe_writable_roots
            .iter()
            .any(|reserved| path.starts_with(reserved.as_str()))
        && path
            .components()
            .all(|component| matches!(component, Component::RootDir | Component::Normal(_)))
}

fn device_numbers(path: &str) -> Option<(i64, i64)> {
    match path {
        "/dev/null" => Some((1, 3)),
        "/dev/zero" => Some((1, 5)),
        "/dev/full" => Some((1, 7)),
        "/dev/random" => Some((1, 8)),
        "/dev/urandom" => Some((1, 9)),
        _ => None,
    }
}

fn admit_linux_policy(
    policy: &ZonePolicy,
    skipped_hooks: &[String],
    safe_writable_roots: &[String],
) -> Result<()> {
    let mut unsupported = unsupported_linux_controls(policy, safe_writable_roots);
    for hook in skipped_hooks {
        unsupported.push(format!("lsm.{hook}"));
    }

    if unsupported.is_empty() {
        return Ok(());
    }

    let controls = unsupported.join(", ");
    match policy.admission {
        PolicyAdmission::Strict => Err(RauhaError::InvalidPolicy(format!(
            "strict policy requests unsupported or unavailable Linux controls: {controls}"
        ))),
        PolicyAdmission::Audit => {
            tracing::warn!(
                admission = "audit",
                status = "unsupported",
                controls,
                "admitting policy with unsupported controls"
            );
            Ok(())
        }
    }
}

fn oci_capabilities(policy: &ZonePolicy) -> Result<oci_spec::runtime::LinuxCapabilities> {
    use oci_spec::runtime::{Capabilities, Capability, LinuxCapabilitiesBuilder};

    let capabilities = policy
        .capabilities
        .allowed
        .iter()
        .map(|name| {
            let canonical = rauha_common::zone::canonical_linux_capability_name(name);
            canonical
                .strip_prefix("CAP_")
                .ok_or_else(|| RauhaError::InvalidPolicy(format!("unknown capability: {name}")))?
                .parse::<Capability>()
                .map_err(|_| RauhaError::InvalidPolicy(format!("unknown capability: {name}")))
        })
        .collect::<Result<Capabilities>>()?;

    LinuxCapabilitiesBuilder::default()
        .bounding(capabilities.clone())
        .effective(capabilities.clone())
        .inheritable(capabilities.clone())
        .permitted(capabilities.clone())
        .ambient(capabilities)
        .build()
        .map_err(|e| RauhaError::BackendError(format!("failed to build OCI capabilities: {e}")))
}

fn oci_seccomp(policy: &ZonePolicy) -> Result<Option<oci_spec::runtime::LinuxSeccomp>> {
    use oci_spec::runtime::{LinuxSeccompAction, LinuxSeccompBuilder, LinuxSyscallBuilder};

    if policy.syscalls.deny.is_empty() {
        return Ok(None);
    }
    let denied = LinuxSyscallBuilder::default()
        .names(policy.syscalls.deny.clone())
        .action(LinuxSeccompAction::ScmpActErrno)
        .errno_ret(libc::EPERM as u32)
        .build()
        .map_err(|error| {
            RauhaError::BackendError(format!("failed to build OCI seccomp rule: {error}"))
        })?;
    LinuxSeccompBuilder::default()
        .default_action(LinuxSeccompAction::ScmpActAllow)
        .syscalls(vec![denied])
        .build()
        .map(Some)
        .map_err(|error| {
            RauhaError::BackendError(format!("failed to build OCI seccomp profile: {error}"))
        })
}

fn oci_devices(policy: &ZonePolicy) -> Result<Vec<oci_spec::runtime::LinuxDevice>> {
    use oci_spec::runtime::{LinuxDeviceBuilder, LinuxDeviceType};

    policy
        .devices
        .allowed
        .iter()
        .filter_map(|path| device_numbers(path).map(|numbers| (path, numbers)))
        .map(|(path, (major, minor))| {
            LinuxDeviceBuilder::default()
                .path(path)
                .typ(LinuxDeviceType::C)
                .major(major)
                .minor(minor)
                .file_mode(0o666u32)
                .uid(0u32)
                .gid(0u32)
                .build()
                .map_err(|error| {
                    RauhaError::BackendError(format!("failed to build OCI device {path}: {error}"))
                })
        })
        .collect()
}

fn oci_mounts(
    policy: &ZonePolicy,
    rootfs: &Path,
    safe_writable_roots: &[String],
) -> Result<Vec<oci_spec::runtime::Mount>> {
    use oci_spec::runtime::{get_default_mounts, MountBuilder};

    let mut mounts = get_default_mounts();
    // The host cgroup2 hierarchy names every zone and exposes its live
    // counters; the workload has no use for it.
    mounts.retain(|mount| mount.destination() != Path::new("/sys/fs/cgroup"));
    for declared in policy
        .filesystem
        .writable_paths
        .iter()
        .filter(|path| safe_writable_path(path, safe_writable_roots))
    {
        let relative = declared.trim_start_matches('/');
        let mut current = rootfs.to_path_buf();
        for component in Path::new(relative).components() {
            let Component::Normal(component) = component else {
                return Err(RauhaError::InvalidPolicy(format!(
                    "unsafe writable path: {declared}"
                )));
            };
            current.push(component);
            let metadata = std::fs::symlink_metadata(&current).map_err(|error| {
                RauhaError::InvalidPolicy(format!(
                    "writable path {declared} is not present in the image: {error}"
                ))
            })?;
            if metadata.file_type().is_symlink() {
                return Err(RauhaError::InvalidPolicy(format!(
                    "writable path crosses a symlink: {declared}"
                )));
            }
        }
        let metadata = std::fs::metadata(&current).map_err(|error| RauhaError::RootfsError {
            message: format!("failed to inspect writable path {declared}: {error}"),
        })?;
        if !metadata.is_dir() {
            return Err(RauhaError::InvalidPolicy(format!(
                "writable path is not a directory: {declared}"
            )));
        }
        mounts.push(
            MountBuilder::default()
                .destination(declared)
                .typ("tmpfs")
                .source("tmpfs")
                .options(vec![
                    "rw".into(),
                    "nosuid".into(),
                    "nodev".into(),
                    "noexec".into(),
                    format!("mode={:o}", metadata.mode() & 0o7777),
                    "size=65536k".into(),
                ])
                .build()
                .map_err(|error| {
                    RauhaError::BackendError(format!(
                        "failed to build OCI mount {declared}: {error}"
                    ))
                })?,
        );
    }
    Ok(mounts)
}

fn collect_zone_rootfs_inodes(root: &str, zone_name: &str) -> Result<Vec<u64>> {
    let containers = PathBuf::from(root)
        .join("zones")
        .join(zone_name)
        .join("containers");
    if !containers.exists() {
        return Ok(Vec::new());
    }

    let mut inodes = BTreeSet::new();
    let entries = std::fs::read_dir(&containers).map_err(|e| RauhaError::RootfsError {
        message: format!("failed to enumerate {}: {e}", containers.display()),
    })?;
    for entry in entries {
        let container = entry
            .map_err(|e| RauhaError::RootfsError {
                message: format!("failed to enumerate {}: {e}", containers.display()),
            })?
            .path();
        let merged = container.join("merged");
        let legacy = container.join("rootfs");
        let rootfs = if merged.is_dir() {
            merged
        } else if legacy.is_dir() {
            legacy
        } else {
            continue;
        };
        let remaining = rauha_ebpf_common::MAX_INODES.saturating_sub(inodes.len() as u32);
        if remaining == 0 {
            return Err(RauhaError::RootfsError {
                message: format!(
                    "zone rootfs inode count exceeds enforcement capacity of {}",
                    rauha_ebpf_common::MAX_INODES
                ),
            });
        }
        inodes.extend(maps::collect_rootfs_inodes(&rootfs, remaining)?);
    }
    Ok(inodes.into_iter().collect())
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
    fn recover_zone(
        &self,
        zone: &ZoneHandle,
        zone_type: ZoneType,
        policy: &ZonePolicy,
    ) -> Result<()> {
        admit_linux_policy(
            policy,
            &self.enforcer.skipped_hooks(),
            &self.config.policy.safe_writable_roots,
        )?;
        tracing::info!(zone = zone.name, "recovering zone state from metadata");

        // Allocate a compact zone_id (these are ephemeral, not persisted).
        let zone_id = self.allocate_zone_id(zone.id)?;
        let mut recovered_cgroup_id = None;
        let mut ip_marked = false;
        let mut membership_installed = false;
        let recovery = (|| -> Result<()> {
            lock_backend(&self.zone_name_map, "zone_name_map")?.insert(zone.name.clone(), zone.id);

            let cgroup_id = if self.cgroup.zone_cgroup_exists(&zone.name) {
                self.cgroup.cgroup_id_for_zone(&zone.name)?
            } else {
                self.cgroup.create_zone_cgroup(&zone.name)?
            };
            recovered_cgroup_id = Some(cgroup_id);
            self.cgroup.apply_resources(&zone.name, &policy.resources)?;

            if let Some(ref net_state) = zone.network_state {
                let ip = net_state.ip();
                let in_subnet = lock_backend(&self.ip_allocator, "ip_allocator")?.contains(ip);
                if !in_subnet {
                    // The zone was persisted under a different [network]
                    // subnet configuration. Silently skipping the
                    // mark-allocation would leave the zone running with an
                    // unreachable IP and no declaration — fail strict,
                    // declare audit.
                    let err = RauhaError::BackendError(format!(
                        "zone IP {ip} is outside the configured subnet {} — \
                         the [network] subnet changed after this zone was created",
                        self.config.network.subnet
                    ));
                    match policy.admission {
                        PolicyAdmission::Strict => return Err(err),
                        PolicyAdmission::Audit => {
                            self.record_degradation(&zone.name, "network:ip_out_of_subnet")?;
                            tracing::warn!(%err, zone = zone.name, admission = "audit", "recovered zone keeps an out-of-subnet IP");
                        }
                    }
                } else {
                    lock_backend(&self.ip_allocator, "ip_allocator")?.mark_allocated(ip);
                }
                ip_marked = true;
            }

            if policy.network.mode != NetworkMode::Host {
                if !namespace::netns_exists(&zone.name, &self.config.paths.netns_dir) {
                    match namespace::create_netns(&zone.name, &self.config.paths.netns_dir) {
                        Ok(()) => self.clear_degradation(&zone.name, "netns")?,
                        Err(e) if policy.admission == PolicyAdmission::Strict => return Err(e),
                        Err(e) => {
                            self.record_degradation(&zone.name, "netns")?;
                            tracing::warn!(%e, zone = zone.name, admission = "audit", status = "unsupported", "failed to re-create netns during recovery");
                        }
                    }
                }
                if namespace::netns_exists(&zone.name, &self.config.paths.netns_dir)
                    && !network::veth_exists(&zone.name)
                {
                    match network::create_veth_pair(
                        &zone.name,
                        zone.network_state.as_ref(),
                        &self.config.network.bridge,
                    ) {
                        Ok(()) => self.clear_degradation(&zone.name, "network:veth")?,
                        Err(e) if policy.admission == PolicyAdmission::Strict => return Err(e),
                        Err(e) => {
                            self.record_degradation(&zone.name, "network:veth")?;
                            tracing::warn!(%e, zone = zone.name, admission = "audit", status = "unsupported", "failed to re-create veth pair during recovery");
                        }
                    }
                }
            }

            // Policy before membership: a recovered cgroup may already hold
            // processes, so it must never resolve without a policy.
            self.enforcer.set_zone_policy(zone_id, policy)?;
            self.enforcer
                .add_zone_member(cgroup_id, zone_id, zone_type)?;
            membership_installed = true;
            match self.restore_rootfs_inodes(&zone.name, zone_id) {
                Ok(()) => {}
                Err(e) if policy.admission == PolicyAdmission::Strict => return Err(e),
                Err(e) => {
                    self.record_degradation(&zone.name, "filesystem:inode_ownership")?;
                    tracing::warn!(%e, zone = zone.name, admission = "audit", "rootfs inode recovery incomplete");
                }
            }
            self.sync_bpf_allowed_comms(zone_id, &policy.network)?;
            self.apply_nftables_for_zone(zone, policy)?;
            lock_backend(&self.zone_policies, "zone_policies")?
                .insert(zone.name.clone(), policy.clone());
            Ok(())
        })();

        if let Err(e) = recovery {
            if membership_installed && self.cgroup.zone_has_processes(&zone.name).unwrap_or(true) {
                if let Err(drain_error) = self.cgroup.drain_zone(&zone.name) {
                    tracing::error!(zone = zone.name, %e, %drain_error, "recovery failed and live workloads could not be drained — retaining fail-closed membership");
                    return Err(RauhaError::BackendError(format!(
                        "zone recovery failed: {e}; fail-closed drain failed: {drain_error}"
                    )));
                }
                tracing::warn!(zone = zone.name, %e, "recovery failed; drained live workloads before rolling back enforcement");
            }
            if let Some(cgroup_id) = recovered_cgroup_id {
                let _ = self.enforcer.remove_zone_member(cgroup_id);
            }
            if let Ok(mut registered) = lock_backend(&self.registered_inodes, "registered_inodes") {
                if let Some(inodes) = registered.remove(&zone.name) {
                    let _ = self.enforcer.remove_inodes(&inodes);
                }
            }
            let _ = self.sync_bpf_allowed_comms(zone_id, &NetworkPolicy::default());
            let _ = self.enforcer.remove_zone_policy(zone_id);
            let _ = nftables::remove_zone_rules(&zone.name);
            if ip_marked {
                if let Some(ref net_state) = zone.network_state {
                    if let Ok(mut allocator) = lock_backend(&self.ip_allocator, "ip_allocator") {
                        allocator.release(net_state.ip());
                    }
                }
            }
            let _ = self.remove_zone_id(&zone.id);
            if let Ok(mut names) = lock_backend(&self.zone_name_map, "zone_name_map") {
                names.remove(&zone.name);
            }
            if let Ok(mut policies) = lock_backend(&self.zone_policies, "zone_policies") {
                policies.remove(&zone.name);
            }
            if let Ok(mut degraded) = lock_backend(&self.zone_degradations, "zone_degradations") {
                degraded.remove(&zone.name);
            }
            return Err(e);
        }

        let cgroup_id = recovered_cgroup_id.expect("successful recovery resolved a cgroup");

        tracing::info!(zone = zone.name, zone_id, cgroup_id, "zone recovered");
        Ok(())
    }

    fn cleanup_orphans(&self, known_zones: &[ZoneHandle]) -> Result<()> {
        let known_names: std::collections::HashSet<&str> =
            known_zones.iter().map(|z| z.name.as_str()).collect();
        let mut live_orphans = std::collections::HashSet::new();

        // Clean up orphaned cgroups under rauha.slice/.
        let slice_path = std::path::Path::new("/sys/fs/cgroup/rauha.slice");
        if slice_path.exists() {
            if let Ok(entries) = std::fs::read_dir(slice_path) {
                for entry in entries.flatten() {
                    let name = entry.file_name();
                    let name_str = name.to_string_lossy();
                    if let Some(zone_name) = name_str.strip_prefix("zone-") {
                        if !known_names.contains(zone_name) {
                            if self.cgroup.zone_has_processes(zone_name).unwrap_or(true) {
                                live_orphans.insert(zone_name.to_string());
                                tracing::error!(cgroup = %name_str, "retaining live orphan cgroup and its fail-closed membership");
                                continue;
                            }
                            tracing::warn!(cgroup = %name_str, "cleaning up orphaned cgroup");
                            if let Ok(cgroup_id) = self.cgroup.cgroup_id_for_zone(zone_name) {
                                let _ = self.enforcer.remove_zone_member(cgroup_id);
                            }
                            let _ = self.cgroup.destroy_zone_cgroup(zone_name);
                        }
                    }
                }
            }
        }

        // Clean up orphaned network namespaces.
        let netns_dir = std::path::Path::new(&self.config.paths.netns_dir);
        if netns_dir.exists() {
            if let Ok(entries) = std::fs::read_dir(netns_dir) {
                for entry in entries.flatten() {
                    let name = entry.file_name();
                    let name_str = name.to_string_lossy();
                    if let Some(zone_name) = name_str.strip_prefix("rauha-") {
                        if !known_names.contains(zone_name) && !live_orphans.contains(zone_name) {
                            tracing::warn!(netns = %name_str, "cleaning up orphaned netns");
                            let _ =
                                namespace::destroy_netns(zone_name, &self.config.paths.netns_dir);
                        }
                    }
                }
            }
        }

        Ok(())
    }

    fn create_zone(&self, config: &ZoneConfig) -> Result<ZoneHandle> {
        admit_linux_policy(
            &config.policy,
            &self.enforcer.skipped_hooks(),
            &self.config.policy.safe_writable_roots,
        )?;
        tracing::info!(zone = config.name, backend = "linux-ebpf", "creating zone");

        let zone_uuid = Uuid::new_v4();
        let zone_id = self.allocate_zone_id(zone_uuid)?;

        // Track zone name → uuid mapping.
        lock_backend(&self.zone_name_map, "zone_name_map")?.insert(config.name.clone(), zone_uuid);

        // Step 1: Create cgroup.
        let cgroup_id = match self.cgroup.create_zone_cgroup(&config.name) {
            Ok(id) => id,
            Err(e) => {
                let _ = self.remove_zone_id(&zone_uuid);
                return Err(e);
            }
        };

        let rollback_zone = |reason: &str, net_state: Option<&ZoneNetworkState>| {
            tracing::warn!(
                zone = config.name,
                reason,
                "rolling back failed zone creation"
            );
            if let Some(net_state) = net_state {
                match lock_backend(&self.ip_allocator, "ip_allocator") {
                    Ok(mut alloc) => alloc.release(net_state.ip()),
                    Err(e) => tracing::error!(%e, "failed to release zone IP during rollback"),
                }
            }
            let _ = network::destroy_veth_pair(&config.name);
            let _ = namespace::destroy_netns(&config.name, &self.config.paths.netns_dir);
            let _ = self.cgroup.destroy_zone_cgroup(&config.name);
            let _ = self.remove_zone_id(&zone_uuid);
            match lock_backend(&self.zone_name_map, "zone_name_map") {
                Ok(mut names) => {
                    names.remove(&config.name);
                }
                Err(e) => tracing::error!(%e, "failed to remove zone name during rollback"),
            }
            if let Ok(mut degraded) = lock_backend(&self.zone_degradations, "zone_degradations") {
                degraded.remove(&config.name);
            }
        };

        // Step 2: Create network namespace + veth with IP assignment.
        let net_state = if config.policy.network.mode != NetworkMode::Host {
            // Allocate an IP for this zone.
            let ip_state = match (|| -> Result<ZoneNetworkState> {
                let mut alloc = lock_backend(&self.ip_allocator, "ip_allocator")?;
                let ip = alloc.allocate()?;
                Ok(ZoneNetworkState {
                    ip: ip.octets(),
                    gateway: alloc.gateway().octets(),
                    prefix_len: alloc.prefix_len(),
                })
            })() {
                Ok(state) => state,
                Err(e) => {
                    rollback_zone("ip-allocation", None);
                    return Err(e);
                }
            };

            if let Err(e) = namespace::create_netns(&config.name, &self.config.paths.netns_dir) {
                rollback_zone("network-namespace", Some(&ip_state));
                return Err(e);
            }
            if let Err(e) = network::create_veth_pair(
                &config.name,
                Some(&ip_state),
                &self.config.network.bridge,
            ) {
                if config.policy.admission == PolicyAdmission::Strict {
                    rollback_zone("network-veth", Some(&ip_state));
                    return Err(e);
                }
                if let Err(state_error) = self.record_degradation(&config.name, "network:veth") {
                    rollback_zone("degradation-state", Some(&ip_state));
                    return Err(state_error);
                }
                tracing::warn!(%e, zone = config.name, admission = "audit", status = "unsupported", "failed to create veth pair — zone networking is degraded");
            }

            Some(ip_state)
        } else {
            // Host mode: zone shares the host's network stack.
            // No network namespace or veth pair — the zone's processes use
            // the host interfaces directly.
            None
        };

        // Step 3: Populate BPF maps. Missing enforcement is fatal.
        // Write the policy before membership: once a process resolves to a
        // zone via ZONE_MEMBERSHIP, its ZONE_POLICY must already exist, or
        // the fail-closed capable() hook would deny it in the gap.
        if let Err(e) = self.enforcer.set_zone_policy(zone_id, &config.policy) {
            rollback_zone("bpf-policy", net_state.as_ref());
            return Err(e);
        }

        if let Err(e) = self
            .enforcer
            .add_zone_member(cgroup_id, zone_id, config.zone_type)
        {
            let _ = self.enforcer.remove_zone_policy(zone_id);
            rollback_zone("bpf-membership", net_state.as_ref());
            return Err(e);
        }

        // Step 4: Apply cgroup resource limits.
        if let Err(e) = self
            .cgroup
            .apply_resources(&config.name, &config.policy.resources)
        {
            if let Some(zone_id) = self.get_zone_id(&zone_uuid)? {
                let _ = self.enforcer.remove_zone_member(cgroup_id);
                let _ = self.enforcer.remove_zone_policy(zone_id);
            }
            rollback_zone("resource-limits", net_state.as_ref());
            return Err(e);
        }

        tracing::info!(zone = config.name, zone_id, cgroup_id, "zone created");

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
            let mut conns = lock_backend(&self.shim_connections, "shim_connections")?;
            if let Some(conn) = conns.remove(&zone.name) {
                let _ = conn.send_request(&ShimRequest::Shutdown);
            }
        }

        // A failed teardown must leave live workloads enforced. Drain and
        // remove the cgroup before deleting any BPF membership or policy.
        self.cgroup.drain_zone(&zone.name)?;
        self.cgroup.destroy_zone_cgroup(&zone.name)?;

        // The cgroup is now gone, so stale cleanup state cannot make a live
        // workload fail open.
        let zone_id = self.remove_zone_id(&zone.id)?;
        // Remove stored inodes from BPF map (uses stored list, no re-walk).
        let stored_inodes = self
            .registered_inodes
            .lock()
            .map_err(|_| {
                tracing::error!(
                    state = "registered_inodes",
                    "mutex poisoned — refusing backend operation"
                );
                RauhaError::BackendError("linux backend state poisoned: registered_inodes".into())
            })?
            .remove(&zone.name)
            .unwrap_or_default();

        if let Some(zone_id) = zone_id {
            if !stored_inodes.is_empty() {
                if let Err(e) = self.enforcer.remove_inodes(&stored_inodes) {
                    tracing::warn!(%e, zone = zone.name, "failed to unregister rootfs inodes");
                }
            }

            let _ = self.enforcer.remove_zone_member(zone.platform_id);
            let _ = self.enforcer.remove_zone_policy(zone_id);
        }

        // Release IP back to allocator.
        if let Some(ref net_state) = zone.network_state {
            let mut alloc = lock_backend(&self.ip_allocator, "ip_allocator")?;
            alloc.release(net_state.ip());
        }

        // Remove nftables rules for this zone.
        if let Err(e) = nftables::remove_zone_rules(&zone.name) {
            tracing::warn!(%e, zone = zone.name, "failed to remove nftables rules");
        }

        // Tear down network.
        let _ = network::destroy_veth_pair(&zone.name);
        let _ = namespace::destroy_netns(&zone.name, &self.config.paths.netns_dir);

        lock_backend(&self.zone_name_map, "zone_name_map")?.remove(&zone.name);
        lock_backend(&self.zone_policies, "zone_policies")?.remove(&zone.name);
        lock_backend(&self.zone_degradations, "zone_degradations")?.remove(&zone.name);

        // Clean up shim socket.
        let socket_path = self.shim_socket_path(&zone.name);
        let _ = std::fs::remove_file(&socket_path);

        tracing::info!(zone = zone.name, "zone destroyed");
        Ok(())
    }

    fn enforce_policy(&self, zone: &ZoneHandle, policy: &ZonePolicy) -> Result<()> {
        admit_linux_policy(
            policy,
            &self.enforcer.skipped_hooks(),
            &self.config.policy.safe_writable_roots,
        )?;
        tracing::info!(zone = zone.name, "enforcing policy");

        // Update BPF policy map. Route through the enforcement seam's neutral
        // `ZoneEnforcement` vocabulary so the policy that reaches the kernel is
        // exactly what crosses the Rauha/enforcer boundary.
        let zone_id = self.get_zone_id(&zone.id)?.ok_or_else(|| {
            RauhaError::BackendError(format!("zone {} has no kernel identifier", zone.name))
        })?;
        self.enforcer
            .apply_zone_enforcement(zone_id, &policy.to_enforcement()?)?;

        // Wire up ZONE_ALLOWED_COMMS BPF map for defense-in-depth.
        self.sync_bpf_allowed_comms(zone_id, &policy.network)?;

        // Apply nftables forward rules for this zone.
        self.apply_nftables_for_zone(zone, policy)?;

        // Update cgroup resource limits.
        self.cgroup.apply_resources(&zone.name, &policy.resources)?;

        lock_backend(&self.zone_policies, "zone_policies")?
            .insert(zone.name.clone(), policy.clone());

        Ok(())
    }

    fn hot_reload_policy(&self, zone: &ZoneHandle, policy: &ZonePolicy) -> Result<()> {
        admit_linux_policy(
            policy,
            &self.enforcer.skipped_hooks(),
            &self.config.policy.safe_writable_roots,
        )?;
        tracing::info!(zone = zone.name, "hot-reloading policy");

        let previous = lock_backend(&self.zone_policies, "zone_policies")?
            .get(&zone.name)
            .cloned()
            .ok_or_else(|| {
                RauhaError::BackendError(format!("zone {} has no policy to reload", zone.name))
            })?;
        let zone_id = self.get_zone_id(&zone.id)?.ok_or_else(|| {
            RauhaError::BackendError(format!("zone {} has no kernel identifier", zone.name))
        })?;

        let update = (|| -> Result<()> {
            self.enforcer.hot_reload_policy(zone_id, policy)?;
            self.sync_bpf_allowed_comms(zone_id, &policy.network)?;
            self.apply_nftables_for_zone(zone, policy)?;
            self.cgroup.apply_resources(&zone.name, &policy.resources)?;
            Ok(())
        })();
        if let Err(error) = update {
            if let Err(e) = self.enforcer.hot_reload_policy(zone_id, &previous) {
                tracing::error!(%e, zone = zone.name, "failed to restore BPF policy after rejected reload");
            }
            if let Err(e) = self.sync_bpf_allowed_comms(zone_id, &previous.network) {
                tracing::error!(%e, zone = zone.name, "failed to restore cross-zone permissions after rejected reload");
            }
            if let Err(e) = self.apply_nftables_for_zone(zone, &previous) {
                tracing::error!(%e, zone = zone.name, "failed to restore network policy after rejected reload");
            }
            if let Err(e) = self.cgroup.apply_resources(&zone.name, &previous.resources) {
                tracing::error!(%e, zone = zone.name, "failed to restore resources after rejected reload");
            }
            return Err(error);
        }

        lock_backend(&self.zone_policies, "zone_policies")?
            .insert(zone.name.clone(), policy.clone());

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
        let policy = lock_backend(&self.zone_policies, "zone_policies")?
            .get(&zone.name)
            .cloned()
            .ok_or_else(|| {
                RauhaError::BackendError(format!(
                    "zone {} has no admitted policy; refusing container creation",
                    zone.name
                ))
            })?;
        let capabilities = oci_capabilities(&policy)?;

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
            snapshotter.mount_overlay(&container_id.to_string(), overlay_layers, &container_dir)?
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
        let resolv_content = crate::network::dns::generate_resolv_conf_with_fallback(
            &self.config.network.dns_fallback,
        );
        if let Err(e) = std::fs::write(&resolv_conf_path, &resolv_content) {
            tracing::warn!(%e, "failed to write resolv.conf — DNS may not work inside container");
        }

        // Generate OCI runtime spec.
        use oci_spec::runtime::{LinuxBuilder, LinuxNamespaceBuilder, LinuxNamespaceType};
        let mut namespaces = vec![
            LinuxNamespaceBuilder::default()
                .typ(LinuxNamespaceType::Mount)
                .build()
                .unwrap(),
            LinuxNamespaceBuilder::default()
                .typ(LinuxNamespaceType::Uts)
                .build()
                .unwrap(),
            LinuxNamespaceBuilder::default()
                .typ(LinuxNamespaceType::Ipc)
                .build()
                .unwrap(),
            LinuxNamespaceBuilder::default()
                .typ(LinuxNamespaceType::Pid)
                .build()
                .unwrap(),
            LinuxNamespaceBuilder::default()
                .typ(LinuxNamespaceType::Cgroup)
                .build()
                .unwrap(),
        ];
        if policy.network.mode != NetworkMode::Host {
            namespaces.push(
                LinuxNamespaceBuilder::default()
                    .typ(LinuxNamespaceType::Network)
                    .path(namespace::netns_path(
                        &zone.name,
                        &self.config.paths.netns_dir,
                    ))
                    .build()
                    .unwrap(),
            );
        }
        let mut linux = LinuxBuilder::default()
            .namespaces(namespaces)
            .devices(oci_devices(&policy)?)
            .build()
            .map_err(|e| {
                RauhaError::BackendError(format!("failed to build OCI Linux spec: {e}"))
            })?;
        if let Some(seccomp) = oci_seccomp(&policy)? {
            linux.set_seccomp(Some(seccomp));
        }
        let mounts = oci_mounts(
            &policy,
            &rootfs_dir,
            &self.config.policy.safe_writable_roots,
        )?;
        let runtime_spec = serde_json::to_value(
            oci_spec::runtime::SpecBuilder::default()
                .annotations(HashMap::from([(
                    "run.oci.seccomp_fail_unknown_syscall".to_string(),
                    "1".to_string(),
                )]))
                .mounts(mounts)
                .version("1.0.2")
                .root(
                    oci_spec::runtime::RootBuilder::default()
                        .path(rootfs_dir.to_string_lossy().as_ref())
                        .readonly(true)
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
                        .capabilities(capabilities)
                        .no_new_privileges(true)
                        .build()
                        .unwrap(),
                )
                .linux(linux)
                .hostname(spec.name.clone())
                .build()
                .unwrap(),
        )
        .map_err(|e| RauhaError::BackendError(format!("failed to serialize spec: {e}")))?;
        let spec_json = serde_json::to_string(&runtime_spec)
            .map_err(|e| RauhaError::BackendError(format!("failed to serialize spec: {e}")))?;

        // Register rootfs inodes in BPF map for file isolation.
        // Phase 1: Collect inodes from filesystem (no lock, may be slow for large rootfs).
        // Phase 2: Insert into BPF map (short lock hold).
        if let Some(zone_id) = self.get_zone_id(&zone.id)? {
            let is_overlay = rootfs_dir.ends_with("merged");
            tracing::debug!(
                zone = zone.name,
                path = %rootfs_dir.display(),
                overlay = is_overlay,
                "collecting rootfs inodes for BPF file isolation"
            );

            let registration = (|| -> Result<(Vec<u64>, usize)> {
                let inodes =
                    maps::collect_rootfs_inodes(&rootfs_dir, rauha_ebpf_common::MAX_INODES)?;
                let collected = inodes.len();
                let inserted = self.enforcer.insert_inodes(&inodes, zone_id)?;
                Ok((inserted, collected))
            })();

            match registration {
                Ok((inserted, collected)) => {
                    lock_backend(&self.registered_inodes, "registered_inodes")?
                        .entry(zone.name.clone())
                        .or_default()
                        .extend_from_slice(&inserted);
                    if inserted.len() != collected {
                        let error = RauhaError::BackendError(format!(
                            "rootfs inode enforcement incomplete: registered {} of {collected}",
                            inserted.len()
                        ));
                        if policy.admission == PolicyAdmission::Strict {
                            return Err(error);
                        }
                        self.record_degradation(&zone.name, "filesystem:inode_ownership")?;
                        tracing::warn!(%error, zone = zone.name, container = %container_id, admission = "audit", "file isolation incomplete");
                    }
                    tracing::info!(
                        zone = zone.name,
                        container = %container_id,
                        count = inserted.len(),
                        collected,
                        "registered container rootfs inodes in BPF map"
                    );
                }
                Err(e) if policy.admission == PolicyAdmission::Strict => return Err(e),
                Err(e) => {
                    self.record_degradation(&zone.name, "filesystem:inode_ownership")?;
                    tracing::warn!(
                        %e,
                        zone = zone.name,
                        container = %container_id,
                        admission = "audit",
                        "failed to register rootfs inodes — file isolation incomplete"
                    );
                }
            }
        } else {
            return Err(RauhaError::BackendError(format!(
                "zone {} has no kernel identifier; refusing container creation",
                zone.name
            )));
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
        let zone_names = lock_backend(&self.zone_name_map, "zone_name_map")?;
        let zone_name = zone_names
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

        let zone_names = lock_backend(&self.zone_name_map, "zone_name_map")?;
        let zone_name = zone_names
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
        let admitted_policy = lock_backend(&self.zone_policies, "zone_policies")?
            .get(&zone.name)
            .cloned();
        let mut policy_controls_ok = admitted_policy.is_some();
        if admitted_policy.is_none() {
            checks.push(IsolationCheck {
                name: "policy:admitted".into(),
                passed: false,
                detail: "zone has no admitted backend policy".into(),
            });
        }
        if let Some(policy) = admitted_policy.as_ref() {
            for control in
                unsupported_linux_controls(policy, &self.config.policy.safe_writable_roots)
            {
                policy_controls_ok = false;
                checks.push(IsolationCheck {
                    name: format!("policy:{control}"),
                    passed: false,
                    detail: "requested control is unsupported by the Linux backend".into(),
                });
            }
        }
        let degradations = lock_backend(&self.zone_degradations, "zone_degradations")?
            .get(&zone.name)
            .cloned()
            .unwrap_or_default();
        for control in &degradations {
            checks.push(IsolationCheck {
                name: control.clone(),
                passed: false,
                detail: "control degraded during runtime setup".into(),
            });
        }

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
        let ebpf_ok = match self.enforcer.health_check() {
            Ok(statuses) => {
                let skipped = self.enforcer.skipped_hooks();
                let all_ok = statuses.iter().all(|s| s.loaded && s.attached) && skipped.is_empty();
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
                for hook in skipped {
                    checks.push(IsolationCheck {
                        name: format!("ebpf:{hook}"),
                        passed: false,
                        detail: "kernel does not expose this required BPF-LSM hook".into(),
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
        };

        // Check 3: zone membership in BPF map.
        let (membership_ok, membership_detail) = match self.get_zone_id(&zone.id)? {
            Some(zone_id) => match self.enforcer.zone_member_matches(zone.platform_id, zone_id) {
                Ok(true) => (
                    true,
                    "zone cgroup is registered in the BPF membership map".into(),
                ),
                Ok(false) => (
                    false,
                    "zone cgroup is missing or mismatched in the BPF membership map".into(),
                ),
                Err(e) => (false, format!("failed to read BPF membership map: {e}")),
            },
            None => (false, "zone has no userspace kernel identifier".into()),
        };
        checks.push(IsolationCheck {
            name: "bpf_membership".into(),
            passed: membership_ok,
            detail: membership_detail,
        });

        let (inode_ok, inode_detail) = match self.get_zone_id(&zone.id)? {
            Some(zone_id) => match collect_zone_rootfs_inodes(&self.root, &zone.name) {
                Ok(expected)
                    if expected.is_empty()
                        && self.cgroup.zone_has_processes(&zone.name).unwrap_or(true) =>
                {
                    (
                        false,
                        "live zone has no discoverable rootfs inode ownership".into(),
                    )
                }
                Ok(expected) => {
                    let mut recorded = lock_backend(&self.registered_inodes, "registered_inodes")?
                        .get(&zone.name)
                        .cloned()
                        .unwrap_or_default();
                    let mut expected_sorted = expected;
                    recorded.sort_unstable();
                    recorded.dedup();
                    expected_sorted.sort_unstable();
                    expected_sorted.dedup();
                    if recorded != expected_sorted {
                        (
                            false,
                            format!(
                                "userspace inode ownership differs from rootfs: recorded {}, expected {}",
                                recorded.len(),
                                expected_sorted.len()
                            ),
                        )
                    } else {
                        match self.enforcer.inodes_match(&expected_sorted, zone_id) {
                            Ok(true) => (
                                true,
                                format!("{} rootfs inodes registered", expected_sorted.len()),
                            ),
                            Ok(false) => (
                                false,
                                "kernel inode ownership map is incomplete or mismatched".into(),
                            ),
                            Err(e) => (false, format!("failed to verify inode ownership map: {e}")),
                        }
                    }
                }
                Err(e) => (false, format!("failed to enumerate zone rootfs: {e}")),
            },
            None => (false, "zone has no userspace kernel identifier".into()),
        };
        checks.push(IsolationCheck {
            name: "filesystem:inode_ownership".into(),
            passed: inode_ok,
            detail: inode_detail,
        });

        // Check 4: requested network isolation and its filtering rules.
        let network_mode = admitted_policy
            .as_ref()
            .map(|policy| policy.network.mode)
            .unwrap_or(NetworkMode::Isolated);
        let requires_netns = network_mode != NetworkMode::Host;
        let netns_ok =
            !requires_netns || namespace::netns_exists(&zone.name, &self.config.paths.netns_dir);
        checks.push(IsolationCheck {
            name: "netns".into(),
            passed: netns_ok,
            detail: if !requires_netns {
                "host network mode intentionally shares the host namespace".into()
            } else if netns_ok {
                "network namespace exists".into()
            } else {
                "network namespace missing — network not isolated".into()
            },
        });
        let veth_ok = !requires_netns || network::veth_exists(&zone.name);
        checks.push(IsolationCheck {
            name: "network:veth".into(),
            passed: veth_ok,
            detail: if !requires_netns {
                "host network mode does not require a veth".into()
            } else if veth_ok {
                "zone veth exists".into()
            } else {
                "zone veth missing — network namespace is disconnected".into()
            },
        });
        let veth_name = network::veth_host_name_for(&zone.name);
        let fallback_policy = NetworkPolicy::default();
        let network_policy = admitted_policy
            .as_ref()
            .map(|policy| &policy.network)
            .unwrap_or(&fallback_policy);
        let nft_ok = nftables::zone_rules_exist(&zone.name, &veth_name, network_policy);
        checks.push(IsolationCheck {
            name: "network:nftables".into(),
            passed: nft_ok,
            detail: if nft_ok {
                "zone network policy rules are installed".into()
            } else {
                "zone nftables rules missing — network policy is not enforced".into()
            },
        });

        // Check 5: enforcement counters — detect silent enforcement failure.
        if let Ok(counters) = self.enforcer.read_enforcement_counters() {
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
                        detail: format!("allow={}, deny={}, error={}", c.allow, c.deny, c.error),
                    });
                }
            }
        }

        let is_isolated = policy_controls_ok
            && degradations.is_empty()
            && cgroup_ok
            && ebpf_ok
            && membership_ok
            && inode_ok
            && netns_ok
            && veth_ok
            && nft_ok;

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

    fn enforcement_degraded_reason(&self) -> Option<String> {
        let skipped = self.enforcer.skipped_hooks();
        if skipped.is_empty() {
            None
        } else {
            Some(format!("lsm_hooks_unavailable:{}", skipped.join(",")))
        }
    }

    fn kernel_zone_id(&self, zone: &ZoneHandle) -> Option<u32> {
        // The compact id is the same value stamped on enforcement events as
        // `caller_zone`. A poisoned lock or unmapped zone yields None — callers
        // treat that as "can't attribute events", not an error.
        self.get_zone_id(&zone.id).ok().flatten()
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

#[cfg(test)]
mod tests {
    use super::{
        admit_linux_policy, collect_zone_rootfs_inodes, lock_backend, oci_capabilities,
        oci_devices, oci_mounts, oci_seccomp, unsupported_linux_controls,
    };
    use rauha_common::zone::{PolicyAdmission, ZonePolicy};
    use std::os::unix::fs::MetadataExt;
    use std::sync::{Arc, Mutex};

    #[test]
    fn poisoned_backend_lock_returns_error() {
        let mutex = Arc::new(Mutex::new(()));
        let poisoned = Arc::clone(&mutex);

        let _ = std::thread::spawn(move || {
            let _guard = poisoned.lock().expect("test lock should be available");
            panic!("poison test mutex");
        })
        .join();

        let err = lock_backend(&mutex, "test_state").expect_err("poisoned lock must fail closed");
        assert!(err.to_string().contains("test_state"));
    }

    #[test]
    fn strict_admission_rejects_unsupported_controls() {
        let safe = crate::config::DaemonConfig::default()
            .policy
            .safe_writable_roots;
        let mut policy = ZonePolicy::default();
        policy.filesystem.writable_paths = vec!["/proc".into()];
        policy.devices.allowed = vec!["/dev/sda".into()];
        policy.syscalls.deny = vec!["mount".into()];
        policy.network.allowed_ingress = vec!["0.0.0.0/0:8080".into()];

        assert_eq!(
            unsupported_linux_controls(&policy, &safe),
            vec!["filesystem.writable_paths", "devices.allowed",]
        );

        let err =
            admit_linux_policy(&policy, &[], &safe).expect_err("strict policy must fail closed");
        assert!(err.to_string().contains("filesystem.writable_paths"));

        policy.admission = PolicyAdmission::Audit;
        admit_linux_policy(&policy, &[], &safe)
            .expect("audit mode explicitly accepts degraded admission");
    }

    #[test]
    fn supported_controls_build_oci_seccomp_devices_and_mounts() {
        let root = tempfile::tempdir().unwrap();
        let safe = crate::config::DaemonConfig::default()
            .policy
            .safe_writable_roots;
        std::fs::create_dir(root.path().join("tmp")).unwrap();
        let mut policy = ZonePolicy::default();
        policy.filesystem.writable_paths = vec!["/tmp".into()];
        policy.devices.allowed = vec!["/dev/null".into()];
        policy.syscalls.deny = vec!["mount".into()];

        assert!(unsupported_linux_controls(&policy, &safe).is_empty());
        assert_eq!(oci_devices(&policy).unwrap().len(), 1);
        assert!(oci_seccomp(&policy).unwrap().is_some());
        let mounts =
            serde_json::to_value(oci_mounts(&policy, root.path(), &safe).unwrap()).unwrap();
        assert!(mounts
            .as_array()
            .unwrap()
            .iter()
            .any(|mount| mount["destination"] == "/tmp"));
    }

    #[test]
    fn strict_admission_rejects_missing_kernel_hooks() {
        let err = admit_linux_policy(
            &ZonePolicy::default(),
            &["cgroup_attach_task".into()],
            &crate::config::DaemonConfig::default()
                .policy
                .safe_writable_roots,
        )
        .expect_err("strict policy must reject degraded kernel enforcement");
        assert!(err.to_string().contains("lsm.cgroup_attach_task"));
    }

    #[test]
    fn empty_policy_builds_empty_oci_capability_sets() {
        let capabilities = oci_capabilities(&ZonePolicy::default()).unwrap();
        assert!(capabilities.bounding().as_ref().unwrap().is_empty());
        assert!(capabilities.effective().as_ref().unwrap().is_empty());
        assert!(capabilities.inheritable().as_ref().unwrap().is_empty());
        assert!(capabilities.permitted().as_ref().unwrap().is_empty());
        assert!(capabilities.ambient().as_ref().unwrap().is_empty());
    }

    #[test]
    fn named_policy_capabilities_convert_to_oci_capabilities() {
        let mut policy = ZonePolicy::default();
        policy.capabilities.allowed = vec!["CAP_NET_RAW".into(), "chown".into()];

        let capabilities = oci_capabilities(&policy).unwrap();
        let effective = capabilities.effective().as_ref().unwrap();
        assert!(effective.contains(&oci_spec::runtime::Capability::NetRaw));
        assert!(effective.contains(&oci_spec::runtime::Capability::Chown));
    }

    #[test]
    fn recovery_collects_every_container_rootfs() {
        let root = tempfile::tempdir().unwrap();
        let containers = root.path().join("zones/test/containers");
        let first = containers.join("one/merged");
        let second = containers.join("two/rootfs");
        std::fs::create_dir_all(&first).unwrap();
        std::fs::create_dir_all(&second).unwrap();
        let first_file = first.join("first");
        let second_file = second.join("second");
        std::fs::write(&first_file, b"one").unwrap();
        std::fs::write(&second_file, b"two").unwrap();

        let inodes = collect_zone_rootfs_inodes(root.path().to_str().unwrap(), "test").unwrap();
        assert!(inodes.contains(&first_file.metadata().unwrap().ino()));
        assert!(inodes.contains(&second_file.metadata().unwrap().ino()));
    }
}
