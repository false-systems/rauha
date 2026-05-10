use chrono::Utc;
use rauha_common::backend::IsolationBackend;
use rauha_common::container::{Container, ContainerHandle, ContainerSpec, ContainerState};
use rauha_common::error::{RauhaError, Result};
use rauha_common::zone::*;
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;
use uuid::Uuid;

use crate::metadata::db::MetadataStore;

/// Manages zone lifecycle and container membership.
///
/// The registry is the source of truth for what zones exist and what containers
/// belong to them. It coordinates between the metadata store (persistence)
/// and the isolation backend (enforcement).
pub struct ZoneRegistry {
    metadata: Arc<MetadataStore>,
    backend: Arc<dyn IsolationBackend>,
    image_service: Arc<rauha_oci::image::ImageService>,
    #[allow(dead_code)] // Used on Linux for overlayfs snapshotter paths.
    root: String,
    /// In-memory cache of zone handles for fast backend operations.
    handles: RwLock<HashMap<String, ZoneHandle>>,
    /// In-memory cache of container handles (needed for start/stop operations).
    container_handles: RwLock<HashMap<Uuid, ContainerHandle>>,
    /// Serializes zone create/delete operations to prevent TOCTOU races.
    /// The duplicate check and metadata write must be atomic — this lock
    /// ensures no two creates with the same name can interleave.
    zone_mutation_lock: tokio::sync::Mutex<()>,
}

/// Validate that a zone name is safe (no path traversal, no special chars).
fn validate_zone_name(name: &str) -> Result<()> {
    if name.is_empty() {
        return Err(RauhaError::InvalidInput(
            "zone name cannot be empty".into(),
        ));
    }
    if name.contains('/') || name.contains('\\') || name.contains('\0') {
        return Err(RauhaError::InvalidInput(
            "zone name must not contain path separators".into(),
        ));
    }
    if name == "." || name == ".." {
        return Err(RauhaError::InvalidInput(
            "zone name must not be '.' or '..'".into(),
        ));
    }
    if name.len() > 128 {
        return Err(RauhaError::InvalidInput(
            "zone name must be 128 characters or fewer".into(),
        ));
    }
    Ok(())
}

impl ZoneRegistry {
    pub fn new(
        metadata: Arc<MetadataStore>,
        backend: Arc<dyn IsolationBackend>,
        image_service: Arc<rauha_oci::image::ImageService>,
        root: String,
    ) -> Self {
        Self {
            metadata,
            backend,
            image_service,
            root,
            handles: RwLock::new(HashMap::new()),
            container_handles: RwLock::new(HashMap::new()),
            zone_mutation_lock: tokio::sync::Mutex::new(()),
        }
    }

    /// Return the root data directory path.
    #[allow(dead_code)] // Used on Linux for overlayfs snapshotter paths.
    pub fn root_path(&self) -> String {
        self.root.clone()
    }

    /// Reconcile persisted metadata with kernel state on startup.
    ///
    /// redb is the source of truth. For each persisted zone, re-establish
    /// kernel state (cgroups, BPF maps, netns). Then clean up any orphaned
    /// kernel state that doesn't correspond to a known zone.
    ///
    /// This handles the crash recovery case: rauhad dies between writing
    /// to redb and updating kernel state, leaving them inconsistent.
    pub async fn reconcile(&self) -> Result<()> {
        let zones = self.metadata.list_zones()?;
        if zones.is_empty() {
            tracing::info!("no zones to reconcile");
            self.backend.cleanup_orphans(&[])?;
            return Ok(());
        }

        tracing::info!(count = zones.len(), "reconciling zones from metadata");

        let mut handles = Vec::new();
        for zone in &zones {
            let mut handle = ZoneHandle {
                id: zone.id,
                name: zone.name.clone(),
                platform_id: 0, // Updated by recover_zone with live cgroup_id.
                network_state: zone.network_state.clone(),
            };

            match self.backend.recover_zone(&handle, zone.zone_type, &zone.policy) {
                Ok(()) => {
                    // Update handle with live cgroup_id from the filesystem.
                    // recover_zone re-stats the cgroup directory, but the handle
                    // passed in still has platform_id=0. Resolve it now.
                    if let Ok(live_cgroup_id) = self.resolve_live_cgroup_id(&zone.name) {
                        handle.platform_id = live_cgroup_id;
                    }
                    handles.push(handle.clone());
                    self.handles.write().await.insert(zone.name.clone(), handle);
                    tracing::info!(zone = zone.name, "zone reconciled");
                }
                Err(e) => {
                    tracing::error!(zone = zone.name, %e, "failed to reconcile zone — zone will be unavailable");
                }
            }
        }

        // Clean up orphaned kernel state.
        if let Err(e) = self.backend.cleanup_orphans(&handles) {
            tracing::warn!(%e, "failed to clean up orphaned kernel state");
        }

        tracing::info!(recovered = handles.len(), total = zones.len(), "reconciliation complete");
        Ok(())
    }

    /// Resolve a zone's live cgroup_id from the filesystem.
    ///
    /// The cgroup_id is the inode of the cgroup directory. After a crash,
    /// the cgroup may have been recreated with a new inode — this returns
    /// the current one, not the stored one.
    #[cfg(target_os = "linux")]
    fn resolve_live_cgroup_id(&self, zone_name: &str) -> Result<u64> {
        use std::os::unix::fs::MetadataExt;
        let path = format!("/sys/fs/cgroup/rauha.slice/zone-{zone_name}");
        let meta = std::fs::metadata(&path).map_err(|e| RauhaError::CgroupError {
            message: format!("failed to stat cgroup {path}: {e}"),
            hint: "cgroup may not exist".into(),
        })?;
        Ok(meta.ino())
    }

    #[cfg(not(target_os = "linux"))]
    fn resolve_live_cgroup_id(&self, _zone_name: &str) -> Result<u64> {
        Ok(0)
    }

    pub async fn create_zone(&self, name: &str, zone_type: ZoneType, policy: ZonePolicy) -> Result<Zone> {
        // Validate zone name: reject path traversal and unsafe characters.
        validate_zone_name(name)?;

        // Serialize zone mutations to prevent TOCTOU: two concurrent creates
        // with the same name could both pass the duplicate check before either
        // writes to metadata. The lock ensures check-and-create is atomic.
        let _guard = self.zone_mutation_lock.lock().await;

        // Check for duplicates (protected by zone_mutation_lock).
        if self.metadata.get_zone(name)?.is_some() {
            return Err(RauhaError::ZoneAlreadyExists(name.into()));
        }

        let config = ZoneConfig {
            name: name.into(),
            zone_type,
            policy: policy.clone(),
        };

        // Create in backend first (sets up isolation primitives).
        let handle = self.backend.create_zone(&config)?;

        // Apply the policy.
        self.backend.enforce_policy(&handle, &policy)?;

        let now = Utc::now();
        let zone = Zone {
            id: handle.id,
            name: name.into(),
            zone_type,
            state: ZoneState::Ready,
            policy,
            created_at: now,
            updated_at: now,
            network_state: handle.network_state.clone(),
        };

        // Persist.
        self.metadata.put_zone(&zone)?;

        // Cache handle.
        self.handles.write().await.insert(name.into(), handle);

        tracing::info!(zone = name, "zone created");
        Ok(zone)
    }

    pub async fn delete_zone(&self, name: &str, force: bool) -> Result<()> {
        let _guard = self.zone_mutation_lock.lock().await;

        let zone = self
            .metadata
            .get_zone(name)?
            .ok_or_else(|| RauhaError::ZoneNotFound(name.into()))?;

        // Check for running containers unless force.
        let containers = self.metadata.list_containers(Some(&zone.id))?;
        if !containers.is_empty() && !force {
            return Err(RauhaError::ZoneNotEmpty {
                count: containers.len(),
            });
        }

        // Clean up containers if force.
        if force {
            for container in &containers {
                // Stop running containers.
                if container.state == ContainerState::Running {
                    if let Some(handle) = self.container_handles.write().await.remove(&container.id) {
                        let _ = self.backend.stop_container(&handle);
                    }
                }
                self.metadata.delete_container(&container.id)?;
            }
        }

        // Destroy in backend.
        if let Some(handle) = self.handles.write().await.remove(name) {
            self.backend.destroy_zone(&handle)?;
        }

        // Remove from metadata.
        self.metadata.delete_zone(name)?;

        tracing::info!(zone = name, "zone deleted");
        Ok(())
    }

    pub async fn get_zone(&self, name: &str) -> Result<Zone> {
        self.metadata
            .get_zone(name)?
            .ok_or_else(|| RauhaError::ZoneNotFound(name.into()))
    }

    pub fn list_zones(&self) -> Result<Vec<Zone>> {
        self.metadata.list_zones()
    }

    pub async fn apply_policy(&self, zone_name: &str, policy: ZonePolicy) -> Result<()> {
        let mut zone = self.get_zone(zone_name).await?;
        let handles = self.handles.read().await;
        let handle = handles
            .get(zone_name)
            .ok_or_else(|| RauhaError::ZoneNotFound(zone_name.into()))?;

        // If the zone was deleted concurrently, the backend call may fail.
        // Treat "zone not found" backend errors as ZoneNotFound, not Internal.
        match self.backend.hot_reload_policy(handle, &policy) {
            Ok(()) => {}
            Err(RauhaError::ZoneNotFound(_)) => {
                return Err(RauhaError::ZoneNotFound(zone_name.into()));
            }
            Err(e) => return Err(e),
        }

        zone.policy = policy;
        zone.updated_at = Utc::now();
        self.metadata.put_zone(&zone)?;

        tracing::info!(zone = zone_name, "policy updated");
        Ok(())
    }

    pub async fn create_container(
        &self,
        zone_name: &str,
        spec: ContainerSpec,
    ) -> Result<Container> {
        let zone = self.get_zone(zone_name).await?;

        // Prepare rootfs from image if one is specified.
        // Uses spawn_blocking because layer extraction does heavy I/O.
        //
        // On Linux, extract per-layer directories for overlayfs (O(1) mount).
        // On other platforms, fall back to full rootfs copy.
        let mut spec = spec;
        if !spec.image.is_empty() {
            let image_svc = self.image_service.clone();
            let image_ref = spec.image.clone();
            #[cfg(target_os = "linux")]
            {
                let zone_root = self.root_path();
                let zone_name_owned = zone_name.to_string();
                let layers = tokio::task::spawn_blocking(move || {
                    let safe_name = image_svc.image_safe_name(&image_ref)?;
                    let (digests, content_root) = image_svc.layer_digests(&image_ref)?;

                    let zone_data = std::path::PathBuf::from(&zone_root)
                        .join("zones")
                        .join(&zone_name_owned);
                    let snapshotter =
                        rauha_oci::snapshotter::OverlayfsSnapshotter::new(&zone_data);
                    let layer_paths =
                        snapshotter.prepare_layers(&safe_name, &digests, &content_root)?;

                    // Skip prepare_base_rootfs — overlayfs mounts the per-layer
                    // directories directly. The merged rootfs would be redundant.
                    Ok::<_, RauhaError>(layer_paths)
                })
                .await
                .map_err(|e| RauhaError::BackendError(format!("rootfs task panicked: {e}")))??;

                spec.overlay_layers = Some(layers);
            }

            #[cfg(not(target_os = "linux"))]
            {
                let base = tokio::task::spawn_blocking(move || {
                    image_svc.prepare_base_rootfs(&image_ref)
                })
                .await
                .map_err(|e| RauhaError::BackendError(format!("rootfs task panicked: {e}")))??;
                spec.rootfs_path = Some(base);
            }
        }

        let handles = self.handles.read().await;
        let handle = handles
            .get(zone_name)
            .ok_or_else(|| RauhaError::ZoneNotFound(zone_name.into()))?;

        let container_handle = self.backend.create_container(handle, &spec)?;

        let now = Utc::now();
        let container = Container {
            id: container_handle.id,
            name: spec.name,
            zone_id: zone.id,
            image: spec.image,
            state: ContainerState::Created,
            pid: Some(container_handle.pid),
            created_at: now,
            started_at: None,
            finished_at: None,
            exit_code: None,
        };

        self.metadata.put_container(&container)?;

        // Cache container handle for start/stop operations.
        self.container_handles
            .write()
            .await
            .insert(container_handle.id, container_handle);

        tracing::info!(container = %container.id, zone = zone_name, "container created");
        Ok(container)
    }

    /// Start a previously created container.
    pub async fn start_container(&self, container_id: &Uuid) -> Result<()> {
        let container = self
            .metadata
            .get_container(container_id)?
            .ok_or_else(|| RauhaError::ContainerNotFound(*container_id))?;

        let container_handle = self
            .container_handles
            .read()
            .await
            .get(container_id)
            .cloned()
            .ok_or_else(|| RauhaError::ContainerNotFound(*container_id))?;

        let pid = self.backend.start_container(&container_handle)?;

        // Update metadata with PID from the backend.
        let mut updated = container;
        updated.state = ContainerState::Running;
        updated.started_at = Some(Utc::now());
        updated.pid = Some(pid);
        self.metadata.put_container(&updated)?;

        // Update in-memory cache with the real PID.
        {
            let mut handles = self.container_handles.write().await;
            if let Some(handle) = handles.get_mut(container_id) {
                handle.pid = pid;
            }
        }

        tracing::info!(container = %container_id, pid, "container started");
        Ok(())
    }

    /// Stop a running container.
    pub async fn stop_container(&self, container_id: &Uuid, _timeout: u32) -> Result<()> {
        let container = self
            .metadata
            .get_container(container_id)?
            .ok_or_else(|| RauhaError::ContainerNotFound(*container_id))?;

        let container_handle = self
            .container_handles
            .read()
            .await
            .get(container_id)
            .cloned()
            .ok_or_else(|| RauhaError::ContainerNotFound(*container_id))?;

        self.backend.stop_container(&container_handle)?;

        // Update metadata.
        let mut updated = container;
        updated.state = ContainerState::Stopped;
        updated.finished_at = Some(Utc::now());
        self.metadata.put_container(&updated)?;

        tracing::info!(container = %container_id, "container stopped");
        Ok(())
    }

    /// Query the zone shim for container state and persist stopped metadata.
    #[allow(dead_code)] // Used by sandbox wait support in the next PR.
    pub async fn get_container_state(&self, container_id: &Uuid) -> Result<(String, Option<i32>)> {
        let container = self
            .metadata
            .get_container(container_id)?
            .ok_or_else(|| RauhaError::ContainerNotFound(*container_id))?;

        let zone_name = self
            .zone_name_for_container(&container.zone_id)
            .await
            .ok_or_else(|| RauhaError::ZoneNotFound(container.zone_id.to_string()))?;

        let response = self
            .shim_request(
                &zone_name,
                &rauha_common::shim::ShimRequest::GetState {
                    id: container_id.to_string(),
                },
            )
            .await?;

        match response {
            rauha_common::shim::ShimResponse::State {
                status, exit_code, ..
            } => {
                if status == "stopped" {
                    let mut updated = container;
                    updated.state = ContainerState::Stopped;
                    updated.finished_at.get_or_insert_with(Utc::now);
                    updated.exit_code = exit_code;
                    self.metadata.put_container(&updated)?;
                }
                Ok((status, exit_code))
            }
            rauha_common::shim::ShimResponse::Error { message } => Err(RauhaError::ShimError {
                zone: zone_name,
                message,
            }),
            other => Err(RauhaError::ShimError {
                zone: zone_name,
                message: format!("unexpected shim response to GetState: {other:?}"),
            }),
        }
    }

    /// Delete a container, stopping it first if needed.
    pub async fn delete_container(&self, container_id: &Uuid, force: bool) -> Result<()> {
        let container = self
            .metadata
            .get_container(container_id)?
            .ok_or_else(|| RauhaError::ContainerNotFound(*container_id))?;

        if container.state == ContainerState::Running {
            if force {
                self.stop_container(container_id, 10).await?;
            } else {
                return Err(RauhaError::BackendError(format!(
                    "container {} is running, use force to stop it first",
                    container_id
                )));
            }
        }

        // Unmount overlayfs if applicable (Linux only, no-op on other platforms).
        #[cfg(target_os = "linux")]
        {
            let zone_name = self.zone_name_for_container(&container.zone_id).await;
            if let Some(zone_name) = zone_name {
                let zone_data = std::path::PathBuf::from(&self.root)
                    .join("zones")
                    .join(&zone_name);
                let container_root = zone_data
                    .join("containers")
                    .join(container_id.to_string());
                let snapshotter =
                    rauha_oci::snapshotter::OverlayfsSnapshotter::new(&zone_data);
                if let Err(e) = snapshotter.unmount_overlay(&container_root) {
                    tracing::warn!(container = %container_id, %e, "failed to unmount overlay");
                }
            }
        }

        self.container_handles.write().await.remove(container_id);
        self.metadata.delete_container(container_id)?;

        tracing::info!(container = %container_id, "container deleted");
        Ok(())
    }

    /// Get a container by ID.
    /// Lazily updates state: if a Running container's process has exited,
    /// the state is updated to Stopped before returning.
    pub fn get_container(&self, container_id: &Uuid) -> Result<Container> {
        let container = self.metadata
            .get_container(container_id)?
            .ok_or_else(|| RauhaError::ContainerNotFound(*container_id))?;

        self.maybe_reap_container(container)
    }

    pub fn list_containers(&self, zone_name: Option<&str>) -> Result<Vec<Container>> {
        let containers = if let Some(name) = zone_name {
            let zone = self
                .metadata
                .get_zone(name)?
                .ok_or_else(|| RauhaError::ZoneNotFound(name.into()))?;
            self.metadata.list_containers(Some(&zone.id))?
        } else {
            self.metadata.list_containers(None)?
        };

        // Lazily reap exited containers.
        containers.into_iter().map(|c| self.maybe_reap_container(c)).collect()
    }

    /// If a container is Running but its process has exited, update state to Stopped.
    ///
    /// On Linux, uses kill(pid, 0) to check host-side PID liveness.
    /// On macOS, the PID is from inside the VM — host-side kill() cannot check it,
    /// so we skip the liveness check (macOS containers are reaped via guest agent).
    fn maybe_reap_container(&self, mut container: Container) -> Result<Container> {
        if container.state == ContainerState::Running {
            if let Some(pid) = container.pid.filter(|&p| p > 0) {
                let dead = Self::is_process_dead(pid);
                if dead {
                    container.state = ContainerState::Stopped;
                    container.finished_at = Some(Utc::now());
                    // Best-effort update — don't fail the get/list if metadata write fails.
                    if let Err(e) = self.metadata.put_container(&container) {
                        tracing::warn!(
                            container = %container.id,
                            error = %e,
                            "failed to persist reaped container state"
                        );
                    }
                }
            }
        }
        Ok(container)
    }

    /// Check if a process is dead. Linux only — uses kill(pid, 0).
    /// On macOS, PIDs are from inside VMs so host kill() can't check them.
    #[cfg(target_os = "linux")]
    fn is_process_dead(pid: u32) -> bool {
        let ret = unsafe { libc::kill(pid as i32, 0) };
        if ret == -1 && std::io::Error::last_os_error().raw_os_error() == Some(libc::ESRCH) {
            return true;
        }
        // Process exists but might be a zombie (parent hasn't called waitpid yet).
        // Check /proc/{pid}/status for "State: Z (zombie)".
        if let Ok(status) = std::fs::read_to_string(format!("/proc/{pid}/status")) {
            if let Some(line) = status.lines().find(|l| l.starts_with("State:")) {
                return line.contains("Z (zombie)") || line.contains("X (dead)");
            }
        }
        false
    }

    #[cfg(not(target_os = "linux"))]
    fn is_process_dead(_pid: u32) -> bool {
        // On macOS, container PIDs are inside VMs — can't check from host.
        false
    }

    pub async fn zone_stats(&self, zone_name: &str) -> Result<ZoneStats> {
        let handles = self.handles.read().await;
        let handle = handles
            .get(zone_name)
            .ok_or_else(|| RauhaError::ZoneNotFound(zone_name.into()))?;
        let mut stats = self.backend.zone_stats(handle)?;

        // Backfill memory_limit from policy if the backend didn't set it.
        // macOS VM backend returns 0 because limits are set at VM boot,
        // not readable from the guest agent.
        if stats.memory_limit_bytes == 0 {
            match self.metadata.get_zone(zone_name) {
                Ok(Some(zone)) => {
                    stats.memory_limit_bytes = zone.policy.resources.memory_limit;
                }
                Ok(None) => {}
                Err(e) => {
                    tracing::warn!(
                        zone = zone_name,
                        error = %e,
                        "failed to read zone metadata for stats backfill"
                    );
                }
            }
        }

        Ok(stats)
    }

    pub async fn verify_isolation(&self, zone_name: &str) -> Result<IsolationReport> {
        let handles = self.handles.read().await;
        let handle = handles
            .get(zone_name)
            .ok_or_else(|| RauhaError::ZoneNotFound(zone_name.into()))?;
        self.backend.verify_isolation(handle)
    }

    /// Look up the zone name for a container's zone_id.
    pub async fn zone_name_for_container(&self, zone_id: &Uuid) -> Option<String> {
        let handles = self.handles.read().await;
        handles
            .iter()
            .find(|(_, h)| h.id == *zone_id)
            .map(|(name, _)| name.clone())
    }

    /// Send a shim request for a zone.
    ///
    /// On Linux, connects via Unix socket to the zone's shim process.
    /// On macOS (or when no Unix socket exists), delegates to the backend,
    /// which routes through vsock to the guest agent inside the VM.
    pub async fn shim_request(
        &self,
        zone_name: &str,
        request: &rauha_common::shim::ShimRequest,
    ) -> Result<rauha_common::shim::ShimResponse> {
        let socket_path = format!("/run/rauha/shim-{zone_name}.sock");
        let path = std::path::PathBuf::from(&socket_path);

        if path.exists() {
            // Linux: connect via Unix socket to the shim process.
            let request_clone = rauha_common::shim::encode(request).map_err(|e| {
                RauhaError::ShimError {
                    zone: zone_name.into(),
                    message: format!("failed to encode request: {e}"),
                }
            })?;

            let zone_name_owned = zone_name.to_string();
            tokio::task::spawn_blocking(move || {
                use std::io::Write;
                let mut stream =
                    std::os::unix::net::UnixStream::connect(&path).map_err(|e| {
                        RauhaError::ShimError {
                            zone: zone_name_owned.clone(),
                            message: format!("failed to connect to shim: {e}"),
                        }
                    })?;

                stream
                    .set_read_timeout(Some(std::time::Duration::from_secs(30)))
                    .ok();
                stream
                    .set_write_timeout(Some(std::time::Duration::from_secs(10)))
                    .ok();

                stream
                    .write_all(&request_clone)
                    .map_err(|e| RauhaError::ShimError {
                        zone: zone_name_owned.clone(),
                        message: format!("failed to send request: {e}"),
                    })?;
                stream.flush().map_err(|e| RauhaError::ShimError {
                    zone: zone_name_owned.clone(),
                    message: format!("failed to flush: {e}"),
                })?;

                rauha_common::shim::decode_from::<rauha_common::shim::ShimResponse>(&mut stream)
                    .map_err(|e| RauhaError::ShimError {
                        zone: zone_name_owned,
                        message: format!("failed to read response: {e}"),
                    })
            })
            .await
            .map_err(|e| RauhaError::BackendError(format!("shim task panicked: {e}")))?
        } else if cfg!(target_os = "macos") {
            // macOS: no Unix socket — route through backend (vsock to guest agent).
            let backend = self.backend.clone();
            let zone = zone_name.to_string();
            let request = request.clone();
            tokio::task::spawn_blocking(move || backend.shim_request(&zone, &request))
                .await
                .map_err(|e| RauhaError::BackendError(format!("shim task panicked: {e}")))?
        } else {
            return Err(RauhaError::ShimError {
                zone: zone_name.into(),
                message: format!("shim socket not found at {socket_path}"),
            });
        }
    }

    /// Connect to a vsock port on a zone's VM for exec I/O relay.
    ///
    /// Returns an async stream wrapping the vsock fd. Only works on macOS
    /// (where exec sessions use vsock); on Linux, exec sessions use Unix
    /// sockets and this method is never called.
    pub async fn connect_exec_vsock(
        &self,
        zone_name: &str,
        port: u32,
    ) -> Result<VsockAsyncStream> {
        let backend = self.backend.clone();
        let zone = zone_name.to_string();
        let fd = tokio::task::spawn_blocking(move || backend.connect_vsock_port(&zone, port))
            .await
            .map_err(|e| {
                RauhaError::BackendError(format!("vsock connect task panicked: {e}"))
            })??;

        VsockAsyncStream::new(fd)
            .map_err(|e| RauhaError::BackendError(format!("async vsock wrap failed: {e}")))
    }
}

/// Async I/O wrapper for a vsock file descriptor.
///
/// Uses `AsyncFd` to provide `AsyncRead + AsyncWrite` on a raw vsock fd
/// from Virtualization.framework. This avoids type-punning the fd as a
/// Unix stream — the wrapper is honest about what it wraps.
pub(crate) struct VsockAsyncStream {
    inner: tokio::io::unix::AsyncFd<std::fs::File>,
}

impl VsockAsyncStream {
    fn new(fd: std::os::fd::OwnedFd) -> std::io::Result<Self> {
        use std::os::fd::AsRawFd;
        let file = std::fs::File::from(fd);
        // AsyncFd requires the fd to be in nonblocking mode.
        let raw = file.as_raw_fd();
        let flags = unsafe { libc::fcntl(raw, libc::F_GETFL) };
        if flags >= 0 {
            unsafe { libc::fcntl(raw, libc::F_SETFL, flags | libc::O_NONBLOCK) };
        }
        Ok(Self {
            inner: tokio::io::unix::AsyncFd::new(file)?,
        })
    }
}

impl tokio::io::AsyncRead for VsockAsyncStream {
    fn poll_read(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        loop {
            let mut guard = match self.inner.poll_read_ready(cx) {
                std::task::Poll::Ready(Ok(g)) => g,
                std::task::Poll::Ready(Err(e)) => return std::task::Poll::Ready(Err(e)),
                std::task::Poll::Pending => return std::task::Poll::Pending,
            };

            match guard.try_io(|inner| {
                use std::io::Read;
                (&*inner.get_ref()).read(buf.initialize_unfilled())
            }) {
                Ok(Ok(n)) => {
                    buf.advance(n);
                    return std::task::Poll::Ready(Ok(()));
                }
                Ok(Err(e)) => return std::task::Poll::Ready(Err(e)),
                Err(_would_block) => continue,
            }
        }
    }
}

impl tokio::io::AsyncWrite for VsockAsyncStream {
    fn poll_write(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &[u8],
    ) -> std::task::Poll<std::io::Result<usize>> {
        loop {
            let mut guard = match self.inner.poll_write_ready(cx) {
                std::task::Poll::Ready(Ok(g)) => g,
                std::task::Poll::Ready(Err(e)) => return std::task::Poll::Ready(Err(e)),
                std::task::Poll::Pending => return std::task::Poll::Pending,
            };

            match guard.try_io(|inner| {
                use std::io::Write;
                (&*inner.get_ref()).write(buf)
            }) {
                Ok(result) => return std::task::Poll::Ready(result),
                Err(_would_block) => continue,
            }
        }
    }

    fn poll_flush(
        self: std::pin::Pin<&mut Self>,
        _cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        std::task::Poll::Ready(Ok(()))
    }

    fn poll_shutdown(
        self: std::pin::Pin<&mut Self>,
        _cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        std::task::Poll::Ready(Ok(()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rauha_common::backend::IsolationBackend;
    use rauha_common::container::{ContainerHandle, ContainerSpec};
    use std::sync::atomic::{AtomicU64, Ordering};
    use tempfile::TempDir;

    /// Minimal mock backend for testing registry logic.
    struct MockBackend {
        next_id: AtomicU64,
    }

    impl MockBackend {
        fn new() -> Self {
            Self {
                next_id: AtomicU64::new(1),
            }
        }
    }

    impl IsolationBackend for MockBackend {
        fn create_zone(&self, _config: &ZoneConfig) -> Result<ZoneHandle> {
            Ok(ZoneHandle {
                id: Uuid::new_v4(),
                name: _config.name.clone(),
                platform_id: self.next_id.fetch_add(1, Ordering::Relaxed),
                network_state: None,
            })
        }

        fn destroy_zone(&self, _zone: &ZoneHandle) -> Result<()> {
            Ok(())
        }

        fn enforce_policy(&self, _zone: &ZoneHandle, _policy: &ZonePolicy) -> Result<()> {
            Ok(())
        }

        fn hot_reload_policy(&self, _zone: &ZoneHandle, _policy: &ZonePolicy) -> Result<()> {
            Ok(())
        }

        fn create_container(
            &self,
            zone: &ZoneHandle,
            _spec: &ContainerSpec,
        ) -> Result<ContainerHandle> {
            Ok(ContainerHandle {
                id: Uuid::new_v4(),
                zone_id: zone.id,
                pid: 9999,
                platform_id: self.next_id.fetch_add(1, Ordering::Relaxed),
            })
        }

        fn start_container(&self, _container: &ContainerHandle) -> Result<u32> {
            // Return current process PID so liveness check (kill(pid,0)) passes.
            Ok(std::process::id())
        }

        fn stop_container(&self, _container: &ContainerHandle) -> Result<()> {
            Ok(())
        }

        fn zone_stats(&self, zone: &ZoneHandle) -> Result<ZoneStats> {
            Ok(ZoneStats {
                zone_id: zone.id,
                container_count: 0,
                cpu_usage_percent: 0.0,
                memory_usage_bytes: 0,
                memory_limit_bytes: 0,
                network_rx_bytes: 0,
                network_tx_bytes: 0,
                pids_current: 0,
            })
        }

        fn verify_isolation(&self, zone: &ZoneHandle) -> Result<IsolationReport> {
            Ok(IsolationReport {
                zone_id: zone.id,
                model: IsolationModel::SyscallPolicy,
                is_isolated: true,
                checks: vec![],
            })
        }

        fn recover_zone(
            &self,
            _zone: &ZoneHandle,
            _zone_type: ZoneType,
            _policy: &ZonePolicy,
        ) -> Result<()> {
            Ok(())
        }

        fn cleanup_orphans(&self, _known_zones: &[ZoneHandle]) -> Result<()> {
            Ok(())
        }

        fn isolation_model(&self) -> IsolationModel {
            IsolationModel::SyscallPolicy
        }

        fn name(&self) -> &str {
            "mock"
        }
    }

    fn test_registry(tmp: &TempDir) -> ZoneRegistry {
        let db_path = tmp.path().join("test.redb");
        let content_path = tmp.path().join("content");
        let metadata = Arc::new(MetadataStore::open(&db_path).unwrap());
        let content = Arc::new(
            rauha_oci::content::ContentStore::new(&content_path).unwrap(),
        );
        let image_svc = Arc::new(rauha_oci::image::ImageService::new(
            content,
            tmp.path().to_path_buf(),
        ));
        let backend: Arc<dyn IsolationBackend> = Arc::new(MockBackend::new());
        ZoneRegistry::new(metadata, backend, image_svc, tmp.path().to_string_lossy().into())
    }

    fn make_spec(name: &str) -> ContainerSpec {
        ContainerSpec {
            name: name.into(),
            image: String::new(), // empty skips rootfs preparation
            command: vec!["/bin/sh".into()],
            env: vec![],
            working_dir: None,
            rootfs_path: None,
            overlay_layers: None,
        }
    }

    #[tokio::test]
    async fn create_zone_persists() {
        let tmp = TempDir::new().unwrap();
        let reg = test_registry(&tmp);

        let zone = reg
            .create_zone("alpha", ZoneType::NonGlobal, ZonePolicy::default())
            .await
            .unwrap();

        assert_eq!(zone.name, "alpha");
        assert_eq!(zone.state, ZoneState::Ready);

        // Verify it's in metadata.
        let loaded = reg.get_zone("alpha").await.unwrap();
        assert_eq!(loaded.id, zone.id);
    }

    #[tokio::test]
    async fn duplicate_zone_rejected() {
        let tmp = TempDir::new().unwrap();
        let reg = test_registry(&tmp);

        reg.create_zone("dup", ZoneType::NonGlobal, ZonePolicy::default())
            .await
            .unwrap();

        let err = reg
            .create_zone("dup", ZoneType::NonGlobal, ZonePolicy::default())
            .await
            .unwrap_err();

        assert!(
            matches!(err, RauhaError::ZoneAlreadyExists(_)),
            "expected ZoneAlreadyExists, got: {err:?}"
        );
    }

    #[tokio::test]
    async fn delete_zone_removes_from_metadata() {
        let tmp = TempDir::new().unwrap();
        let reg = test_registry(&tmp);

        reg.create_zone("gone", ZoneType::NonGlobal, ZonePolicy::default())
            .await
            .unwrap();
        reg.delete_zone("gone", false).await.unwrap();

        let err = reg.get_zone("gone").await.unwrap_err();
        assert!(matches!(err, RauhaError::ZoneNotFound(_)));
    }

    #[tokio::test]
    async fn delete_nonexistent_zone_errors() {
        let tmp = TempDir::new().unwrap();
        let reg = test_registry(&tmp);

        let err = reg.delete_zone("nope", false).await.unwrap_err();
        assert!(matches!(err, RauhaError::ZoneNotFound(_)));
    }

    #[tokio::test]
    async fn create_container_in_zone() {
        let tmp = TempDir::new().unwrap();
        let reg = test_registry(&tmp);

        let zone = reg
            .create_zone("myzone", ZoneType::NonGlobal, ZonePolicy::default())
            .await
            .unwrap();

        let container = reg
            .create_container("myzone", make_spec("ctr1"))
            .await
            .unwrap();

        assert_eq!(container.zone_id, zone.id);
        assert_eq!(container.name, "ctr1");
        assert_eq!(container.state, rauha_common::container::ContainerState::Created);

        // Verify persisted.
        let loaded = reg.get_container(&container.id).unwrap();
        assert_eq!(loaded.id, container.id);
    }

    #[tokio::test]
    async fn create_container_in_missing_zone() {
        let tmp = TempDir::new().unwrap();
        let reg = test_registry(&tmp);

        let err = reg
            .create_container("ghost", make_spec("ctr1"))
            .await
            .unwrap_err();
        assert!(matches!(err, RauhaError::ZoneNotFound(_)));
    }

    #[tokio::test]
    async fn delete_zone_blocked_by_containers() {
        let tmp = TempDir::new().unwrap();
        let reg = test_registry(&tmp);

        reg.create_zone("busy", ZoneType::NonGlobal, ZonePolicy::default())
            .await
            .unwrap();
        reg.create_container("busy", make_spec("ctr1"))
            .await
            .unwrap();

        let err = reg.delete_zone("busy", false).await.unwrap_err();
        assert!(matches!(err, RauhaError::ZoneNotEmpty { .. }));
    }

    #[tokio::test]
    async fn force_delete_zone_with_containers() {
        let tmp = TempDir::new().unwrap();
        let reg = test_registry(&tmp);

        reg.create_zone("forceme", ZoneType::NonGlobal, ZonePolicy::default())
            .await
            .unwrap();
        let ctr = reg
            .create_container("forceme", make_spec("ctr1"))
            .await
            .unwrap();

        reg.delete_zone("forceme", true).await.unwrap();

        // Zone gone.
        assert!(reg.get_zone("forceme").await.is_err());
        // Container gone.
        assert!(reg.get_container(&ctr.id).is_err());
    }

    #[tokio::test]
    async fn container_lifecycle_states() {
        let tmp = TempDir::new().unwrap();
        let reg = test_registry(&tmp);

        reg.create_zone("lc", ZoneType::NonGlobal, ZonePolicy::default())
            .await
            .unwrap();
        let ctr = reg.create_container("lc", make_spec("ctr")).await.unwrap();
        assert_eq!(ctr.state, rauha_common::container::ContainerState::Created);

        // Start.
        reg.start_container(&ctr.id).await.unwrap();
        let running = reg.get_container(&ctr.id).unwrap();
        assert_eq!(running.state, rauha_common::container::ContainerState::Running);
        assert!(running.started_at.is_some());
        assert!(running.pid.is_some(), "started container must have a PID");

        // Stop.
        reg.stop_container(&ctr.id, 10).await.unwrap();
        let stopped = reg.get_container(&ctr.id).unwrap();
        assert_eq!(stopped.state, rauha_common::container::ContainerState::Stopped);
        assert!(stopped.finished_at.is_some());

        // Delete.
        reg.delete_container(&ctr.id, false).await.unwrap();
        assert!(reg.get_container(&ctr.id).is_err());
    }

    #[tokio::test]
    #[cfg(target_os = "linux")]
    async fn reap_dead_container_on_get() {
        use rauha_common::container::ContainerState;

        let tmp = TempDir::new().unwrap();
        let reg = test_registry(&tmp);

        reg.create_zone("reap", ZoneType::NonGlobal, ZonePolicy::default())
            .await
            .unwrap();
        let ctr = reg.create_container("reap", make_spec("ephemeral")).await.unwrap();

        // Start (MockBackend returns our PID, which is alive).
        reg.start_container(&ctr.id).await.unwrap();
        let running = reg.get_container(&ctr.id).unwrap();
        assert_eq!(running.state, ContainerState::Running);

        // Manually set a dead PID (PID 1 is always alive, but PID 999999999 is not).
        let mut hacked = running;
        hacked.pid = Some(999_999_999);
        reg.metadata.put_container(&hacked).unwrap();

        // get_container should lazily reap it.
        let reaped = reg.get_container(&ctr.id).unwrap();
        assert_eq!(reaped.state, ContainerState::Stopped, "dead PID must be reaped to Stopped");
        assert!(reaped.finished_at.is_some(), "reaped container must have finished_at");

        // list_containers should also show Stopped.
        let listed = reg.list_containers(Some("reap")).unwrap();
        assert_eq!(listed[0].state, ContainerState::Stopped);
    }

    #[tokio::test]
    async fn list_containers_filters_by_zone() {
        let tmp = TempDir::new().unwrap();
        let reg = test_registry(&tmp);

        reg.create_zone("z1", ZoneType::NonGlobal, ZonePolicy::default())
            .await
            .unwrap();
        reg.create_zone("z2", ZoneType::NonGlobal, ZonePolicy::default())
            .await
            .unwrap();

        reg.create_container("z1", make_spec("a")).await.unwrap();
        reg.create_container("z1", make_spec("b")).await.unwrap();
        reg.create_container("z2", make_spec("c")).await.unwrap();

        assert_eq!(reg.list_containers(Some("z1")).unwrap().len(), 2);
        assert_eq!(reg.list_containers(Some("z2")).unwrap().len(), 1);
        assert_eq!(reg.list_containers(None).unwrap().len(), 3);
    }

    #[tokio::test]
    async fn zone_name_for_container_lookup() {
        let tmp = TempDir::new().unwrap();
        let reg = test_registry(&tmp);

        let zone = reg
            .create_zone("lookup", ZoneType::NonGlobal, ZonePolicy::default())
            .await
            .unwrap();

        let name = reg.zone_name_for_container(&zone.id).await;
        assert_eq!(name.as_deref(), Some("lookup"));

        // Unknown zone_id.
        assert!(reg.zone_name_for_container(&Uuid::new_v4()).await.is_none());
    }

    #[tokio::test]
    async fn apply_policy_updates_metadata() {
        let tmp = TempDir::new().unwrap();
        let reg = test_registry(&tmp);

        reg.create_zone("pol", ZoneType::NonGlobal, ZonePolicy::default())
            .await
            .unwrap();

        let mut new_policy = ZonePolicy::default();
        new_policy.resources.pids_max = 999;

        reg.apply_policy("pol", new_policy).await.unwrap();

        let zone = reg.get_zone("pol").await.unwrap();
        assert_eq!(zone.policy.resources.pids_max, 999);
    }

    #[tokio::test]
    async fn concurrent_create_same_name_one_wins() {
        let tmp = TempDir::new().unwrap();
        let reg = Arc::new(test_registry(&tmp));

        let mut handles = Vec::new();
        for _ in 0..10 {
            let r = Arc::clone(&reg);
            handles.push(tokio::spawn(async move {
                r.create_zone("dup-race", ZoneType::NonGlobal, ZonePolicy::default())
                    .await
            }));
        }

        let mut results = Vec::new();
        for handle in handles {
            results.push(handle.await.unwrap());
        }

        let successes = results.iter().filter(|r| r.is_ok()).count();
        let already_exists = results
            .iter()
            .filter(|r| matches!(r, Err(RauhaError::ZoneAlreadyExists(_))))
            .count();

        assert_eq!(successes, 1, "exactly one create should succeed");
        assert_eq!(already_exists, 9, "all others should get AlreadyExists");
    }
}
