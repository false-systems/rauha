use crate::container::{ContainerHandle, ContainerSpec};
use crate::error::Result;
use crate::shim::{ShimRequest, ShimResponse};
use crate::zone::{IsolationModel, IsolationReport, ZoneConfig, ZoneHandle, ZonePolicy, ZoneStats, ZoneType};

/// The core abstraction for platform-specific isolation.
///
/// Linux and macOS backends implement this trait. `rauhad` uses
/// `dyn IsolationBackend` to remain platform-agnostic while Rauha keeps
/// ownership of user-facing zone lifecycle. Linux kernel enforcement currently
/// lives in this repository, but the architectural boundary is Syva-backed:
/// Rauha creates zones; Syva makes the Linux kernel respect them.
pub trait IsolationBackend: Send + Sync {
    /// Create a new isolation zone.
    fn create_zone(&self, config: &ZoneConfig) -> Result<ZoneHandle>;

    /// Destroy a zone and release all associated resources.
    fn destroy_zone(&self, zone: &ZoneHandle) -> Result<()>;

    /// Apply or replace the enforcement policy for a zone.
    fn enforce_policy(&self, zone: &ZoneHandle, policy: &ZonePolicy) -> Result<()>;

    /// Hot-reload a policy without restarting the zone or its containers.
    fn hot_reload_policy(&self, zone: &ZoneHandle, policy: &ZonePolicy) -> Result<()>;

    /// Create a container within a zone.
    fn create_container(&self, zone: &ZoneHandle, spec: &ContainerSpec) -> Result<ContainerHandle>;

    /// Start a previously created container. Returns the container's PID.
    fn start_container(&self, container: &ContainerHandle) -> Result<u32>;

    /// Stop a running container.
    fn stop_container(&self, container: &ContainerHandle) -> Result<()>;

    /// Get runtime statistics for a zone.
    fn zone_stats(&self, zone: &ZoneHandle) -> Result<ZoneStats>;

    /// Verify that zone isolation is intact.
    fn verify_isolation(&self, zone: &ZoneHandle) -> Result<IsolationReport>;

    /// Re-establish kernel state for a zone from persisted metadata.
    ///
    /// Called on daemon startup to reconcile redb (source of truth) with
    /// kernel state (BPF maps, cgroups, netns) that may be stale or missing
    /// after a crash. Implementations should be idempotent — calling this
    /// on an already-consistent zone should be a no-op.
    fn recover_zone(&self, zone: &ZoneHandle, zone_type: ZoneType, policy: &ZonePolicy) -> Result<()>;

    /// Clean up orphaned kernel state not associated with any known zone.
    ///
    /// Called on startup after all known zones have been recovered.
    /// Implementations should remove cgroups, BPF map entries, and netns
    /// that don't correspond to any zone in the provided list.
    fn cleanup_orphans(&self, known_zones: &[ZoneHandle]) -> Result<()>;

    /// The enforcement model this backend uses.
    ///
    /// Callers interpreting isolation reports or enforcement events must
    /// check this — `SyscallPolicy` and `HardwareBoundary` have fundamentally
    /// different semantics for what "cross-zone access denied" means.
    fn isolation_model(&self) -> IsolationModel;

    /// The name of this backend (e.g., "linux-ebpf", "macos-virt").
    fn name(&self) -> &str;

    /// Why enforcement is degraded, if it is — e.g. LSM hooks the running
    /// kernel does not expose. `None` means full enforcement. Backends that
    /// cannot be partially degraded keep the default.
    fn enforcement_degraded_reason(&self) -> Option<String> {
        None
    }

    /// Resolve the backend's compact, kernel-side identifier for a zone.
    ///
    /// Kernel enforcement events carry this compact id (not the user-facing
    /// UUID), so callers correlating events back to a zone need it. Returns
    /// `None` when the backend assigns no kernel-side id — e.g. macOS VMs
    /// (the VM is the boundary) or Linux with eBPF not loaded.
    fn kernel_zone_id(&self, _zone: &ZoneHandle) -> Option<u32> {
        None
    }

    /// Send a shim request via the backend's native transport.
    ///
    /// On macOS, this routes through vsock to the guest agent inside the VM.
    /// On Linux, the registry handles shim communication directly via Unix
    /// socket, so this default (error) is fine.
    fn shim_request(&self, _zone_name: &str, _request: &ShimRequest) -> Result<ShimResponse> {
        Err(crate::error::RauhaError::BackendError(
            "shim_request not supported by this backend".into(),
        ))
    }

    /// Connect to a vsock port on a zone's VM for exec I/O relay.
    ///
    /// Returns a raw fd for bidirectional streaming. Only implemented by the
    /// macOS backend — Linux exec uses Unix sockets instead.
    fn connect_vsock_port(
        &self,
        _zone_name: &str,
        _port: u32,
    ) -> Result<std::os::fd::OwnedFd> {
        Err(crate::error::RauhaError::BackendError(
            "vsock not available on this backend".into(),
        ))
    }
}
