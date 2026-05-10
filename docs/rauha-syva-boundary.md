# Rauha and Syva Boundary

Rauha creates the zones. Syva makes the Linux kernel respect them.

This boundary keeps Rauha from becoming "the eBPF project" and keeps Syva from
becoming a runtime.

## Rauha Owns

- agent sandbox execution
- zone lifecycle
- container lifecycle
- daemon, CLI, and API
- policy loading and validation
- image/rootfs handling
- networking
- metadata
- logs and audit events
- Kubernetes/containerd integration
- macOS VM-per-zone backend
- user-facing enforcement event surfaces

## Syva Owns

- Linux kernel enforcement
- eBPF LSM programs
- BPF maps
- ring buffer events
- file/open enforcement
- exec enforcement
- ptrace enforcement
- signal enforcement
- cgroup attach enforcement
- enforcement counters
- kernel capability verification
- privileged kernel self-tests

## Current Transitional State

The Rauha repository still contains Linux eBPF code:

- `rauha-ebpf`
- `rauha-ebpf-common`
- `rauhad/src/backend/linux/ebpf.rs`
- `rauhad/src/backend/linux/maps.rs`
- `rauhad/src/backend/linux/events.rs`
- `rauha-enforce`

That code is still useful, but architecturally it should sit behind a Syva
enforcement boundary.

## Future Seam

A future implementation should introduce a small kernel-enforcement interface
behind Rauha's zone lifecycle. Conceptually:

```rust
trait KernelEnforcer {
    fn load(&self) -> Result<()>;
    fn create_zone(&self, spec: ZoneKernelSpec) -> Result<()>;
    fn delete_zone(&self, zone_id: ZoneId) -> Result<()>;
    fn apply_policy(&self, zone_id: ZoneId, policy: KernelZonePolicy) -> Result<()>;
    fn watch_events(&self) -> EnforcementEventStream;
    fn stats(&self) -> Result<EnforcementStats>;
    fn verify(&self) -> Result<KernelEnforcementReport>;
}
```

This is a design sketch, not a committed API.

The important rules are:

- Rauha owns user-facing runtime lifecycle.
- Rauha owns user-facing policy.
- Syva owns Linux kernel enforcement.
- Rauha translates Rauha policy into Syva/kernel-facing policy.
- Rauha exposes Syva events through Rauha APIs and sandbox results.
- macOS does not use Syva.
- unsupported platforms should use an explicit Noop/Unsupported enforcer.

Do not delete the current eBPF crates until an external Syva integration exists
and tests prove the replacement path.
