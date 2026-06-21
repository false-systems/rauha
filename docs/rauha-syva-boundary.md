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

## Enforcement Seam

`rauha-enforcer-api` defines the kernel-enforcement interface behind Rauha's
zone lifecycle. It has no eBPF dependency and does not expose Rauha policy
types. Rauha translates user-facing policy into enforcement vocabulary before
calling the backend. The trait is the complete, name-keyed enforcement
contract — see [rauha-product-abilities.md](rauha-product-abilities.md) for how
it splits Rauha (the product) from the enforcer behind it.

```rust
trait EnforcerBackend {
    async fn load(&self) -> Result<(), EnforcerError>;
    async fn shutdown(&self) -> Result<(), EnforcerError>;

    async fn register_zone(&self, name: &str, policy: &EnforcementPolicy)
        -> Result<u32, EnforcerError>;            // returns the kernel zone id
    async fn remove_zone(&self, name: &str, drain: bool) -> Result<(), EnforcerError>;
    async fn apply_policy(&self, zone: &ZoneRef, policy: &EnforcementPolicy)
        -> Result<(), EnforcerError>;

    async fn attach_container(&self, zone: &ZoneRef, container_id: &str, cgroup_id: u64)
        -> Result<(), EnforcerError>;
    async fn detach_container(&self, container_id: &str, cgroup_id: u64)
        -> Result<(), EnforcerError>;
    async fn register_host_path(&self, zone: &ZoneRef, path: &str, recursive: bool)
        -> Result<u32, EnforcerError>;
    async fn allow_comm(&self, a: &ZoneRef, b: &ZoneRef) -> Result<(), EnforcerError>;
    async fn deny_comm(&self, a: &ZoneRef, b: &ZoneRef) -> Result<(), EnforcerError>;

    fn watch_events(&self) -> EventStream;
    async fn stats(&self, zone: &ZoneRef) -> Result<EnforcementStats, EnforcerError>;
    async fn verify(&self, zone: &ZoneRef, policy: &EnforcementPolicy)
        -> Result<VerifyReport, EnforcerError>;
    fn capabilities(&self) -> Capabilities;
}
```

The trait is **name-keyed** because the zone name is the stable handle both the
in-repo eBPF backend (which also keeps a compact `u32` map key) and Syva
(`register_zone` returns its own `u32`) share. `ZoneRef { name, kernel_id }`
carries both so each backend uses whichever it needs. This shape mirrors
`syva.core.v1` (`RegisterZone`/`AttachContainer`/`RegisterHostPath`/`AllowComm`/
`WatchEvents`), so a `SyvaEnforcer` is a direct implementation.

`verify` is a drift/parity self-check: it answers whether the backend's loaded
state for a zone matches Rauha's intended `EnforcementPolicy`. BPF verifier or
program-load errors belong to `load`.

`EnforcementPolicy` carries a `ZoneEnforcement` record — the seam's own neutral
policy vocabulary (`{ caps_mask, allow_ptrace, allow_host_net }`), plus a
deliberately small list of per-hook rules. Rauha translates its user-facing
`ZonePolicy` into `ZoneEnforcement` (`ZonePolicy::to_enforcement`, the single
source of truth for policy meaning); the Linux adapter maps `ZoneEnforcement`
onto the kernel `ZonePolicyKernel` flag bits (`enforcement_to_kernel`, the only
place that knows the kernel ABI). The seam never imports Rauha or eBPF policy
types. On Linux, `apply_policy` and the daemon's synchronous `enforce_policy`
share one sync core (`LinuxEnforcer::apply_zone_enforcement`), so both write the
same `ZONE_POLICY` entry without either blocking a tokio runtime.

The important rules are:

- Rauha owns user-facing runtime lifecycle.
- Rauha owns user-facing policy.
- Syva owns Linux kernel enforcement.
- Rauha translates Rauha policy into Syva/kernel-facing policy.
- Rauha exposes Syva events through Rauha APIs and sandbox results.
- macOS does not use Syva.
- unsupported platforms use an explicit noop/unsupported enforcer with honest
  capabilities. A backend without kernel enforcement must reject LSM-required
  rules instead of silently accepting them.

Do not delete the current eBPF crates until an external Syva integration exists
and tests prove the replacement path.
