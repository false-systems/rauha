# Rauha

**Kernel-level enforcement and observability for container isolation.**

Docker gives you namespaces and cgroups. That's structural isolation — it sets up walls, but nothing watches the doors. A process can't see across a namespace boundary, but the kernel doesn't know that two containers *shouldn't* talk to each other. There's no enforcement at the syscall level, no audit trail of what was allowed or denied, no way to prove a workload stayed inside its boundary.

Rauha adds what's missing. Five eBPF LSM hooks run inside the kernel on every `open()`, `exec()`, `kill()`, `ptrace()`, and `cgroup_attach()`. Every call is checked against zone membership. Every deny is recorded with the process, the zone, and the target. This works on any cgroup-based workload — Rauha's own containers, or containers managed by containerd, Docker, or Kubernetes.

**Two ways to use Rauha:**

- **Rauha runtime** — a standalone container runtime where zones are first-class. Zones unify cgroups, namespaces, and eBPF enforcement under one API. Integrates with Kubernetes via a containerd shim v2. Linux uses eBPF LSM; macOS uses Virtualization.framework VMs.

- **[Syvä](https://github.com/false-systems/syva)** — the drop-on enforcement layer for existing clusters has been extracted into its own product. Different audience, different brand: keep your stack, Syvä adds eBPF enforcement on top.

**Why this matters for AI infrastructure:**

AI agents execute arbitrary code. Training jobs touch sensitive data. Model weights are high-value IP. GPU workloads share nodes. The isolation story for all of this is "a Docker container" — which means a shared kernel and hope.

Rauha's eBPF hooks give you enforceable, auditable isolation: an agent sandbox where you can prove the agent never read files outside its zone. A training job where you have kernel-level evidence of which datasets were accessed. Millisecond zone startup with no VM boot overhead. Every enforcement decision streamed in real time for compliance and anomaly detection.

> *Rauha* (Finnish) — peace, calm. What your production systems should be.

## The Zone Model

A zone is not a namespace. It's not a cgroup. It's the *concept* that ties them together.

```
┌─────────────────────────────────────────────────────────┐
│                   Global Zone (Host)                    │
│                                                         │
│   rauhad ─── gRPC :9876 ──── rauha CLI                 │
│                                                         │
│   ┌─────────────────────┐   ┌─────────────────────┐    │
│   │       Zone A        │   │       Zone B         │    │
│   │                     │   │                      │    │
│   │   nginx             │   │   postgres           │    │
│   │   app-server        │   │   redis              │    │
│   │                     │   │                      │    │
│   │   10.89.0.2/16      │   │   10.89.0.3/16       │    │
│   │   own cgroup        │   │   own cgroup          │    │
│   │   own netns         │   │   own netns           │    │
│   │   own rootfs        │   │   own rootfs          │    │
│   └─────────────────────┘   └──────────────────────┘    │
│              ╳ denied by default ╳                       │
└─────────────────────────────────────────────────────────┘
```

Every container belongs to exactly one zone. Zones are the unit of:

| Concern | What it means |
|---------|---------------|
| **Visibility** | Processes in Zone A cannot see Zone B's processes |
| **Access** | Files, IPC, and signals cannot cross zone boundaries |
| **Networking** | Each zone gets its own IP, bridge connectivity, and firewall rules |
| **Resources** | CPU, memory, I/O, and PID limits scoped per zone |
| **Policy** | TOML-based, allow-list only, hot-reloadable without restart |

Cross-zone communication requires an explicit policy rule — allow-list, not deny-list.

## How It Works

### Linux: eBPF makes the kernel zone-aware

Rauha loads eBPF programs into kernel LSM hooks that enforce zone boundaries at the syscall level. Every `open()`, `kill()`, `connect()`, and `ptrace()` checks zone membership before proceeding.

```
Process in Zone A calls open("/data/file.txt")
  │
  ├─ kernel reaches file_open LSM hook
  ├─ rauha eBPF program fires
  ├─ lookup: process cgroup → zone_id = A
  ├─ lookup: file inode → file_zone = B
  ├─ A ≠ B → return -EACCES
  │
  └─ process gets "Permission denied"
```

This isn't a userspace check — it's enforced in the kernel on every access with no daemon round-trip. Policy changes are a BPF map update, not a process restart.

| eBPF Program | LSM Hook | Blocks |
|-------------|----------|--------|
| `rauha_file_open` | `file_open` | Cross-zone file access |
| `rauha_bprm_check` | `bprm_check_security` | Cross-zone binary execution |
| `rauha_ptrace_check` | `ptrace_access_check` | Cross-zone debugging/tracing |
| `rauha_task_kill` | `task_kill` | Cross-zone signals |
| `rauha_cgroup_attach` | `cgroup_attach_task` | Zone escape via cgroup manipulation |

Every deny is emitted to a ring buffer with the caller PID, zone IDs, and context (inode, cgroup ID) for audit and debugging.

Requires Linux 6.1+ with `CONFIG_BPF_LSM=y`.

### macOS: native VMs via Virtualization.framework

Each zone is a lightweight Linux VM — not a hidden shared VM like Docker Desktop. Each zone gets its own VM with hardware-enforced isolation.

The `rauha-guest-agent` runs inside each VM and manages container processes over virtio-vsock, using the same postcard IPC protocol as the Linux shim. APFS `clonefile()` provides instant, zero-copy rootfs clones. Network isolation uses pf firewall anchors per zone.

Same CLI. Same policy format. Same guarantees.

### Zone Networking

Each zone gets a unique IP from the `10.89.0.0/16` subnet. The `rauha0` bridge acts as gateway. nftables handles NAT masquerade for internet access and per-zone forward chains for traffic filtering.

```
Zone A (10.89.0.2)                    Zone B (10.89.0.3)
    │                                     │
  eth0 ──── veth-a ─┐       ┌── veth-b ── eth0
                    │       │
              ┌─────┴───────┴─────┐
              │     rauha0        │
              │   10.89.0.1/16    │
              │   (bridge+gw)     │
              └────────┬──────────┘
                       │
                 IP forwarding
                       │
                nftables NAT
                (masquerade)
                       │
                 host interface
                       │
                    internet
```

**Enforcement layering:** nftables handles packet filtering (L3/L4). eBPF `ZONE_ALLOWED_COMMS` map provides defense-in-depth for cross-zone socket operations. Network namespaces provide structural isolation. Three independent layers — if one is bypassed, the others still hold.

## Architecture

```
┌──────────────────┐
│    rauha CLI     │
└────────┬─────────┘
         │ gRPC :9876
┌────────▼─────────────────────────────────────────────┐
│                        rauhad                        │
│                                                      │
│  Zone Registry ── Policy Engine ── Metadata (redb)   │
│       │                                              │
│  IsolationBackend (trait)                            │
│       │                                              │
│  Image Service ── Content Store ── IP Allocator      │
└───────┬──────────────────────────────────┬───────────┘
        │                                  │
┌───────▼──────────┐            ┌──────────▼───────────┐
│  Linux Backend   │            │   macOS Backend      │
│                  │            │                      │
│  eBPF LSM hooks  │            │  Virtualization.fw   │
│  cgroups v2      │            │  APFS clonefile      │
│  network ns      │            │  pf firewall         │
│  nftables NAT    │            │  virtio-vsock        │
│  IP allocator    │            │  VM-per-zone         │
└───────┬──────────┘            └──────────┬───────────┘
        │ one per zone                     │ one VM per zone
┌───────▼──────────┐            ┌──────────▼───────────┐
│   rauha-shim     │            │ rauha-guest-agent    │
│ sync, fork-safe  │            │   inside Linux VM    │
│ Unix socket IPC  │            │   vsock port 5123    │
│ postcard codec   │            │   postcard codec     │
└──────────────────┘            └──────────────────────┘
```

### The `IsolationBackend` trait

The key abstraction. Both backends implement the same interface — `rauhad` is platform-agnostic.

```rust
trait IsolationBackend: Send + Sync {
    fn create_zone(&self, config: &ZoneConfig) -> Result<ZoneHandle>;
    fn destroy_zone(&self, zone: &ZoneHandle) -> Result<()>;
    fn enforce_policy(&self, zone: &ZoneHandle, policy: &ZonePolicy) -> Result<()>;
    fn hot_reload_policy(&self, zone: &ZoneHandle, policy: &ZonePolicy) -> Result<()>;
    fn create_container(&self, zone: &ZoneHandle, spec: &ContainerSpec) -> Result<ContainerHandle>;
    fn start_container(&self, container: &ContainerHandle) -> Result<u32>;
    fn stop_container(&self, container: &ContainerHandle) -> Result<()>;
    fn zone_stats(&self, zone: &ZoneHandle) -> Result<ZoneStats>;
    fn verify_isolation(&self, zone: &ZoneHandle) -> Result<IsolationReport>;
    fn recover_zone(&self, zone: &ZoneHandle, zone_type: ZoneType, policy: &ZonePolicy) -> Result<()>;
    fn cleanup_orphans(&self, known_zones: &[ZoneHandle]) -> Result<()>;
    fn isolation_model(&self) -> IsolationModel; // SyscallPolicy | HardwareBoundary
    fn name(&self) -> &str;
}
```

### Crate Structure

| Crate | Purpose |
|-------|---------|
| `rauha-common` | Shared types, `IsolationBackend` trait, policy parsing, shim IPC protocol |
| `rauhad` | Daemon — gRPC server, zone registry, metadata (redb), networking, backends |
| `rauha-cli` | CLI binary |
| `rauha-shim` | Per-zone sync process — fork/run containers (Linux only) |
| `rauha-guest-agent` | Guest-side daemon inside macOS VMs |
| `rauha-oci` | OCI image pull, content store, rootfs preparation |
| `rauha-ebpf` | eBPF LSM programs (kernel-side, separate build) |
| `rauha-ebpf-common` | Shared `#[repr(C)]` types between eBPF and userspace |
| `containerd-shim-rauha-v2` | containerd shim v2 — bridges containerd to rauhad for Kubernetes |
| `rauha-enforce` | *Legacy.* Superseded by [Syvä](https://github.com/false-systems/syva) — a separate product. |
| `xtask` | Build helper for eBPF compilation |

### Kubernetes Integration

Rauha integrates with Kubernetes via a containerd shim v2. The `containerd-shim-rauha-v2` binary bridges containerd's Task ttrpc API to rauhad's gRPC API:

```
kubelet → containerd → containerd-shim-rauha-v2 (ttrpc) → rauhad (gRPC)
```

Sandbox creation maps to Rauha zone creation. Container operations map to Rauha container operations within that zone. Use `runtimeClassName: rauha` in pod specs.

### Enforcement Observability

Every deny decision from the 7 LSM hooks is emitted to a BPF ring buffer and streamed to userspace. Each event carries the timestamp, PID, caller zone, target zone, and hook-specific context (inode for file access, cgroup ID for cgroup escape attempts).

This provides:
- **Audit trails** — provable evidence that a workload never escaped its zone
- **Real-time visibility** — see enforcement decisions as they happen
- **Debugging** — understand exactly why access was denied

Enforcement counters (allow/deny/error per hook, per CPU) are always available for aggregate monitoring.

## Usage

```bash
# Create zones with policies
rauha zone create --name frontend --policy policies/standard.toml
rauha zone create --name database --policy policies/strict.toml

# Run containers in zones
rauha run --zone frontend nginx:latest
rauha run --zone database postgres:16

# Verify isolation
rauha zone verify frontend

# Image management
rauha image pull alpine:latest
rauha image ls
rauha image inspect alpine:latest

# Observe
rauha ps --zone frontend
rauha logs <container-id> --follow
rauha exec -it <container-id> /bin/sh
```

### Zone Policies

Declarative TOML. Allow-list model — nothing is permitted unless explicitly listed.

```toml
[zone]
name = "production"
type = "non-global"

[capabilities]
allowed = ["CAP_NET_BIND_SERVICE", "CAP_CHOWN"]

[resources]
cpu_shares = 1024
memory_limit = "4Gi"
pids_max = 512

[network]
mode = "bridged"
allowed_zones = ["frontend"]
allowed_egress = ["0.0.0.0/0:443"]

[filesystem]
writable_paths = ["/data", "/tmp", "/var/log"]

[syscalls]
deny = ["mount", "umount2", "pivot_root"]
```

## Oracle Test Suite

Rauha includes a ground-truth oracle (`eval/oracle/`) — a standalone Rust binary that validates rauhad through its gRPC API. 55 numbered test cases across 11 categories. The oracle never reads source code, never mocks. When a case fails, it means the system's public contract is broken.

```bash
cd eval/oracle
RAUHA_GRPC_ENDPOINT=http://[::1]:9876 cargo test           # all cases
RAUHA_GRPC_ENDPOINT=http://[::1]:9876 cargo test -- case_001  # one case
```

| Range | Category | Cases |
|-------|----------|-------|
| 001-003 | Zone lifecycle | create, list, delete, duplicates |
| 004-006 | Container lifecycle | create, start, stop, exit |
| 007-009 | Image management | pull, inspect, remove |
| 010-012 | Isolation verification | healthy, nonexistent, policy reload |
| 013-015 | Policy enforcement | apply, memory limits, invalid rejection |
| 016-018 | Networking | bridged, host mode, DNS |
| 019-021 | Observability | stats, NotFound paths |
| 022-029 | Resilience | input validation (8 cases) |
| 030-034 | Multi-zone | coexistence, scoping, force-delete |
| 035-039 | Container edge cases | NotFound, invalid UUID |
| 040-054 | Invariants & stress | ID consistency, boundaries, rapid cycles |

## Building

```bash
# Build all workspace crates
cargo build

# Run unit tests
cargo test

# Start the daemon
RUST_LOG=rauhad=debug cargo run --bin rauhad

# macOS: sign after every build
codesign --entitlements rauhad/rauhad.entitlements -s - target/debug/rauhad

# Build eBPF programs (requires nightly)
cargo xtask build-ebpf
```

**Linux:** kernel 6.1+, `CONFIG_BPF_LSM=y`, `CONFIG_BPF_SYSCALL=y`, `CONFIG_DEBUG_INFO_BTF=y`, boot with `lsm=lockdown,capability,bpf`

**macOS:** macOS 15+ (Sequoia), Apple Silicon or Intel with VT-x, `com.apple.security.virtualization` entitlement

## Trade-offs

**eBPF is not a kernel primitive.** Zone identity is reconstructed via BPF map lookup on every enforcement call. Defended by the `zone_cgroup_lock` LSM hook, but it's defense-in-depth, not a hardware boundary.

**LSM is additive-only.** eBPF LSM programs can deny access but cannot override SELinux/AppArmor denials. Zone policy must be a subset of existing MAC policy.

**Struct offsets are resolved at load time.** eBPF programs read kernel struct fields (e.g., `file->f_inode`, `task_struct->cgroups`) via configurable offsets injected as globals by userspace. When `pahole` is available, real offsets are read from the running kernel's BTF and patched into the programs before loading — no rebuild needed for different kernels. A runtime self-test validates the offset chain on first execution. If pahole is not installed, sensible defaults for Linux 6.1+ are used.

**Covert channels** via shared kernel resources (CPU cache timing, memory pressure) are not addressable by eBPF. Same limitation as all OS-level isolation.

**IPv4-focused networking.** Zone networking uses the `10.89.0.0/16` subnet. IPv6 addresses and routes are not configured for zones, and IPv6-specific egress allow-listing / NAT are not implemented. The nftables `inet` filtering rules apply to both IPv4 and IPv6, but zone network setup and IPv4-specific `ip saddr` / `ip daddr` matches mean inter-zone IPv6 networking is not supported today.

## License

Apache-2.0
