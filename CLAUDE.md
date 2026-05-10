# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What This Is

Rauha is an agent sandbox runtime built on controlled execution zones. A zone is the task/workload boundary that ties together filesystem view, processes, networking, resources, policy, logs, audit events, and optional enforcement events.

The product hierarchy is load-bearing:

1. Agent sandbox runtime.
2. Zone-based runtime foundation.
3. Kubernetes/containerd and existing-workload deployment paths.

Do not present Rauha as primarily an eBPF project or a Kubernetes runtime. Rauha creates the zones. Syva makes the Linux kernel respect them. Current Linux eBPF code may still live in this repository, but architecturally it belongs behind the Syva enforcement boundary.

## Build & Test Commands

```bash
cargo build                          # Build all workspace crates
cargo test                           # Run all unit tests
cargo test -p rauha-oci              # Test a single crate
cargo test test_name                 # Run a single test by name
cargo build --bin rauhad             # Build just the daemon
cargo build --bin rauha              # Build just the CLI
cargo build --bin rauha-shim         # Build the per-zone shim
cargo build --bin rauha-guest-agent  # Build the macOS VM guest agent
cargo build --bin rauha-enforce      # Build standalone enforcement agent
cargo build -p containerd-shim-rauha-v2  # Build the containerd shim

# eBPF programs (separate build, requires nightly Rust)
cargo xtask build-ebpf               # Debug build
cargo xtask build-ebpf --release     # Release build
cargo xtask build-guest-agent        # Cross-compile guest agent (aarch64-unknown-linux-musl)
cargo xtask build-initramfs          # Build initramfs with guest agent (for macOS VMs)

# macOS: sign rauhad after every build (required for Virtualization.framework)
codesign --entitlements rauhad/rauhad.entitlements -s - target/debug/rauhad

# Run the daemon (development, listens on [::1]:9876)
RUST_LOG=rauhad=debug cargo run --bin rauhad

# Use the CLI (connects to RAUHA_ADDR or http://[::1]:9876)
cargo run --bin rauha -- zone create --name test
cargo run --bin rauha -- zone list
cargo run --bin rauha -- image pull alpine:latest
cargo run --bin rauha -- run --zone test alpine:latest /bin/echo hello

# Integration tests (Linux only, require root + running rauhad)
bash tests/integration/test-image-pull.sh
bash tests/integration/test-container-lifecycle.sh
bash tests/integration/test-zone-isolation.sh
bash tests/integration/test-zone-networking.sh
bash tests/integration/test-exec.sh
bash tests/integration/test-logs.sh
bash tests/integration/test-cgroup-lock.sh          # eBPF enforcement required

# Oracle tests (require running rauhad, any platform)
cd eval/oracle
RAUHA_GRPC_ENDPOINT=http://[::1]:9876 cargo test           # all cases
RAUHA_GRPC_ENDPOINT=http://[::1]:9876 cargo test -- case_001  # one case
```

Proto files are in `proto/` (zone.proto, container.proto, image.proto). They compile automatically via `build.rs` in rauhad and rauha-cli.

## Core Principles

1. **Easy to understand** — no clever abstractions, no indirection for its own sake.
2. **Easy to use** — `rauha zone create`, `rauha run`. No 50-flag commands.
3. **Easy to fix** — small files, clear boundaries, minimal dependencies.
4. **Reliable as bedrock** — every code path tested, every error handled with context.

**Non-negotiables:** No YAML (TOML only). No premature abstractions. No "design for the future."

## Architecture

### Key Abstraction: `IsolationBackend` trait (`rauha-common/src/backend.rs`)

Both platform backends implement this trait. rauhad is platform-agnostic — it calls trait methods and doesn't know which OS it's on.

### Async/Sync Boundary

- **rauhad** is async (tokio) — gRPC server, concurrent zone management
- **rauha-shim** is deliberately sync — `fork()` in a multithreaded async runtime is UB. The shim is single-threaded so it can safely fork, setns, pivot_root, and run the container process
- IPC between daemon and shim: length-prefixed postcard over Unix socket (`rauha-common/src/shim.rs`). The protocol includes attach/exec commands — Linux shim returns a Unix socket path, macOS guest agent returns a vsock port for bidirectional I/O.

### One Shim Per Zone (Not Per Container)

This diverges from containerd's one-shim-per-container model. Zones are the isolation boundary, not containers. Multiple containers in a zone share namespaces. rauhad spawns one `rauha-shim` per zone; the shim forks additional container processes on request. Shim binary search: same directory as rauhad, then `target/debug/`, `target/release/`, then `/usr/local/bin`, `/usr/bin`. Socket at `/run/rauha/shim-{zone_name}.sock` — rauhad polls for up to 5 seconds after spawning.

### Container Fork Flow (Linux)

The sync pipe pattern in `rauha-shim/src/container.rs` prevents a TOCTOU race: the child must be in the zone's cgroup **before** it runs, otherwise eBPF enforcement doesn't apply. Parent writes child PID to cgroup, then signals the pipe; child blocks until confirmed.

**Fork-safety invariant:** All code after `fork()` in the child must be async-signal-safe. This means: no `std::env::set_var`/`vars` (holds a global mutex), no `eprintln!`/`panic!` (Rust panic machinery), no heap allocation. Use `libc::putenv` with pre-allocated `CString`s, `libc::write` for output, and `libc::_exit` instead of `std::process::exit`. Pre-allocate all strings and paths before fork.

### macOS Backend: VM-Per-Zone (`rauhad/src/backend/macos/`)

On macOS, each zone is a lightweight Linux VM via Apple's Virtualization.framework. The VM itself is the isolation boundary — no cgroups or namespaces needed.

- **vm.rs** — VM lifecycle. VZVirtualMachine must be created and operated from a GCD serial dispatch queue (one queue per VM).
- **vsock.rs** — virtio-vsock (port 5123) bridge between rauhad and the guest agent inside the VM.
- **apfs.rs** — APFS `clonefile()` for instant, zero-copy rootfs clones (macOS equivalent of overlayfs).
- **pf.rs** — macOS packet filter (pf) firewall anchors, one per zone, generated from ZonePolicy.

The `rauha-guest-agent` runs inside the VM and handles `ShimRequest`/`ShimResponse` messages (same postcard protocol as the Linux shim). It's simpler than `rauha-shim`: no cgroup enrollment (VM is the boundary), no `setns` (already in the right namespace).

- **attach.rs** — PTY fork + vsock relay for exec sessions. Mirrors the Linux shim's attach but uses vsock ports (starting at 6000) instead of Unix sockets, and chroots into virtiofs-mounted rootfs at `/mnt/rauha/containers/{id}/...`. The post-fork async-signal-safety rules apply to the exec child path too — not just initial container fork.

Resource limits (CPU/memory) are set at VM boot and require restart to change. Filesystem sharing uses virtio-fs, mounting the container rootfs from host into the VM at `/mnt/rauha`.

macOS requires the `com.apple.security.virtualization` entitlement — see `rauhad/rauhad.entitlements`. After every build of rauhad, re-sign: `codesign --entitlements rauhad/rauhad.entitlements -s - target/debug/rauhad`.

ObjC exceptions from Virtualization.framework are caught via `objc2::exception::catch` — without this, they abort the Rust process. All VZ API calls in `vm.rs` must go through exception-safe wrappers. VM operations (start, stop, vsock connect) must be dispatched to the VM's serial dispatch queue.

pf firewall rules require root. When running rauhad without root (development), pf errors are logged as warnings and network isolation is inactive.

### Zone Networking (`rauhad/src/network/`, `rauhad/src/backend/linux/nftables.rs`)

Zones get full network connectivity on Linux via: veth pairs → rauha0 bridge (gateway 10.89.0.1) → nftables NAT masquerade → internet. Each zone is assigned a unique IP from the 10.89.0.0/16 subnet by `IpAllocator`, persisted in `Zone.network_state`. DNS resolv.conf is injected into container rootfs (handles systemd-resolved stub detection).

**Enforcement layering:** nftables handles packet filtering (L3/L4). eBPF `ZONE_ALLOWED_COMMS` map is defense-in-depth for cross-zone socket operations. Neither replaces the other.

- **allocator.rs** — stateless IPAM; rebuilds from persisted zone metadata on startup
- **dns.rs** — generates resolv.conf; filters localhost stubs, falls back to 1.1.1.1/8.8.8.8
- **nftables.rs** — NAT masquerade + per-zone forward chains; forward chain defaults to drop; jump rules cleaned by handle on zone deletion

Network setup failures (nftables, bridge, pf) are logged as warnings, not fatal errors — zones still run without network filtering. This allows rootless development on both platforms.

On macOS, VMs get NAT from Virtualization.framework. pf handles per-zone firewall rules (requires root). `allowed_zones` cross-VM support is not yet implemented.

### Enforcement Event Streaming (`rauhad/src/backend/linux/events.rs`)

Every deny decision from the 7 LSM hooks is emitted to a BPF ring buffer (`ENFORCEMENT_EVENTS`, 256 pages / ~1MB). A background task drains the ring buffer every 100ms, decodes `EnforcementEvent` structs (48 bytes, `read_unaligned` — ring buffer data is unaligned), and broadcasts them via `tokio::sync::broadcast`. The `WatchEvents` gRPC stream relays these to clients. Only deny events hit the ring buffer; allows are tracked in per-CPU counters (`ENFORCEMENT_COUNTERS`).

### Zone ID Compaction

User-visible zone IDs are UUIDs (stored in redb). Kernel-side zone IDs are compact `u32` (BPF map keys). The Linux backend maintains a `zone_id_map: Mutex<HashMap<Uuid, u32>>` with an atomic counter for allocation. This mapping is rebuilt from redb on daemon startup via `reconcile()`.

### Kubernetes Integration: containerd-shim-rauha-v2

Bridges containerd's Task ttrpc API to rauhad's gRPC: `kubelet → containerd → containerd-shim-rauha-v2 (ttrpc) → rauhad (gRPC)`.

- Sandbox creation (pause container with `io.kubernetes.cri.container-type=sandbox` annotation) creates a Rauha zone named `k8s-{12-char-sandbox-id-prefix}`
- Subsequent app containers in the pod join the same zone via the `io.kubernetes.cri.sandbox-id` annotation
- Deleting a sandbox zone forces deletion of all containers in it
- Connects to rauhad at `RAUHA_ADDR` or defaults to `http://[::1]:9876`
- Use `runtimeClassName: rauha` in pod specs

### rauha-enforce (legacy — superseded by Syvä)

The `rauha-enforce/` crate in this repo is a **legacy seed**. The standalone enforcement product has been extracted to **Syvä**, a separate repo (`github.com/false-systems/syva`, local at `~/projects/syva`). Syvä has evolved well past the original extraction: it now has a control plane (`syva-cp`), three adapters (`syva-adapter-{file,k8s,api}`), local and cp operating modes, and its own oracle+harness eval framework.

Don't extend `rauha-enforce/` — new enforcement work goes in the syva repo. Bug fixes only if absolutely necessary. The crate still builds for now; the daemonset YAML in `deploy/` is also legacy.

What's still documented here for context: it loaded the same eBPF LSM programs as rauhad, used label-driven zone assignment via the `rauha.dev/zone` OCI annotation, and refused to load if BPF maps were already pinned at `/sys/fs/bpf/rauha/` (mutual exclusion with rauhad).

### gRPC Error Boundary (`rauhad/src/server.rs`)

`to_status()` maps `RauhaError` variants to correct gRPC status codes. When adding new error variants, update this function — the oracle will catch incorrect mappings. Key mappings: `ZoneNotFound`/`ContainerNotFound`/`ImageNotFound`→`NotFound`, `ZoneAlreadyExists`/`ContainerAlreadyExists`→`AlreadyExists`, `InvalidInput`/`InvalidPolicy`→`InvalidArgument`, `PermissionDenied`/`CrossZoneAccessDenied`→`PermissionDenied`, `ZoneNotEmpty`→`FailedPrecondition`.

### Data Stores

- **redb** (`{root}/metadata/rauha.redb`) — persisted zone/container metadata. Source of truth on crash recovery. Uses postcard serialization — adding fields to `Zone`/`Container` structs can break deserialization of old entries. `list_zones()`/`get_zone()` skip incompatible entries with a warning rather than crashing. If the daemon won't start after schema changes, delete the stale db: `rm {root}/metadata/rauha.redb`.
- **BPF maps** (pinned at `/sys/fs/bpf/rauha/`) — in-kernel enforcement state. Reconciled from redb on daemon startup. Linux only.
- **Content store** (`{root}/content/blobs/sha256/`) — content-addressable OCI blob storage.
- **VM assets** (`/var/lib/rauha/vm/vmlinux`, `initramfs.img`) — kernel and initramfs for macOS VMs. Installed via `rauha setup`.

Root directory: `/var/lib/rauha` on Linux, `/tmp/rauha` on macOS (dev default, override with `RAUHA_ROOT`).

On startup, rauhad runs `reconcile()`: loads all zones from redb, calls `recover_zone()` on each to re-establish kernel state (BPF maps, cgroups, network), then `cleanup_orphans()` to remove stale kernel state. Stale BPF pins are removed before loading new programs — redb is the source of truth.

### eBPF Programs (`rauha-ebpf/src/`)

Seven LSM hooks enforce zone boundaries at the kernel level: `file_open`, `bprm_check_security`, `ptrace_access_check`, `task_kill`, `cgroup_attach_task`, `capable`, `socket_connect`. All kernel memory reads use `bpf_probe_read_kernel` (not raw pointer dereference). Kernel struct offsets are hardcoded in `rauha-ebpf/src/main.rs::offsets` module and validated at startup via pahole + a runtime self-test. Unsupported hooks are skipped gracefully — the daemon continues with whatever subset the kernel supports. Shared kernel/userspace types live in `rauha-ebpf-common`.

Seven BPF maps: `ZONE_MEMBERSHIP` (cgroup→zone), `ZONE_POLICY` (zone→policy flags), `INODE_ZONE_MAP` (inode→zone for file isolation), `ZONE_ALLOWED_COMMS` (cross-zone permission pairs), `SELF_TEST` (startup offset validation), `ENFORCEMENT_COUNTERS` (per-hook allow/deny/error counts, PerCpuArray), `ENFORCEMENT_EVENTS` (ring buffer, deny events to userspace).

The offset self-test (`SELF_TEST` map) compares `bpf_get_current_cgroup_id()` against the offset-chain-derived cgroup_id on first `file_open`. If they differ, `EbpfManager::load()` returns an error and the daemon runs in degraded mode (no eBPF enforcement). This prevents silent enforcement failure from wrong offsets.

At load time, userspace reads real offsets from BTF via `pahole` and injects them into eBPF globals via `BpfLoader::set_global()`. If `pahole` is not available, sensible defaults for Linux 6.1+ are used. If pahole finds an offset mismatch vs. defaults, loading fails — no silent enforcement with wrong offsets. The self-test then verifies the full offset chain at runtime.

Built separately via `cargo xtask build-ebpf` targeting `bpfel-unknown-none`. Requires `-Zub-checks=no` (BPF verifier rejects the alignment panic intrinsics). Not part of the normal workspace build.

## Code Conventions

- Error messages include what went wrong AND what to do about it. Many error variants have a `hint` field.
- Linux-only code uses `#[cfg(target_os = "linux")]` with stub implementations for other platforms.
- Policies are TOML. See `policies/standard.toml` for the canonical example.
- Tests go in `#[cfg(test)]` modules within source files, not in separate test files.
- macOS backend code uses `#[cfg(target_os = "macos")]` and ObjC2 bindings for Virtualization.framework.

## Workspace Crates

| Crate | Purpose |
|-------|---------|
| `rauha-common` | Shared types, `IsolationBackend` trait, error types, policy parsing, shim IPC protocol |
| `rauhad` | Daemon — gRPC server, zone registry, metadata (redb), networking, Linux/macOS backends |
| `rauha-cli` | CLI binary — connects to rauhad via gRPC |
| `rauha-shim` | Per-zone sync process — fork/run containers (Linux only) |
| `rauha-guest-agent` | Guest-side daemon inside macOS VMs — container lifecycle over virtio-vsock |
| `rauha-oci` | OCI image pull, content store, rootfs preparation, runtime spec generation |
| `containerd-shim-rauha-v2` | containerd shim v2 — bridges containerd Task ttrpc API to rauhad gRPC for Kubernetes |
| `rauha-enforce` | **Legacy** — superseded by Syvä (separate repo at `github.com/false-systems/syva`). Do not extend. |
| `rauha-ebpf` | eBPF LSM programs (kernel-side, not in workspace, separate build) |
| `rauha-ebpf-common` | Shared `#[repr(C)]` types between eBPF programs and userspace |
| `xtask` | Build helper for eBPF compilation |

## Oracle (`eval/oracle/`)

Standalone ground-truth test binary (NOT in workspace). Validates rauhad through its gRPC API — never reads source code, never mocks. 55 numbered cases (001-055) across zone lifecycle, container lifecycle, image management, isolation, policy, observability, resilience, invariants, stress, and boundaries. When a case fails, it means the system's public contract is broken.

The oracle must not be modified as a side effect of modifying the system. It has its own `[workspace]` in Cargo.toml and its own copy of the proto files.

## Platform Requirements

### Linux (eBPF enforcement)

- Linux 6.1+ with `CONFIG_BPF_LSM=y`, `CONFIG_BPF_SYSCALL=y`, `CONFIG_DEBUG_INFO_BTF=y`
- Boot parameter: `lsm=lockdown,capability,bpf`
- BTF at `/sys/kernel/btf/vmlinux`

### macOS (Virtualization.framework)

- macOS 15+ (Sequoia) for full Containers API support
- Apple Silicon or Intel with VT-x
- rauhad binary must be signed after every build: `codesign --entitlements rauhad/rauhad.entitlements -s - target/debug/rauhad`
- VM assets must be installed at `/var/lib/rauha/vm/` (vmlinux + initramfs.img) — use `rauha setup`
- Running without root works for development (pf network isolation will be inactive)
