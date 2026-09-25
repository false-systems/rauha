# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What This Is

Rauha is an agent sandbox runtime built on controlled execution zones. A zone is the task/workload boundary that ties together filesystem view, processes, networking, resources, policy, logs, audit events, and optional enforcement events.

The product hierarchy is load-bearing:

1. Agent sandbox runtime.
2. Zone-based runtime foundation.
3. Kubernetes/containerd and existing-workload deployment paths.

Do not present Rauha as primarily an eBPF project or a Kubernetes runtime. Rauha creates the zones. Syva makes the Linux kernel respect them. Current Linux eBPF code may still live in this repository, but architecturally it belongs behind the Syva enforcement boundary.

Product direction (see `docs/positioning-and-roadmap.md`): the zone is the boundary, the **run** is the product — `rauha run -- <agent cmd>` with fork/compare/accept is planned, `rauha sandbox` is what ships. README claims must be shipped or explicitly marked planned. `docs/architecture.md` holds the diagram, crate map, and full control surface.

## Build & Test Commands

```bash
cargo build                          # Build all workspace crates
cargo test                           # Run all unit tests
cargo test -p rauha-oci              # Test a single crate
cargo test test_name                 # Run a single test by name
cargo fmt --all -- --check           # CI gate
cargo clippy --workspace --all-targets -- -D warnings   # CI gate
cargo build --bin rauhad             # Build just the daemon
cargo build --bin rauha              # Build just the CLI
cargo build --bin rauha-shim         # Build the per-zone shim
cargo build --bin rauha-enforce      # Build standalone enforcement agent
cargo build -p containerd-shim-rauha-v2  # Build the containerd shim

# eBPF programs (separate build, requires nightly Rust and a Linux host)
cargo xtask build-ebpf               # Debug build
cargo xtask build-ebpf --release     # Release build

# Run the daemon (development, listens on [::1]:9876)
RUST_LOG=rauhad=debug cargo run --bin rauhad

# Use the CLI (connects to RAUHA_ADDR or http://[::1]:9876)
cargo run --bin rauha -- zone create --name test
cargo run --bin rauha -- zone list
cargo run --bin rauha -- image pull alpine:latest
cargo run --bin rauha -- run --zone test alpine:latest /bin/echo hello

# Agent sandbox task (primary product shape; implemented end to end)
cargo run --bin rauha -- sandbox --image alpine:latest -- /bin/echo hello
cargo run --bin rauha -- sandbox --image alpine:latest --audit --keep-zone -- /bin/sh -c id
cargo run --bin rauha -- zone verify test --json   # boundary self-check (named checks, passed/detail)

# Observability / evidence surface
cargo run --bin rauha -- trace --zone test          # syscall trace for a zone
cargo run --bin rauha -- top                         # per-zone resource usage
cargo run --bin rauha -- events                      # stream zone enforcement events
cargo run --bin rauha -- logs <container>            # stream container stdout/stderr
cargo run --bin rauha -- exec <container> /bin/sh    # exec in a running container
cargo run --bin rauha -- attach <container>          # attach to a running container

# Integration tests (Linux only, require root + running rauhad)
bash tests/integration/test-image-pull.sh
bash tests/integration/test-container-lifecycle.sh
bash tests/integration/test-zone-isolation.sh
bash tests/integration/test-zone-networking.sh
bash tests/integration/test-exec.sh
bash tests/integration/test-logs.sh
bash tests/integration/test-sandbox.sh         # agent sandbox task end-to-end
bash tests/integration/test-host-boundaries.sh # adversarial host-impact probes
bash tests/integration/test-cgroup-lock.sh          # eBPF enforcement required

# Authoritative privileged security gate (Linux, BPF-LSM kernel, passwordless sudo, crun, jq):
# fmt + clippy + tests + eBPF build, then daemon, every integration test, the crash-recovery
# probe (kill -9 rauhad mid-workload, restart, verify PID/cgroup/inode ownership survive),
# the crun executor probe, and the oracle. This is the Sykli `full` task (sykli.json).
bash tests/security/linux-gate.sh
bash tests/security/run.sh --gate      # same, via Sykli on this host or one running Lima VM (RAUHA_LIMA_INSTANCE)

# Oracle tests (require running rauhad, any platform)
cd eval/oracle
RAUHA_GRPC_ENDPOINT=http://[::1]:9876 cargo test           # all cases
RAUHA_GRPC_ENDPOINT=http://[::1]:9876 cargo test -- case_001  # one case
```

Proto files are in `proto/` (zone.proto, container.proto, image.proto, sandbox.proto). They compile automatically via `build.rs` in rauhad and rauha-cli. `sandbox.proto` defines `SandboxService.RunSandbox` (package `rauha.sandbox.v1`) — the agent-sandbox task contract that runs a command in its own zone and captures stdout/stderr/exit-code plus enforcement events into one result. `SandboxServiceImpl` (`rauhad/src/server.rs`) implements it on top of the zone/container primitives: resolve-or-allocate a zone, create+start one container, poll to exit (or timeout), read shim log files for output, and drain the enforcement-event broadcast scoped to the task's zone. Temporary zones (empty `name`) are torn down after the run unless `keep_zone` is set; a runtime failure that prevents producing a result comes back as a `runtime_error` result, not a gRPC error. The `rauha sandbox` CLI mirrors the task's exit code.

Most read-only/list commands accept `--json`; `events --json` emits JSON Lines.
Interactive commands (`top`, `logs`, `exec`, `attach`) do not support
it, and the unimplemented `trace` command exits with an error.

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
- IPC between daemon and shim: length-prefixed postcard over Unix socket (`rauha-common/src/shim.rs`). The protocol includes attach/exec commands — the shim returns a Unix socket path for bidirectional I/O.

### One Shim Per Zone (Not Per Container)

This diverges from containerd's one-shim-per-container model. Zones are the isolation boundary, not containers. Multiple containers in a zone share namespaces. rauhad spawns one `rauha-shim` per zone; the shim supervises one crun-created init per container on request, and remains the zone lifecycle and evidence bridge. Shim binary search: same directory as rauhad, then `target/debug/`, `target/release/`, then `/usr/local/bin`, `/usr/bin`. Socket at `/run/rauha/shim-{zone_name}.sock` — rauhad polls for up to 5 seconds after spawning.

### Container Start Flow (Linux): crun + enrollment before start

The shim no longer builds containers itself; `rauha-shim/src/container.rs` delegates OCI construction to `/usr/bin/crun` (required, `--cgroup-manager=disabled` so Rauha keeps cgroup ownership). The order is the security invariant — no image code may run before the process is in the zone cgroup, otherwise eBPF enforcement doesn't apply:

1. `crun create --bundle … --pid-file init.pid` — crun does all privileged setup (namespaces, mounts, pivot_root, capability drop, seccomp) and parks init on its `exec.fifo`. This setup runs *outside* the zone cgroup, so the eBPF `capable` hook does not judge crun's own `CAP_SYS_ADMIN` work against the workload policy.
2. Read `init.pid`, `pidfd_open` it (the pidfd is held for the container's lifetime; signal via `pidfd_send_signal`, wait via `poll` on the pidfd — immune to PID reuse).
3. Write the PID to `/sys/fs/cgroup/rauha.slice/zone-{name}/cgroup.procs`. Failure → `crun delete --force`, fail closed.
4. `crun start` — only now does init `execve` the image entrypoint, inside the boundary.

Never enroll via OCI `startContainer` hooks: crun runs them after pivot_root and privilege drop, resolving `path` in the *image* rootfs — untrusted code with no `CAP_SYS_ADMIN`. `createRuntime` hooks (host binary, state JSON on stdin) are the spec-blessed alternative if a hook is ever needed. Analysis and crun source references: `docs/positioning-and-roadmap.md` § Enrollment.

**Fork-safety invariant (still applies to `attach.rs` exec/PTY paths):** all code after `fork()`/`clone3()` in the child must be async-signal-safe — no `std::env::set_var`/`vars`, no `eprintln!`/`panic!`, no heap allocation. Use `libc::putenv` with pre-allocated `CString`s, `libc::write` for output, and `libc::_exit`. Pre-allocate all strings and paths before fork.

### Platform Policy (Linux-only)

Rauha is Linux-only. The former macOS VM-per-zone backend (Virtualization.framework, `rauha-guest-agent`, pf, APFS clonefile) was removed: it could confine but not observe — no deny events, no enforcement counters, no receipts — and it had drifted to non-compiling since CI is Linux-only. If a VM tier returns, the likely shape is the **same Linux stack inside a VM** (one enforcement code path, one receipt schema), not a parallel macOS backend. The workspace still compiles and its unit tests run on any OS; the daemon refuses to start without the Linux backend (`create_backend` returns `UnsupportedPlatform`).

### Zone Networking (`rauhad/src/network/`, `rauhad/src/backend/linux/nftables.rs`)

Zones get full network connectivity on Linux via: veth pairs → rauha0 bridge (gateway 10.89.0.1) → nftables NAT masquerade → internet. Each zone is assigned a unique IP from the 10.89.0.0/16 subnet by `IpAllocator`, persisted in `Zone.network_state`. DNS resolv.conf is injected into container rootfs (handles systemd-resolved stub detection).

**Enforcement layering:** nftables handles packet filtering (L3/L4). eBPF `ZONE_ALLOWED_COMMS` map is defense-in-depth for cross-zone socket operations. Neither replaces the other.

- **allocator.rs** — stateless IPAM; rebuilds from persisted zone metadata on startup
- **dns.rs** — generates resolv.conf; filters localhost stubs, falls back to 1.1.1.1/8.8.8.8
- **nftables.rs** — NAT masquerade + per-zone forward chains; forward chain defaults to drop; jump rules cleaned by handle on zone deletion

Network setup failures (nftables, bridge) are logged as warnings, not fatal errors — zones still run without network filtering.

### Enforcement Event Streaming (`rauhad/src/backend/linux/events.rs`)

Every deny decision from the 7 LSM hooks is emitted to a BPF ring buffer (`ENFORCEMENT_EVENTS`, `RingBuf::with_byte_size(1024 * 4096, 0)` = 4MB / 1024 pages). A background task drains the ring buffer every 100ms, decodes `EnforcementEvent` structs (48 bytes, `read_unaligned` — ring buffer data is unaligned), and broadcasts them via `tokio::sync::broadcast`. The `WatchEvents` gRPC stream relays these to clients. Only deny events hit the ring buffer; allows are tracked in per-CPU counters (`ENFORCEMENT_COUNTERS`).

### Evidence & Observability Surface (`rauha-evidence`, `rauhad/src/logs.rs`)

Ownership reading: **Syva enforces; Rauha observes.** The `rauha-evidence` crate is the normalization layer — it consumes raw enforcement records (from the eBPF backend / Syva) plus Rauha lifecycle events and projects them into one stable schema. It does **not** enforce policy. Event names are stable string constants in `rauha_evidence::event_name` (e.g. `zone.file.denied`, `zone.exec.denied`, `zone.escape.cgroup_attach`, `zone.created`, `container.exited`, `image.pulled`, `policy.loaded`, plus pipeline-health events `ringbuf.drop` / `pipeline.shed`). Output goes through pluggable sinks (file / JSON).

Rauha is the telemetry source, not the collector. The daemon emits structured
JSON to stdout/stderr and may export through OTLP; cloud tags, pod/namespace
enrichment, Fluent Bit or sidecar wiring, cold storage, and retention policy are
downstream concerns. Observability config is TOML only; see
`docs/observability.md`.

User-facing side (CLI in `rauha-cli/src/commands/trace.rs` + formatting in `output.rs`):
- `rauha trace` — per-zone syscall trace
- `rauha top` — per-zone resource usage snapshot
- `rauha events` — live stream of enforcement/lifecycle events (rides the `WatchEvents` gRPC stream)

`rauhad/src/logs.rs` is separate from the evidence schema: it tails shim-written container log files (`/run/rauha/containers/{id}/stdout.log` and `stderr.log`) in one-shot or follow mode, backing the `rauha logs` command.

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

### Policy Admission: enforced, audited, or refused (`rauhad/src/backend/linux/mod.rs`)

`ZonePolicy.admission` is `strict` (default) or `audit` (`policies/audit.toml`). At zone creation `admit_linux_policy()` classifies every requested control; `unsupported_linux_controls()` currently lists `filesystem.writable_paths` (unless a safe path), `devices.allowed`, `syscalls.deny`, plus any LSM hook the kernel skipped (`lsm.<hook>`). Strict admission **refuses** the zone with the control names in the error; audit admits it, records the names in `zone_degradations`, and they surface as `policy:<control>` checks in `zone verify` and as `unavailable_controls` in the sandbox result. The Linux daemon itself fails closed at startup (root + BPF-LSM required, no degraded mode) — `audit` only relaxes per-zone policy controls, never enforcement presence.

`verify_isolation()` (`rauha zone verify --json`) emits named checks — `policy:admitted`, `cgroup`, `ebpf:health`, `bpf_membership`, `filesystem:inode_ownership`, `netns`, `network:veth`, `network:nftables` — each with `passed` and `detail`. The security probes (`tests/security/*.sh`) key on these names; adding a control means adding a check here, not just a code path.

`rauha-enforcer-api` defines the enforcement boundary as a backend-neutral async trait (`EnforcerBackend`: `register_zone`, `attach_container`, `register_host_path`, `verify`, `capabilities`, …) with `NoopEnforcer` as the honesty baseline and a shared conformance harness. Today `LinuxBackend` still drives the in-repo `LinuxEnforcer` through inherent id-keyed methods (sync `IsolationBackend` vs. async trait); the seam is real but not yet the sole enforcement path. See `docs/rauha-product-abilities.md`.

### gRPC Error Boundary (`rauhad/src/server.rs`)

`to_status()` maps `RauhaError` variants to correct gRPC status codes. When adding new error variants, update this function — the oracle will catch incorrect mappings. Key mappings: `ZoneNotFound`/`ContainerNotFound`/`ImageNotFound`→`NotFound`, `ZoneAlreadyExists`/`ContainerAlreadyExists`→`AlreadyExists`, `InvalidInput`/`InvalidPolicy`→`InvalidArgument`, `PermissionDenied`/`CrossZoneAccessDenied`→`PermissionDenied`, `ZoneNotEmpty`→`FailedPrecondition`.

### Data Stores

- **redb** (`{root}/metadata/rauha.redb`) — persisted zone/container metadata. Source of truth on crash recovery. Uses postcard serialization — adding fields to `Zone`/`Container` structs can break deserialization of old entries. `list_zones()`/`get_zone()` skip incompatible entries with a warning rather than crashing. If the daemon won't start after schema changes, delete the stale db: `rm {root}/metadata/rauha.redb`.
- **BPF maps** (pinned at `/sys/fs/bpf/rauha/`) — in-kernel enforcement state. Reconciled from redb on daemon startup. Linux only.
- **Content store** (`{root}/content/blobs/sha256/`) — content-addressable OCI blob storage.

Root directory: `/var/lib/rauha` (override with `RAUHA_ROOT`).

On startup, rauhad runs `reconcile()`: loads all zones from redb, calls `recover_zone()` on each to re-establish kernel state (BPF maps, cgroups, network), then `cleanup_orphans()` to remove stale kernel state. Stale BPF pins are removed before loading new programs — redb is the source of truth.

### eBPF Programs (`rauha-ebpf/src/`)

Seven LSM hooks enforce zone boundaries at the kernel level: `file_open`, `bprm_check_security`, `ptrace_access_check`, `task_kill`, `cgroup_attach_task`, `capable`, `socket_connect`. All kernel memory reads use `bpf_probe_read_kernel` (not raw pointer dereference). Kernel struct offsets are **generated at build time from the target kernel's BTF** (`cargo xtask build-ebpf` → pahole → compiled in behind the `generated-offsets` feature, with a sidecar manifest binding them to the object's SHA-256), re-validated against the local kernel's BTF at load time, and verified by a runtime self-test. Unsupported hooks are skipped gracefully at load time — the daemon continues with whatever subset the kernel supports. At **runtime**, hook logic that errors (e.g. a failed `bpf_probe_read_kernel`) **fails closed**: the hook returns `-EPERM` (deny) and emits an error event rather than allowing the operation. Shared kernel/userspace types live in `rauha-ebpf-common`.

Seven BPF maps: `ZONE_MEMBERSHIP` (cgroup→zone), `ZONE_POLICY` (zone→policy flags), `INODE_ZONE_MAP` (inode→zone for file isolation), `ZONE_ALLOWED_COMMS` (cross-zone permission pairs), `SELF_TEST` (startup offset validation), `ENFORCEMENT_COUNTERS` (per-hook allow/deny/error counts, PerCpuArray), `ENFORCEMENT_EVENTS` (ring buffer, deny events to userspace).

The offset self-test (`SELF_TEST` map) compares `bpf_get_current_cgroup_id()` against the offset-chain-derived cgroup_id on first `file_open`. If they differ, `EbpfManager::load()` returns an error — wrong offsets can never silently mis-enforce. The hardcoded `offsets_default.rs` is only for plain crate builds, which are not production artifacts.

Built separately via `cargo xtask build-ebpf` targeting `bpfel-unknown-none`. Requires `-Zub-checks=no` (BPF verifier rejects the alignment panic intrinsics). Not part of the normal workspace build.

## Code Conventions

- Error messages include what went wrong AND what to do about it. Many error variants have a `hint` field.
- Linux-only code uses `#[cfg(target_os = "linux")]` with stub implementations for other platforms.
- Policies are TOML. See `policies/standard.toml` for the canonical example.
- Tests go in `#[cfg(test)]` modules within source files, not in separate test files.

## Workspace Crates

| Crate | Purpose |
|-------|---------|
| `rauha-common` | Shared types, `IsolationBackend` trait, error types, policy parsing, sandbox result types, shim IPC protocol |
| `rauha-enforcer-api` | `EnforcerBackend` trait, kernel-facing policy/event types, `Capabilities`, `NoopEnforcer`, shared conformance harness |
| `rauhad` | Daemon — gRPC server, zone registry, metadata (redb), networking, Linux backend |
| `rauha-cli` | CLI binary — connects to rauhad via gRPC |
| `rauha-shim` | Per-zone sync supervisor (Linux only) — crun create/enroll/start per container, pidfd lifetime, exec/attach |
| `rauha-oci` | OCI image pull, content store, rootfs preparation, runtime spec generation |
| `rauha-evidence` | Evidence-grade observability schema, projections, and sinks. Normalizes Syva/backend enforcement records + Rauha lifecycle events into one schema. Does not enforce. Consumed only by `rauhad`. |
| `containerd-shim-rauha-v2` | containerd shim v2 — bridges containerd Task ttrpc API to rauhad gRPC for Kubernetes |
| `rauha-enforce` | **Legacy** — superseded by Syvä (separate repo at `github.com/false-systems/syva`). Do not extend. |
| `rauha-ebpf` | eBPF LSM programs (kernel-side, not in workspace, separate build) |
| `rauha-ebpf-common` | Shared `#[repr(C)]` types between eBPF programs and userspace |
| `xtask` | Build helper for eBPF compilation |

## Work tooling in this repo

- `sykli.json` / `sykli.lock` — the locked Sykli work graph; its single `full` task is the privileged security gate above. Changes to `tests/security/linux-gate.sh` usually go together with these two files.
- `.toimija/` — Toimija session packets (the workset contract shown at session start). `.toimija/current.*`, `sessions/`, `runs/` are gitignored; `history.*` currently is not. Run `toimija verify` before committing; declare reads outside the packet's workset with `toimija intent "<why>" --scope <path>`.

## Oracle (`eval/oracle/`)

Standalone ground-truth test binary (NOT in workspace). Validates rauhad through its gRPC API — never reads source code, never mocks. 55 numbered cases (001-055) across zone lifecycle, container lifecycle, image management, isolation, policy, observability, resilience, invariants, stress, and boundaries. When a case fails, it means the system's public contract is broken.

The oracle must not be modified as a side effect of modifying the system. It has its own `[workspace]` in Cargo.toml and its own copy of the proto files.

## Platform Requirements

### Linux (the only supported platform)

- Linux 6.1+ with `CONFIG_BPF_LSM=y`, `CONFIG_BPF_SYSCALL=y`, `CONFIG_DEBUG_INFO_BTF=y`
- Boot parameter: `lsm=lockdown,capability,bpf`
- BTF at `/sys/kernel/btf/vmlinux`
- `crun` at `/usr/bin/crun` (container construction is delegated to it); `jq` for the security probes

### Other platforms

- The workspace compiles and unit tests run anywhere (useful on macOS dev
  machines; use a Lima VM for anything needing the daemon). rauhad refuses to
  start on non-Linux (`UnsupportedPlatform`) — there is no second backend.
