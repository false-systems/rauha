# Rauha Results

Captured: 2026-06-14

Measurement environment for Linux binary sizes: Lima instance `ubuntu`,
`aarch64-unknown-linux-gnu`, same workspace checkout as this commit.

## Phase 1: Release Profile

Lever: workspace release profile only.

Chosen profile:

```toml
[profile.release]
opt-level = "z"
lto = "fat"
codegen-units = 1
panic = "abort"
strip = "symbols"
```

`opt-level = "z"` and `"s"` were both measured with the same LTO, codegen,
panic, and strip settings. `z` was smaller for every required binary, so `z`
was selected.

Commands:

```sh
CARGO_TARGET_DIR=$HOME/rauha-target-size-before cargo build --release --bins
CARGO_PROFILE_RELEASE_OPT_LEVEL=z \
  CARGO_PROFILE_RELEASE_LTO=fat \
  CARGO_PROFILE_RELEASE_CODEGEN_UNITS=1 \
  CARGO_PROFILE_RELEASE_PANIC=abort \
  CARGO_PROFILE_RELEASE_STRIP=symbols \
  CARGO_TARGET_DIR=$HOME/rauha-target-size-z \
  cargo build --release --bins
CARGO_PROFILE_RELEASE_OPT_LEVEL=s \
  CARGO_PROFILE_RELEASE_LTO=fat \
  CARGO_PROFILE_RELEASE_CODEGEN_UNITS=1 \
  CARGO_PROFILE_RELEASE_PANIC=abort \
  CARGO_PROFILE_RELEASE_STRIP=symbols \
  CARGO_TARGET_DIR=$HOME/rauha-target-size-s \
  cargo build --release --bins
```

Before sizes are current stripped release binaries before this profile change.
After sizes are release binaries emitted by the selected profile, which strips
symbols as part of the build.

| Binary | Before stripped bytes | `z` bytes | `s` bytes | Selected delta | Selected delta |
| --- | ---: | ---: | ---: | ---: | ---: |
| `rauhad` | 8,341,328 | 4,212,464 | 4,540,144 | -4,128,864 | -49.50% |
| `rauha` | 4,929,224 | 2,438,776 | 2,635,360 | -2,490,448 | -50.52% |
| `rauha-shim` | 3,349,200 | 2,104,000 | 2,235,072 | -1,245,200 | -37.18% |
| `rauha-guest-agent` | 2,955,840 | 1,907,240 | 2,038,320 | -1,048,600 | -35.48% |
| `rauha-enforce` | 4,798,792 | 2,701,600 | 2,898,160 | -2,097,192 | -43.70% |
| `containerd-shim-rauha-v2` | 5,845,816 | 2,823,528 | 3,085,672 | -3,022,288 | -51.70% |

Current unstripped pre-profile release sizes, measured before this lever:

| Binary | Unstripped bytes |
| --- | ---: |
| `rauhad` | 11,847,128 |
| `rauha` | 6,981,472 |
| `rauha-shim` | 4,717,488 |
| `rauha-guest-agent` | 4,188,632 |
| `rauha-enforce` | 6,972,808 |
| `containerd-shim-rauha-v2` | 8,489,080 |

Correctness notes:

- This profile does not change CLI grammar, gRPC contracts, sandbox types, or
  the `IsolationBackend` trait.
- `panic = "abort"` does not add a permissive fallback. It makes any remaining
  panic terminate the process instead of unwinding; request and enforcement path
  panics still need to be removed under the strictness work.
- No isolation checks or enforcement setup are skipped for size.

Verification:

- Linux selected release build:
  `CARGO_TARGET_DIR=$HOME/rauha-target-size-after cargo build --release --bins`
  passed and reproduced the selected size table above.
- Linux `cargo build --workspace` passed.
- Linux `cargo test --workspace` passed.
- Linux `cargo clippy --workspace --all-targets` passed with existing warnings.
- macOS `cargo check -p rauhad` passed on the host with existing warnings.
- Oracle suite in `eval/oracle` compiled, then failed before exercising Rauha:
  all 55 cases failed at connection setup because no daemon was listening on
  `http://[::1]:9876` (`Connection refused`). This requires a running privileged
  Linux `rauhad` environment.

## Phase 1: Tracing Subscriber Feature Diet

Lever: workspace direct `tracing-subscriber` dependency features only.

Before:

```toml
tracing-subscriber = { version = "0.3", features = ["env-filter"] }
```

After:

```toml
tracing-subscriber = { version = "0.3", default-features = false, features = ["env-filter", "fmt"] }
```

The selected feature set covers the workspace's direct subscriber usage:
`tracing_subscriber::fmt()`, `EnvFilter::from_default_env()`,
`with_env_filter(...)`, and `init()`. Rauha does not use subscriber-provided
ANSI coloring, `tracing-log` bridging, JSON formatting, local time, or valuable
support on these initialization paths.

Commands:

```sh
CARGO_TARGET_DIR=$HOME/rauha-target-tracing-diet cargo build --workspace
CARGO_TARGET_DIR=$HOME/rauha-target-tracing-diet-release cargo build --release --bins
cargo tree -e features -i tracing-subscriber
```

Release binary size delta:

| Binary | Before bytes | After bytes | Delta | Delta |
| --- | ---: | ---: | ---: | ---: |
| `rauhad` | 4,212,464 | 4,145,832 | -66,632 | -1.58% |
| `rauha` | 2,438,776 | 2,437,688 | -1,088 | -0.04% |
| `rauha-shim` | 2,104,000 | 2,037,376 | -66,624 | -3.17% |
| `rauha-guest-agent` | 1,907,240 | 1,906,152 | -1,088 | -0.06% |
| `rauha-enforce` | 2,701,600 | 2,634,968 | -66,632 | -2.47% |
| `containerd-shim-rauha-v2` | 2,823,528 | 2,823,528 | 0 | 0.00% |

Dependency notes:

- `cargo tree -e features -i tracing-subscriber` no longer shows
  `tracing-subscriber/default`, `ansi`, `nu-ansi-term`, `tracing-log`, or
  `smallvec` requested by Rauha.
- Remaining required subscriber features are `fmt`, `env-filter`, `registry`,
  `std`, `thread_local`, `matchers`, `once_cell`, `sharded-slab`, and
  `tracing`.
- `containerd-shim-rauha-v2` did not shrink measurably under the final stripped
  size profile; its heavier containerd/TTRPC dependency graph still dominates.

Correctness notes:

- This change does not alter CLI grammar, gRPC contracts, sandbox types, or the
  `IsolationBackend` trait.
- No enforcement, policy validation, lifecycle, or fail-closed path is changed.
- Logging remains initialized with the same `fmt` subscriber and env filter
  behavior, minus unused default formatting support.

Verification:

- Linux `cargo build --workspace` passed.
- Linux `cargo test --workspace` passed.
- Linux `cargo clippy --workspace --all-targets` passed with existing warnings.
- macOS `cargo check -p rauhad` passed on the host with existing warnings.
- Oracle suite in `eval/oracle` compiled, then failed before exercising Rauha:
  all 55 cases failed at connection setup because no daemon was listening on
  `http://[::1]:9876` (`Connection refused`). This requires a running privileged
  Linux `rauhad` environment.

Requires privileged/macOS CI verification:

- eBPF LSM load, BPF maps, namespace setup, cgroups, and root integration tests.
- macOS Virtualization.framework VM lifecycle and vsock paths.

## Phase 3: eBPF Hook Error Paths Fail Closed

Lever: eBPF LSM hook internal error branches only.

Before:

- `file_open`, `bprm_check_security`, `ptrace_access_check`, `task_kill`,
  `cgroup_attach_task`, and `capable` emitted an error event on internal
  lookup/logic failure, then returned allow from the hook.

After:

- The same error branches still emit the error event, but return deny from the
  hook. Explicit unzoned, global, same-zone, and allow-list paths are unchanged.
- `socket_connect` remains unchanged because it is currently audit-only and
  network enforcement is delegated outside this hook.

eBPF object size delta:

| Artifact | Before bytes | After bytes | Delta | Delta |
| --- | ---: | ---: | ---: | ---: |
| `rauha-ebpf` object | 11,152 | 11,192 | +40 | +0.36% |

Commands:

```sh
CARGO_TARGET_DIR=$HOME/rauha-target-ebpf-before cargo run -p xtask -- build-ebpf
CARGO_TARGET_DIR=$HOME/rauha-target-ebpf-after-obj cargo run -p xtask -- build-ebpf
stat -c '%s' $HOME/rauha-target-ebpf-before/bpfel-unknown-none/debug/rauha-ebpf
stat -c '%s' $HOME/rauha-target-ebpf-after-obj/bpfel-unknown-none/debug/rauha-ebpf
```

Correctness notes:

- This strengthens fail-closed behavior and does not add a permissive fallback.
- This change does not alter CLI grammar, gRPC contracts, sandbox types, or the
  `IsolationBackend` trait.
- `rauha sandbox` remains the explicit unimplemented contract.
- Capability policy semantics for missing/zero policy entries are intentionally
  left for a separate deny-by-default policy lever with focused tests.

Verification:

- Linux `cargo build --workspace` passed.
- Linux `cargo test --workspace` passed.
- Linux `cargo clippy --workspace --all-targets` passed with existing warnings.
- macOS `cargo check -p rauhad` passed on the host with existing warnings.
- Lima eBPF build `cargo run -p xtask -- build-ebpf` passed after installing
  `rust-src` for nightly and `bpf-linker`. Host eBPF build failed because the
  local `bpf-linker` could not find an LLVM shared library.
- Oracle suite in `eval/oracle` compiled, then failed before exercising Rauha:
  all 55 cases failed at connection setup because no daemon was listening on
  `http://[::1]:9876` (`Connection refused`). This requires a running privileged
  Linux `rauhad` environment.

Requires privileged/macOS CI verification:

- eBPF LSM load, verifier acceptance, hook attach, and runtime deny behavior for
  the changed hook error branches.
- macOS Virtualization.framework VM lifecycle and vsock paths.

## Phase 1: Tokio Feature Diet

Lever: workspace direct Tokio dependency features only.

Before:

```toml
tokio = { version = "1", features = ["full"] }
```

After:

```toml
tokio = { version = "1", default-features = false, features = ["io-std", "io-util", "macros", "net", "rt-multi-thread", "signal", "sync", "time"] }
```

The selected direct feature set covers the workspace's direct Tokio usage:
`#[tokio::main]`, `#[tokio::test]`, `tokio::spawn`, `spawn_blocking`,
`select!`, timers, signals, Unix streams, async stdio, async read/write
helpers, and sync channels/locks.

Commands:

```sh
CARGO_TARGET_DIR=$HOME/rauha-target-tokio-diet cargo build --workspace
CARGO_TARGET_DIR=$HOME/rauha-target-tokio-diet-release cargo build --release --bins
cargo tree -e features -i tokio
```

The release binary size delta is zero for this lever:

| Binary | Before bytes | After bytes | Delta | Delta |
| --- | ---: | ---: | ---: | ---: |
| `rauhad` | 4,212,464 | 4,212,464 | 0 | 0.00% |
| `rauha` | 2,438,776 | 2,438,776 | 0 | 0.00% |
| `rauha-shim` | 2,104,000 | 2,104,000 | 0 | 0.00% |
| `rauha-guest-agent` | 1,907,240 | 1,907,240 | 0 | 0.00% |
| `rauha-enforce` | 2,701,600 | 2,701,600 | 0 | 0.00% |
| `containerd-shim-rauha-v2` | 2,823,528 | 2,823,528 | 0 | 0.00% |

Dependency notes:

- Rauha no longer requests `tokio/full` directly from the workspace dependency.
- `cargo tree -e features -i tokio` still shows `tokio/full` enabled
  transitively by `containerd-shim v0.10.0`, including `fs`, `process`, and
  `parking_lot`. That transitive dependency explains the zero-byte binary-size
  result.
- The next measurable dependency-size lever is likely around the
  `containerd-shim`/TTRPC stack or feature-gating the shim binary, not Tokio
  features in Rauha's direct dependency declaration.

Correctness notes:

- This change does not alter CLI grammar, gRPC contracts, sandbox types, or the
  `IsolationBackend` trait.
- No isolation checks, enforcement setup, policy validation, or fail-closed
  paths are relaxed.
- `rauha sandbox` remains the explicit unimplemented contract.

Verification:

- Linux `cargo build --workspace` passed.
- Linux `cargo test --workspace` passed.
- Linux `cargo clippy --workspace --all-targets` passed with existing warnings.
- macOS `cargo check -p rauhad` passed on the host with existing warnings.
- Oracle suite in `eval/oracle` compiled, then failed before exercising Rauha:
  all 55 cases failed at connection setup because no daemon was listening on
  `http://[::1]:9876` (`Connection refused`). This requires a running privileged
  Linux `rauhad` environment.
