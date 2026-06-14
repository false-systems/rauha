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

Requires privileged/macOS CI verification:

- eBPF LSM load, BPF maps, namespace setup, cgroups, and root integration tests.
- macOS Virtualization.framework VM lifecycle and vsock paths.
