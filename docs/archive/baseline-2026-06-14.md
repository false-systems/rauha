# Rauha Baseline

Captured: 2026-06-14

Host/control machine: macOS (`aarch64-apple-darwin`), using Lima instance `ubuntu` for Linux measurements.

Linux measurement environment:
- `rustc 1.95.0 (59807616e 2026-04-14)`
- host triple: `aarch64-unknown-linux-gnu`
- `cargo-bloat 0.12.1`
- target dir: `$HOME/rauha-target-baseline` inside the Lima guest
- build prerequisites installed in the guest during baseline capture: `pkg-config`, `libssl-dev`, `protobuf-compiler`

## Binary Sizes

Command:

```sh
CARGO_TARGET_DIR=$HOME/rauha-target-baseline cargo build --release --bins
```

Stripped sizes were measured by copying each binary and running `strip` on the copy.

| Binary | Unstripped bytes | Stripped bytes |
| --- | ---: | ---: |
| `rauhad` | 11,767,264 | 8,275,768 |
| `rauha` | 6,981,464 | 4,929,224 |
| `rauha-shim` | 4,717,488 | 3,349,200 |
| `rauha-guest-agent` | 4,188,632 | 2,955,840 |
| `rauha-enforce` | 6,972,720 | 4,798,792 |
| `containerd-shim-rauha-v2` | 8,488,960 | 5,845,816 |

## Dependency Weight

Command:

```sh
CARGO_TARGET_DIR=$HOME/rauha-target-baseline cargo bloat --release --crates --bin rauhad -n 25
```

Top `rauhad` `.text` contributors:

| Crate | Size |
| --- | ---: |
| `std` | 1019.8 KiB |
| `redb` | 430.7 KiB |
| `reqwest` | 425.2 KiB |
| `rauhad` | 420.8 KiB |
| `tokio` | 245.0 KiB |
| `h2` | 229.0 KiB |
| `tonic` | 205.5 KiB |
| `aya_obj` | 175.2 KiB |
| `regex_syntax` | 171.3 KiB |
| `toml_edit` | 161.5 KiB |

`rauhad` total `.text`: 4.9 MiB. File size reported by `cargo bloat`: 15.0 MiB.

Command:

```sh
CARGO_TARGET_DIR=$HOME/rauha-target-baseline cargo bloat --release --crates --bin containerd-shim-rauha-v2 -n 25
```

Top `containerd-shim-rauha-v2` `.text` contributors:

| Crate | Size |
| --- | ---: |
| `std` | 814.3 KiB |
| `regex_automata` | 381.0 KiB |
| `tokio` | 286.4 KiB |
| `h2` | 224.5 KiB |
| `serde_json` | 218.3 KiB |
| `ttrpc` | 203.8 KiB |
| `regex_syntax` | 185.9 KiB |
| `cgroups_rs` | 146.6 KiB |
| `tonic` | 133.5 KiB |
| `containerd_shim` | 126.3 KiB |

`containerd-shim-rauha-v2` total `.text`: 3.3 MiB. File size reported by `cargo bloat`: 11.8 MiB.

### Duplicate Dependencies

Command:

```sh
cargo tree --duplicates
```

Notable duplicate/multiple-version stacks:

- `nix`: `0.24.3`, `0.25.1`, `0.26.4`, `0.29.0`
- `prost`: `0.8.0`, `0.13.5`
- `prost-build`: `0.8.0`, `0.13.5`
- `prost-types`: `0.8.0`, `0.13.5`
- `tower`: `0.4.13`, `0.5.3`
- `rustix`: `0.38.44`, `1.1.4`
- `bitflags`: `1.3.2`, `2.11.0`
- `indexmap`: `1.9.3`, `2.13.0`
- `hashbrown`: `0.12.3`, `0.15.5`, `0.16.1`
- `syn`: `1.0.109`, `2.0.117`

`containerd-shim`, `containerd-shim-protos`, `ttrpc`, and `containerd-client` pull several older protobuf/TTRPC-era versions.

### Tokio/Tonic/Prost Features

Current workspace dependency:

```toml
tokio = { version = "1", features = ["full"] }
tonic = "0.12"
prost = "0.13"
```

`cargo tree -e features -i tokio` confirms `tokio/full` is enabled by workspace crates including `rauhad`, `rauha-cli`, `rauha-oci`, `rauha-enforce`, and `containerd-shim-rauha-v2`.

`cargo tree -e features -i tonic` confirms default `tonic` features, including `transport`, `channel`, `server`, `router`, `prost`, and `codegen`.

`cargo tree -e features -i prost` is ambiguous because both `prost@0.8.0` and `prost@0.13.5` are present.

## Cold-Path Latency

Criterion benches added in `rauha-common/benches/cold_path.rs`.

Command:

```sh
CARGO_TARGET_DIR=$HOME/rauha-target-baseline cargo bench -p rauha-common --bench cold_path -- --sample-size 50
```

| Benchmark | Mean range |
| --- | ---: |
| `policy_parse_validate` | 7.8736 us - 7.9079 us |
| `zone_object_construction` | 121.10 ns - 122.33 ns |

Not yet measured in this baseline:

- OCI rootfs prep: needs a dedicated fixture that avoids pulling from the network and avoids privileged overlay assumptions.
- gRPC request round-trip on a no-op call: needs a daemon test harness with an unprivileged no-op/negative request path.

## Panic/Abort Surface

Command:

```sh
rg -n 'unwrap\(|expect\(|panic!\(|unreachable!' <crate> -g '*.rs' | wc -l
```

| Crate | Count |
| --- | ---: |
| `rauha-common` | 28 |
| `rauhad` | 151 |
| `rauha-cli` | 5 |
| `rauha-shim` | 5 |
| `rauha-guest-agent` | 6 |
| `rauha-oci` | 150 |
| `rauha-enforce` | 0 |
| `containerd-shim-rauha-v2` | 0 |
| `rauha-ebpf-common` | 0 |
| `rauha-ebpf` | 0 |

Initial request/enforcement-path candidates observed in the raw grep:

- `rauha-shim/src/container.rs` and `rauha-shim/src/attach.rs`: `CString::new(...).unwrap()` on process args/env.
- `rauha-shim/src/state.rs`: mutable container lookup with `unwrap()`.
- `rauha-guest-agent/src/container.rs`, `attach.rs`, and `main.rs`: `CString::new(...).unwrap()` and container lookup with `unwrap()`.
- `rauhad/src/main.rs`: content-store initialization uses `expect(...)`.
- `rauhad/src/backend/macos/vm.rs`: several mutex/result `unwrap()` calls on the macOS backend path.
- `rauha-oci/src/image.rs`: extraction mutex `unwrap()` on runtime path.

Many other hits are test-only assertions and should be separated before enforcing a no-panic runtime policy.

## eBPF Crates

- `rauha-ebpf/src/main.rs` has `#![no_std]` and `#![no_main]`.
- `rauha-ebpf/Cargo.toml` sets `panic = "abort"` for dev and release.
- `rauha-ebpf-common/src/lib.rs` uses `#![cfg_attr(not(feature = "userspace"), no_std)]`.
- `rauha-ebpf-common` only enables `aya` for the `userspace` feature.

## Verification Status

Measured/compiled/passed:

- Linux release workspace binaries compile in Lima with `cargo build --release --bins`.
- Linux workspace tests pass in Lima with `cargo test --workspace`.
- Linux workspace build passes in Lima with `cargo build --workspace`.
- Linux clippy exits successfully in Lima with `cargo clippy --workspace --all-targets`; existing warnings remain.
- macOS `rauhad` backend compile-check passes on the host with `cargo check -p rauhad`; existing warnings remain.
- Native macOS all-binaries build was attempted on the host and failed because `rauha-enforce` depends on Linux-only `aya` symbols when built on macOS.
- `rauhad` startup in the unprivileged Lima VM with writable `RAUHA_ROOT` fails closed while creating `/sys/fs/cgroup/rauha.slice` with `Permission denied`.

Test-suite adjustment:

- `rauha-oci` overlayfs unit tests now treat Linux `EPERM`/operation-not-permitted mount failures as an unprivileged-environment skip after asserting the expected directory setup. Runtime overlay mount/unmount behavior is unchanged and still returns an error on failure.

Requires follow-up verification:

- Oracle suite in `eval/oracle` with `rauhad` running under a privileged Linux environment.
- Privileged Linux checks: eBPF LSM load, BPF maps, namespace setup, cgroups, root integration tests.
- macOS runtime checks: Virtualization.framework VM lifecycle and vsock paths.
