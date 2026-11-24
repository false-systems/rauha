# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

Keep this file to rules and pointers. Anything that describes how the code works
belongs in `docs/` or can be read from the code. Add a line here only when its
absence caused a real mistake.

## What This Is

Rauha is an agent sandbox runtime built on controlled execution zones. A zone is the
task boundary that ties together filesystem view, processes, networking, resources,
policy, logs and enforcement evidence. The product hierarchy is load-bearing:

1. Agent sandbox runtime.
2. Zone-based runtime foundation.
3. Kubernetes/containerd and existing-workload deployment paths.

Do not present Rauha as primarily an eBPF project or a Kubernetes runtime. Rauha
creates the zones; its eBPF-LSM layer makes the kernel respect them, behind the
kernel-enforcement boundary (`docs/kernel-enforcement-boundary.md`).

The zone is the boundary, the **run** is the product: `rauha run -- <agent cmd>` with
fork/compare/accept is *planned*; `rauha sandbox` is what ships. (Today's
`rauha run --zone <z> <image>` is a plain container run.) README and doc claims must be
shipped or explicitly marked planned.

Linux-only. The workspace compiles and unit tests run anywhere; rauhad refuses to start
off Linux. Use a Lima VM for daemon work on other hosts.

## Where to read

- `docs/architecture.md`: diagram, crate map, full control surface
- `docs/sandbox-runtime.md`: sandbox task contract, result budgets, receipts, interruption semantics
- `docs/run-protocol-v0.md`, `docs/journal-testing.md`: Run lifecycle and journal
- `docs/positioning-and-roadmap.md`: product direction, what is shipped vs planned
- `docs/hardening-2026-10-10.md`: current containerd/exec/recovery scope and limits
- `docs/observability.md`: evidence schema, sinks, TOML config
- `rauhad/src/config.rs`: the one `rauha.toml` schema (`RAUHA_CONFIG` → `{root}/rauha.toml` → defaults; unknown fields rejected)

## Commands

```bash
cargo build
cargo test                                   # unit tests
cargo test -p rauha-oci                      # one crate
cargo test test_name                         # one test
cargo fmt --all -- --check                   # CI gate
cargo clippy --workspace --all-targets -- -D warnings   # CI gate

cargo xtask build-ebpf [--release]           # eBPF: separate build, nightly, Linux host

RUST_LOG=rauhad=debug cargo run --bin rauhad # Linux root; socket /run/rauha/rauhad.sock
cargo run --bin rauha -- sandbox --image alpine:latest -- /bin/echo hello
cargo run --bin rauha -- zone verify <zone> --json

# Integration scenarios (Linux, root, running rauhad). tests/integration/*.sh are
# thin launchers; scenarios live in xtask/src/checks.rs.
cargo xtask integration <scenario>           # image-pull, container-lifecycle, logs, sandbox,
                                             # broker, exec, host-boundaries, zone-isolation,
                                             # zone-networking, cgroup-lock

# Authoritative privileged gate: fmt, clippy, tests, eBPF build, every integration
# scenario, crash-recovery probe, crun executor probe, live containerd test, oracle.
cargo xtask linux-gate
cargo xtask security                         # same, here or in a Lima VM (RAUHA_LIMA_INSTANCE)
```

Root dir is `/var/lib/rauha` (`RAUHA_ROOT`). redb uses postcard, so adding fields to
persisted structs can break old entries. If the daemon won't start after a schema
change, delete `{root}/metadata/rauha.redb`.

## Invariants (do not break)

- **Enrollment before start.** Container start is `crun create` → `pidfd_open` the init
  → write the PID to the zone cgroup (fail closed: `crun delete --force`) → `crun start`.
  No image code may run before the process is in the zone cgroup. Never enroll via OCI
  `startContainer` hooks: they run in the image rootfs after privilege drop.
- **Exec uses the shared native crun path.** Never reintroduce manual post-fork
  namespace setup into the multithreaded shim.
- **One shim per zone**, not per container.
- **Fail closed.** The daemon requires root and working BPF-LSM; there is no degraded
  mode. Enforcing-hook errors deny. `audit` admission relaxes per-zone policy controls
  only, never enforcement presence. Strict admission refuses a zone it can't enforce.
- **Adding a policy control means adding a named check** in `verify_isolation()`
  (`rauhad/src/backend/linux/mod.rs`, surfaced by `zone verify --json`). The security probes key on those check names.
- **Adding a `RauhaError` variant means updating `to_status()`** in `rauhad/src/server.rs`.
  The oracle catches wrong gRPC codes.
- **Brokered syscalls:** the allowed names are `rauha_common::zone::BROKERABLE_SYSCALLS`.
  The shim's tests fail if the shim and that list drift. The broker opens read-only,
  openat2-confined, and only ever ORs in the caller's `RESOLVE_*` flags, never weakens them.
- **The Run journal's committed prefix is immutable**, and recovery never replays a
  command. `task_run.rs` grants no ownership or external-effect authority.
- **The oracle (`eval/oracle/`) is immutable** relative to system changes. It has its
  own workspace and proto copies. Do not modify it as a side effect, and do not
  expose a host TCP proxy for the privileged Unix socket.
- **Rauha is the telemetry source, not the collector.** `rauha-evidence` normalizes;
  it does not enforce.

## Conventions

- **Never hardcode environment-varying values** (paths, addresses, subnets, binaries,
  capacities, timeouts). They go in the `rauha.toml` schema. The only exempt constants
  are documented security invariants and named physical constants.
- **No YAML** (TOML only). No premature abstractions, no designing for the future.
- **Languages:** prefer Rust, or Elixir/Erlang. Python and Go are allowed when they
  clearly fit the job (an existing tool, a library or prior art), not by default.
- Error messages say what went wrong and what to do (many variants have a `hint`).
- Linux-only code uses `#[cfg(target_os = "linux")]` with stubs elsewhere.
- Tests live in `#[cfg(test)]` modules in source files. The exception is
  `containerd-shim-rauha-v2/tests/lifecycle.rs`, a live `ctr` test that is `#[ignore]`d
  by default and run by the Linux gate.
- Policies are TOML. See `policies/standard.toml`, `policies/broker.toml` and `policies/audit.toml`.
- Most read-only CLI commands accept `--json` (`events --json` is JSON Lines);
  `logs`/`exec`/`attach` don't.

## Work tooling

Run `toimija enter` at the start and again after HEAD or the branch changes.
Declare reads outside the packet's workset with `toimija intent "<why>" --scope <path>`.
