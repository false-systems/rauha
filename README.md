# Rauha

**Run coding agents unattended. Keep control of what leaves.**

Give a coding agent a ready-to-use computer for every task, let it work
unattended, and review the code, effects, checks, and behaviour before
anything leaves. No Dockerfiles. No secret mounts. No cleanup.

[![license](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](#license)
[![release](https://img.shields.io/badge/release-v0.1.0-2ea44f.svg)](Cargo.toml)
[![platform](https://img.shields.io/badge/platform-Linux-informational.svg)](#requirements)
[![enforcement](https://img.shields.io/badge/enforcement-Syv%C3%A4%20(Linux%20BPF--LSM)-8a2be2.svg)](#rauha-and-syvä)

Today, letting a coding agent work on a real repository means assembling a
Dockerfile, a bind-mounted checkout, a devcontainer, API keys, SSH agent
forwarding, a Docker socket, toolchains, caches, sidecars, cleanup scripts, and
hope. And Docker still only understands *a process in a container*. It does
not understand the piece of work the agent is trying to finish.

Rauha runs each agent task in its own **zone** — filesystem view, processes,
network, resources, policy, and audit as one unit — and hands back one
structured result: what ran, how it exited, what it produced, and what the
boundary stopped. Docker runs the process. Rauha operates the work.

> *Rauha* (Finnish) — *peace*. What you get when untrusted execution stays inside its boundary.

> **New work targets the cell: local containment and effect enforcement, and the boundary-grade sensor backend Selko attaches (owner matrix, `perusta:docs/system/authority-matrix-v0.md`). The Run / receipt / `compare` / `accept` / supervisor framing in `docs/product-thesis.md` and `docs/run-protocol-v0.md` predates that matrix — comparison is Ruuma's, acceptance is Vartio's, stop and settle are Ote's, recording is Selko's — and is maintained as legacy until a named decision retires or absorbs it. Do not extend it.** (system briefing S-08, 2026-09-02)

## What you get today

One command, one result:

```sh
rauha sandbox --image python:3.12 --repo-path . -- pytest tests/
```

```json
{
  "task_id": "task-4348c0a8…",
  "zone_id": "09c95680-6c4b-4f1e-8b8f-cfdd3e144ac7",
  "status": "succeeded",
  "exit_code": 0,
  "stdout": "…",
  "stderr": "",
  "duration_ms": 418,
  "admission": "audit",
  "unavailable_controls": [],
  "events": [],
  "enforcement_events": [
    {
      "hook": "seccomp_notify",
      "action": "zone.syscall.brokered.granted",
      "decision": "allow",
      "object": "path:/etc/hostname"
    }
  ],
  "receipt": { "sha256": "…", "…": "signed, verified by the CLI" }
}
```

The daemon allocates a zone for the task, starts the container, waits, captures
stdout/stderr/exit code, collects lifecycle and enforcement events, signs a
receipt, and tears the zone down unless you pass `--keep-zone`. **Strict
admission is the default**: if a control your policy asks for cannot be
enforced on this host, the task is refused rather than run degraded. `--audit`
lets a temporary zone run anyway, and the result says exactly which controls
were missing. Every result carries two verifiable receipt forms — a legacy
Ed25519 signature and a DSSE in-toto envelope — checkable offline with
`rauha receipt`.

Underneath, the same primitives are available directly:

```sh
rauha zone create --name frontend --policy policies/standard.toml
rauha run --zone frontend alpine:latest /bin/echo hello
rauha events                       # live zone + enforcement events
rauha zone verify frontend --json  # is the boundary actually intact?
```

See [`docs/architecture.md`](docs/architecture.md) for the full control surface.

### Brokered authority (ships today)

One line of policy flips a zone from ambient authority to capability-style
handles:

```toml
[syscalls]
broker = ["openat", "openat2"]
```

Brokered calls suspend in the kernel (`seccomp` `SCMP_ACT_NOTIFY`) and are
judged by the zone shim: read-only, confined opens are satisfied by the
**broker** opening the file — `openat2` with `RESOLVE_IN_ROOT`/`RESOLVE_BENEATH`,
the caller's own resolve restrictions OR'd in, never weakened — and injecting
the fd. The workload never opens anything itself; symlinks, `..`, and magic
links cannot escape by construction. Denials answer honest errnos (`EPERM` for
policy, the kernel's own errno otherwise), so tools fail the way they would on
the host. Every decision is evidence: one JSON line in the container's
root-only `broker.log`, streamed live on `rauha events` and carried in the
sandbox result — `zone.syscall.brokered.granted` / `.denied`. See
[`policies/broker.toml`](policies/broker.toml) for the canonical policy.

## Where this is going

**Any agent. Any environment. One Run.** Docker made applications portable
across computers; Rauha makes agentic work portable across agents,
environments, and stages. The zone is the boundary. The **Run** is the
product: work, workspace, authority, journal, effects, behaviour, checks, and
receipt as one portable, supervised object — whatever machinery its Cell runs
on. The canonical thesis is [`docs/product-thesis.md`](docs/product-thesis.md).

```sh
rauha run -- claude -p "upgrade Postgres and fix the migration"   # planned
rauha fork run-42 --agent codex                                    # planned
rauha compare run-43 run-44                                        # planned
rauha accept run-44                                                # planned
```

Rauha gives every agent a disposable computer, a set of trusted capabilities,
and a persistent supervisor that follows its work until it is genuinely
finished. Each run gets a copy-on-write workspace, brokered credentials it can
use but never read, proof gates, and a signed receipt of what was enforced.
Every run has a supervisor; an optional management layer makes it durable
across machines and teams. The Run's wire contract is [`docs/run-protocol-v0.md`](docs/run-protocol-v0.md);
the market survey and hardening roadmap are in
[`docs/positioning-and-roadmap.md`](docs/positioning-and-roadmap.md).

## Why not just Docker, or a hosted sandbox?

- **The task is the unit, not the container.** You reason about what the work
  did, not about a pile of container IDs.
- **Authority can be held without being exercised.** Brokered syscalls
  suspend in the kernel and are judged by the boundary: the agent receives
  granted handles, never ambient access. Capsicum's shape, on stock Linux.
- **Nothing degrades silently.** A requested control is enforced, audited, or
  the task is refused. The result always says which.
- **The boundary explains itself.** Logs, lifecycle, and kernel deny events
  come back through one watch API and one stable event schema
  ([`rauha-evidence`](docs/observability.md)). Isolation you cannot observe is
  isolation you cannot trust.
- **Crash recovery keeps the boundary.** Kill the daemon mid-task; on restart
  the same workload keeps its cgroup, kernel membership, and file ownership —
  probed on every Linux release.
- **Same model on your laptop and your cluster.** Linux builds zones from
  cgroups, namespaces, and an OCI rootfs, with Syvä enforcing in the kernel.
- **Neutral.** Claude, Codex, or your own agent — Rauha does not care which.

## How it works

Four moving parts, one boundary:

```
rauha (CLI) ──gRPC──▶ rauhad ──spawns──▶ rauha-shim (one per zone) ──▶ crun ──▶ workload
                        │                     │
                        │                     ├── broker.log, stdout/stderr  (root-only)
                        │                     └── exec/attach IPC
                        ├── redb: zones, containers — source of truth on restart
                        └── evidence events ──▶ `rauha events`, sandbox results
```

**The daemon is platform-agnostic on purpose.** `rauhad` is one async
daemon (tokio, gRPC on `[::1]:9876`) behind a single `IsolationBackend`
trait; the `rauha` CLI and `containerd-shim-rauha-v2` are thin clients.
Zone metadata lives in redb and is the source of truth on restart: on
boot the daemon reconciles — reloads every zone, rebuilds kernel state
(BPF maps, cgroups, network), then cleans up orphans.

**One shim per zone, not per container.** The zone — not the container —
is the isolation boundary; containers in a zone share namespaces, and
the sync, fork-safe `rauha-shim` supervises all of them (crun builds
each container; the shim holds pidfds, exec/attach IPC, logs, and the
syscall broker). Deliberately synchronous where it forks: `fork()` in a
multithreaded async runtime is UB, so the shim is not one.

**Enrollment before execution — the security invariant.** crun builds
the container (namespaces, mounts, capabilities) and *parks* init on its
exec fifo — outside the zone cgroup. The shim reads the PID, pidfd-opens
it, writes it into `/sys/fs/cgroup/rauha.slice/zone-{name}/cgroup.procs`,
and only then runs `crun start`, which execs the image entrypoint — inside
the boundary. No image code ever runs before it is enrolled; otherwise
kernel enforcement would not apply to it. (Enrollment is never an OCI
hook: crun runs those after pivot_root in the image's own rootfs.)

**Three enforcement layers, each doing its own job.** nftables owns L3/L4
— every bridge base chain defaults to drop, zones get connectivity only
through their per-zone jump rules, and NAT masquerades the zone subnet.
Syvä/eBPF-LSM owns the in-kernel, deny-before-it-happens decisions on
file/exec/ptrace/signal/cgroup/capability. And for policy-marked syscalls,
the **seccomp-notify broker** (above) owns capability-style judgment in
userspace. Defense-in-depth, not redundancy: none replaces another.

**Policy is admission-checked, never guessed.** Policies are TOML
(`policies/standard.toml`): capabilities, resources, network mode and
egress, filesystem rules, devices, syscalls, cross-zone communication.
At zone creation every requested control is classified: enforced, audited
(with the degradation recorded and surfaced in `zone verify` and the
sandbox result), or the zone is refused outright. Nothing degrades
silently.

**Observability is evidence, not logging.** Lifecycle events, kernel deny
events, and broker decisions all normalize into one stable schema
(`rauha-evidence`) and reach one watch API. `rauha zone verify --json`
runs the named boundary self-checks (cgroup, BPF membership, inode
ownership, netns, veth, nftables) — the same names the security probes
key on.

Details, diagram, and crate map: [`docs/architecture.md`](docs/architecture.md).

## Rauha and Syvä

**Rauha creates the zones. Syvä makes the Linux kernel respect them.**

| Rauha owns | Syvä owns |
| --- | --- |
| Runtime lifecycle, zone create/delete | Linux kernel enforcement (BPF-LSM) |
| Sandbox/container execution | eBPF programs, BPF maps, ring-buffer events |
| Seccomp-notify broker: judged, capability-style opens | file / exec / ptrace / signal / cgroup / capability deny decisions (socket is audit-only; nftables enforces network) |
| Policy loading and validation | file / exec / ptrace / signal / cgroup / capability deny decisions (socket is audit-only; nftables enforces network) |
| Image, rootfs, networking, metadata | per-hook counters and privileged self-tests |
| Logs, audit, user-facing event surfaces | the in-kernel deny-before-it-happens decision |
| Kubernetes / containerd integration | |

Syvä is a separate product ([`github.com/false-systems/syva`](https://github.com/false-systems/syva)).
`rauha-enforcer-api` defines the boundary as a backend-neutral trait with a
`NoopEnforcer` and a conformance harness every backend must pass. Today's state,
precisely: the in-repo Linux eBPF backend is what the daemon runs, an external
Syvä backend is not yet wired in, and routing live enforcement entirely through
the trait is in progress. **The seam is real, but not yet the sole enforcement
path.** See [`docs/rauha-syva-boundary.md`](docs/rauha-syva-boundary.md).

## Limitations (honest)

- **The run experience above is planned, not shipped.** What ships is
  `rauha sandbox`, the zone primitives, and the brokered-opens policy.
  Fork, compare, accept, and brokered credentials are roadmap; signed
  sandbox receipts ship today (Ed25519 + DSSE in-toto, verified by the CLI
  and offline by `rauha receipt`).
- **Brokered opens are read-only, v1-shape** — `openat`/`openat2` only,
  judged with kernel-faithful errnos. The brokerable set is a pinned
  contract (`BROKERABLE_SYSCALLS`) shared by daemon and shim with a drift
  test. One documented exposure remains: a sibling thread of the target
  can `chroot`/`chdir` the shared filesystem between suspension and
  judgment — the open stays confined to a subtree of the container rootfs,
  which is the zone boundary.
- **Three policy controls are unsupported on Linux today** and strict admission
  refuses them: `filesystem.writable_paths`, `devices.allowed`, `syscalls.deny`.
  The roadmap closes them with Landlock, cgroup device BPF, and seccomp.
- **Sandbox event capture is best-effort** — enforcement events ride a
  daemon-wide broadcast and can be absent or partial; they are not an
  audit-complete log. In the contract's single assurance vocabulary
  (`perusta:docs/system/assurance-v0.md`, ruling S-07) that sentence reads:
  Rauha's LSM hooks are one more *sensor* (`signed_by: rauha-lsm/<version>`)
  whose `source` is `boundary` for the domains it hooks from below — `file`,
  `process`, `capability`, `privilege`, and `network` through the socket hook —
  but whose `loss` is `unknown` until the broadcast's drops are counted
  (run-protocol RP-24), so every domain is `authoritative: no` and any drift
  comparison over such a commit is `INVALID`, never a false `SAME`. Counting
  the drops (system SO-06) is what earns `authoritative: yes`; nothing in the
  profile is upgraded by anyone else. `trust_level` in Rauha's own events is
  an operational field and never a profile value.
- **A sandbox, not a hardware boundary** — BPF-LSM is OS-level isolation and is
  additive-only: it can deny, but cannot override SELinux/AppArmor. Covert
  channels through shared kernel resources are out of scope.
- **Linux-only** — the former macOS VM backend was removed (it could confine
  but not observe, and had drifted to non-compiling); a future VM tier would
  run the same Linux stack inside a VM instead of a parallel macOS backend.
- **Kubernetes integration requires containerd + RuntimeClass wiring**;
  installation docs and examples are still being written.

## Requirements

Rauha runs on Linux. The workspace also compiles and its unit tests run on
other platforms (e.g. macOS dev machines), but the daemon refuses to start
there — there is no non-Linux backend.

- **Linux** — 6.1+ with `CONFIG_BPF_LSM=y`, `CONFIG_BPF_SYSCALL=y`,
  `CONFIG_DEBUG_INFO_BTF=y`; boot parameter `lsm=lockdown,capability,bpf`; BTF
  at `/sys/kernel/btf/vmlinux`. The Linux daemon
  **fails closed**: it requires root and a working BPF-LSM kernel and refuses to
  start without enforcement. There is no degraded Linux mode.
- **nftables** — `nf_tables` + `nf_nat` are hard requirements (the daemon
  refuses to start without them); `nf_tables_bridge` powers cross-zone L2
  filtering and degrades explicitly when absent — strict zones refuse network
  admission, audit zones record `network:nftables` and `zone verify` reports
  it.

Root directory: `/var/lib/rauha` (override with `RAUHA_ROOT`).

## Build, test, and verify

```sh
cargo build                          # all workspace crates
cargo test                           # all unit tests
cargo xtask build-ebpf --release     # eBPF object + offsets sidecar for this kernel
RUST_LOG=rauhad=debug cargo run --bin rauhad   # daemon on [::1]:9876
```

Three layers of verification, each independent of the source:

- **Oracle** (`eval/oracle`, 55 numbered gRPC cases against a running daemon):
  `RAUHA_GRPC_ENDPOINT=http://[::1]:9876 cargo test`
- **Linux integration and security gate** (`tests/integration/`,
  `tests/security/linux-gate.sh`; root + BPF-LSM kernel): lifecycle, isolation,
  networking, crash recovery, and adversarial host-impact probes. On GitHub the
  privileged workflow runs the gate directly on a self-hosted BPF-LSM runner.
- **Enforcer conformance**: runs against `NoopEnforcer` in ordinary tests; the
  real eBPF backend is opt-in on an isolated root host with
  `RAUHA_RUN_EBPF_CONFORMANCE=1 cargo test -p rauhad linux_enforcer_passes_basic_conformance`.

## Roadmap

In order:

1. Finish safe user-namespace support on a runtime/storage combination that can
   make the rootfs private after entering the target user namespace.
2. Run Protocol v0 — the journal, reducer, lifecycle, ownership epochs,
   capability intents, checkpoints, forks, and adoption.
3. Local custodian and tier-0 supervisor with three built-in services:
   workspace, credential/egress broker, witness/receipt.
4. The `rauha run` experience: copy-on-write workspace, code diff plus
   behavioural diff, accept or discard.
5. Close the unsupported Linux controls (Landlock, cgroup device BPF, seccomp)
   and adopt the new mount API for rootfs assembly.
6. Signed execution receipts as an in-toto predicate; external Syvä backend
   through `rauha-enforcer-api`.
7. Optional management layer: durable runs across machines, fork/compare,
   Kubernetes `agent-sandbox` integration.

## License

Licensed under the [Apache License, Version 2.0](LICENSE). Unless you explicitly
state otherwise, any contribution intentionally submitted for inclusion in this
work as defined in the Apache-2.0 license shall be licensed as above, without any
additional terms or conditions.
