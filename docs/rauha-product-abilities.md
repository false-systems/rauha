# Rauha Product Abilities and the Enforcement Boundary

Rauha is its own product: an **agent sandbox runtime** built on zones. This
document states what Rauha owns as a product, and where its responsibilities
end — the enforcement boundary, behind which a kernel enforcer (the in-repo
eBPF backend today, [Syva](rauha-syva-boundary.md) tomorrow) makes the Linux
kernel respect what Rauha declares.

The one-line split: **Rauha creates and runs zones; an enforcer makes the
kernel respect them.**

## What Rauha owns (its abilities)

A zone is the task/workload boundary. Rauha-the-product owns everything about a
zone's lifecycle and shape:

- **Zone lifecycle** — create, list, recover (from redb on restart), destroy.
- **Containers** — pull OCI images, prepare rootfs, create/start/stop/exec/attach
  containers within a zone (one shim per zone on Linux; one VM per zone on macOS).
- **Filesystem view** — overlay/clone rootfs, writable paths, DNS injection.
- **Networking** — veth/bridge/NAT and per-zone firewalling, IP allocation.
- **Resources** — CPU/memory/pids limits via cgroups (Linux) or VM bounds (macOS).
- **Policy (user-facing)** — the TOML `ZonePolicy`: capabilities, resources,
  network, filesystem, devices, syscalls.
- **The agent-sandbox task** — `RunSandbox`: run a command in its own zone and
  capture stdout/stderr/exit-code plus enforcement-event summaries.
- **Evidence & observability** — normalize enforcement records + lifecycle events
  into one stable schema (`rauha-evidence`); `trace`/`top`/`events`/`logs`.
- **Metadata** — redb is the source of truth; reconciliation on startup.

Rauha keeps ownership of the **name** of a zone and its user-facing policy. It
translates that policy into the enforcement boundary's neutral vocabulary before
crossing it.

## What crosses the enforcement boundary

Kernel enforcement is **not** a Rauha ability — it is delegated across the
`EnforcerBackend` trait (`rauha-enforcer-api`). That trait is the complete,
name-keyed contract for everything Rauha needs from an enforcer:

| Boundary operation | Meaning |
|---|---|
| `load` / `shutdown` | bring the enforcer up / tear it down |
| `register_zone(name, policy) -> kernel_id` | declare a zone + its policy |
| `remove_zone(name, drain)` | retire a zone |
| `apply_policy(zone, policy)` | replace a zone's policy |
| `attach_container` / `detach_container` | zone membership for a cgroup |
| `register_host_path(zone, path, recursive)` | filesystem ownership |
| `allow_comm` / `deny_comm` | cross-zone communication |
| `watch_events` | raw enforcement (deny) events |
| `stats` / `verify` | counters and drift/parity self-check |
| `capabilities` | what the backend can actually enforce |

The boundary's vocabulary is deliberately neutral — it imports neither Rauha's
user-facing policy types nor any eBPF/Syva types:

- **`ZoneRef { name, kernel_id }`** — a zone handle carrying both the stable
  name (name-keyed backends like Syva use it) and the compact kernel id
  (the in-repo eBPF backend uses it as a BPF map key).
- **`ZoneEnforcement { caps_mask, allow_ptrace, allow_host_net, kind }`** — the
  zone-wide policy in enforcement terms. Rauha produces it via
  `ZonePolicy::to_enforcement` (the single source of truth for policy meaning);
  the backend maps it onto its own representation.
- **`Capabilities`** — a backend advertises what it can enforce, and must
  **reject** policy it cannot enforce rather than silently accept it.

## Backends behind the boundary

- **`NoopEnforcer`** (`rauha-enforcer-api`) — the reference implementation and
  honesty baseline. No kernel enforcement: it tracks zones/membership in memory,
  accepts enforceable policy, and **rejects** kernel-required rules instead of
  pretending. It passes the `conformance` suite.
- **`LinuxEnforcer`** (`rauhad/src/backend/linux`) — the in-repo eBPF backend.
  It loads the LSM programs and programs the BPF maps. It implements the full
  boundary contract.
- **Syva** — the external enforcement product. A future `SyvaEnforcer` will
  implement the same trait by calling `syva.core.v1` over a Unix socket. See
  [rauha-syva-boundary.md](rauha-syva-boundary.md).

## Current state and the migration ahead

The boundary contract is complete and the in-repo eBPF backend satisfies it.
One seam remains between "contract complete" and "contract load-bearing":

- `LinuxBackend` (Rauha's product code) still drives `LinuxEnforcer` through its
  **inherent, id-keyed** methods and keeps its own zone name↔id map, rather than
  consuming the `EnforcerBackend` trait via `dyn`. This is because
  `IsolationBackend` is synchronous while `EnforcerBackend` is async (chosen for
  the network-backed Syva future); a synchronous call into the async trait would
  block a tokio runtime. The unification — moving the name↔id map into the
  enforcer and having `LinuxBackend` consume the trait — is the next step and
  needs Linux validation.

Until that lands, "Rauha never touches a BPF map" holds at the code level
(`LinuxBackend` only calls `LinuxEnforcer`, never `aya`/maps directly), and the
trait fully describes the boundary — so swapping in Syva is implementing one
trait, not re-plumbing Rauha.
