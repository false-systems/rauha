# Rauha Product Abilities and the Enforcement Boundary

Rauha is its own product: an **agent sandbox runtime** built on zones. This
document states what Rauha owns as a product, and where its responsibilities
end — the enforcement boundary, behind which a kernel enforcer (the in-repo
eBPF backend today, an external backend tomorrow) makes the Linux
kernel respect what Rauha declares.

The one-line split: **Rauha creates and runs zones; an enforcer makes the
kernel respect them.**

## What Rauha owns (its abilities)

A zone is the task/workload boundary. Rauha-the-product owns everything about a
zone's lifecycle and shape:

- **Zone lifecycle** — create, list, recover (from redb on restart), destroy.
- **Containers** — pull OCI images, prepare rootfs, create/start/stop/delete and
  exec within a zone (one shim per zone on Linux). Existing-container attach is
  not implemented by the zone shim. There is no macOS execution backend.
- **Filesystem view** — overlay/clone rootfs, writable paths, DNS injection.
- **Networking** — veth/bridge/NAT and per-zone firewalling, IP allocation.
- **Resources** — CPU/memory/pids limits via Linux cgroups v2.
- **Policy (user-facing)** — the TOML `ZonePolicy`: capabilities, resources,
  network, filesystem, devices, syscalls.
- **The agent-sandbox task** — `RunSandbox`: run a command in its own zone and
  capture stdout/stderr/exit-code plus enforcement-event summaries.
- **Evidence & observability** — normalize enforcement records + lifecycle events
  into one stable schema (`rauha-evidence`); `events`/`logs` and signed task receipts.
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
user-facing policy types nor any eBPF/enforcer types:

- **`ZoneRef { name, kernel_id }`** — a zone handle carrying both the stable
  name (name-keyed external backends use it) and the compact kernel id
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
- **External enforcement backend** — a future enforcer will implement the
  same trait over a Unix socket, taking over kernel enforcement without
  touching the runtime above it. See
  [kernel-enforcement-boundary.md](kernel-enforcement-boundary.md).

## Current state and the migration ahead

The boundary contract is complete and the in-repo eBPF backend satisfies it.
One seam remains between "contract complete" and "contract load-bearing":

- `LinuxBackend` (Rauha's product code) still drives `LinuxEnforcer` through its
  **inherent, id-keyed** methods and keeps its own zone name↔id map, rather than
  consuming the `EnforcerBackend` trait via `dyn`. This is because
  `IsolationBackend` is synchronous while `EnforcerBackend` is async (chosen for
  the network-backed external future); a synchronous call into the async trait would
  block a tokio runtime. The unification — moving the name↔id map into the
  enforcer and having `LinuxBackend` consume the trait — is the next step and
  needs Linux validation.

Until that lands, "Rauha never touches a BPF map" holds at the code level
(`LinuxBackend` only calls `LinuxEnforcer`, never `aya`/maps directly), and the
trait fully describes the boundary — so swapping backends is implementing one
trait, not re-plumbing Rauha.

## Supported controls and limits

This section describes implemented behavior, not a release certification or a
claim that every configuration has passed privileged integration tests.

| Surface | Supported behavior and boundary |
| --- | --- |
| Control API | Private Unix socket, default `/run/rauha/rauhad.sock`; no TCP listener |
| Workspaces | Image contents only; nonempty `repo_path` is rejected, not mounted |
| Filesystem policy | Read-only root and writable mounts; writable paths must be normalized absolute paths, not `/`, and outside reserved roots (default `/proc`, `/sys`, `/dev`, `/run`) |
| Devices | Only `/dev/null`, `/dev/zero`, `/dev/full`, `/dev/random`, `/dev/urandom` are admitted as supported device rules |
| Syscalls | OCI seccomp deny rules; read-only `openat`/`openat2` notification broker; deny/broker overlap is rejected |
| Policy updates | Creation-time controls require a zone without containers; empty zones can switch isolated/bridged networking, but host/external identity changes require zone recreation; dynamic updates freeze execution and roll back on failure |
| Image snapshots | Ordered layers flattened into one immutable snapshot; whiteouts applied during composition, with a per-snapshot lock and atomic publication; less per-layer sharing |
| Image limits | 4 GiB compressed blob, 4 MiB manifest/token response, 16 GiB expanded per layer; downloads have connect/request timeouts |
| CLI monitoring | `events` (including NDJSON) and `logs`; placeholder `trace`/`top` removed |

These image limits do not bound total cache disk usage. Audit admission may
accept unsupported controls with explicit degradation; it must not be used to
describe those controls as enforced.

## Upgrade notes

- Drain workloads before updating the BPF object and daemon together: inode
  ownership now uses `(device, inode)`, changing the pinned map ABI. Rebuild the
  object and offsets sidecar for the deployment kernel. Do not perform a rolling
  in-place live-map upgrade with running workloads.
- Legacy image-reference filenames could alias distinct names. They are not
  trusted or migrated: pull tags again to populate `references-v2`. Existing
  content-addressed blobs remain cached. Do not delete the entire content store.
- `snapshots-v2` replaces independent per-layer extraction. Old snapshot/cache
  directories are not proof that their contents are safe to reuse; reclaim old
  storage only after draining workloads and confirming no mount references it.
- Replace TCP endpoint configuration with the private socket path. The parent
  directory must be daemon-owned and private (0700); the socket is 0600.

Historical measurements and superseded audits live in [archive](archive/README.md).
Current audit follow-up and verification boundaries are recorded in the
[hardening status](hardening-2026-10-10.md).
