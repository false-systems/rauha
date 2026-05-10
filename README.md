# Rauha

Agent sandbox runtime for controlled, observable execution.

Rauha is a sandbox runtime for AI agents, built on controlled execution zones.
It runs agent tasks where they can be bounded, observed, audited, and later
enforced by the platform underneath them.

## Why Rauha Exists

Agents do not just answer questions anymore.

They run commands, inspect repositories, modify files, generate patches, call
APIs, open sockets, spawn processes, and execute tools.

Most of that execution still happens in environments designed for human
operators:

- local shells
- CI runners
- Docker containers
- Kubernetes jobs
- ad-hoc sandboxes

Those environments provide structure, but not a clear task-level execution
contract. Rauha gives each agent task a zone: an isolated, policy-bound runtime
boundary with structured execution results and auditability.

## The Short Version

Rauha runs each task inside a zone.

A zone is the boundary around execution:

- filesystem
- processes
- networking
- resources
- policy
- logs
- audit events
- enforcement events

For an agent, a zone is the sandbox around a task. For a container, a zone is
the runtime boundary around a workload. For Kubernetes, a zone can back a pod
or workload. On Linux, Syva can enforce those boundaries inside the kernel.

Rauha is an agent sandbox runtime built on a zone-based container runtime, with
Kubernetes integration as one deployment path.

## Agent Sandboxing

The intended task-level user experience is:

```bash
rauha sandbox --image python:3.12 --repo . -- pytest tests/
```

Structured output should look like:

```json
{
  "task_id": "task_123",
  "zone_id": "zone_456",
  "command": ["pytest", "tests/"],
  "status": "succeeded",
  "exit_code": 0,
  "duration_ms": 1842,
  "stdout": "...",
  "stderr": "",
  "events": [],
  "enforcement_events": []
}
```

Status: API contract landed, runtime execution planned. The `rauha sandbox`
CLI command, the `rauha.sandbox.v1.SandboxService` gRPC service, and the
`SandboxExecResult` types in `rauha-common` are wired through the daemon and
CLI. Calling the command today returns:

```
Error: sandbox execution is not implemented yet; use zone/run/exec commands or see docs/sandbox-runtime.md
```

The runtime path — allocating a task zone, starting a container, waiting,
capturing stdout/stderr/exit code, collecting enforcement events, and cleaning
up — is the next PR. Once that lands, the JSON result shape above will be
populated from real execution without changing the user-facing contract.

The current `rauha run` command starts a container in a zone and returns the
container ID; it is asynchronous container lifecycle, not task-level execution.

## What Is a Zone?

A zone is not only a namespace.
A zone is not only a cgroup.

A zone is Rauha's unit of execution, policy, isolation, observability, and
enforcement.

A zone ties together:

- cgroups
- namespaces
- rootfs/filesystem view
- network namespace, bridge, and rules
- runtime metadata
- policy
- audit stream
- optional kernel enforcement

On macOS, the zone boundary is a lightweight VM. On Linux, the zone boundary is
constructed from cgroups, namespaces, networking, rootfs handling, and optional
kernel enforcement.

## What Rauha Gives You

- controlled agent execution
- isolated task zones
- structured stdout/stderr/exit-code result contracts
- filesystem and process boundaries
- network policy
- resource limits
- logs and audit events
- future or optional Syva-backed kernel enforcement
- Kubernetes/containerd integration as a deployment path

## Current CLI

The implemented CLI works at the zone and container level:

```bash
rauha zone create --name frontend --policy policies/standard.toml
rauha image pull alpine:latest
rauha run --zone frontend alpine:latest /bin/echo hello
rauha ps --zone frontend
rauha logs <container-id>
rauha exec <container-id> -- /bin/sh
rauha stop <container-id>
rauha delete <container-id>
rauha zone delete --name frontend --force
```

Use `--json` on non-streaming commands for machine-readable output.

## Beyond Agents: Zone-Based Containers

Rauha's agent sandbox model is built on a general zone runtime.

The runtime can create zones, place containers inside those zones, apply policy,
record metadata, expose logs, and report isolation state. This is the technical
foundation beneath the future task-level sandbox command.

Important crates:

| Crate | Purpose |
| --- | --- |
| `rauha-common` | Shared types, `IsolationBackend`, zone/container models, sandbox result types, errors, shim IPC |
| `rauhad` | Daemon, gRPC server, zone registry, metadata, networking, Linux/macOS backends |
| `rauha-cli` | CLI binary that talks to `rauhad` |
| `rauha-shim` | Per-zone Linux shim that forks and runs container processes |
| `rauha-guest-agent` | Guest-side daemon inside macOS VMs |
| `rauha-oci` | OCI image pull, content store, rootfs preparation |
| `containerd-shim-rauha-v2` | containerd shim v2 for Kubernetes/containerd integration |
| `rauha-enforce` | Transitional workload discovery and zone-mapping agent for existing clusters |
| `rauha-ebpf` | Current in-repo Linux eBPF LSM programs |
| `rauha-ebpf-common` | Shared fixed-layout kernel/userspace types |
| `xtask` | Build helper for eBPF and guest-agent artifacts |

## Kubernetes Integration

Kubernetes is a deployment path, not Rauha's primary identity.

The current repository includes `containerd-shim-rauha-v2`, which bridges
containerd's Task API to `rauhad`:

```text
kubelet -> containerd -> containerd-shim-rauha-v2 -> rauhad -> Rauha zone
```

The shim maps a pod sandbox to a Rauha zone and places app containers in that
zone. This supports the same zone model under Kubernetes through RuntimeClass
configuration once installed and wired into containerd.

Existing clusters can also be mapped to zones through `rauha-enforce`, which
watches workload metadata and programs the current enforcement boundary. That
role is discovery and zone mapping, not Rauha's product identity.

## Syva-Backed Enforcement

Rauha creates the zones. Syva makes the Linux kernel respect them.

Rauha owns:

- runtime lifecycle
- zone creation and deletion
- sandbox/container execution
- policy loading and validation
- image/rootfs handling
- networking
- metadata
- logs, audit, and user-facing event surfaces
- Kubernetes/containerd integration

Syva owns:

- Linux kernel enforcement
- eBPF LSM programs
- BPF maps
- ring buffer events
- file/open enforcement
- exec enforcement
- ptrace enforcement
- signal enforcement
- cgroup attach enforcement
- enforcement counters
- kernel capability verification
- privileged kernel self-tests

Current Linux enforcement code may still live inside this repository, but
architecturally it belongs behind the Syva enforcement boundary.

## Architecture

Rauha is split around the `IsolationBackend` trait in
`rauha-common/src/backend.rs`. The daemon is platform-agnostic and delegates
zone/container work to the active backend.

Linux backend:

- cgroups v2 for membership and resource grouping
- namespaces and rootfs setup through the per-zone shim
- network namespaces, veth pairs, bridge, and nftables
- current in-repo eBPF LSM integration for syscall-level enforcement
- enforcement events streamed through a BPF ring buffer and gRPC watch API

macOS backend:

- one lightweight Linux VM per zone through Virtualization.framework
- virtio-vsock to the guest agent
- virtio-fs/APFS clonefile-backed rootfs handling
- pf anchors for network policy where available

The two backends are intentionally different. Linux uses OS-level isolation
plus optional kernel enforcement. macOS uses a VM boundary per zone.

## Policy Model

Policies are TOML. See `policies/standard.toml`.

Policy can describe:

- zone type
- filesystem rules
- network mode and egress
- resource limits
- capabilities
- syscall policy
- devices
- allowed zone communication

Rauha owns user-facing policy. Linux kernel-facing enforcement policy should
eventually be translated into Syva's policy and map model behind an explicit
boundary.

## Current Status

Implemented today:

- zone create/list/show/delete
- policy parse/apply/show
- container create/start/stop/delete/list
- image pull/list/inspect/remove
- logs, exec, attach, trace/events surfaces
- `IsolationBackend` abstraction
- Linux backend with cgroups, namespaces, networking, shim orchestration, and
  current in-repo eBPF LSM support
- macOS VM-per-zone backend path
- containerd shim v2 code path
- `rauha-enforce` transitional workload discovery/zone mapping agent
- structured sandbox result types in `rauha-common`
- gRPC oracle suite under `eval/oracle`

Planned:

- `rauha sandbox` task-level CLI
- synchronous sandbox execution API
- structured task result emission from the daemon
- cleanup/keep-zone behavior for task zones
- sandbox enforcement event collection in task results
- explicit Syva enforcer boundary
- external Syva integration
- Kubernetes installation docs and RuntimeClass examples

Future:

- move or wrap in-repo eBPF code behind Syva
- privileged Syva/Rauha kernel enforcement test suite
- richer agent orchestration/SDK surfaces
- deeper workload discovery for existing clusters

## Building and Testing

```bash
cargo build
cargo test
cargo build --bin rauhad
cargo build --bin rauha
cargo build --bin rauha-shim
cargo build --bin rauha-guest-agent
cargo build --bin rauha-enforce
cargo build -p containerd-shim-rauha-v2
```

Run the daemon:

```bash
RUST_LOG=rauhad=debug cargo run --bin rauhad
```

Use the CLI:

```bash
cargo run --bin rauha -- zone create --name test
cargo run --bin rauha -- image pull alpine:latest
cargo run --bin rauha -- run --zone test alpine:latest /bin/echo hello
```

Build eBPF programs:

```bash
cargo xtask build-ebpf
```

Oracle tests live in `eval/oracle` and require a running daemon:

```bash
cd eval/oracle
RAUHA_GRPC_ENDPOINT=http://[::1]:9876 cargo test
```

Linux integration tests under `tests/integration` require root and a running
daemon. eBPF enforcement tests require a kernel with BPF LSM support.

## Trade-Offs

- eBPF LSM is OS-level isolation, not a hardware boundary.
- macOS VM-per-zone isolation is a different model from Linux cgroups and
  namespaces.
- LSM is additive-only: BPF LSM can deny access but cannot override SELinux,
  AppArmor, or other MAC denials.
- Current Linux enforcement depends on kernel support for BPF LSM, BTF, and
  compatible struct offsets.
- Covert channels through shared kernel resources are out of scope.
- Kubernetes integration requires containerd and RuntimeClass configuration.
- The task-level `rauha sandbox` command is planned, not implemented.
