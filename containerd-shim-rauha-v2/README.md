# containerd runtime

`containerd-shim-rauha-v2` implements containerd's Task v2 API using the Rauha
daemon and its OCI supervisor. Linux, cgroups v2, crun, and a running privileged
`rauhad` are required. Build the workspace and put the shim binary on containerd's
`PATH`; its runtime name is `io.containerd.rauha.v2`.

The executor must support the OCI version containerd submits. For example,
containerd versions generating OCI 1.3 require a compatible crun; crun 1.14.1
advertises OCI 1.0 and rejects those newer specs. The adapter never silently
downgrades the version or discards newer semantics.

The shim uses the private `/run/rauha/rauhad.sock` Unix socket. For a non-default
location, set `RAUHA_ADDR` in **containerd's service environment** so its shim
children inherit it. TCP daemon addresses are not supported.

For containerd 1.x configuration:

```toml
[plugins."io.containerd.grpc.v1.cri".containerd.runtimes.rauha]
runtime_type = "io.containerd.rauha.v2"
```

For containerd 2.x configuration version 3, the table is
`plugins."io.containerd.cri.v1.runtime".containerd.runtimes.rauha` instead.
Select the `rauha` handler through a Kubernetes RuntimeClass, or use
`ctr run --runtime io.containerd.rauha.v2 ...` directly.

## Lifecycle and policy

The adapter imports containerd's mounted rootfs and OCI process configuration;
task IDs are never interpreted as image names. A standalone task owns a zone.
A CRI sandbox owns a zone shared by its pod's containers. Init and exec processes
have real host PIDs, exit codes, timestamps, FIFO/terminal IO, signals, and
containerd lifecycle events. Pause/resume, resource updates, process listing,
and cgroup statistics operate on the container's child cgroup.

Set `RAUHA_CONTAINERD_POLICY` in containerd's service environment to an absolute
policy-file path using the same TOML as `rauha zone create --policy`. The file
must be regular, nonsymlink, root-owned, not group/world-writable, and no larger
than 1 MiB. It is read through a validated file descriptor. The zone name/type
are assigned by the adapter. Caller-supplied `io.rauha.policy` annotations are
explicitly rejected: pod metadata cannot grant privileges.
Without an administrator policy file, normal restrictive zone defaults apply:
an empty capability set, read-only root, resource limits, and denied networking.
Requested capabilities and device permissions are intersected with zone policy.
Host-executed OCI hooks, caller overrides of runtime security annotations, and
mount propagation into the host are rejected.

Containerd's standard OCI spec requests a writable `/run` tmpfs. Admit it
explicitly in the administrator policy when using that spec:

```toml
[filesystem]
writable_paths = ["/run"]
```

The daemon also reserves `/run` by default. An administrator choosing this
configuration must explicitly remove it from the daemon's reserved-root list
in `rauha.toml` (the legacy setting name is `safe_writable_roots`):

```toml
[policy]
safe_writable_roots = ["/proc", "/sys", "/dev"]
```

An undeclared writable mount is rejected; the adapter does not silently make
paths writable to accommodate containerd defaults.

Read-only host bind mounts are accepted from the privileged containerd caller;
recursive read-only bindings require crun's `rro` support. Writable volumes must
target zone-declared writable paths or the admitted shared-memory mount. Mount
restrictions such as `noexec`, `nosuid`, and `nodev` are retained. The host cgroup
hierarchy is not exposed inside the container.

CNI-provided network namespaces are pinned for the zone. Rauha leaves CNI's links
and addressing intact and installs default-deny nftables rules **inside that
namespace**. Configure explicit `allowed_ingress`/`allowed_egress` CIDRs and
optional TCP ports in the policy. External namespaces cannot grant `NET_ADMIN`
or `SYS_ADMIN`, and use CIDRs rather than `allowed_zones`. A missing namespace
pin during recovery is an error, not permission to join a replacement namespace.
Network mode cannot change while containers exist. An empty zone may switch
between isolated and bridged modes without changing its namespace identity;
host/external transitions or a different external namespace require recreating
the zone.
Pod IPC/UTS/PID joins are permitted only through a live process in the same zone;
those namespace handles are pinned before OCI creation too.

Caller seccomp restrictions are retained. Common default-deny profiles compose
with the zone's unconditional deny/broker rules; ambiguous overlapping actions
are rejected rather than dropping either policy. Exec in notification-broker
containers is rejected because the broker currently supports only one descriptor
handoff; ordinary seccomp-deny profiles support exec. Checkpoint/restore is not
implemented. This is not a claim of Kubernetes conformance or support for every
privileged/host-namespace pod configuration.

## Verification

The ignored Rust `lifecycle` integration test starts its own containerd instance,
copies an unpacked Alpine fixture, and tests actual exit status/output, exec,
terminal IO, pause/resume, resource updates, metrics, signals, deletion, and an
unavailable daemon. Pod-style tests verify shared network/IPC/UTS/PID namespace
identity and reject cross-pod network namespace reuse. Force-delete also drains
surviving execs after init death. The privileged test uses
an explicit administrator audit policy because its VM lacks one required LSM
hook; this does not change the adapter's strict production default.
It explicitly submits an OCI 1.0.2 fixture using `ctr --config` for the test
VM's older crun. Passing this gate does not establish OCI 1.3 compatibility.
It requires `RAUHA_ADDR` and `RAUHA_TEST_ROOTFS`; `CONTAINERD_BINARY`, `CTR_BINARY`,
and `RAUHA_SHIM_BINARY` optionally select binaries. It does not reconfigure an
existing containerd or Kubernetes installation. See
[hardening status](../docs/hardening-2026-10-10.md) for the checks actually run.
