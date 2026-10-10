# Hardening implementation status — 2026-10-10

This records the changes following the [deep audit](deep-audit-2026-10-10.md),
not a replacement for its historical evidence. The user chose to complete the
containerd integration rather than remove it. Implementation and unit checks
are distinct from deployment validation: the final combined privileged Linux
gate **passed**, including live containerd and the unchanged oracle. The tested
scope and deployment limitations are recorded below.

## Audit dispositions

| # | Disposition and current behavior |
| --- | --- |
| 1 | DNS injection uses directory-descriptor-relative operations, rejects image-controlled symlink/hardlink/special destinations, and publishes a replacement file atomically. Regression fixtures preserve host sentinels. |
| 2 | Rootfs snapshots compose ordered layers into one immutable tree, applying whiteouts before same-layer additions. Whiteout/opaque-directory and concurrent-publication tests cover final image contents. |
| 3 | Creation-time controls cannot change while a zone has containers: capabilities, filesystem layout, devices and syscall rules require container recreation. Empty zones can switch isolated/bridged network policy while retaining their namespace identity. Host/external identity transitions or a different external namespace require zone recreation. Resource/egress changes use the frozen update path. |
| 4 | Privileged gRPC uses a private Unix socket instead of unauthenticated TCP. Socket ownership and a separate global kernel-enforcement lock prevent conflicting daemons. |
| 5 | Nonempty `repo_path` is rejected explicitly; it is not a host checkout mount. Examples now run commands supplied by an image. Workspace provisioning remains future work. |
| 6 | Container preparation returns the manifest digest from the same resolution that supplied its layers. Receipts no longer re-resolve a mutable tag after preparation. |
| 7 | Adapter completed for native bundle/rootfs import, init/exec lifecycles, real exit status, events, signals, FIFO/PTY I/O, pause/resource updates, metrics and persisted task identity. Focused live lifecycle, pod namespace isolation and cleanup tests passed. Optional checkpoint/restore remains unsupported; see the tested scope below. |
| 8 | Full image references are hashed into `references-v2`; stored reference/digest pairs are checked. Ambiguous legacy reference filenames are not reused. |
| 9 | Snapshot creation has a cross-process lock, private staging, file/directory synchronization and atomic publication. Legacy base-rootfs preparation uses this same path. |
| 10 | Deletion confirms executor cleanup before releasing memberships, inode ownership, namespace pins and rootfs storage. Failures retain retry state; failed creation cleans up or preserves a retry target. Stopped orphan storage can be reclaimed; live or unconfirmed orphan execution is retained. |
| 11 | Policy updates serialize with lifecycle mutations and freeze execution before changing enforcement/database state. Failure restores the previous policy before thaw; failed restoration leaves execution frozen. Tests inject backend, metadata, freeze and restoration failures and check contention. |
| 12 | Inode keys include filesystem device identity. Per-container ownership records preserve shared same-zone keys while removing deleted-container keys; another zone cannot overwrite ownership. Recovery reconstructs these records. |
| 13 | Registry bodies stream into verified temporary blobs instead of one unbounded buffer. Limits are 4 GiB per compressed blob, 4 MiB per manifest/token and 16 GiB expanded per layer, with 15-second connect and 300-second request timeouts. These are not total disk-cache quotas. |
| 14 | README, architecture, security and capability guidance reconciled with code. Dated baseline/results and the superseded observability audit are preserved in [archive](archive/README.md); risk research is labeled historical. |
| 15 | Placeholder `trace` and `top` CLI commands removed. Real `events` (including NDJSON), logs and exec remain. Existing-container attach is still explicitly unsupported by the zone shim. |
| 16 | Integration/security/probe orchestration moved into Rust `xtask`; old shell entry points are thin launchers. Rust supplies fixtures and the isolated transport needed by the unchanged TCP oracle. |

## Containerd and process scope

The adapter imports the supplied OCI bundle/rootfs instead of treating a task ID
as an image name. Admission preserves requested restrictions while applying zone
capability/device limits; it refuses host hooks and conflicting runtime
annotations. Writable volume destinations require zone writable-path admission.
Policy comes from the administrator's `RAUHA_CONTAINERD_POLICY` service setting,
not the workload: `io.rauha.policy` annotations are rejected. The absolute policy
file must be a regular root-owned file, not group/world writable or a symlink,
and no larger than 1 MiB.
The live containerd fixture explicitly admits its standard `/run` tmpfs in that
administrator policy and removes `/run` from the test daemon's reserved-root
list. Default reserved roots remain unchanged; workload annotations cannot grant
this exception.

CRI sandbox tasks own zones. External CNI network namespaces and same-zone
IPC/UTS/PID joins are pinned; foreign namespace joins are rejected. External
network policy uses namespace-local default-deny filtering with explicit
ingress/egress allowances. Checkpoint/restore remains unsupported and is
reported as such, not silently accepted. No full Kubernetes/CRI conformance
claim follows from unit tests or a successful `ctr` lifecycle test.

The runtime now creates a real suspended crun init before start. Each container
has a native child cgroup beneath its zone; membership is installed before
image execution. Exec must share the container's resource and pause boundary.
The zone remains the outer policy/resource limit.

Native exec uses a private child cgroup beneath the container. A single-use
runtime-setup flag allows only the capabilities needed by crun before execution;
the BPF executable-admission hook consumes it before any workload starts. The
shim verifies consumption before reporting success. With the required hooks
available, workloads cannot join, signal or trace setup tasks. Membership-map
descriptors are inherited privately,
close-on-exec, and refreshed while recovery keeps execution frozen; recovery
does not rearm setup permission. Exec cleanup kills descendants and retains
enforcement until the group is empty. Live native exec, real nonzero exit status
and exec through a recovered shim's refreshed map descriptor have passed.

Interactive CLI exec also uses native crun, not manual post-fork namespace and
capability setup inside the multithreaded shim. Its PTY relay owns descriptors
and signals disconnected sessions; only the shim runtime owner reaps the process.
Finished interactive exec records remain until the daemon drains output, obtains
the real exit status and deletes the session. CLI exec receives that status;
unknown status or failed cleanup is an error, not an assumed zero exit. Exec in
notification-broker containers is explicitly unsupported:
the broker listener currently accepts only one notification-descriptor handoff.
Ordinary seccomp-deny profiles do not have this limitation.

I/O cleanup closes stdin and drains terminal output. A blocked output consumer
returns a retryable cleanup error rather than silently discarding queued bytes.
Empty stdin closure, output backpressure/retry, delivery failure and PTY output
without a requested output FIFO have Linux regressions. Resource-update failure
leaves the container paused. Optional features are not inferred from empty
success responses.

## Upgrade and operation

1. **Drain workloads before upgrading daemon, shim and BPF artifacts together.**
   Device-qualified inode keys change the map ABI, and native child cgroups change
   runtime enrollment. This is not a mixed-version rolling-upgrade guarantee.
   Rebuild the BPF object and offsets sidecar for the deployment kernel.
2. Startup takes `/run/rauha-enforcement.lock` before touching shared enforcement
   state, freezes existing zone cgroups, replaces only known Rauha pins, and
   reconstructs policy/membership before thawing. A failed recovery may leave a
   zone frozen; investigate rather than manually bypassing that boundary.
3. Replace TCP addresses with `/run/rauha/rauhad.sock` (or another absolute path)
   in `RAUHA_ADDR` and `[server].addr`. The socket is 0600 and its parent must be
   daemon-owned and private (0700). Socket access is privileged; do not expose a
   host TCP proxy. The oracle's proxy exists only in an isolated test network
   namespace.
4. Pull image tags again to populate `references-v2`. Content-addressed blobs
   remain reusable; do not erase the whole store. Old reference names are too
   ambiguous to migrate safely. `snapshots-v2` replaces old extraction caches;
   reclaim old storage only after draining and confirming no mounts reference it.
5. Delete containers before changing creation-time policy controls. Empty zones
   may switch isolated/bridged network policy; host/external identity transitions
   or a different external network namespace require zone recreation. A failed
   dynamic update or output cleanup is an actionable error, not permission to
   thaw execution or drop retained state without diagnosis.

## Verification

The combined gate completed successfully (local log: `.gate/full-gate-pass.log`).
No production code changed afterward.

- Native workspace: **240 passed, five ignored**. No project compiler warnings;
  the dependency `proc-macro-error2` emits a future-compatibility notice.
- Linux workspace: **391 top-level tests passed, 15 ignored**, plus four nested
  evidence subprocess checks. Formatting, warning-denied Clippy, workspace build
  and generated-offset BPF build all passed.
- Real containerd lifecycle: **passed in the combined gate** and focused runs.
  Verified init
  exits 0/7 and output, real PID/process lists/metrics, resource updates,
  pause/resume, empty capability sets, exec exit 7, PTY output and signal exit 42.
  Pod tasks shared network/IPC/UTS/PID namespaces; cross-pod joins were rejected.
  Force-delete drained surviving execs after init death, removed zone resources,
  and unavailable-daemon requests failed rather than succeeding spuriously.
- The combined runtime gate passed all ten integration scenarios, hostile and
  disconnected output, two crash/recovery rounds including new exec after map
  refresh, OCI create/enroll/start with inode consistency, and the unchanged
  oracle **55/55**. Live probes covered overlay/namespace-pin cleanup,
  external-network filtering, actual cross-zone file-open denial, CLI exit 7,
  and seccomp filtering with a denied syscall, zero effective capabilities and
  no-new-privileges.
- A subsequent test-only exact-owner cleanup adjustment passed its additional
  unit test, adapter lint/unit checks and a focused real lifecycle rerun in
  **9.20 seconds** (`.gate/containerd-cleanup-pass.log`). This does not change
  the combined-run count of 391 Linux tests above.

Final read-only cleanup verification found no Rauha test daemons, adapter shims,
private containerd processes, test cgroups, veths, BPF pin directories or DNS
directories. The original three CNI namespaces and six nftables tables remained,
and k3s was still active. These results are summarized here independently of the
local log files.

The containerd fixture explicitly uses **OCI 1.0.2 with crun 1.14.1**. These
results do not establish OCI 1.3 support or full Kubernetes/CRI conformance.
The passing image-pull run used the official public ECR Alpine/BusyBox mirrors
after Docker Hub returned HTTP 429; real registry pulls remain part of the gate.

The test VM kernel lacks the `cgroup_attach_task` LSM hook. Live runtime scenarios
on that kernel explicitly use audit admission, so they do not establish complete
strict enforcement. A separate negative check verifies that strict admission
rejects the missing hook. Production defaults remain strict; audit-mode test
results are not permission to deploy with that protection silently absent.

The isolated Linux gate requires host IPv4 forwarding to be enabled already;
it refuses to change that host sysctl. Its `198.19.255.0/30` test uplink must not
overlap an existing nondefault route. Gate-owned network and mount namespaces
keep its firewall and BPF mounts separate from existing workloads.

Non-Linux compilation is development support, not a supported
execution backend. Event capture remains best-effort, not an audit-complete log.
