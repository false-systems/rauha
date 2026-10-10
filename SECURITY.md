# Rauha security model and limits

Rauha runs Linux workloads in zones. The daemon, zone shim, OCI runtime,
host kernel and root administrator are trusted. This is OS-level containment,
not a hardware boundary and not protection against a compromised host root.
Non-Linux builds support development and unit tests, not workload execution.

## Control plane

The privileged gRPC API listens on `/run/rauha/rauhad.sock`, mode 0600, in a
private daemon-owned directory. `RAUHA_ADDR` and `[server].addr` select an
absolute Unix socket path. TCP is not supported. Do not forward this socket
to untrusted clients: access grants privileged workload and policy control.

## Enforcement

Linux requires root, cgroups v2, BPF-LSM and the required nftables facilities.
The in-repo `LinuxEnforcer` loads the eBPF programs; an external enforcer is
an architectural direction, not the active runtime dependency.

- crun creates a parked init process; the shim enrolls it in its zone cgroup
  before starting image code. The privileged setup path remains in the TCB.
- BPF-LSM mediates file access, exec, ptrace, signal, cgroup attachment and
  capabilities. Filesystem ownership keys include device and inode.
- Ptrace/signal guards resolve both caller and target membership through
  BTF-derived task/cgroup offsets. Zoned callers cannot act on unzoned host
  tasks; cross-zone operations require an allowed communication relationship.
- nftables enforces network traffic; the socket LSM hook is audit-only.
- OCI seccomp implements denied syscalls; selected `openat`/`openat2` calls
  can use the read-only seccomp-notify broker. See [the README](README.md#limitations-honest)
  for its shared-filesystem race limit.

Strict admission refuses unavailable requested controls. Audit admission
records degradation instead; it is not equivalent to strict isolation.
Filesystem/device admission has a deliberately limited supported subset:
see [capabilities](docs/rauha-product-abilities.md).

Kernel struct offsets are generated from the target kernel's BTF by
`cargo xtask build-ebpf`. A sidecar binds offsets to the object's SHA-256;
startup validates both against the running kernel and runs a self-test.
Missing/stale metadata is fatal. Rebuild for the deployment kernel rather
than treating a successful portable crate build as a deployable BPF artifact.

## Policy and recovery

Creation-time controls cannot change while a zone has containers. Dynamic
policy changes serialize updates and freeze execution while enforcing and
persisting the new policy. If an update fails, the previous policy is restored
before thawing; an unsuccessful restoration leaves execution frozen.
Startup reconciles from redb while the zone is frozen. This is a fail-closed
recovery protocol, not a single atomic transaction across kernel, firewall,
cgroups and database. Investigate a frozen zone rather than thawing it manually.

Task recovery stops interrupted execution and records uncertainty; it never
replays the command. See [durable task recovery](docs/sandbox-runtime.md#durable-task-recovery).

## Remaining boundaries

- Kernel vulnerabilities and shared-resource covert channels are out of scope.
  Namespace/procfs restrictions do not make the host kernel a hardware boundary.
- Event streams are best-effort. Subscriber lag is counted, but missing kernel
  ring-buffer records and bounded broker logs prevent an audit-completeness claim.
  Signed receipts attest the captured record, not the absence of uncaptured actions.
- The daemon's signing key and local journal are trusted host state, not remote
  hardware attestation. Verify receipts off-host when independent checking matters.
- Image extraction rejects unsafe paths and DNS writes reject image symlink and
  hardlink destinations. Image inputs remain untrusted; download and expansion
  bounds limit individual objects, not total disk use across all cached images.

Drain workloads before upgrading the inode-map ABI; see [upgrade notes](docs/rauha-product-abilities.md#upgrade-notes).
