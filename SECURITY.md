# Rauha — Security Model & Known Limitations

Honest documentation of what Rauha can and cannot guarantee.

Rauha is an agent sandbox runtime built on controlled execution zones. It owns
zone lifecycle, container/task execution, policy loading, metadata, networking,
logs, and user-facing event surfaces.

Rauha creates the zones. Syva makes the Linux kernel respect them.

The Linux kernel enforcement code currently lives in this repository as a
transitional implementation. Architecturally, those eBPF LSM programs, BPF
maps, ring buffer events, counters, and kernel self-tests belong behind the
Syva enforcement boundary. This distinction matters: Rauha is the runtime and
zone control plane, not the kernel enforcement product.

## Isolation Models

Rauha exposes fundamentally different isolation models on each platform.
They are **not equivalent** — each has different strengths and weaknesses.

### Linux: Per-Syscall Software Policy (Syva/eBPF LSM)

On Linux, zone boundaries can be enforced by eBPF LSM programs that check
zone membership in BPF maps on security-relevant operations such as
file_open, exec, ptrace, signal delivery, cgroup attach, capability checks,
and socket connect.

In the current transitional codebase, `rauhad` still loads and manages these
programs directly from `rauhad/src/backend/linux/` and `rauha-ebpf/`.
The target architecture moves this behind Syva while keeping Rauha as the
runtime API and event surface.

**Strengths:**
- Granular observability — every denied operation is visible
- Dynamic policy — BPF map updates take effect immediately
- No performance cliff — enforcement cost is per-syscall, constant time

**Weaknesses:**
- Software policy, not hardware boundary — kernel bugs can bypass enforcement
- Requires kernel 6.1+ with CONFIG_BPF_LSM=y and `lsm=bpf` in boot cmdline
- eBPF verifier limits complexity of individual programs (512-byte stack)
- Struct offset assumptions (file->f_inode, etc.) are fragile across kernel versions
  until CO-RE BTF support is added

### Former macOS Backend (removed)

The macOS Virtualization.framework backend (VM per zone, `rauha-guest-agent`,
pf anchors, APFS clonefile) was removed. It could confine but not observe —
no deny events, no enforcement counters, no receipts — and had drifted to
non-compiling. If a VM tier returns, the shape is the same Linux stack inside
a VM, not a parallel macOS backend.

### What This Means for Users

`rauha zone verify` returns an `IsolationReport` with a `model` field
(`SyscallPolicy` or `HardwareBoundary`). Code that evaluates isolation
status or interprets enforcement events **must** check this field.

Agent sandbox results should treat enforcement events as backend-specific:
Linux/Syva-backed zones require eBPF enforcement events to be available before
the daemon starts.

## Known Limitations

### Shim Privilege Window (Linux, Phase 3)

The rauha-shim process runs in the host namespace to perform zone setup
(namespace creation, cgroup configuration, rootfs mounting). This is
necessary but creates a privilege window:

1. Shim starts in host namespace with elevated privileges
2. Shim creates zone namespace infrastructure
3. Shim forks container process into zone
4. Syva/eBPF enforcement is fully active

Between steps 1-3, a compromised shim can manipulate zone setup before
kernel enforcement is in place. Mitigations planned:
- Minimize shim capabilities to only what's needed for setup
- Drop privileges immediately after namespace setup
- Validate zone state before marking it Ready (verify_isolation check)

This window is inherent to the Linux container model — containerd, CRI-O,
and gVisor all have equivalent privilege windows during setup.

### /proc Filtering Bypasses (Linux)

Filtering /proc visibility via getdents64 interception is defense-in-depth,
not a complete solution. Known bypasses:

- **Direct inode access:** `open("/proc/1234/status")` bypasses directory listing
- **/proc/self/fd traversal:** FDs obtained before filtering can access filtered entries
- **openat with pre-existing dirfd:** A directory FD from before zone entry sees everything

This is a known hard problem. containerd and gVisor both learned this:
- containerd uses pid namespaces (structural) + procfs masking (defense-in-depth)
- gVisor reimplements procfs entirely (expensive, complete)

Rauha's approach: pid namespaces provide the structural isolation, and
Syva/eBPF proc filtering is defense-in-depth. We document it as such, not as
primary isolation.

### Kernel Enforcement / Metadata Consistency (Linux)

BPF maps (current in-kernel enforcement state) and redb (Rauha's persisted
zone/policy metadata) are separate stores. If rauhad crashes between updating
one and the other, they can diverge.

**Recovery:** On startup, rauhad reconciles by treating redb as the source
of truth. It re-pushes all zone policies to the current kernel enforcement
boundary, re-creates missing cgroups and network namespaces, and cleans up
orphaned kernel state.
See `ZoneRegistry::reconcile()`.

**Remaining gap:** During the window between rauhad crash and restart,
stale kernel enforcement maps continue enforcing the old policy. This is acceptable
because stale policy is either correct (crash happened before redb write)
or more restrictive than intended (crash happened after redb write but
before the kernel-enforcement update relaxed a policy). Policy updates are never less
restrictive during this window.

### ptrace and signal Guards (Linux)

The ptrace_access_check and task_kill guards in the current in-repo eBPF
implementation are incomplete. They can identify the calling process's zone
but cannot reliably determine the target process's zone without CO-RE BTF
support for cross-kernel `task_struct` field access.

Current state: these guards check if the caller is in a zone with ptrace
allowed, but do not verify the target is in the same zone. Full cross-zone
ptrace/signal blocking requires:
- CO-RE BTF for `task_struct->cgroups` traversal
- Or a secondary BPF map keyed by pid→zone_id (requires tracking all pids)

### Kernel Version Sensitivity (Linux)

The current in-repo eBPF programs compile kernel struct offsets into the BPF
object (for example, `struct file->f_inode`). `cargo xtask build-ebpf` resolves
those offsets from the target kernel's BTF with `pahole` and writes a sidecar
manifest beside the object, including the object's SHA-256 hash. `rauhad`
validates the sidecar against both the object and the running kernel before
loading; missing or stale offset metadata is a fatal startup error.

Fix: migrate to CO-RE (Compile Once, Run Everywhere) using BTF-based
field access. Aya supports this but it adds build complexity. Longer-term,
this kernel compatibility work belongs in Syva, with Rauha consuming the
result through an enforcement boundary.
