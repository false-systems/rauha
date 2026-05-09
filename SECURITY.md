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

### macOS: Hardware Boundary (Virtualization.framework)

Each zone runs in a lightweight Linux VM using Apple's Virtualization.framework.
The hypervisor boundary prevents cross-zone access structurally — no need to
intercept individual syscalls. Communication between the host daemon (rauhad)
and each VM happens over virtio-vsock using the same ShimRequest/ShimResponse
protocol as the Linux shim.

**Architecture:**
- One VM per zone, containing a minimal Linux kernel + initramfs
- Guest agent (rauha-guest-agent) inside each VM handles container lifecycle
- Container rootfs shared from host via virtio-fs, cloned with APFS clonefile()
- Network isolation via pf firewall anchors (one per zone)

**Strengths:**
- Hardware isolation — stronger guarantee than software policy
- Simpler enforcement model — VM boundary is all-or-nothing
- No kernel version fragmentation
- Sub-second VM boot times with minimal kernel + initramfs (~15MB)

**Weaknesses:**
- Fewer observability hooks — `rauha trace` cannot show per-syscall events
  without DTrace integration (painful, limited on modern macOS)
- Higher per-zone overhead (VM startup vs. cgroup creation)
- Policy granularity limited to VM-level controls
- VMs do not survive daemon restart — zones must be recovered on startup
- CPU/memory limits set at VM boot time; changes require zone restart
- Requires `com.apple.security.virtualization` entitlement on rauhad binary

### What This Means for Users

`rauha zone verify` returns an `IsolationReport` with a `model` field
(`SyscallPolicy` or `HardwareBoundary`). Code that evaluates isolation
status or interprets enforcement events **must** check this field.
A report from Linux and macOS cannot be compared directly.

Agent sandbox results should treat enforcement events as an optional stream:
Linux/Syva-backed zones can populate them, macOS VM-backed zones may expose
different audit information, and unsupported/degraded Linux hosts may have no
kernel enforcement events at all.

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

### VM Lifecycle and Daemon Restart (macOS)

Unlike Linux cgroups and network namespaces which persist in the kernel,
Virtualization.framework VMs die when rauhad exits. On daemon restart,
`recover_zone` re-boots VMs for zones that should be active (based on
persisted redb state). Container processes inside VMs are lost on
daemon crash — there is no way to reattach to a VM that was destroyed.

**Implications:**
- Running containers are terminated on daemon crash/restart
- Zone recovery involves a full VM reboot (sub-second with warm cache)
- pf rules are re-applied from zone policy on recovery
- Container rootfs data persists (on host APFS) across restarts

### Kernel Version Sensitivity (Linux)

The current in-repo eBPF programs use hardcoded struct offsets (e.g.,
`struct file->f_inode` at offset 32). These are correct for Linux 6.1+ but
may break on future kernels that change struct layouts.

Fix: migrate to CO-RE (Compile Once, Run Everywhere) using BTF-based
field access. Aya supports this but it adds build complexity. Longer-term,
this kernel compatibility work belongs in Syva, with Rauha consuming the
result through an enforcement boundary.
