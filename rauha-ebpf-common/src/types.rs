//! Shared types between eBPF kernel programs and userspace.
//!
//! All types are `#[repr(C)]` with fixed sizes for BPF map compatibility.
//! No pointers, no heap, no padding surprises.

/// Maximum number of zones the system can track.
pub const MAX_ZONES: u32 = 4096;

/// Maximum number of cgroups (zone memberships) tracked in BPF maps.
pub const MAX_CGROUPS: u32 = 65536;

/// Maximum number of inodes tracked for file-zone ownership.
/// 256K entries × ~76 bytes/entry ≈ 19MB pinned kernel memory.
/// Covers most container rootfs scenarios (Alpine ~800, Ubuntu ~35K).
pub const MAX_INODES: u32 = 262_144;

/// Value in the ZONE_MEMBERSHIP map. Keyed by cgroup_id (u64).
#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct ZoneInfoKernel {
    /// Compact zone identifier (monotonic u32, not the Uuid).
    pub zone_id: u32,
    /// Bit flags for zone properties.
    /// Bit 0: is_privileged
    /// Bit 1: is_global
    pub flags: u32,
}

/// Value in the ZONE_POLICY map. Keyed by zone_id (u32).
#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct ZonePolicyKernel {
    /// Bitmask of allowed Linux capabilities (CAP_* values).
    pub caps_mask: u64,
    /// Policy flags.
    /// Bit 0: allow_ptrace
    /// Bit 1: allow_host_network
    pub flags: u32,
    pub _pad: u32,
}

/// Key in the ZONE_ALLOWED_COMMS map. Value is u8 (1 = allowed).
#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ZoneCommKey {
    pub src_zone: u32,
    pub dst_zone: u32,
}

// Flag constants for ZoneInfoKernel.flags
pub const ZONE_FLAG_PRIVILEGED: u32 = 1 << 0;
pub const ZONE_FLAG_GLOBAL: u32 = 1 << 1;

// Flag constants for ZonePolicyKernel.flags
pub const POLICY_FLAG_ALLOW_PTRACE: u32 = 1 << 0;
pub const POLICY_FLAG_ALLOW_HOST_NET: u32 = 1 << 1;

/// Result of the startup self-test that validates kernel struct offsets.
///
/// Written by the `file_open` hook on its first invocation. Userspace reads
/// this after triggering a file open and compares the two cgroup_id values.
/// If they differ, the hardcoded offsets are wrong for this kernel.
#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct SelfTestResult {
    /// cgroup_id from `bpf_get_current_cgroup_id()` (known-good BPF helper).
    pub helper_cgroup_id: u64,
    /// cgroup_id derived from the hardcoded offset chain:
    /// `bpf_get_current_task() -> cgroups -> dfl_cgrp -> kn -> id`
    pub offset_cgroup_id: u64,
}

/// Per-hook enforcement decision counters.
///
/// One entry per LSM program in the ENFORCEMENT_COUNTERS PerCpuArray.
/// Each CPU has its own copy — no contention. Userspace sums across CPUs.
#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct EnforcementCounters {
    /// Number of times this hook returned 0 (allow).
    pub allow: u64,
    /// Number of times this hook returned -1 (deny).
    pub deny: u64,
    /// Number of times the hook hit an error path and fell through to allow.
    /// High error + zero deny = enforcement silently failing.
    pub error: u64,
}

// Program indices in the ENFORCEMENT_COUNTERS array.
pub const PROG_FILE_OPEN: u32 = 0;
pub const PROG_BPRM_CHECK: u32 = 1;
pub const PROG_PTRACE_CHECK: u32 = 2;
pub const PROG_TASK_KILL: u32 = 3;
pub const PROG_CGROUP_ATTACH: u32 = 4;
pub const PROG_CAPABLE: u32 = 5;
pub const PROG_SOCKET_CONNECT: u32 = 6;
pub const ENFORCEMENT_COUNTER_ENTRIES: u32 = 7;

// Hook type constants for EnforcementEvent.
pub const HOOK_FILE_OPEN: u8 = 0;
pub const HOOK_BPRM_CHECK: u8 = 1;
pub const HOOK_PTRACE_CHECK: u8 = 2;
pub const HOOK_TASK_KILL: u8 = 3;
pub const HOOK_CGROUP_ATTACH: u8 = 4;
pub const HOOK_CAPABLE: u8 = 5;
pub const HOOK_SOCKET_CONNECT: u8 = 6;

// Decision constants for EnforcementEvent.
pub const DECISION_ALLOW: u8 = 0;
pub const DECISION_ERROR: u8 = 2;
pub const DECISION_DENY: u8 = 1;

/// Enforcement event emitted from BPF hooks via ring buffer.
///
/// Fixed 48-byte struct. All hooks populate the common fields;
/// hook-specific context goes in the `context` field:
///   - file_open / bprm_check: the denied inode number
///   - cgroup_attach: the destination cgroup_id
///   - ptrace / task_kill: 0 (target PID to be added later)
#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct EnforcementEvent {
    /// Monotonic timestamp from bpf_ktime_get_ns().
    pub timestamp_ns: u64,
    /// Caller's tgid (process ID).
    pub pid: u32,
    /// Which LSM hook (HOOK_FILE_OPEN, etc.).
    pub hook: u8,
    /// Decision (DECISION_DENY, etc.).
    pub decision: u8,
    pub _pad0: [u8; 2],
    /// Caller's zone_id (0 = unzoned).
    pub caller_zone: u32,
    /// Target zone_id (for cross-zone denies).
    pub target_zone: u32,
    /// Hook-specific context data.
    pub context: u64,
    /// Reserved for future use (comm name, etc.).
    pub _reserved: [u64; 2],
}

#[cfg(feature = "userspace")]
mod cap_convert {
    use super::ZonePolicyKernel;

    /// Known Linux capability names mapped to their bit position.
    const CAPS: &[&str] = &[
        "CAP_CHOWN",            // 0
        "CAP_DAC_OVERRIDE",     // 1
        "CAP_DAC_READ_SEARCH",  // 2
        "CAP_FOWNER",           // 3
        "CAP_FSETID",           // 4
        "CAP_KILL",             // 5
        "CAP_SETGID",           // 6
        "CAP_SETUID",           // 7
        "CAP_SETPCAP",          // 8
        "CAP_LINUX_IMMUTABLE",  // 9
        "CAP_NET_BIND_SERVICE", // 10
        "CAP_NET_BROADCAST",    // 11
        "CAP_NET_ADMIN",        // 12
        "CAP_NET_RAW",          // 13
        "CAP_IPC_LOCK",         // 14
        "CAP_IPC_OWNER",        // 15
        "CAP_SYS_MODULE",       // 16
        "CAP_SYS_RAWIO",        // 17
        "CAP_SYS_CHROOT",       // 18
        "CAP_SYS_PTRACE",       // 19
        "CAP_SYS_PACCT",        // 20
        "CAP_SYS_ADMIN",        // 21
        "CAP_SYS_BOOT",         // 22
        "CAP_SYS_NICE",         // 23
        "CAP_SYS_RESOURCE",     // 24
        "CAP_SYS_TIME",         // 25
        "CAP_SYS_TTY_CONFIG",   // 26
        "CAP_MKNOD",            // 27
        "CAP_LEASE",            // 28
        "CAP_AUDIT_WRITE",      // 29
        "CAP_AUDIT_CONTROL",    // 30
        "CAP_SETFCAP",          // 31
        "CAP_MAC_OVERRIDE",     // 32
        "CAP_MAC_ADMIN",        // 33
        "CAP_SYSLOG",           // 34
        "CAP_WAKE_ALARM",       // 35
        "CAP_BLOCK_SUSPEND",    // 36
        "CAP_AUDIT_READ",       // 37
        "CAP_PERFMON",          // 38
        "CAP_BPF",              // 39
        "CAP_CHECKPOINT_RESTORE", // 40
    ];

    /// Convert prevalidated capability name strings to a bitmask.
    ///
    /// Policy input must be validated before this low-level fixed-layout
    /// helper is called. Unknown names have no bit in the kernel mask.
    pub fn caps_to_mask(caps: &[impl AsRef<str>]) -> u64 {
        let mut mask = 0u64;
        for cap in caps {
            let name = cap.as_ref().to_uppercase();
            let name = if name.starts_with("CAP_") {
                name
            } else {
                // Allow short form: "NET_ADMIN" -> "CAP_NET_ADMIN"
                let mut prefixed = "CAP_".to_owned();
                prefixed.push_str(&name);
                prefixed
            };
            if let Some(pos) = CAPS.iter().position(|&c| c == name) {
                mask |= 1u64 << pos;
            }
        }
        mask
    }

    impl ZonePolicyKernel {
        /// Create a new policy from capability names and flags.
        pub fn from_caps(caps: &[impl AsRef<str>], allow_ptrace: bool, allow_host_net: bool) -> Self {
            let mut flags = 0u32;
            if allow_ptrace {
                flags |= super::POLICY_FLAG_ALLOW_PTRACE;
            }
            if allow_host_net {
                flags |= super::POLICY_FLAG_ALLOW_HOST_NET;
            }
            Self {
                caps_mask: caps_to_mask(caps),
                flags,
                _pad: 0,
            }
        }
    }
}

#[cfg(feature = "userspace")]
pub use cap_convert::caps_to_mask;

// Ensure types are safe to use as BPF map keys/values.
// They must be Copy + Clone + fixed-size with no padding surprises.
unsafe impl Sync for ZoneInfoKernel {}
unsafe impl Send for ZoneInfoKernel {}
unsafe impl Sync for ZonePolicyKernel {}
unsafe impl Send for ZonePolicyKernel {}
unsafe impl Sync for ZoneCommKey {}
unsafe impl Send for ZoneCommKey {}
unsafe impl Sync for SelfTestResult {}
unsafe impl Send for SelfTestResult {}
unsafe impl Sync for EnforcementCounters {}
unsafe impl Send for EnforcementCounters {}
unsafe impl Sync for EnforcementEvent {}
unsafe impl Send for EnforcementEvent {}

// aya::Pod is required for types used as BPF map keys/values on the userspace side.
// All three types are #[repr(C)], Copy, and have no padding — safe to implement.
#[cfg(feature = "userspace")]
unsafe impl aya::Pod for ZoneInfoKernel {}
#[cfg(feature = "userspace")]
unsafe impl aya::Pod for ZonePolicyKernel {}
#[cfg(feature = "userspace")]
unsafe impl aya::Pod for ZoneCommKey {}
#[cfg(feature = "userspace")]
unsafe impl aya::Pod for SelfTestResult {}
#[cfg(feature = "userspace")]
unsafe impl aya::Pod for EnforcementCounters {}
#[cfg(feature = "userspace")]
unsafe impl aya::Pod for EnforcementEvent {}

#[cfg(test)]
mod tests {
    use super::*;
    use core::mem::size_of;

    #[test]
    fn zone_info_kernel_size() {
        assert_eq!(size_of::<ZoneInfoKernel>(), 8);
    }

    #[test]
    fn zone_policy_kernel_size() {
        assert_eq!(size_of::<ZonePolicyKernel>(), 16);
    }

    #[test]
    fn zone_comm_key_size() {
        assert_eq!(size_of::<ZoneCommKey>(), 8);
    }

    #[test]
    fn self_test_result_size() {
        assert_eq!(size_of::<SelfTestResult>(), 16);
    }

    #[test]
    fn enforcement_counters_size() {
        assert_eq!(size_of::<EnforcementCounters>(), 24);
    }

    #[test]
    fn enforcement_event_size() {
        assert_eq!(size_of::<EnforcementEvent>(), 48);
    }

    #[test]
    #[cfg(feature = "userspace")]
    fn caps_to_mask_basic() {
        let mask = caps_to_mask(&["CAP_NET_ADMIN", "CAP_SYS_PTRACE"]);
        assert_eq!(mask, (1 << 12) | (1 << 19));
    }

    #[test]
    #[cfg(feature = "userspace")]
    fn caps_to_mask_short_form() {
        let mask = caps_to_mask(&["NET_ADMIN"]);
        assert_eq!(mask, 1 << 12);
    }
}
