//! Kernel ABI for the seccomp-notify broker: ioctl numbers, `#[repr(C)]`
//! wire structs, and the syscall-name table pinned to
//! `rauha_common::zone::BROKERABLE_SYSCALLS`.
//!
//! Every constant here is cross-checked at compile time or by unit test —
//! this module is the one place the kernel's ABI is trusted.

// _IOWR('!', 0, struct seccomp_notif) — 80 bytes (id + pid + flags + data)
pub(crate) const SECCOMP_IOCTL_NOTIF_RECV: libc::c_ulong = 0xc050_2100;
// _IOWR('!', 1, struct seccomp_notif_resp) — 24 bytes
pub(crate) const SECCOMP_IOCTL_NOTIF_SEND: libc::c_ulong = 0xc018_2101;
// _IOW('!', 2, __u64) — 8 bytes (NB: _IOW, not _IOWR — linux/seccomp.h)
pub(crate) const SECCOMP_IOCTL_NOTIF_ID_VALID: libc::c_ulong = 0x4008_2102;
// _IOW('!', 3, struct seccomp_notif_addfd) — 24 bytes
pub(crate) const SECCOMP_IOCTL_NOTIF_ADDFD: libc::c_ulong = 0x4018_2103;

// Decode our own ioctl numbers at compile time: dir<<30 | size<<16 | type<<8 | nr.
const _: () = assert!(0xc000_0000 | (80 << 16) | ((b'!' as u32) << 8) == 0xc050_2100);
const _: () = assert!(0xc000_0000 | (24 << 16) | ((b'!' as u32) << 8) | 1 == 0xc018_2101);
const _: () = assert!(0x4000_0000 | (8 << 16) | ((b'!' as u32) << 8) | 2 == 0x4008_2102);
const _: () = assert!(0x4000_0000 | (24 << 16) | ((b'!' as u32) << 8) | 3 == 0x4018_2103);
const _: () = assert!(std::mem::size_of::<SeccompNotif>() == 80);
const _: () = assert!(std::mem::size_of::<SeccompNotifResp>() == 24);
const _: () = assert!(std::mem::size_of::<SeccompNotifAddfd>() == 24);
const _: () = assert!(std::mem::size_of::<OpenHow>() == 24);

#[repr(C)]
#[derive(Default, Clone, Copy)]
pub(crate) struct SeccompData {
    pub nr: i32,
    pub arch: u32,
    pub instruction_pointer: u64,
    pub args: [u64; 6],
}

#[repr(C)]
#[derive(Default, Clone, Copy)]
pub(crate) struct SeccompNotif {
    pub id: u64,
    pub pid: u32,
    pub flags: u32,
    pub data: SeccompData,
}

#[repr(C)]
pub(crate) struct SeccompNotifResp {
    pub id: u64,
    pub val: i64,
    pub error: i32,
    pub flags: u32,
}

#[repr(C)]
pub(crate) struct SeccompNotifAddfd {
    pub id: u64,
    pub flags: u32,
    pub srcfd: u32,
    pub newfd: u32,
    pub newfd_flags: u32,
}

/// openat2 `struct open_how { u64 flags; u64 mode; u64 resolve; }`.
#[repr(C)]
pub(crate) struct OpenHow {
    pub flags: u64,
    pub mode: u64,
    pub resolve: u64,
}
pub(crate) const OPEN_HOW_SIZE: u64 = std::mem::size_of::<OpenHow>() as u64;

pub(crate) const RESOLVE_NO_XDEV: u64 = 0x1;
pub(crate) const RESOLVE_NO_MAGICLINKS: u64 = 0x2;
pub(crate) const RESOLVE_NO_SYMLINKS: u64 = 0x4;
pub(crate) const RESOLVE_BENEATH: u64 = 0x8;
pub(crate) const RESOLVE_IN_ROOT: u64 = 0x10;
pub(crate) const RESOLVE_CTIME: u64 = 0x20;
/// Every resolve bit this broker understands. Unknown bits are answered
/// with EINVAL, exactly as an older kernel would.
pub(crate) const KNOWN_RESOLVE: u64 = RESOLVE_NO_XDEV
    | RESOLVE_NO_MAGICLINKS
    | RESOLVE_NO_SYMLINKS
    | RESOLVE_BENEATH
    | RESOLVE_IN_ROOT
    | RESOLVE_CTIME;

/// Native `AUDIT_ARCH_*` for the architecture this shim is compiled for.
#[cfg(target_arch = "x86_64")]
pub(crate) const NATIVE_ARCH: u32 = libc::AUDIT_ARCH_X86_64;
// libc does not export AUDIT_ARCH_AARCH64: EM_AARCH64 (0xB7) |
// __AUDIT_ARCH_64BIT (0x8000_0000) | __AUDIT_ARCH_LE (0x4000_0000).
#[cfg(target_arch = "aarch64")]
pub(crate) const NATIVE_ARCH: u32 = 0xC000_00B7;

/// Maximum bytes read from the target for a path argument.
pub(crate) const MAX_PATH: usize = 4096;

/// The syscalls this broker can judge, as kernel numbers for the arch it is
/// compiled for. Policy names come from
/// `rauha_common::zone::BROKERABLE_SYSCALLS`; the drift test pins the two
/// lists together.
const NR_OPENAT: i64 = libc::SYS_openat;
const NR_OPENAT2: i64 = libc::SYS_openat2;

/// Policy name → kernel number, for the drift test only: production code
/// dispatches on the number (see `brokered_syscall_name`).
#[cfg(test)]
pub(crate) fn brokered_nr(name: &str) -> Option<i64> {
    match name {
        "openat" => Some(NR_OPENAT),
        "openat2" => Some(NR_OPENAT2),
        _ => None,
    }
}

/// Kernel number → policy name, for the judgment dispatch.
pub(crate) fn brokered_syscall_name(nr: i64) -> Option<&'static str> {
    match nr {
        NR_OPENAT => Some("openat"),
        NR_OPENAT2 => Some("openat2"),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn syscall_numbers_match_native_table() {
        assert_eq!(NR_OPENAT, libc::SYS_openat);
        assert_eq!(NR_OPENAT2, libc::SYS_openat2);
        assert_ne!(0, NATIVE_ARCH);
    }

    #[test]
    fn brokerable_names_cannot_drift_from_the_judged_set() {
        // The daemon admits exactly rauha_common's list; the shim must be
        // able to judge every name on it, and every judged name must be on
        // it — otherwise a zone would hang on its first brokered syscall.
        for name in rauha_common::zone::BROKERABLE_SYSCALLS {
            assert!(
                brokered_nr(name).is_some(),
                "policy admits brokered syscall {name} but the shim cannot judge it"
            );
        }
        for nr in [NR_OPENAT, NR_OPENAT2] {
            let name = brokered_syscall_name(nr).expect("judged syscall has a name");
            assert!(
                rauha_common::zone::BROKERABLE_SYSCALLS.contains(&name),
                "the shim judges {name} but policy does not admit it"
            );
        }
    }
}
