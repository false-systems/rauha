//! Pure judgment: classifying one suspended open into a confined grant or
//! an errno-honest denial. Everything here is unit-testable without a live
//! container — the runtime never invents a decision, it only executes one
//! of these.

use super::abi::{
    KNOWN_RESOLVE, MAX_PATH, OPEN_HOW_SIZE, RESOLVE_BENEATH, RESOLVE_IN_ROOT,
    RESOLVE_NO_MAGICLINKS, RESOLVE_NO_SYMLINKS,
};

/// One classified, grantable open. `resolve` is the complete openat2
/// resolve set the broker will use: its own containment (`RESOLVE_IN_ROOT`
/// or `RESOLVE_BENEATH`) OR'd with every restriction the caller asked for —
/// never fewer than the caller asked. `cloexec`/`nonblock` mirror the
/// caller's fd flags onto the injected descriptor so the grant has the
/// semantics the workload asked for.
#[derive(Debug)]
pub(crate) struct Grant {
    pub anchored: Anchor,
    pub path: Vec<u8>,
    pub resolve: u64,
    pub cloexec: bool,
    pub nonblock: bool,
}

#[derive(Debug)]
pub(crate) enum Anchor {
    /// Absolute path: resolve inside the task's root (`/proc/<pid>/root`).
    TaskRoot,
    /// Relative path: resolve against the task's own `dirfd` (borrowed via
    /// `pidfd_getfd`) or its cwd.
    TaskDir { dirfd: i64 },
}

/// Why a call cannot be granted. Policy denials answer `EPERM`; argument
/// shapes the kernel itself would reject answer the errno the kernel would
/// have returned, so the workload sees honest failures either way.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Denial {
    pub errno: i32,
    pub reason: &'static str,
}

impl Denial {
    /// The workload asked for authority the broker does not grant.
    pub(crate) fn policy(reason: &'static str) -> Self {
        Self {
            errno: libc::EPERM,
            reason,
        }
    }

    /// Argument shape the kernel itself would reject — answer as the
    /// kernel would, not with a blanket EPERM.
    pub(crate) fn kernel(errno: i32, reason: &'static str) -> Self {
        Self { errno, reason }
    }
}

/// resolve-flags for one confined open. `no_follow` maps O_NOFOLLOW onto
/// the stricter RESOLVE_NO_SYMLINKS (which implies NO_MAGICLINKS): the
/// broker cannot distinguish a trailing symlink per-component, so it
/// refuses symlinks anywhere on the path — grant semantics stay honest.
pub(crate) fn resolve_flags(rooted: bool, no_follow: bool) -> u64 {
    let base = if rooted {
        RESOLVE_IN_ROOT
    } else {
        RESOLVE_BENEATH
    };
    base | caller_restrictions(if no_follow {
        RESOLVE_NO_SYMLINKS
    } else {
        RESOLVE_NO_MAGICLINKS
    })
}

/// Restriction bits the caller asked for, masked to what the broker
/// understands. OR-ing caller restrictions is always safe: the result can
/// only be stricter than either side. BENEATH/IN_ROOT are excluded — the
/// containment anchor is the broker's decision, made by the matrix below.
pub(crate) fn caller_restrictions(resolve: u64) -> u64 {
    resolve & KNOWN_RESOLVE & !(RESOLVE_BENEATH | RESOLVE_IN_ROOT)
}

/// Pure classification of one suspended `openat`: is it grantable, how?
pub(crate) fn classify_openat(dirfd: i64, flags: i32, path: &[u8]) -> Result<Grant, Denial> {
    check_open_flags(flags)?;
    check_path(path)?;
    let no_follow = flags & libc::O_NOFOLLOW != 0;
    let absolute = path[0] == b'/';
    Ok(Grant {
        anchored: if absolute {
            Anchor::TaskRoot
        } else {
            Anchor::TaskDir { dirfd }
        },
        path: path.to_vec(),
        resolve: resolve_flags(absolute, no_follow),
        cloexec: flags & libc::O_CLOEXEC != 0,
        nonblock: flags & libc::O_NONBLOCK != 0,
    })
}

/// Pure classification of one suspended `openat2`. `size` is the syscall's
/// size argument; `how` is the `struct open_how` read from the target.
///
/// Kernel-faithful argument validation (see openat2(2)): a size larger
/// than `sizeof(struct open_how)` answers E2BIG, smaller EINVAL, unknown
/// resolve bits EINVAL, `RESOLVE_BENEATH|RESOLVE_IN_ROOT` EINVAL, and an
/// absolute path under RESOLVE_BENEATH EXDEV.
pub(crate) fn classify_openat2(
    dirfd: i64,
    size: u64,
    how: &super::abi::OpenHow,
    path: &[u8],
) -> Result<Grant, Denial> {
    if size > OPEN_HOW_SIZE {
        return Err(Denial::kernel(libc::E2BIG, "oversized open_how"));
    }
    if size < OPEN_HOW_SIZE {
        return Err(Denial::kernel(libc::EINVAL, "undersized open_how"));
    }
    if how.resolve & !KNOWN_RESOLVE != 0 {
        return Err(Denial::kernel(libc::EINVAL, "unknown resolve flags"));
    }
    if how.resolve & (RESOLVE_BENEATH | RESOLVE_IN_ROOT) == (RESOLVE_BENEATH | RESOLVE_IN_ROOT) {
        return Err(Denial::kernel(
            libc::EINVAL,
            "RESOLVE_BENEATH and RESOLVE_IN_ROOT are mutually exclusive",
        ));
    }
    // open_how.flags is 64-bit; on 64-bit targets every high bit is an
    // unknown O_* flag the kernel would reject.
    if how.flags >> 32 != 0 {
        return Err(Denial::kernel(libc::EINVAL, "unknown high flag bits"));
    }
    let flags = how.flags as i32;
    check_open_flags(flags)?;
    check_path(path)?;
    let absolute = path[0] == b'/';
    let beneath = how.resolve & RESOLVE_BENEATH != 0;
    let in_root = how.resolve & RESOLVE_IN_ROOT != 0;
    let restrictions = caller_restrictions(how.resolve)
        | if flags & libc::O_NOFOLLOW != 0 {
            RESOLVE_NO_SYMLINKS
        } else {
            RESOLVE_NO_MAGICLINKS
        };
    if absolute {
        if beneath {
            // Exactly what the kernel answers for an absolute path
            // resolved with RESOLVE_BENEATH.
            return Err(Denial::kernel(
                libc::EXDEV,
                "absolute path under RESOLVE_BENEATH",
            ));
        }
        Ok(Grant {
            anchored: Anchor::TaskRoot,
            path: path.to_vec(),
            // in_root or unset: the broker confines to the task's root
            // either way.
            resolve: RESOLVE_IN_ROOT | restrictions,
            cloexec: flags & libc::O_CLOEXEC != 0,
            nonblock: flags & libc::O_NONBLOCK != 0,
        })
    } else {
        // Relative: anchored at the task's own dirfd. A caller that asked
        // for RESOLVE_IN_ROOT gets it — ".." clamps at the dirfd's subtree
        // root, which cannot leave the container; otherwise BENEATH.
        let containment = if in_root {
            RESOLVE_IN_ROOT
        } else {
            RESOLVE_BENEATH
        };
        Ok(Grant {
            anchored: Anchor::TaskDir { dirfd },
            path: path.to_vec(),
            resolve: containment | restrictions,
            cloexec: flags & libc::O_CLOEXEC != 0,
            nonblock: flags & libc::O_NONBLOCK != 0,
        })
    }
}

/// Flags shared by openat/openat2. The broker grants read-only opens with
/// no side effects and no semantics it cannot honour on the injected fd:
///
/// - mirrored: `O_CLOEXEC` (via the ADDFD newfd_flags), `O_NONBLOCK`
///   (a plain fd flag), `O_NOFOLLOW` (escalated to the stricter
///   RESOLVE_NO_SYMLINKS), `O_DIRECTORY`, `O_NOCTTY` (never a controlling
///   tty — the broker opens with O_NOCTTY itself);
/// - denied: write modes, create/truncate/tmpfile side effects, `O_PATH`
///   (not a readable handle), `O_DIRECT` (alignment semantics the broker's
///   own open cannot faithfully reproduce).
fn check_open_flags(flags: i32) -> Result<(), Denial> {
    if flags & libc::O_ACCMODE != libc::O_RDONLY {
        return Err(Denial::policy("not read-only"));
    }
    // O_TMPFILE is __O_TMPFILE | O_DIRECTORY — a bit mask, not a single
    // flag. Testing any bit would deny every legitimate O_DIRECTORY open
    // (v0 bug, caught by the directory-grant test); the kernel's own
    // convention is full-mask equality.
    if flags & libc::O_TMPFILE == libc::O_TMPFILE {
        return Err(Denial::policy("O_TMPFILE"));
    }
    for (flag, reason) in [
        (libc::O_CREAT, "O_CREAT"),
        (libc::O_TRUNC, "O_TRUNC"),
        (libc::O_PATH, "O_PATH"),
        (libc::O_DIRECT, "O_DIRECT"),
    ] {
        if flags & flag != 0 {
            return Err(Denial::policy(reason));
        }
    }
    Ok(())
}

/// Path shapes, answered with the errno the kernel itself would return.
fn check_path(path: &[u8]) -> Result<(), Denial> {
    if path.is_empty() {
        return Err(Denial::kernel(libc::ENOENT, "empty path"));
    }
    if path.len() >= MAX_PATH {
        return Err(Denial::kernel(libc::ENAMETOOLONG, "path too long"));
    }
    // Interior NUL is caught by CString later; report it here uniformly.
    if path.contains(&0) {
        return Err(Denial::kernel(libc::EINVAL, "NUL in path"));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::super::abi::{OpenHow, RESOLVE_CTIME, RESOLVE_NO_XDEV};
    use super::*;

    fn grant_openat(dirfd: i64, flags: i32, path: &[u8]) -> Grant {
        classify_openat(dirfd, flags, path).expect("grantable")
    }

    fn deny_openat(flags: i32, path: &[u8]) -> Denial {
        classify_openat(3, flags, path).expect_err("denied")
    }

    fn how(flags: i64, resolve: u64) -> OpenHow {
        OpenHow {
            flags: flags as u64,
            mode: 0,
            resolve,
        }
    }

    #[test]
    fn grants_at_fdcwd_as_beneath() {
        // AT_FDCWD is resolved against the task's cwd by the judge —
        // classification only needs to keep it a TaskDir grant.
        match grant_openat(libc::AT_FDCWD as i64, libc::O_RDONLY, b"rel") {
            Grant {
                anchored: Anchor::TaskDir { dirfd },
                ..
            } => assert_eq!(dirfd, libc::AT_FDCWD as i64),
            other => panic!("relative path must anchor at the task's dirfd: {other:?}"),
        }
    }

    #[test]
    fn grants_absolute_read_only_openat() {
        match grant_openat(3, libc::O_RDONLY, b"/etc/hostname") {
            Grant {
                anchored: Anchor::TaskRoot,
                path,
                resolve,
                ..
            } => {
                assert_eq!(path, b"/etc/hostname");
                assert_eq!(resolve, RESOLVE_IN_ROOT | RESOLVE_NO_MAGICLINKS);
            }
            other => panic!("absolute path must resolve in-root: {other:?}"),
        }
    }

    #[test]
    fn grants_relative_paths_against_the_tasks_own_dirfd() {
        match grant_openat(3, libc::O_RDONLY, b"src/lib.rs") {
            Grant {
                anchored: Anchor::TaskDir { .. },
                resolve,
                ..
            } => assert_eq!(resolve, RESOLVE_BENEATH | RESOLVE_NO_MAGICLINKS),
            other => panic!("relative path must resolve beneath the dirfd: {other:?}"),
        }
    }

    #[test]
    fn openat_denials_are_errno_honest() {
        // Policy denials answer EPERM.
        assert_eq!(
            deny_openat(libc::O_WRONLY, b"/x"),
            Denial::policy("not read-only")
        );
        assert_eq!(
            deny_openat(libc::O_RDONLY | libc::O_CREAT, b"/x"),
            Denial::policy("O_CREAT")
        );
        assert_eq!(
            deny_openat(libc::O_RDONLY | libc::O_TRUNC, b"/x"),
            Denial::policy("O_TRUNC")
        );
        // Full-mask O_TMPFILE: __O_TMPFILE | O_DIRECTORY. The O_DIRECTORY
        // bit alone must NOT trip it.
        assert_eq!(
            deny_openat(libc::O_RDONLY | libc::O_TMPFILE, b"/x"),
            Denial::policy("O_TMPFILE")
        );
        assert_eq!(deny_openat(libc::O_PATH, b"/x"), Denial::policy("O_PATH"));
        assert_eq!(
            deny_openat(libc::O_RDONLY | libc::O_DIRECT, b"/x"),
            Denial::policy("O_DIRECT")
        );
        // Argument shapes answer the kernel's own errno.
        assert_eq!(
            deny_openat(libc::O_RDONLY, b""),
            Denial::kernel(libc::ENOENT, "empty path")
        );
        assert_eq!(
            deny_openat(libc::O_RDONLY, &[b'x'; MAX_PATH]),
            Denial::kernel(libc::ENAMETOOLONG, "path too long")
        );
        assert_eq!(
            deny_openat(libc::O_RDONLY, b"we\0ird"),
            Denial::kernel(libc::EINVAL, "NUL in path")
        );
    }

    #[test]
    fn mirrors_fd_flags_the_broker_can_honour() {
        let grant = grant_openat(
            3,
            libc::O_RDONLY | libc::O_CLOEXEC | libc::O_NONBLOCK | libc::O_NOCTTY,
            b"/etc/hostname",
        );
        assert!(grant.cloexec, "O_CLOEXEC must reach the injected fd");
        assert!(grant.nonblock, "O_NONBLOCK must reach the broker's open");
    }

    #[test]
    fn read_only_directory_opens_are_grantable() {
        // A directory fd is confined exactly like a file fd; the workload
        // may enumerate but not escape.
        let grant = grant_openat(3, libc::O_RDONLY | libc::O_DIRECTORY, b"/etc");
        assert!(matches!(grant.anchored, Anchor::TaskRoot));
    }

    #[test]
    fn honors_o_nofollow_by_requesting_no_symlinks() {
        let Grant { resolve, .. } =
            grant_openat(3, libc::O_RDONLY | libc::O_NOFOLLOW, b"/etc/passwd");
        assert_eq!(resolve, RESOLVE_IN_ROOT | RESOLVE_NO_SYMLINKS);
    }

    #[test]
    fn path_may_be_non_utf8() {
        // Valid Linux path bytes that are not UTF-8 must classify, not deny.
        let Grant { path, .. } = grant_openat(3, libc::O_RDONLY, b"/tmp/\xff\xfe");
        assert_eq!(path, b"/tmp/\xff\xfe");
    }

    #[test]
    fn caller_restrictions_never_widen_containment() {
        // BENEATH/IN_ROOT are decided by the matrix, not copied from the
        // caller; every other known bit is a pure restriction.
        assert_eq!(caller_restrictions(RESOLVE_IN_ROOT), 0);
        assert_eq!(caller_restrictions(RESOLVE_BENEATH), 0);
        assert_eq!(
            caller_restrictions(RESOLVE_NO_XDEV | RESOLVE_CTIME | (1 << 10)),
            RESOLVE_NO_XDEV | RESOLVE_CTIME
        );
    }

    #[test]
    fn resolve_flags_combine_confinement_with_follow_policy() {
        assert_eq!(
            resolve_flags(true, false),
            RESOLVE_IN_ROOT | RESOLVE_NO_MAGICLINKS
        );
        assert_eq!(
            resolve_flags(false, true),
            RESOLVE_BENEATH | RESOLVE_NO_SYMLINKS
        );
    }

    // ---- openat2 classification ----

    #[test]
    fn openat2_grants_absolute_with_caller_restrictions_merged() {
        let how = how(libc::O_RDONLY as i64, RESOLVE_NO_XDEV);
        match classify_openat2(3, OPEN_HOW_SIZE, &how, b"/etc/hostname").expect("grantable") {
            Grant {
                anchored: Anchor::TaskRoot,
                resolve,
                ..
            } => assert_eq!(
                resolve,
                RESOLVE_IN_ROOT | RESOLVE_NO_MAGICLINKS | RESOLVE_NO_XDEV
            ),
            other => panic!("{other:?}"),
        }
    }

    #[test]
    fn openat2_grants_relative_beneath_the_dirfd() {
        let how = how(libc::O_RDONLY as i64, 0);
        match classify_openat2(3, OPEN_HOW_SIZE, &how, b"src/lib.rs").expect("grantable") {
            Grant {
                anchored: Anchor::TaskDir { dirfd },
                resolve,
                ..
            } => {
                assert_eq!(dirfd, 3);
                assert_eq!(resolve, RESOLVE_BENEATH | RESOLVE_NO_MAGICLINKS);
            }
            other => panic!("{other:?}"),
        }
    }

    #[test]
    fn openat2_relative_in_root_stays_anchored_at_the_dirfd() {
        // Caller asked for RESOLVE_IN_ROOT with a relative path: ".."
        // clamps at the dirfd subtree — still confined, still anchored at
        // the caller's own directory context.
        let how = how(libc::O_RDONLY as i64, RESOLVE_IN_ROOT);
        let Grant {
            anchored: Anchor::TaskDir { .. },
            resolve,
            ..
        } = classify_openat2(3, OPEN_HOW_SIZE, &how, b"../etc/hostname").expect("grantable")
        else {
            panic!("relative path must anchor at the task's dirfd")
        };
        assert_eq!(resolve, RESOLVE_IN_ROOT | RESOLVE_NO_MAGICLINKS);
    }

    #[test]
    fn openat2_rejects_impossible_argument_shapes_like_the_kernel() {
        let ok = how(libc::O_RDONLY as i64, 0);
        // Size: larger answers E2BIG, smaller EINVAL (openat2(2)).
        assert_eq!(
            classify_openat2(3, OPEN_HOW_SIZE + 8, &ok, b"/x").unwrap_err(),
            Denial::kernel(libc::E2BIG, "oversized open_how")
        );
        assert_eq!(
            classify_openat2(3, OPEN_HOW_SIZE - 8, &ok, b"/x").unwrap_err(),
            Denial::kernel(libc::EINVAL, "undersized open_how")
        );
        // Unknown resolve bits: EINVAL, as an older kernel would.
        let unknown = how(libc::O_RDONLY as i64, 1 << 10);
        assert_eq!(
            classify_openat2(3, OPEN_HOW_SIZE, &unknown, b"/x").unwrap_err(),
            Denial::kernel(libc::EINVAL, "unknown resolve flags")
        );
        // BENEATH and IN_ROOT are mutually exclusive.
        let both = how(libc::O_RDONLY as i64, RESOLVE_BENEATH | RESOLVE_IN_ROOT);
        assert!(
            classify_openat2(3, OPEN_HOW_SIZE, &both, b"/x")
                .unwrap_err()
                .errno
                == libc::EINVAL
        );
        // Absolute path under RESOLVE_BENEATH: EXDEV, exactly as the kernel.
        let beneath = how(libc::O_RDONLY as i64, RESOLVE_BENEATH);
        assert_eq!(
            classify_openat2(3, OPEN_HOW_SIZE, &beneath, b"/etc/hostname").unwrap_err(),
            Denial::kernel(libc::EXDEV, "absolute path under RESOLVE_BENEATH")
        );
        // High flag bits are unknown O_* flags on 64-bit: EINVAL.
        let high = how((1i64 << 40) | libc::O_RDONLY as i64, 0);
        assert_eq!(
            classify_openat2(3, OPEN_HOW_SIZE, &high, b"/x").unwrap_err(),
            Denial::kernel(libc::EINVAL, "unknown high flag bits")
        );
        // Same open-flag policy as openat.
        let write = how(libc::O_WRONLY as i64, 0);
        assert_eq!(
            classify_openat2(3, OPEN_HOW_SIZE, &write, b"/x").unwrap_err(),
            Denial::policy("not read-only")
        );
        // O_NOFOLLOW escalates to NO_SYMLINKS, like the openat path.
        let nofollow = how((libc::O_RDONLY | libc::O_NOFOLLOW) as i64, 0);
        let Grant { resolve, .. } =
            classify_openat2(3, OPEN_HOW_SIZE, &nofollow, b"rel").expect("grantable");
        assert_eq!(resolve, RESOLVE_BENEATH | RESOLVE_NO_SYMLINKS);
    }

    #[test]
    fn openat2_mirrors_fd_flags_too() {
        let how = how((libc::O_RDONLY | libc::O_CLOEXEC) as i64, 0);
        let Grant { cloexec, .. } =
            classify_openat2(3, OPEN_HOW_SIZE, &how, b"/x").expect("grantable");
        assert!(cloexec);
    }
}
