#![cfg(target_os = "linux")]

//! Seccomp-notify broker: the Capsicum-shaped primitive.
//!
//! When a policy marks syscalls as brokered (`[syscalls] broker = [...]`,
//! validated to [`rauha_common::zone::BROKERABLE_SYSCALLS`]), the OCI
//! seccomp profile emits `SCMP_ACT_NOTIFY` with this module's socket as
//! `listener_path`. crun ships the kernel notify fd here; the workload's
//! brokered syscalls then suspend in the kernel and are judged by the shim:
//!
//! - denied calls are answered with an honest errno (`EPERM` for policy
//!   denials, the errno the kernel itself would have returned for argument
//!   shapes) without ever executing;
//! - granted `openat`/`openat2` calls are satisfied by the *broker* opening
//!   the file read-only, confined, and injecting it with
//!   `SECCOMP_IOCTL_NOTIF_ADDFD`.
//!
//! The workload never exercises ambient authority for brokered calls — it
//! holds only the handles it was given.
//!
//! ## Security model of the judgment path
//!
//! seccomp-notify brokers are attacked through the races the kernel
//! documentation warns about (see `Documentation/userspace-api/seccomp_filter.rst`,
//! "Kernel-supplied notification IDs"). The sequence here is:
//!
//! 1. `pidfd_open(pid)` — pins the exact task, immune to pid reuse.
//! 2. Open `/proc/<pid>/mem` (path read) and `/proc/<pid>/root` (O_PATH).
//! 3. `SECCOMP_IOCTL_NOTIF_ID_VALID` — prove the suspended task is still
//!    alive *after* the /proc fds were opened. If the notification is gone,
//!    the fds are dropped unused: they may belong to a pid-reusing
//!    impostor and must not be acted on.
//! 4. Only then read the arguments and resolve the open.
//!
//! If the notification is still valid at (3), the task was alive at that
//! instant, so the pid could not have been reused since (1)/(2) — the fds
//! belong to the suspended task. If the task dies between (3) and the
//! response, `ADDFD`/`SEND` fail with ENOENT and nothing is injected.
//!
//! The [`PinCache`] holds the (pidfd, mem, root) triple per task id across
//! notifications. This is race-equivalent to the cold path: the pidfd pins
//! the task struct for the cache's lifetime, so a reused tid cannot
//! redirect cached fds to an impostor, and entries are evicted the moment
//! `poll(pidfd)` reports the task exited. The cached root pins the task's
//! root *as first seen*; a later chroot by the task changes neither the
//! cached root nor the containment (still a subtree of the container
//! rootfs — the zone boundary).
//!
//! Containment is kernel-enforced, not string-checked: the broker resolves
//! paths with `openat2` — absolute paths with `RESOLVE_IN_ROOT` relative to
//! the task's root (`/proc/<pid>/root`), relative paths with
//! `RESOLVE_BENEATH` relative to the task's own `dirfd` (borrowed via
//! `pidfd_getfd`) or its cwd. For `openat2` calls the caller's own
//! `RESOLVE_*` restrictions are OR'd in — the broker is never less strict
//! than the workload asked. Symlinks, `..`, and magic links cannot escape
//! the container by construction. (Remaining v0 exposure: a sibling thread
//! of the target can `chroot`/`chdir` the shared fs between suspension and
//! judgment; the open is still confined to some subtree of the container
//! rootfs, which is the zone boundary.)
//!
//! The judgment loop is single-threaded on purpose. Notifications are
//! received serially from one ioctl, and judging each takes a handful of
//! syscalls — serial judgment is also a rate limiter: a hostile zone
//! cannot widen its judgment surface by forging parallel brokered calls.
//!
//! Every decision is recorded as one JSON line in the container's
//! `broker.log` (final outcome only, sequence-numbered) — the seed for
//! evidence projection — and as a tracing log line.
//!
//! ABI verified against linux/seccomp.h: `seccomp_notif` embeds
//! `seccomp_data` (80 bytes total on 64-bit), ioctl numbers computed from
//! _IOWR('!', ...) / _IOW('!', ...) and cross-checked on the target kernel.

use std::collections::HashMap;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::Path;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::{bail, Context, Result};

// _IOWR('!', 0, struct seccomp_notif) — 80 bytes (id + pid + flags + data)
const SECCOMP_IOCTL_NOTIF_RECV: libc::c_ulong = 0xc050_2100;
// _IOWR('!', 1, struct seccomp_notif_resp) — 24 bytes
const SECCOMP_IOCTL_NOTIF_SEND: libc::c_ulong = 0xc018_2101;
// _IOW('!', 2, __u64) — 8 bytes (NB: _IOW, not _IOWR — linux/seccomp.h)
const SECCOMP_IOCTL_NOTIF_ID_VALID: libc::c_ulong = 0x4008_2102;
// _IOW('!', 3, struct seccomp_notif_addfd) — 24 bytes
const SECCOMP_IOCTL_NOTIF_ADDFD: libc::c_ulong = 0x4018_2103;

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
struct SeccompData {
    nr: i32,
    arch: u32,
    instruction_pointer: u64,
    args: [u64; 6],
}

#[repr(C)]
#[derive(Default, Clone, Copy)]
struct SeccompNotif {
    id: u64,
    pid: u32,
    flags: u32,
    data: SeccompData,
}

#[repr(C)]
struct SeccompNotifResp {
    id: u64,
    val: i64,
    error: i32,
    flags: u32,
}

#[repr(C)]
struct SeccompNotifAddfd {
    id: u64,
    flags: u32,
    srcfd: u32,
    newfd: u32,
    newfd_flags: u32,
}

/// Maximum bytes read from the target for a path argument.
const MAX_PATH: usize = 4096;

/// The syscalls this broker can judge, as kernel numbers for the arch it is
/// compiled for. Policy names come from
/// `rauha_common::zone::BROKERABLE_SYSCALLS`; the drift test pins the two
/// lists together.
const NR_OPENAT: i64 = libc::SYS_openat;
const NR_OPENAT2: i64 = libc::SYS_openat2;

/// Policy name → kernel number, for the drift test only: production code
/// dispatches on the number (see `brokered_syscall_name`).
#[cfg(test)]
fn brokered_nr(name: &str) -> Option<i64> {
    match name {
        "openat" => Some(NR_OPENAT),
        "openat2" => Some(NR_OPENAT2),
        _ => None,
    }
}

fn brokered_syscall_name(nr: i64) -> Option<&'static str> {
    match nr {
        NR_OPENAT => Some("openat"),
        NR_OPENAT2 => Some("openat2"),
        _ => None,
    }
}

/// Native `AUDIT_ARCH_*` for the architecture this shim is compiled for.
#[cfg(target_arch = "x86_64")]
const NATIVE_ARCH: u32 = libc::AUDIT_ARCH_X86_64;
// libc does not export AUDIT_ARCH_AARCH64: EM_AARCH64 (0xB7) |
// __AUDIT_ARCH_64BIT (0x8000_0000) | __AUDIT_ARCH_LE (0x4000_0000).
#[cfg(target_arch = "aarch64")]
const NATIVE_ARCH: u32 = 0xC000_00B7;

/// Default task-pin cache capacity when the daemon passes no override
/// (`RAUHA_BROKER_CACHE_MAX`, from `rauha.toml` `[broker] cache_max_tasks`).
const DEFAULT_CACHE_MAX_TASKS: usize = 512;

/// Remove the listener socket however `serve` exits.
struct SocketGuard<'a>(&'a Path);
impl Drop for SocketGuard<'_> {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(self.0);
    }
}

/// Serve the seccomp listener socket: accept one connection (crun's
/// listener helper), receive the notify fd, and judge notifications until
/// the fd closes. Runs on its own thread; the container blocks while each
/// decision is made, so the loop must stay fast and panic-free — a panic
/// here would leave every brokered syscall suspended forever, which is a
/// zone deadlock, not a degraded mode. Every decision is appended to
/// `decision_log_path` (one JSON line per judged call).
pub fn serve(listener_path: &Path, decision_log_path: &Path) -> Result<()> {
    let _ = std::fs::remove_file(listener_path);
    let listener = UnixListener::bind(listener_path)
        .with_context(|| format!("bind seccomp listener {}", listener_path.display()))?;
    let _guard = SocketGuard(listener_path);
    // Explicit, not umask-dependent: only the shim (root) connects here,
    // and nobody else should ever be able to hand us a notify fd.
    let sock_c = std::ffi::CString::new(listener_path.as_os_str().as_encoded_bytes())
        .with_context(|| format!("listener path {} not a C string", listener_path.display()))?;
    unsafe {
        libc::chmod(sock_c.as_ptr(), 0o600);
    }

    // crun's helper connects and sends the fd; one connection per container.
    let (stream, _) = listener.accept().context("accept seccomp listener")?;
    let notify_fd = recv_fd(&stream).context("receive seccomp notify fd")?;

    let mut log = DecisionLog::open(decision_log_path);
    let mut cache = PinCache::new(cache_max_tasks());
    judge_loop(notify_fd, &mut cache, &mut log)
}

/// Task-pin cache capacity: the daemon passes `[broker] cache_max_tasks`
/// from rauha.toml as `RAUHA_BROKER_CACHE_MAX`. `0` disables caching.
fn cache_max_tasks() -> usize {
    std::env::var("RAUHA_BROKER_CACHE_MAX")
        .ok()
        .and_then(|value| value.parse().ok())
        .unwrap_or(DEFAULT_CACHE_MAX_TASKS)
}

/// Receive one SCM_RIGHTS descriptor from the stream.
fn recv_fd(stream: &UnixStream) -> Result<OwnedFd> {
    let mut buf = [0u8; 1];
    let mut cmsg_space = [0u8; unsafe { libc::CMSG_SPACE(1) } as usize];
    let mut msg: libc::msghdr = unsafe { std::mem::zeroed() };
    let mut iov = libc::iovec {
        iov_base: buf.as_mut_ptr().cast::<libc::c_void>(),
        iov_len: buf.len(),
    };
    msg.msg_iov = &mut iov;
    msg.msg_iovlen = 1;
    msg.msg_control = cmsg_space.as_mut_ptr().cast::<libc::c_void>();
    msg.msg_controllen = cmsg_space.len();

    let n = unsafe { libc::recvmsg(stream.as_raw_fd(), &mut msg, 0) };
    if n < 0 {
        bail!(
            "recvmsg on seccomp listener: {}",
            std::io::Error::last_os_error()
        );
    }
    // Exactly one int-sized descriptor is expected; anything else is a
    // malformed hand-off. Excess fds received in a cmsg are already
    // installed by the kernel — close them before failing loudly.
    let cmsg = match unsafe { libc::CMSG_FIRSTHDR(&msg).as_ref() } {
        Some(h) => h,
        None => bail!("no control message on seccomp listener"),
    };
    let bytes = cmsg.cmsg_len as usize - unsafe { libc::CMSG_LEN(0) } as usize;
    if cmsg.cmsg_level != libc::SOL_SOCKET || cmsg.cmsg_type != libc::SCM_RIGHTS {
        bail!("unexpected cmsg on seccomp listener");
    }
    if !bytes.is_multiple_of(std::mem::size_of::<libc::c_int>()) {
        bail!("malformed SCM_RIGHTS cmsg on seccomp listener");
    }
    let fds = unsafe {
        std::slice::from_raw_parts(libc::CMSG_DATA(cmsg) as *const libc::c_int, bytes / 4)
    };
    if fds.len() != 1 {
        for fd in fds {
            // fds < 0 cannot appear in a well-formed SCM_RIGHTS cmsg; the
            // kernel only installs what the sender duplicated.
            unsafe { libc::close(*fd) };
        }
        bail!(
            "expected exactly one fd from the seccomp listener, got {}",
            fds.len()
        );
    }
    if fds[0] < 0 {
        bail!("invalid fd from seccomp listener");
    }
    Ok(unsafe { OwnedFd::from_raw_fd(fds[0]) })
}

/// The judgment loop: receive one notification, decide, respond. Repeat
/// until the kernel closes the fd (container exited). Nothing inside the
/// loop is fatal except RECV terminal errors — a broker thread that dies
/// mid-container leaves every later brokered syscall suspended forever,
/// which is a zone deadlock, not a degraded mode.
fn judge_loop(notify_fd: OwnedFd, cache: &mut PinCache, log: &mut DecisionLog) -> Result<()> {
    let fd = notify_fd.as_raw_fd();
    loop {
        let mut notif = SeccompNotif::default();
        let n = unsafe {
            libc::ioctl(
                fd,
                SECCOMP_IOCTL_NOTIF_RECV,
                &mut notif as *mut SeccompNotif,
            )
        };
        if n != 0 {
            let err = std::io::Error::last_os_error();
            match err.raw_os_error() {
                Some(libc::ENOTTY) => {
                    bail!("seccomp notify not supported by this kernel")
                }
                Some(libc::EINTR) => continue,
                // The container exited and the listener has nothing left.
                Some(libc::ENOENT) | Some(libc::EBADF) | Some(libc::ESHUTDOWN) => return Ok(()),
                // crun treats any other RECV error as end-of-notifications;
                // a dead container must not spam the log.
                _ => {
                    tracing::info!("broker: RECV ended ({err})");
                    return Ok(());
                }
            }
        }

        // The judge path must never unwind: a panic would suspend every
        // brokered syscall of the zone forever. Fall back to EPERM instead.
        let judged =
            std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| judge(fd, &notif, cache)))
                .unwrap_or_else(|panic| {
                    let reason = panic
                        .downcast_ref::<&str>()
                        .map(|s| (*s).to_string())
                        .or_else(|| panic.downcast_ref::<String>().cloned())
                        .unwrap_or_else(|| "unknown panic".into());
                    tracing::error!(id = notif.id, %reason, "broker: judge panicked — denying");
                    Judged::panic(&reason)
                });
        // respond() records the decision and never fails the loop: a
        // transient SEND error is survivable, a dead broker is not.
        respond(fd, notif.id, judged, log);
    }
}

/// One classified, grantable open. `resolve` is the complete openat2
/// resolve set the broker will use: its own containment (`RESOLVE_IN_ROOT`
/// or `RESOLVE_BENEATH`) OR'd with every restriction the caller asked for —
/// never fewer than the caller asked.
#[derive(Debug)]
struct Grant {
    anchored: Anchor,
    path: Vec<u8>,
    resolve: u64,
}

#[derive(Debug)]
enum Anchor {
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
struct Denial {
    errno: i32,
    reason: &'static str,
}

impl Denial {
    /// The workload asked for authority the broker does not grant.
    fn policy(reason: &'static str) -> Self {
        Self {
            errno: libc::EPERM,
            reason,
        }
    }

    /// Argument shape the kernel itself would reject — answer as the
    /// kernel would, not with a blanket EPERM.
    fn kernel(errno: i32, reason: &'static str) -> Self {
        Self { errno, reason }
    }
}

/// openat2 { flags, mode, resolve }.
#[repr(C)]
struct OpenHow {
    flags: u64,
    mode: u64,
    resolve: u64,
}
const OPEN_HOW_SIZE: u64 = std::mem::size_of::<OpenHow>() as u64;
const RESOLVE_NO_XDEV: u64 = 0x1;
const RESOLVE_NO_MAGICLINKS: u64 = 0x2;
const RESOLVE_NO_SYMLINKS: u64 = 0x4;
const RESOLVE_BENEATH: u64 = 0x8;
const RESOLVE_IN_ROOT: u64 = 0x10;
const RESOLVE_CTIME: u64 = 0x20;
/// Every resolve bit this broker understands. Unknown bits are answered
/// with EINVAL, exactly as an older kernel would.
const KNOWN_RESOLVE: u64 = RESOLVE_NO_XDEV
    | RESOLVE_NO_MAGICLINKS
    | RESOLVE_NO_SYMLINKS
    | RESOLVE_BENEATH
    | RESOLVE_IN_ROOT
    | RESOLVE_CTIME;

/// resolve-flags for one confined open. `no_follow` maps O_NOFOLLOW onto
/// the stricter RESOLVE_NO_SYMLINKS (which implies NO_MAGICLINKS): the
/// broker cannot distinguish a trailing symlink per-component, so it
/// refuses symlinks anywhere on the path — grant semantics stay honest.
fn resolve_flags(rooted: bool, no_follow: bool) -> u64 {
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
/// only be stricter than either side.
fn caller_restrictions(resolve: u64) -> u64 {
    resolve & KNOWN_RESOLVE & !(RESOLVE_BENEATH | RESOLVE_IN_ROOT)
}

/// Pure classification of one suspended `openat`: is it grantable, how?
/// Unit-testable without a live container.
fn classify_openat(dirfd: i64, flags: i32, path: &[u8]) -> Result<Grant, Denial> {
    check_open_flags(flags)?;
    check_path(path)?;
    let no_follow = flags & libc::O_NOFOLLOW != 0;
    if path[0] == b'/' {
        Ok(Grant {
            anchored: Anchor::TaskRoot,
            path: path.to_vec(),
            resolve: resolve_flags(true, no_follow),
        })
    } else {
        Ok(Grant {
            anchored: Anchor::TaskDir { dirfd },
            path: path.to_vec(),
            resolve: resolve_flags(false, no_follow),
        })
    }
}

/// Pure classification of one suspended `openat2`. `size` is the syscall's
/// size argument; `how` is the `struct open_how` read from the target.
///
/// Kernel-faithful argument validation (see openat2(2)): a size larger
/// than `sizeof(struct open_how)` answers E2BIG, smaller EINVAL, unknown
/// resolve bits EINVAL, `RESOLVE_BENEATH|RESOLVE_IN_ROOT` EINVAL, and an
/// absolute path under RESOLVE_BENEATH EXDEV.
fn classify_openat2(dirfd: i64, size: u64, how: &OpenHow, path: &[u8]) -> Result<Grant, Denial> {
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
    check_open_flags(how.flags as i32)?;
    check_path(path)?;
    let absolute = path[0] == b'/';
    let beneath = how.resolve & RESOLVE_BENEATH != 0;
    let in_root = how.resolve & RESOLVE_IN_ROOT != 0;
    let restrictions = caller_restrictions(how.resolve)
        | if how.flags as i32 & libc::O_NOFOLLOW != 0 {
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
        })
    }
}

/// Flags shared by openat/openat2: the broker only grants read-only opens
/// with no side effects and no semantics it cannot honour.
fn check_open_flags(flags: i32) -> Result<(), Denial> {
    if flags & libc::O_ACCMODE != libc::O_RDONLY {
        return Err(Denial::policy("not read-only"));
    }
    for (flag, reason) in [
        (libc::O_CREAT, "O_CREAT"),
        (libc::O_TRUNC, "O_TRUNC"),
        (libc::O_TMPFILE, "O_TMPFILE"),
        (libc::O_PATH, "O_PATH"),
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

/// What the judge decided, plus the context the decision log needs.
struct Judged {
    syscall: &'static str,
    tid: u32,
    path: Vec<u8>,
    decision: Decision,
}

impl Judged {
    fn panic(reason: &str) -> Self {
        Self {
            syscall: "unknown",
            tid: 0,
            path: Vec::new(),
            decision: Decision::Deny {
                errno: libc::EPERM,
                reason: format!("judge panicked: {reason}"),
            },
        }
    }
}

enum Decision {
    Deny { errno: i32, reason: String },
    InjectFd(std::fs::File),
}

impl Decision {
    fn deny(errno: i32, reason: impl Into<String>) -> Self {
        Decision::Deny {
            errno,
            reason: reason.into(),
        }
    }
}

/// Judge one notification: pin the task, validate the notification is
/// still live, then resolve the open on the workload's behalf.
fn judge(fd: libc::c_int, notif: &SeccompNotif, cache: &mut PinCache) -> Judged {
    let tid = notif.pid;
    let syscall = match brokered_syscall_name(notif.data.nr as i64) {
        Some(name) => name,
        None => {
            // Policy and shim disagree — the daemon only admits
            // BROKERABLE_SYSCALLS. Deny, loudly.
            tracing::error!(
                nr = notif.data.nr,
                "broker: syscall not brokerable (policy/shim mismatch) — denying"
            );
            return Judged {
                syscall: "unknown",
                tid,
                path: Vec::new(),
                decision: Decision::deny(libc::EPERM, "not brokerable (policy/shim mismatch)"),
            };
        }
    };
    if notif.data.arch != NATIVE_ARCH {
        return Judged {
            syscall,
            tid,
            path: Vec::new(),
            decision: Decision::deny(libc::EPERM, "non-native arch"),
        };
    }

    // 1-3 of the race protocol (see module docs), with the pin cache
    // shortening the cold path. for_task opens the /proc objects, then
    // id_valid proves the notification is still live afterwards.
    let pins = match cache.for_task(tid) {
        Ok(pins) => pins,
        Err(errno) => {
            let error = std::io::Error::from_raw_os_error(errno);
            tracing::info!(tid, "broker: denied (task pins: {error})");
            return Judged {
                syscall,
                tid,
                path: Vec::new(),
                decision: Decision::deny(errno, "task pins"),
            };
        }
    };
    if let Err(e) = id_valid(fd, notif.id) {
        tracing::info!(id = notif.id, errno = %e, "broker: notification expired — denying");
        // The syscall must still be answered: an unanswered notification
        // suspends the task forever. For a truly dead notification SEND
        // just returns ENOENT.
        return Judged {
            syscall,
            tid,
            path: Vec::new(),
            decision: Decision::deny(libc::ESRCH, "notification expired"),
        };
    }

    // 4. Safe to read the target's memory and classify.
    let path_ptr = notif.data.args[1];
    let dirfd = notif.data.args[0] as i64;
    let path_bytes = match read_path(&pins.mem, path_ptr) {
        Some(p) => p,
        None => {
            tracing::warn!(tid, "broker: unreadable path — denying");
            return Judged {
                syscall,
                tid,
                path: Vec::new(),
                decision: Decision::deny(libc::EFAULT, "unreadable path"),
            };
        }
    };
    let grant = match syscall {
        "openat" => classify_openat(dirfd, notif.data.args[2] as i32, &path_bytes),
        "openat2" => {
            let how = match read_open_how(&pins.mem, notif.data.args[2]) {
                Some(how) => how,
                None => {
                    tracing::warn!(tid, "broker: unreadable open_how — denying");
                    return Judged {
                        syscall,
                        tid,
                        path: path_bytes,
                        decision: Decision::deny(libc::EFAULT, "unreadable open_how"),
                    };
                }
            };
            classify_openat2(dirfd, notif.data.args[3], &how, &path_bytes)
        }
        // brokered_syscall_name only returns names with a judge above.
        _ => unreachable!("unhandled brokerable syscall"),
    };
    match grant {
        Ok(grant) => open_for_target(&pins, tid, grant, syscall, path_bytes),
        Err(Denial { errno, reason }) => {
            tracing::info!(tid, reason, "broker: denied");
            Judged {
                syscall,
                tid,
                path: path_bytes,
                decision: Decision::deny(errno, reason),
            }
        }
    }
}

/// Perform the confined open for a granted call and wrap the result.
fn open_for_target(
    pins: &TaskPins,
    tid: u32,
    grant: Grant,
    syscall: &'static str,
    path: Vec<u8>,
) -> Judged {
    // Resolve relative paths against the task's own directory context —
    // never the container root, which would silently answer a different
    // question than the workload asked.
    //
    // The base fd must outlive the openat2 below: the raw number handed
    // to the syscall is only valid while its OwnedFd is alive, so the fd
    // lives in `base` for the rest of the function. (A temporary scoped to
    // the match arm would close the fd before the syscall — EBADF.)
    let (base, path) = match grant.anchored {
        Anchor::TaskRoot => (None, grant.path),
        Anchor::TaskDir { dirfd } => {
            let base = if dirfd == libc::AT_FDCWD as i64 {
                let cwd = format!("/proc/{tid}/cwd");
                let cstr = std::ffi::CString::new(cwd).expect("cwd path is a valid C string");
                let fd = unsafe { libc::open(cstr.as_ptr(), libc::O_PATH | libc::O_CLOEXEC) };
                if fd < 0 {
                    let e = std::io::Error::last_os_error();
                    tracing::info!(tid, "broker: denied (no cwd fd: {e})");
                    return Judged {
                        syscall,
                        tid,
                        path,
                        decision: Decision::deny(
                            e.raw_os_error().unwrap_or(libc::EPERM),
                            "no cwd fd",
                        ),
                    };
                }
                unsafe { OwnedFd::from_raw_fd(fd) }
            } else {
                // Borrow the target's own dirfd: pidfd_getfd pins the exact
                // task (never a tid-reusing impostor) and fails with ESRCH
                // the moment it dies.
                let borrowed = unsafe {
                    libc::syscall(
                        libc::SYS_pidfd_getfd,
                        pins.pidfd.as_raw_fd(),
                        dirfd as libc::c_uint,
                        0,
                    )
                };
                if borrowed < 0 {
                    let e = std::io::Error::last_os_error();
                    tracing::info!(tid, dirfd, "broker: denied (borrow dirfd: {e})");
                    return Judged {
                        syscall,
                        tid,
                        path,
                        decision: Decision::deny(
                            e.raw_os_error().unwrap_or(libc::EPERM),
                            "borrow dirfd",
                        ),
                    };
                }
                unsafe { OwnedFd::from_raw_fd(borrowed as libc::c_int) }
            };
            (Some(base), grant.path)
        }
    };
    let dir_fd = base
        .as_ref()
        .map_or(pins.root.as_raw_fd(), |owned| owned.as_raw_fd());

    let path = match std::ffi::CString::new(path) {
        Ok(p) => p,
        Err(_) => {
            // check_path already rejected interior NUL — unreachable.
            return Judged {
                syscall,
                tid,
                path: Vec::new(),
                decision: Decision::deny(libc::EINVAL, "NUL in path"),
            };
        }
    };
    let how = OpenHow {
        flags: (libc::O_RDONLY | libc::O_CLOEXEC) as u64,
        mode: 0,
        resolve: grant.resolve,
    };
    let fd = unsafe {
        libc::syscall(
            libc::SYS_openat2,
            dir_fd,
            path.as_ptr(),
            &how as *const OpenHow,
            std::mem::size_of::<OpenHow>(),
        )
    };
    let decision = match fd {
        raw if raw >= 0 => {
            let file = unsafe { OwnedFd::from_raw_fd(raw as libc::c_int) };
            tracing::info!(
                tid,
                syscall,
                "broker: granted read-only fd (openat2 confined)"
            );
            Decision::InjectFd(std::fs::File::from(file))
        }
        _ => {
            // glibc's syscall() wrapper returns -1 and sets errno — it does
            // NOT return -errno (the raw kernel convention). Read the real
            // errno from last_os_error, never from the return value.
            let e = std::io::Error::last_os_error();
            // Pass the real errno through: ENOENT stays ENOENT, EACCES
            // stays EACCES — the workload sees honest failures.
            tracing::info!(tid, syscall, "broker: open failed ({e}) — answering errno");
            Decision::deny(e.raw_os_error().unwrap_or(libc::EPERM), "open failed")
        }
    };
    // Recover the path bytes for the log line (CString consumed them).
    let logged_path = path.into_bytes();
    Judged {
        syscall,
        tid,
        path: logged_path,
        decision,
    }
}

/// pidfd + /proc fds pinned for one task, cached across its notifications.
struct TaskPins {
    pidfd: OwnedFd,
    mem: std::fs::File,
    root: OwnedFd,
}

impl TaskPins {
    /// Cold path: pin the task and its /proc objects. Fails with the errno
    /// of the first failing step (ESRCH when the task is already gone).
    fn open(tid: u32) -> Result<Self, i32> {
        let pidfd = unsafe { libc::syscall(libc::SYS_pidfd_open, tid, 0) };
        if pidfd < 0 {
            return Err(std::io::Error::last_os_error()
                .raw_os_error()
                .unwrap_or(libc::ESRCH));
        }
        let pidfd = unsafe { OwnedFd::from_raw_fd(pidfd as libc::c_int) };
        let mem = std::fs::OpenOptions::new()
            .read(true)
            .open(format!("/proc/{tid}/mem"))
            .map_err(|e| e.raw_os_error().unwrap_or(libc::ESRCH))?;
        let root_path =
            std::ffi::CString::new(format!("/proc/{tid}/root")).map_err(|_| libc::EINVAL)?;
        let root = unsafe { libc::open(root_path.as_ptr(), libc::O_PATH | libc::O_CLOEXEC) };
        if root < 0 {
            return Err(std::io::Error::last_os_error()
                .raw_os_error()
                .unwrap_or(libc::ESRCH));
        }
        Ok(Self {
            pidfd,
            mem,
            root: unsafe { OwnedFd::from_raw_fd(root) },
        })
    }

    /// False once the pinned task has exited (pidfd reports POLLIN on
    /// exit). A poll error also counts as dead — evicting is always safe.
    fn alive(&self) -> bool {
        let mut pollfd = libc::pollfd {
            fd: self.pidfd.as_raw_fd(),
            events: libc::POLLIN,
            revents: 0,
        };
        (unsafe { libc::poll(&mut pollfd, 1, 0) }) <= 0
    }
}

/// Pins for one judgment: usually a cached borrow, or a cold, un-cached
/// lease when the cache is disabled or full (dropped after the judgment).
enum PinHandle<'a> {
    Cached(&'a TaskPins),
    Cold(TaskPins),
}

impl std::ops::Deref for PinHandle<'_> {
    type Target = TaskPins;
    fn deref(&self) -> &TaskPins {
        match self {
            PinHandle::Cached(pins) => pins,
            PinHandle::Cold(pins) => pins,
        }
    }
}

/// Cache of [`TaskPins`] by task id. Bounded: a zone cannot grow the
/// broker's memory by spawning threads that make brokered calls. When the
/// bound is hit (or capacity is 0) the broker takes the cold path and does
/// not cache.
struct PinCache {
    pins: HashMap<u32, TaskPins>,
    max_tasks: usize,
}

impl PinCache {
    fn new(max_tasks: usize) -> Self {
        Self {
            pins: HashMap::new(),
            max_tasks,
        }
    }

    /// Pins for the task, cached when possible. Dead (evicted) entries are
    /// refilled from the cold path, which preserves the race protocol: the
    /// /proc fds are opened *before* the caller's `id_valid` check.
    fn for_task(&mut self, tid: u32) -> Result<PinHandle<'_>, i32> {
        // Two-step lookup: the cached borrow must not outlive the
        // possible remove below.
        let alive = self.pins.get(&tid).is_some_and(TaskPins::alive);
        if alive {
            return Ok(PinHandle::Cached(
                self.pins.get(&tid).expect("alive implies present"),
            ));
        }
        self.pins.remove(&tid);
        if self.pins.len() >= self.max_tasks {
            return TaskPins::open(tid).map(PinHandle::Cold);
        }
        let pins = TaskPins::open(tid)?;
        self.pins.insert(tid, pins);
        Ok(PinHandle::Cached(
            self.pins.get(&tid).expect("just inserted"),
        ))
    }
}

/// Append-only JSON Lines record of every decision: the seed for evidence
/// projection. One line per judged notification, final outcome only, in
/// judgment order. A missing/unwritable log degrades to tracing only — it
/// must never affect the decision itself.
struct DecisionLog {
    file: Option<std::fs::File>,
    seq: AtomicU64,
}

impl DecisionLog {
    fn open(path: &Path) -> Self {
        let file = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(path);
        match file {
            Ok(file) => Self {
                file: Some(file),
                seq: AtomicU64::new(0),
            },
            Err(e) => {
                tracing::warn!(
                    path = %path.display(),
                    %e,
                    "broker: decision log unavailable — decisions will not be recorded"
                );
                Self {
                    file: None,
                    seq: AtomicU64::new(0),
                }
            }
        }
    }

    /// Record the final outcome of one judged notification.
    fn record(
        &mut self,
        id: u64,
        syscall: &str,
        tid: u32,
        path: &[u8],
        errno: i32,
        reason: Option<&str>,
    ) {
        use std::io::Write;
        let Some(file) = self.file.as_mut() else {
            return;
        };
        let seq = self.seq.fetch_add(1, Ordering::Relaxed) + 1;
        let ts_ms = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_millis() as u64)
            .unwrap_or(0);
        let line = serde_json::json!({
            "seq": seq,
            "ts_ms": ts_ms,
            "notif_id": id,
            "tid": tid,
            "syscall": syscall,
            "path": String::from_utf8_lossy(path),
            "decision": if reason.is_some() { "denied" } else { "granted" },
            "errno": errno,
            "reason": reason,
        });
        if let Err(e) = writeln!(file, "{line}") {
            tracing::warn!(%e, "broker: cannot write decision log");
        }
    }
}

/// SECCOMP_IOCTL_NOTIF_ID_VALID: is this notification still pending?
fn id_valid(fd: libc::c_int, id: u64) -> std::io::Result<()> {
    let mut id = id;
    let n = unsafe {
        libc::ioctl(
            fd,
            SECCOMP_IOCTL_NOTIF_ID_VALID,
            &mut id as *mut u64 as *mut libc::c_void,
        )
    };
    if n == 0 {
        Ok(())
    } else {
        Err(std::io::Error::last_os_error())
    }
}

/// Read a NUL-terminated path from the target's memory at `ptr`.
/// Returns raw bytes: paths are not required to be valid UTF-8.
fn read_path(mem: &std::fs::File, ptr: u64) -> Option<Vec<u8>> {
    use std::os::unix::fs::FileExt;
    let mut buf = vec![0u8; MAX_PATH];
    let mut len = 0usize;
    loop {
        let n = mem.read_at(&mut buf[len..], ptr + len as u64).ok()?;
        if n == 0 {
            return None;
        }
        len += n;
        if let Some(pos) = buf[..len].iter().position(|&b| b == 0) {
            return Some(buf[..pos].to_vec());
        }
        if len == MAX_PATH {
            return None;
        }
    }
}

/// Read the target's `struct open_how` at `ptr`.
fn read_open_how(mem: &std::fs::File, ptr: u64) -> Option<OpenHow> {
    use std::os::unix::fs::FileExt;
    let mut buf = [0u8; std::mem::size_of::<OpenHow>()];
    mem.read_exact_at(&mut buf, ptr).ok()?;
    Some(OpenHow {
        flags: u64::from_ne_bytes(buf[0..8].try_into().ok()?),
        mode: u64::from_ne_bytes(buf[8..16].try_into().ok()?),
        resolve: u64::from_ne_bytes(buf[16..24].try_into().ok()?),
    })
}

/// Send the response for one notification and record the decision. Never
/// fatal: SEND failures (other than the benign ENOENT of an exited task)
/// are logged and the loop continues — a dead broker thread would suspend
/// every brokered syscall of the zone forever.
fn respond(fd: libc::c_int, id: u64, judged: Judged, log: &mut DecisionLog) {
    let mut resp = SeccompNotifResp {
        id,
        val: 0,
        error: 0,
        flags: 0,
    };
    let Judged {
        syscall,
        tid,
        path,
        decision,
    } = judged;
    let mut record_errno = 0;
    let mut record_reason: Option<String> = None;
    match decision {
        Decision::Deny { errno, reason } => {
            // The kernel delivers this field raw as the syscall's return
            // value (seccomp_unotify(2): its own example uses a negative
            // errno; a positive value comes back as a successful fd
            // number — verified live: error=+2 made openat return fd 2).
            resp.error = -errno;
            record_errno = errno;
            record_reason = Some(reason);
        }
        Decision::InjectFd(file) => {
            let addfd = SeccompNotifAddfd {
                id,
                flags: 0,
                srcfd: file.as_raw_fd() as u32,
                newfd: 0, // kernel picks
                newfd_flags: 0,
            };
            let target_fd = unsafe {
                libc::ioctl(
                    fd,
                    SECCOMP_IOCTL_NOTIF_ADDFD,
                    &addfd as *const SeccompNotifAddfd,
                )
            };
            if target_fd < 0 {
                let e = std::io::Error::last_os_error();
                tracing::warn!(%e, "broker: ADDFD failed — denying");
                let errno = e.raw_os_error().unwrap_or(libc::EPERM);
                resp.error = -errno;
                record_errno = errno;
                record_reason = Some(format!("addfd: {e}"));
            } else {
                tracing::info!(target_fd, "broker: ADDFD installed");
                resp.val = target_fd as i64;
            }
        }
    }
    log.record(
        id,
        syscall,
        tid,
        &path,
        record_errno,
        record_reason.as_deref(),
    );
    let n = unsafe {
        libc::ioctl(
            fd,
            SECCOMP_IOCTL_NOTIF_SEND,
            &resp as *const SeccompNotifResp,
        )
    };
    if n < 0 {
        let e = std::io::Error::last_os_error();
        if e.raw_os_error() == Some(libc::ENOENT) {
            // The task exited before we responded — not an error.
            return;
        }
        tracing::error!(%e, "broker: SEND failed (notification {id}) — continuing");
    }
}

#[cfg(test)]
mod tests {
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
        assert_eq!(
            deny_openat(libc::O_RDONLY | libc::O_TMPFILE, b"/x"),
            Denial::policy("O_TMPFILE")
        );
        assert_eq!(deny_openat(libc::O_PATH, b"/x"), Denial::policy("O_PATH"));
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

    // ---- fd hand-off ----

    /// Test-only SCM_RIGHTS sender.
    fn send_fds(stream: &UnixStream, fds: &[libc::c_int]) {
        let dummy = [0u8; 1];
        let space = unsafe { libc::CMSG_SPACE((fds.len() * 4) as u32) } as usize;
        let mut cmsg_space = vec![0u8; space];
        let mut msg: libc::msghdr = unsafe { std::mem::zeroed() };
        let mut iov = libc::iovec {
            iov_base: dummy.as_ptr() as *mut libc::c_void,
            iov_len: 1,
        };
        msg.msg_iov = &mut iov;
        msg.msg_iovlen = 1;
        msg.msg_control = cmsg_space.as_mut_ptr().cast::<libc::c_void>();
        msg.msg_controllen = cmsg_space.len();
        let cmsg = unsafe { libc::CMSG_FIRSTHDR(&msg).as_mut().expect("cmsg space") };
        cmsg.cmsg_level = libc::SOL_SOCKET;
        cmsg.cmsg_type = libc::SCM_RIGHTS;
        cmsg.cmsg_len = unsafe { libc::CMSG_LEN((fds.len() * 4) as u32) } as usize;
        unsafe {
            std::ptr::copy_nonoverlapping(
                fds.as_ptr(),
                libc::CMSG_DATA(cmsg) as *mut libc::c_int,
                fds.len(),
            );
            let n = libc::sendmsg(stream.as_raw_fd(), &msg, 0);
            assert_eq!(n, 1, "sendmsg payload");
        }
    }

    #[test]
    fn recv_fd_roundtrips_exactly_one_descriptor() {
        let (theirs, ours) = UnixStream::pair().unwrap();
        let file = std::fs::File::create(
            std::env::temp_dir().join(format!("rauha-broker-recv-{}", std::process::id())),
        )
        .unwrap();
        send_fds(&ours, &[file.as_raw_fd()]);
        let received = recv_fd(&theirs).expect("one fd hand-off");
        // The received fd is a distinct descriptor for the same file.
        assert_ne!(received.as_raw_fd(), file.as_raw_fd());
        std::fs::remove_file(
            std::env::temp_dir().join(format!("rauha-broker-recv-{}", std::process::id())),
        )
        .ok();
    }

    #[test]
    fn recv_fd_refuses_and_closes_surplus_descriptors() {
        let (theirs, ours) = UnixStream::pair().unwrap();
        let a = std::fs::File::open("/dev/null").unwrap();
        let b = std::fs::File::open("/dev/zero").unwrap();
        send_fds(&ours, &[a.as_raw_fd(), b.as_raw_fd()]);
        assert!(recv_fd(&theirs).is_err(), "two fds must be refused");
    }

    // ---- pin cache ----

    #[test]
    fn pin_cache_reuses_live_tasks_and_caches_nothing_when_disabled() {
        // Our own process is a task that is certainly alive.
        let mut cache = PinCache::new(8);
        let pid = std::process::id();
        cache.for_task(pid).expect("pins for a live task");
        cache.for_task(pid).expect("pins reused");
        assert_eq!(cache.pins.len(), 1, "second lookup must reuse the entry");

        // Capacity 0: every judgment is a cold lease, nothing is cached.
        let mut disabled = PinCache::new(0);
        match disabled.for_task(pid).expect("cold path still works") {
            PinHandle::Cold(_) => {}
            PinHandle::Cached(_) => panic!("capacity 0 must not cache"),
        }
        assert!(disabled.pins.is_empty());
    }

    #[test]
    fn pin_cache_cold_path_reports_missing_tasks() {
        // A pid that has been reaped cannot be pinned: ESRCH.
        let mut cache = PinCache::new(8);
        let mut child = std::process::Command::new("true").spawn().unwrap();
        let pid = child.id();
        child.wait().unwrap(); // reaped: the pid is gone
                               // Poll until the kernel forgets the pid (exit + reap makes
                               // pidfd_open fail immediately in practice; retry a moment anyway).
        for _ in 0..50 {
            if let Err(errno) = cache.for_task(pid) {
                assert_eq!(errno, libc::ESRCH);
                return;
            }
            std::thread::sleep(std::time::Duration::from_millis(10));
        }
        panic!("reaped pid {pid} was still pinnable");
    }

    #[test]
    fn full_cache_serves_cold_leases_without_evicting() {
        let mut cache = PinCache::new(1);
        let pid = std::process::id();
        cache.for_task(pid).expect("first task cached");
        // A second distinct live task overflows capacity 1: served cold,
        // the cached entry untouched.
        let mut child = std::process::Command::new("sleep")
            .arg("5")
            .spawn()
            .expect("spawn a second live task");
        match cache.for_task(child.id()) {
            Ok(PinHandle::Cold(_)) => {}
            Ok(PinHandle::Cached(_)) => panic!("a full cache must not insert"),
            Err(errno) => panic!("live task must be servable cold: {errno}"),
        }
        assert_eq!(cache.pins.len(), 1, "cached entry must survive");
        let _ = child.kill();
        let _ = child.wait_with_output();
    }

    #[test]
    fn task_pins_for_our_own_process_read_memory() {
        // The mem fd of a live task can read that task's own memory: prove
        // the pins are usable end to end on this kernel. The NUL makes the
        // read deterministic — read_path stops at it.
        let pins = TaskPins::open(std::process::id()).expect("pins for self");
        let canary = *b"rauha-broker\0";
        let ptr = canary.as_ptr() as u64;
        let read = read_path(&pins.mem, ptr).expect("canary readable");
        assert_eq!(read, b"rauha-broker");
    }

    // ---- decision log ----

    #[test]
    fn decision_log_records_grants_and_denials_in_order() {
        let dir = std::env::temp_dir().join(format!("rauha-broker-log-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("broker.log");
        let mut log = DecisionLog::open(&path);
        log.record(
            7,
            "openat",
            42,
            b"/etc/hostname",
            libc::EPERM,
            Some("not read-only"),
        );
        log.record(8, "openat", 42, b"/etc/hostname", 0, None);
        let content = std::fs::read_to_string(&path).unwrap();
        let lines: Vec<&str> = content.lines().collect();
        assert_eq!(lines.len(), 2);
        assert!(lines[0].contains("\"seq\":1"));
        assert!(lines[0].contains("\"decision\":\"denied\""));
        assert!(lines[0].contains("\"errno\":1"));
        assert!(lines[1].contains("\"seq\":2"));
        assert!(lines[1].contains("\"decision\":\"granted\""));
        std::fs::remove_dir_all(&dir).ok();
    }
}
