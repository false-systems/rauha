#![cfg(target_os = "linux")]

//! Seccomp-notify broker: the Capsicum-shaped primitive.
//!
//! When a policy marks syscalls as brokered (`[syscalls] broker = [...]`,
//! validated to the syscall names this module can actually judge), the OCI
//! seccomp profile emits `SCMP_ACT_NOTIFY` with this module's socket as
//! `listener_path`. crun ships the kernel notify fd here; the workload's
//! brokered syscalls then suspend in the kernel and are judged by the shim:
//!
//! - denied calls return EPERM without ever executing;
//! - granted `openat` calls are satisfied by the *broker* opening the file
//!   and injecting it with `SECCOMP_IOCTL_NOTIF_ADDFD`.
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
//! 4. Only then read the path and resolve it.
//!
//! If the notification is still valid at (3), the task was alive at that
//! instant, so the pid could not have been reused since (1)/(2) — the fds
//! belong to the suspended task. If the task dies between (3) and the
//! response, `ADDFD`/`SEND` fail with ENOENT and nothing is injected.
//!
//! Containment is kernel-enforced, not string-checked: the broker resolves
//! paths with `openat2` — absolute paths with `RESOLVE_IN_ROOT` relative to
//! the task's root (`/proc/<pid>/root`), relative paths with
//! `RESOLVE_BENEATH` relative to the task's own `dirfd` (borrowed via
//! `pidfd_getfd`) or its cwd. Symlinks, `..`, and magic links cannot escape
//! the container by construction. (Remaining v0 exposure: a sibling thread
//! of the target can `chroot`/`chdir` the shared fs between suspension and
//! judgment; the open is still confined to some subtree of the container
//! rootfs, which is the zone boundary.)
//!
//! v0 policy: read-only `openat` under the container rootfs, deny
//! everything else with a logged reason. Every decision is a log line
//! today; evidence events follow.
//!
//! ABI verified against linux/seccomp.h: `seccomp_notif` embeds
//! `seccomp_data` (80 bytes total on 64-bit), ioctl numbers computed from
//! _IOWR('!', ...) / _IOW('!', ...) and cross-checked on the target kernel.

use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::Path;

use anyhow::{bail, Context, Result};

// _IOWR('!', 0, struct seccomp_notif) — 80 bytes (id + pid + flags + data)
const SECCOMP_IOCTL_NOTIF_RECV: libc::c_ulong = 0xc050_2100;
// _IOWR('!', 1, struct seccomp_notif_resp) — 24 bytes
const SECCOMP_IOCTL_NOTIF_SEND: libc::c_ulong = 0xc018_2101;
// _IOWR('!', 2, __u64) — 8 bytes
const SECCOMP_IOCTL_NOTIF_ID_VALID: libc::c_ulong = 0xc008_2102;
// _IOW('!', 3, struct seccomp_notif_addfd) — 24 bytes
const SECCOMP_IOCTL_NOTIF_ADDFD: libc::c_ulong = 0x4018_2103;

// Decode our own ioctl numbers at compile time: dir<<30 | size<<16 | type<<8 | nr.
const _: () = assert!(0xc000_0000 | (80 << 16) | ((b'!' as u32) << 8) == 0xc050_2100);
const _: () = assert!(0xc000_0000 | (24 << 16) | (b'!' as u32) << 8 | 1 == 0xc018_2101);
const _: () = assert!(0xc000_0000 | (8 << 16) | (b'!' as u32) << 8 | 2 == 0xc008_2102);
const _: () = assert!(0x4000_0000 | (24 << 16) | (b'!' as u32) << 8 | 3 == 0x4018_2103);
const _: () = assert!(std::mem::size_of::<SeccompNotif>() == 80);
const _: () = assert!(std::mem::size_of::<SeccompNotifResp>() == 24);
const _: () = assert!(std::mem::size_of::<SeccompNotifAddfd>() == 24);

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

/// The syscall this broker can judge. The daemon refuses to emit
/// `SCMP_ACT_NOTIFY` for anything else; the broker double-checks.
const NR_OPENAT: i64 = libc::SYS_openat;

/// Native `AUDIT_ARCH_*` for the architecture this shim is compiled for.
#[cfg(target_arch = "x86_64")]
const NATIVE_ARCH: u32 = libc::AUDIT_ARCH_X86_64;
// libc does not export AUDIT_ARCH_AARCH64: EM_AARCH64 (0xB7) |
// __AUDIT_ARCH_64BIT (0x8000_0000) | __AUDIT_ARCH_LE (0x4000_0000).
#[cfg(target_arch = "aarch64")]
const NATIVE_ARCH: u32 = 0xC000_00B7;

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
/// zone deadlock, not a degraded mode.
pub fn serve(listener_path: &Path) -> Result<()> {
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

    judge_loop(notify_fd)
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
    // malformed hand-off (excess fds received in a cmsg are already
    // installed by the kernel, so also fail loudly on the shape).
    let cmsg = match unsafe { libc::CMSG_FIRSTHDR(&msg).as_ref() } {
        Some(h) => h,
        None => bail!("no control message on seccomp listener"),
    };
    let bytes = cmsg.cmsg_len as usize - unsafe { libc::CMSG_LEN(0) } as usize;
    if cmsg.cmsg_level != libc::SOL_SOCKET
        || cmsg.cmsg_type != libc::SCM_RIGHTS
        || bytes < std::mem::size_of::<libc::c_int>()
    {
        bail!("unexpected cmsg on seccomp listener");
    }
    let fd = unsafe { *(libc::CMSG_DATA(cmsg) as *const libc::c_int) };
    if fd < 0 {
        bail!("invalid fd from seccomp listener");
    }
    Ok(unsafe { OwnedFd::from_raw_fd(fd) })
}

/// The judgment loop: receive one notification, decide, respond. Repeat
/// until the kernel closes the fd (container exited).
fn judge_loop(notify_fd: OwnedFd) -> Result<()> {
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
        let decision = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| judge(fd, &notif)))
            .unwrap_or_else(|panic| {
                let reason = panic
                    .downcast_ref::<&str>()
                    .map(|s| (*s).to_string())
                    .or_else(|| panic.downcast_ref::<String>().cloned())
                    .unwrap_or_else(|| "unknown panic".into());
                tracing::error!(id = notif.id, %reason, "broker: judge panicked — denying");
                Decision::Deny
            });
        respond(fd, notif.id, decision)?;
    }
}

/// How to satisfy a granted call.
#[derive(Debug)]
enum Grant {
    /// Absolute path: openat2(RESOLVE_IN_ROOT) against the task's root.
    InRoot { path: Vec<u8>, no_follow: bool },
    /// Relative path: openat2(RESOLVE_BENEATH) against the task's own
    /// `dirfd` (borrowed via pidfd_getfd) or its cwd.
    Beneath {
        dirfd: i64,
        path: Vec<u8>,
        no_follow: bool,
    },
}

/// Pure classification of one suspended call: is it grantable, and how?
/// Unit-testable without a live container.
fn classify(
    nr: i64,
    arch: u32,
    flags: i32,
    dirfd: i64,
    path: &[u8],
) -> Result<Grant, &'static str> {
    if arch != NATIVE_ARCH {
        return Err("non-native arch");
    }
    if nr != NR_OPENAT {
        // The daemon only brokers openat; anything else reaching here
        // means policy and shim disagree — deny, loudly.
        return Err("not openat (policy/shim mismatch)");
    }
    if flags & libc::O_ACCMODE != libc::O_RDONLY {
        return Err("not read-only");
    }
    // Flags with side effects or semantics the broker cannot honour
    // must fail explicitly, not silently behave differently.
    if flags & libc::O_CREAT != 0 {
        return Err("O_CREAT");
    }
    if flags & libc::O_TRUNC != 0 {
        return Err("O_TRUNC");
    }
    if flags & libc::O_TMPFILE != 0 {
        return Err("O_TMPFILE");
    }
    if flags & libc::O_PATH != 0 {
        return Err("O_PATH");
    }
    if path.is_empty() {
        return Err("empty path");
    }
    if path.len() >= MAX_PATH {
        return Err("path too long");
    }
    // Interior NUL is caught by CString later; report it here uniformly.
    if path.contains(&0) {
        return Err("NUL in path");
    }
    let no_follow = flags & libc::O_NOFOLLOW != 0;
    if path[0] == b'/' {
        Ok(Grant::InRoot {
            path: path.to_vec(),
            no_follow,
        })
    } else {
        Ok(Grant::Beneath {
            dirfd,
            path: path.to_vec(),
            no_follow,
        })
    }
}

/// Judge one notification: pin the task, validate the notification is
/// still live, then resolve the open on the workload's behalf.
fn judge(fd: libc::c_int, notif: &SeccompNotif) -> Decision {
    let path_ptr = notif.data.args[1];
    let dirfd = notif.data.args[0] as i64;
    let flags = notif.data.args[2] as i32;

    // 1. Pin the suspended task — immune to pid reuse from here on.
    let pidfd = match pidfd_open(notif.pid) {
        Some(p) => p,
        None => {
            tracing::info!(
                id = notif.id,
                pid = notif.pid,
                "broker: task gone — skipping"
            );
            return Decision::Gone;
        }
    };

    // 2. Pin the /proc objects the decision needs.
    let mem = match std::fs::File::open(format!("/proc/{}/mem", notif.pid)) {
        Ok(f) => f,
        Err(e) => {
            tracing::info!(pid = notif.pid, "broker: denied (no mem fd: {e})");
            return Decision::Deny;
        }
    };
    let root_path = match std::ffi::CString::new(format!("/proc/{}/root", notif.pid)) {
        Ok(p) => p,
        Err(_) => return Decision::Deny,
    };
    let root_fd = unsafe { libc::open(root_path.as_ptr(), libc::O_PATH | libc::O_CLOEXEC) };
    if root_fd < 0 {
        let e = std::io::Error::last_os_error();
        tracing::info!(pid = notif.pid, "broker: denied (no root fd: {e})");
        return Decision::Deny;
    }
    let root_fd = unsafe { OwnedFd::from_raw_fd(root_fd) };

    // 3. The race check: if the notification is no longer pending, the
    // task exited before now — the fds above may belong to a pid-reusing
    // impostor and must not be used. See the module docs.
    if !id_valid(fd, notif.id) {
        tracing::info!(id = notif.id, "broker: notification expired — skipping");
        return Decision::Gone;
    }

    // 4. Safe to read the target's memory and resolve.
    let path_bytes = match read_path(&mem, path_ptr) {
        Some(p) => p,
        None => {
            tracing::warn!(pid = notif.pid, "broker: unreadable path — denying");
            return Decision::Deny;
        }
    };
    let grant = match classify(
        notif.data.nr as i64,
        notif.data.arch,
        flags,
        dirfd,
        &path_bytes,
    ) {
        Ok(g) => g,
        Err(reason) => {
            tracing::info!(pid = notif.pid, reason, "broker: denied");
            return Decision::Deny;
        }
    };

    open_for_target(&pidfd, &root_fd, notif.pid, grant)
}

/// openat2 { flags, mode, resolve }.
#[repr(C)]
struct OpenHow {
    flags: u64,
    mode: u64,
    resolve: u64,
}
const RESOLVE_BENEATH: u64 = 0x8;
const RESOLVE_NO_MAGICLINKS: u64 = 0x2;
const RESOLVE_NO_SYMLINKS: u64 = 0x4;
const RESOLVE_IN_ROOT: u64 = 0x10;

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
    if no_follow {
        base | RESOLVE_NO_SYMLINKS
    } else {
        base | RESOLVE_NO_MAGICLINKS
    }
}

/// Perform the confined open for a granted call and wrap the result.
fn open_for_target(pidfd: &OwnedFd, root_fd: &OwnedFd, pid: u32, grant: Grant) -> Decision {
    // Resolve relative paths against the task's own directory context —
    // never the container root, which would silently answer a different
    // question than the workload asked.
    let (dir_fd, resolve, path) = match grant {
        Grant::InRoot { path, no_follow } => {
            (root_fd.as_raw_fd(), resolve_flags(true, no_follow), path)
        }
        Grant::Beneath {
            dirfd,
            path,
            no_follow,
        } => {
            let base = if dirfd == libc::AT_FDCWD as i64 {
                let cwd = format!("/proc/{pid}/cwd");
                let fd = unsafe { libc::open(cwd.as_ptr().cast(), libc::O_PATH | libc::O_CLOEXEC) };
                if fd < 0 {
                    let e = std::io::Error::last_os_error();
                    tracing::info!(pid, "broker: denied (no cwd fd: {e})");
                    return Decision::Deny;
                }
                unsafe { OwnedFd::from_raw_fd(fd) }
            } else {
                // Borrow the target's own dirfd: pidfd_getfd pins the exact
                // task (never a pid-reusing impostor) and fails with ESRCH
                // the moment it dies.
                let borrowed = unsafe {
                    libc::syscall(
                        libc::SYS_pidfd_getfd,
                        pidfd.as_raw_fd(),
                        dirfd as libc::c_uint,
                        0,
                    )
                };
                if borrowed < 0 {
                    let e = std::io::Error::last_os_error();
                    tracing::info!(pid, dirfd, "broker: denied (borrow dirfd: {e})");
                    return Decision::Deny;
                }
                unsafe { OwnedFd::from_raw_fd(borrowed as libc::c_int) }
            };
            (base.as_raw_fd(), resolve_flags(false, no_follow), path)
        }
    };

    let path = match std::ffi::CString::new(path) {
        Ok(p) => p,
        Err(_) => return Decision::Deny, // interior NUL — classify already rejects
    };
    let how = OpenHow {
        flags: (libc::O_RDONLY | libc::O_CLOEXEC) as u64,
        mode: 0,
        resolve,
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
    match fd {
        raw if raw >= 0 => {
            let file = unsafe { OwnedFd::from_raw_fd(raw as libc::c_int) };
            tracing::info!(pid, "broker: granted read-only fd (openat2 confined)");
            Decision::InjectFd(std::fs::File::from(file))
        }
        err => {
            let e = std::io::Error::from_raw_os_error(-(err as i32));
            tracing::info!(pid, "broker: denied (openat2: {e})");
            Decision::Deny
        }
    }
}

enum Decision {
    Deny,
    /// The task exited before judgment; the response would be ENOENT.
    Gone,
    InjectFd(std::fs::File),
}

/// pidfd_open(pid) — pins the task struct, immune to pid reuse.
fn pidfd_open(pid: u32) -> Option<OwnedFd> {
    let fd = unsafe { libc::syscall(libc::SYS_pidfd_open, pid, 0) };
    if fd < 0 {
        return None;
    }
    Some(unsafe { OwnedFd::from_raw_fd(fd as libc::c_int) })
}

/// SECCOMP_IOCTL_NOTIF_ID_VALID: is this notification still pending?
fn id_valid(fd: libc::c_int, id: u64) -> bool {
    let mut id = id;
    let n = unsafe {
        libc::ioctl(
            fd,
            SECCOMP_IOCTL_NOTIF_ID_VALID,
            &mut id as *mut u64 as *mut libc::c_void,
        )
    };
    n == 0
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

/// Send the response for one notification.
fn respond(fd: libc::c_int, id: u64, decision: Decision) -> Result<()> {
    let mut resp = SeccompNotifResp {
        id,
        val: 0,
        error: 0,
        flags: 0,
    };
    match decision {
        Decision::Deny => {
            resp.error = libc::EPERM;
        }
        // Task gone: skip the response; SEND would return ENOENT anyway.
        Decision::Gone => return Ok(()),
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
                resp.error = libc::EPERM;
            } else {
                tracing::info!(target_fd, "broker: ADDFD installed");
                resp.val = target_fd as i64;
            }
        }
    }
    let n = unsafe {
        libc::ioctl(
            fd,
            SECCOMP_IOCTL_NOTIF_SEND,
            &resp as *const SeccompNotifResp,
        )
    };
    if n < 0 {
        let e = std::io::Error::last_os_error();
        // ENOENT: the task exited before we responded — not an error.
        if e.raw_os_error() == Some(libc::ENOENT) {
            return Ok(());
        }
        bail!("SECCOMP_IOCTL_NOTIF_SEND: {e}");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn classify_ok(nr: i64, flags: i32, path: &[u8]) -> Grant {
        classify(nr, NATIVE_ARCH, flags, 3, path).expect("grantable")
    }

    fn deny_reason(nr: i64, flags: i32, path: &[u8]) -> &'static str {
        classify(nr, NATIVE_ARCH, flags, 3, path).expect_err("denied")
    }

    #[test]
    fn grants_at_fdcwd_as_beneath() {
        // AT_FDCWD is resolved against the task's cwd by the judge —
        // classification only needs to keep it a Beneath grant.
        match classify(
            NR_OPENAT,
            NATIVE_ARCH,
            libc::O_RDONLY,
            libc::AT_FDCWD as i64,
            b"rel",
        )
        .expect("grantable")
        {
            Grant::Beneath { dirfd, .. } => assert_eq!(dirfd, libc::AT_FDCWD as i64),
            Grant::InRoot { .. } => panic!("relative path"),
        }
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

    #[test]
    fn grants_absolute_read_only_openat() {
        match classify_ok(NR_OPENAT, libc::O_RDONLY, b"/etc/hostname") {
            Grant::InRoot { path, no_follow } => {
                assert_eq!(path, b"/etc/hostname");
                assert!(!no_follow);
            }
            Grant::Beneath { .. } => panic!("absolute path must resolve in-root"),
        }
    }

    #[test]
    fn grants_relative_paths_against_the_tasks_own_dirfd() {
        match classify_ok(NR_OPENAT, libc::O_RDONLY, b"src/lib.rs") {
            Grant::Beneath { .. } => {}
            Grant::InRoot { .. } => panic!("relative path must resolve beneath the dirfd"),
        }
    }

    #[test]
    fn denies_wrong_arch() {
        let err = classify(NR_OPENAT, 0, libc::O_RDONLY, 3, b"/x").unwrap_err();
        assert_eq!(err, "non-native arch");
    }

    #[test]
    fn denies_syscall_other_than_openat() {
        // e.g. openat2 (also passes a path in args[1]) must not be
        // answered with an fd injection meant for openat.
        assert_eq!(
            deny_reason(libc::SYS_openat2, libc::O_RDONLY, b"/x"),
            "not openat (policy/shim mismatch)"
        );
    }

    #[test]
    fn denies_write_side_effects_and_semantic_drift() {
        for flags in [
            libc::O_WRONLY,
            libc::O_RDWR,
            libc::O_RDONLY | libc::O_CREAT,
            libc::O_RDONLY | libc::O_TRUNC,
            libc::O_RDONLY | libc::O_TMPFILE,
            libc::O_PATH,
        ] {
            let reason = deny_reason(NR_OPENAT, flags, b"/x");
            assert!(
                reason.contains("not read-only") || reason.starts_with("O_") || reason == "O_PATH",
                "unexpected reason for flags {flags:#x}: {reason}"
            );
        }
    }

    #[test]
    fn denies_degenerate_paths() {
        assert_eq!(deny_reason(NR_OPENAT, libc::O_RDONLY, b""), "empty path");
        assert_eq!(
            deny_reason(NR_OPENAT, libc::O_RDONLY, b"we\0ird"),
            "NUL in path"
        );
    }

    #[test]
    fn honors_o_nofollow_by_requesting_no_symlinks() {
        match classify_ok(NR_OPENAT, libc::O_RDONLY | libc::O_NOFOLLOW, b"/etc/passwd") {
            Grant::InRoot { no_follow, .. } => assert!(no_follow),
            Grant::Beneath { .. } => panic!("absolute path"),
        }
    }

    #[test]
    fn path_may_be_non_utf8() {
        // Valid Linux path bytes that are not UTF-8 must classify, not deny.
        match classify_ok(NR_OPENAT, libc::O_RDONLY, b"/tmp/\xff\xfe") {
            Grant::InRoot { path, .. } => assert_eq!(path, b"/tmp/\xff\xfe"),
            Grant::Beneath { .. } => panic!("absolute path"),
        }
    }

    #[test]
    fn syscall_numbers_match_native_openat() {
        // The broker must judge the syscall the kernel reports under the
        // arch it is compiled for — no cross-arch number tables in v0.
        assert_eq!(NR_OPENAT, libc::SYS_openat);
        assert_ne!(0, NATIVE_ARCH);
    }
}
