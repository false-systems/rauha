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
//!   `SECCOMP_IOCTL_NOTIF_ADDFD` — mirroring the caller's `O_CLOEXEC` and
//!   `O_NONBLOCK` so the handle behaves as asked.
//!
//! The workload never exercises ambient authority for brokered calls — it
//! holds only the handles it was given. `SECCOMP_USER_NOTIF_FLAG_CONTINUE`
//! is forbidden here by design: it would re-execute the call with full
//! ambient authority, which is the exact thing brokering removes.
//!
//! ## Security model of the judgment path
//!
//! seccomp-notify brokers are attacked through the races the kernel
//! documentation warns about (see `Documentation/userspace-api/seccomp_filter.rst`,
//! "Kernel-supplied notification IDs"). The sequence here is:
//!
//! 1. `pidfd_open(pid)` — pins the exact task. Holding a pidfd pins the
//!    `struct pid`, so the tid **cannot be reused** while the pin lives.
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
//! response, `ADDFD`/`SEND` fail with ENOENT and nothing is injected —
//! both ioctls re-validate the notification id in the kernel, which is
//! why there is no second userspace `id_valid` after the open.
//!
//! The [`PinCache`](pins::PinCache) holds the (pidfd, mem, root) triple
//! per task across notifications; see `pins.rs` for why that is
//! race-equivalent to the cold path. The cached root pins the task's root
//! *as first seen*; a later chroot by the task changes neither the cached
//! root nor the containment (still a subtree of the container rootfs —
//! the zone boundary).
//!
//! Containment is kernel-enforced, not string-checked: the broker resolves
//! paths with `openat2` — absolute paths with `RESOLVE_IN_ROOT` relative
//! to the task's root (`/proc/<pid>/root`), relative paths with
//! `RESOLVE_BENEATH` relative to the task's own `dirfd` (borrowed via
//! `pidfd_getfd`) or its cwd. For `openat2` calls the caller's own
//! `RESOLVE_*` restrictions are OR'd in — the broker is never less strict
//! than the workload asked. Symlinks, `..`, and magic links cannot escape
//! the container by construction. (Remaining v0 exposure: a sibling
//! thread of the target can `chroot`/`chdir` the shared fs between
//! suspension and judgment; the open is still confined to some subtree of
//! the container rootfs, which is the zone boundary.)
//!
//! The hand-off socket is defense-in-depth layered: bound under a
//! restrictive umask, mode 0600, exactly one accepted connection whose
//! peer uid must equal ours (`SO_PEERCRED`), exactly one `SCM_RIGHTS`
//! descriptor with no truncation, close-on-exec on everything the broker
//! holds (the shim forks and execs helpers).
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
//! ## One wire lesson, recorded
//!
//! `seccomp_notif_resp.error` is delivered **raw** as the suspended
//! syscall's return value. A positive errno comes back as a *successful*
//! small fd number — verified live: `error=+2` made a workload's
//! `openat("/nonexistent")` return fd 2 (its own stderr). The response
//! therefore carries a **negated** errno; see `respond`.
//!
//! Layout: [`abi`] (kernel ABI + drift test), [`classify`] (pure
//! judgment), [`pins`] (task pinning + cache), [`decision`] (decision
//! record + log), and this file (the runtime: serve, judge, respond).

use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::Path;

use anyhow::{bail, Context, Result};

mod abi;
mod classify;
mod decision;
mod pins;

use abi::*;
use classify::{Anchor, Denial, Grant};
use decision::{Decision, DecisionLog, Judged};
use pins::{PinCache, TaskPins};

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

/// Serve the seccomp listener socket: accept one peer-verified connection
/// (crun's listener helper), receive the notify fd, and judge
/// notifications until the fd closes. Runs on its own thread; the
/// container blocks while each decision is made, so the loop must stay
/// fast and panic-free — a panic here would leave every brokered syscall
/// suspended forever, which is a zone deadlock, not a degraded mode.
/// Every decision is appended to `decision_log_path` (one JSON line per
/// judged call).
pub fn serve(listener_path: &Path, decision_log_path: &Path) -> Result<()> {
    let _ = std::fs::remove_file(listener_path);
    // Bind under a restrictive umask so the socket is never briefly
    // world-connectable between bind and chmod; then pin mode 0600
    // explicitly so the on-disk state is umask-independent.
    let saved_umask = unsafe { libc::umask(0o077) };
    let listener = UnixListener::bind(listener_path);
    unsafe { libc::umask(saved_umask) };
    let listener =
        listener.with_context(|| format!("bind seccomp listener {}", listener_path.display()))?;
    let _guard = SocketGuard(listener_path);
    let sock_c = std::ffi::CString::new(listener_path.as_os_str().as_encoded_bytes())
        .with_context(|| format!("listener path {} not a C string", listener_path.display()))?;
    unsafe {
        libc::chmod(sock_c.as_ptr(), 0o600);
    }

    // crun's helper connects and sends the fd; one connection per
    // container, so stop listening the moment we have it — nothing else
    // may even queue.
    let (stream, _) = listener.accept().context("accept seccomp listener")?;
    drop(listener);
    let peer = peer_credentials(&stream)?;
    if peer.uid != unsafe { libc::getuid() } {
        bail!(
            "refusing seccomp hand-off from uid {} (pid {}) — expected our own uid",
            peer.uid,
            peer.pid
        );
    }
    tracing::debug!(peer_pid = peer.pid, "broker: seccomp fd hand-off accepted");
    let notify_fd = recv_fd(&stream).context("receive seccomp notify fd")?;
    drop(stream);

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

/// SO_PEERCRED of the connected peer: who is handing us an fd to judge with.
fn peer_credentials(stream: &UnixStream) -> Result<libc::ucred> {
    let mut ucred: libc::ucred = unsafe { std::mem::zeroed() };
    let mut len = std::mem::size_of::<libc::ucred>() as libc::socklen_t;
    let rc = unsafe {
        libc::getsockopt(
            stream.as_raw_fd(),
            libc::SOL_SOCKET,
            libc::SO_PEERCRED,
            &mut ucred as *mut libc::ucred as *mut libc::c_void,
            &mut len,
        )
    };
    if rc != 0 {
        bail!(
            "SO_PEERCRED on seccomp listener: {}",
            std::io::Error::last_os_error()
        );
    }
    Ok(ucred)
}

/// Receive one SCM_RIGHTS descriptor from the stream. Close-on-exec: the
/// shim forks and execs helpers, and a notify fd in a child is an
/// authority leak.
fn recv_fd(stream: &UnixStream) -> Result<OwnedFd> {
    let mut buf = [0u8; 1];
    // Space for exactly one descriptor: more than that must be refused,
    // and the kernel tells us it dropped some via MSG_CTRUNC.
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
    // malformed hand-off. Parse the cmsg first: fds named in it are
    // already installed in our table by the kernel, so every refusal
    // path must close them — a refused hand-off must not leak handles.
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
    // MSG_CTRUNC: the sender passed more ancillary data than our
    // one-descriptor buffer could receive. The cmsg names only what was
    // delivered (the kernel closed the rest), but a hand-off that large
    // is malformed or hostile — refuse it, closing what arrived.
    if msg.msg_flags & libc::MSG_CTRUNC != 0 {
        for fd in fds {
            unsafe { libc::close(*fd) };
        }
        bail!("truncated SCM_RIGHTS cmsg on seccomp listener");
    }
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
    let fd = unsafe { OwnedFd::from_raw_fd(fds[0]) };
    unsafe { libc::fcntl(fd.as_raw_fd(), libc::F_SETFD, libc::FD_CLOEXEC) };
    Ok(fd)
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

/// Judge one notification: pin the task, validate the notification is
/// still live, then resolve the open on the workload's behalf.
fn judge(fd: libc::c_int, notif: &SeccompNotif, cache: &mut PinCache) -> Judged {
    let tid = notif.pid;
    let Some(syscall) = brokered_syscall_name(notif.data.nr as i64) else {
        // Policy and shim disagree — the daemon only admits
        // BROKERABLE_SYSCALLS. Deny, loudly.
        tracing::error!(
            nr = notif.data.nr,
            "broker: syscall not brokerable (policy/shim mismatch) — denying"
        );
        return Judged::deny(
            "unknown",
            tid,
            Vec::new(),
            libc::EPERM,
            "not brokerable (policy/shim mismatch)",
        );
    };
    if notif.data.arch != NATIVE_ARCH {
        return Judged::deny(syscall, tid, Vec::new(), libc::EPERM, "non-native arch");
    }

    // 1-3 of the race protocol (see module docs), with the pin cache
    // shortening the cold path. for_task opens the /proc objects, then
    // id_valid proves the notification is still live afterwards.
    let pins = match cache.for_task(tid) {
        Ok(pins) => pins,
        Err(errno) => {
            let error = std::io::Error::from_raw_os_error(errno);
            tracing::info!(tid, "broker: denied (task pins: {error})");
            return Judged::deny(syscall, tid, Vec::new(), errno, "task pins");
        }
    };
    if let Err(e) = id_valid(fd, notif.id) {
        tracing::info!(id = notif.id, errno = %e, "broker: notification expired — denying");
        // The syscall must still be answered: an unanswered notification
        // suspends the task forever. For a truly dead notification SEND
        // just returns ENOENT.
        return Judged::deny(
            syscall,
            tid,
            Vec::new(),
            libc::ESRCH,
            "notification expired",
        );
    }

    // 4. Safe to read the target's memory and classify.
    let dirfd = notif.data.args[0] as i64;
    let path_bytes = match read_path(&pins.mem, notif.data.args[1]) {
        Some(p) => p,
        None => {
            tracing::warn!(tid, "broker: unreadable path — denying");
            return Judged::deny(syscall, tid, Vec::new(), libc::EFAULT, "unreadable path");
        }
    };
    let grant = match syscall {
        "openat" => classify::classify_openat(dirfd, notif.data.args[2] as i32, &path_bytes),
        "openat2" => {
            let how = match read_open_how(&pins.mem, notif.data.args[2]) {
                Some(how) => how,
                None => {
                    tracing::warn!(tid, "broker: unreadable open_how — denying");
                    return Judged::deny(
                        syscall,
                        tid,
                        path_bytes,
                        libc::EFAULT,
                        "unreadable open_how",
                    );
                }
            };
            classify::classify_openat2(dirfd, notif.data.args[3], &how, &path_bytes)
        }
        // Unreachable while the drift test holds (abi.rs pins the name
        // table to BROKERABLE_SYSCALLS) — deny rather than trust it.
        _ => {
            return Judged::deny(
                syscall,
                tid,
                path_bytes,
                libc::EPERM,
                "not brokerable (policy/shim mismatch)",
            );
        }
    };
    match grant {
        Ok(grant) => open_for_target(&pins, tid, syscall, grant, path_bytes),
        Err(Denial { errno, reason }) => {
            tracing::info!(tid, reason, "broker: denied");
            Judged::deny(syscall, tid, path_bytes, errno, reason)
        }
    }
}

/// Perform the confined open for a granted call and wrap the result.
fn open_for_target(
    pins: &TaskPins,
    tid: u32,
    syscall: &'static str,
    grant: Grant,
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
                    return Judged::deny(
                        syscall,
                        tid,
                        path,
                        e.raw_os_error().unwrap_or(libc::EPERM),
                        "no cwd fd",
                    );
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
                    return Judged::deny(
                        syscall,
                        tid,
                        path,
                        e.raw_os_error().unwrap_or(libc::EPERM),
                        "borrow dirfd",
                    );
                }
                let borrowed = unsafe { OwnedFd::from_raw_fd(borrowed as libc::c_int) };
                // Close-on-exec while we hold it: the shim execs helpers
                // concurrently on other threads.
                unsafe { libc::fcntl(borrowed.as_raw_fd(), libc::F_SETFD, libc::FD_CLOEXEC) };
                borrowed
            };
            (Some(base), grant.path)
        }
    };
    let dir_fd = base
        .as_ref()
        .map_or(pins.root.as_raw_fd(), |owned| owned.as_raw_fd());

    // Build the C string up front and keep the bytes for the log — no
    // move-and-recover gymnastics.
    let cpath = match std::ffi::CString::new(path.clone()) {
        Ok(p) => p,
        // check_path already rejected interior NUL — unreachable.
        Err(_) => return Judged::deny(syscall, tid, path, libc::EINVAL, "NUL in path"),
    };
    // O_NOCTTY: a tty path must not become the shim's controlling
    // terminal. O_CLOEXEC: the broker's handle dies with the broker.
    // O_NONBLOCK is mirrored from the caller's request; everything else
    // about the injected fd is plain read-only blocking.
    let mut flags = libc::O_RDONLY | libc::O_CLOEXEC | libc::O_NOCTTY;
    if grant.nonblock {
        flags |= libc::O_NONBLOCK;
    }
    let how = OpenHow {
        flags: flags as u64,
        mode: 0,
        resolve: grant.resolve,
    };
    let fd = unsafe {
        libc::syscall(
            libc::SYS_openat2,
            dir_fd,
            cpath.as_ptr(),
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
            Decision::InjectFd {
                file: std::fs::File::from(file),
                cloexec: grant.cloexec,
            }
        }
        _ => {
            // glibc's syscall() wrapper returns -1 and sets errno — it
            // does NOT return -errno (the raw kernel convention). Read
            // the real errno from last_os_error, never the return value.
            let e = std::io::Error::last_os_error();
            // Pass the real errno through: ENOENT stays ENOENT, EACCES
            // stays EACCES — the workload sees honest failures.
            tracing::info!(tid, syscall, "broker: open failed ({e}) — answering errno");
            return Judged::deny(
                syscall,
                tid,
                path,
                e.raw_os_error().unwrap_or(libc::EPERM),
                "open failed",
            );
        }
    };
    Judged {
        syscall,
        tid,
        path,
        decision,
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
/// Returns raw bytes: paths are not required to be valid UTF-8. Offset
/// arithmetic is checked — a hostile register value near u64::MAX must
/// not wrap into a valid low address.
pub(crate) fn read_path(mem: &std::fs::File, ptr: u64) -> Option<Vec<u8>> {
    use std::os::unix::fs::FileExt;
    let mut buf = vec![0u8; MAX_PATH];
    let mut len = 0usize;
    loop {
        let offset = ptr.checked_add(len as u64)?;
        let n = mem.read_at(&mut buf[len..], offset).ok()?;
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
            // value (seccomp_unotify(2); its own example uses a negative
            // errno). A positive value comes back as a successful fd
            // number — verified live: error=+2 made openat return fd 2.
            resp.error = -errno;
            record_errno = errno;
            record_reason = Some(reason);
        }
        Decision::InjectFd { file, cloexec } => {
            let addfd = SeccompNotifAddfd {
                id,
                flags: 0,
                srcfd: file.as_raw_fd() as u32,
                newfd: 0, // kernel picks
                // Mirror the caller's O_CLOEXEC: dup-semantics would
                // otherwise clear it on the injected descriptor.
                newfd_flags: if cloexec { libc::O_CLOEXEC as u32 } else { 0 },
            };
            // ADDFD re-validates the notification id in the kernel: a
            // task that died between the open and here gets ENOENT, not
            // an injected fd.
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
        let tmp = std::env::temp_dir().join(format!("rauha-broker-recv-{}", std::process::id()));
        let file = std::fs::File::create(&tmp).unwrap();
        send_fds(&ours, &[file.as_raw_fd()]);
        let received = recv_fd(&theirs).expect("one fd hand-off");
        // The received fd is a distinct descriptor for the same file.
        assert_ne!(received.as_raw_fd(), file.as_raw_fd());
        std::fs::remove_file(&tmp).ok();
    }

    #[test]
    fn recv_fd_sets_close_on_exec() {
        // The shim execs helpers; the notify fd must not survive into them.
        let (theirs, ours) = UnixStream::pair().unwrap();
        let file = std::fs::File::open("/dev/null").unwrap();
        send_fds(&ours, &[file.as_raw_fd()]);
        let received = recv_fd(&theirs).expect("one fd hand-off");
        let flags = unsafe { libc::fcntl(received.as_raw_fd(), libc::F_GETFD) };
        assert!(flags & libc::FD_CLOEXEC != 0, "must be close-on-exec");
    }

    #[test]
    fn recv_fd_refuses_truncated_hand_offs() {
        // Two fds cannot fit our one-descriptor control buffer: the kernel
        // truncates (MSG_CTRUNC) and the hand-off must be refused.
        let (theirs, ours) = UnixStream::pair().unwrap();
        let a = std::fs::File::open("/dev/null").unwrap();
        let b = std::fs::File::open("/dev/zero").unwrap();
        send_fds(&ours, &[a.as_raw_fd(), b.as_raw_fd()]);
        assert!(recv_fd(&theirs).is_err(), "truncated cmsg must be refused");
    }

    #[test]
    fn peer_credentials_identify_the_hand_off_peer() {
        // A socketpair's peer is ourselves: the uid check in serve()
        // accepts exactly this relationship.
        let (theirs, ours) = UnixStream::pair().unwrap();
        let peer = peer_credentials(&ours).expect("SO_PEERCRED works on unix sockets");
        assert_eq!(peer.uid, unsafe { libc::getuid() });
        assert_eq!(peer.pid, std::process::id() as libc::pid_t);
        drop(theirs);
    }
}
