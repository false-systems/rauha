#![cfg(target_os = "linux")]

//! Seccomp-notify broker: the Capsicum-shaped primitive.
//!
//! When a policy marks syscalls as brokered (`[syscalls] broker = [...]`),
//! the OCI seccomp profile emits `SCMP_ACT_NOTIFY` with this module's socket
//! as `listener_path`. crun ships the kernel notify fd here; the workload's
//! brokered syscalls then suspend in the kernel and are judged by the shim:
//!
//! - denied calls return EPERM without ever executing;
//! - granted `openat` calls are satisfied by the *broker* opening the file
//!   (resolved inside the target's root via `/proc/<pid>/root`, read-only)
//!   and injecting it with `SECCOMP_IOCTL_NOTIF_ADDFD`.
//!
//! The workload never exercises ambient authority for brokered calls — it
//! holds only the handles it was given. That is the 1973 fix, one syscall
//! at a time.
//!
//! v0 policy: read-only grants under the container rootfs, deny everything
//! else. Every decision is a log line today; evidence events follow.
//!
//! ABI verified against linux/seccomp.h: `seccomp_notif` embeds
//! `seccomp_data` (80 bytes total on 64-bit), ioctl numbers computed from
//! _IOWR('!', ...) and cross-checked on the target kernel.

use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::Path;

use anyhow::{bail, Context, Result};

// _IOWR('!', 0, struct seccomp_notif) — 80 bytes (id + pid + flags + data)
const SECCOMP_IOCTL_NOTIF_RECV: libc::c_ulong = 0xc050_2100;
// _IOWR('!', 1, struct seccomp_notif_resp) — 24 bytes
const SECCOMP_IOCTL_NOTIF_SEND: libc::c_ulong = 0xc018_2101;
// _IOW('!', 3, struct seccomp_notif_addfd) — 24 bytes
const SECCOMP_IOCTL_NOTIF_ADDFD: libc::c_ulong = 0x4018_2103;

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

/// Serve the seccomp listener socket: accept one connection (crun's
/// listener helper), receive the notify fd, and judge notifications until
/// the fd closes. Runs on its own thread; the container blocks while each
/// decision is made, so the loop must stay fast and panic-free.
pub fn serve(listener_path: &Path) -> Result<()> {
    let _ = std::fs::remove_file(listener_path);
    let listener = UnixListener::bind(listener_path)
        .with_context(|| format!("bind seccomp listener {}", listener_path.display()))?;

    // crun's helper connects and sends the fd; one connection per container.
    let (stream, _) = listener.accept().context("accept seccomp listener")?;
    let notify_fd = recv_fd(&stream).context("receive seccomp notify fd")?;
    let _ = std::fs::remove_file(listener_path);

    judge_loop(notify_fd)
}

/// Receive one SCM_RIGHTS descriptor from the stream.
fn recv_fd(stream: &UnixStream) -> Result<OwnedFd> {
    let mut buf = [0u8; 1];
    let mut cmsg_space = [0u8; unsafe { libc::CMSG_SPACE(1) } as usize];
    let mut msg: libc::msghdr = unsafe { std::mem::zeroed() };
    let mut iov = libc::iovec {
        iov_base: buf.as_mut_ptr() as *mut libc::c_void,
        iov_len: buf.len(),
    };
    msg.msg_iov = &mut iov;
    msg.msg_iovlen = 1;
    msg.msg_control = cmsg_space.as_mut_ptr() as *mut libc::c_void;
    msg.msg_controllen = cmsg_space.len();

    let n = unsafe { libc::recvmsg(stream.as_raw_fd(), &mut msg, 0) };
    if n < 0 {
        bail!(
            "recvmsg on seccomp listener: {}",
            std::io::Error::last_os_error()
        );
    }
    let cmsg = match unsafe { libc::CMSG_FIRSTHDR(&msg).as_ref() } {
        Some(h) => h,
        None => bail!("no control message on seccomp listener"),
    };
    let (level, typ) = (cmsg.cmsg_level, cmsg.cmsg_type);
    if level != libc::SOL_SOCKET || typ != libc::SCM_RIGHTS {
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
                // The container exited and the listener was shut down.
                Some(libc::EBADF) | Some(libc::ESHUTDOWN) => return Ok(()),
                _ => bail!("SECCOMP_IOCTL_NOTIF_RECV: {err}"),
            }
        }

        let decision = judge(&notif);
        respond(fd, &notif, decision)?;
    }
}

/// The v0 policy, applied to one suspended openat(dirfd, path, flags).
fn judge(notif: &SeccompNotif) -> Decision {
    let path_ptr = notif.data.args[1];
    let path = match read_path(notif.pid, path_ptr) {
        Some(p) => p,
        None => {
            tracing::warn!(pid = notif.pid, "broker: unreadable path — denying");
            return Decision::Deny;
        }
    };

    // v0: read-only grants under the container's root, deny the rest.
    //
    // Containment is kernel-enforced, not string-checked: the broker opens
    // the path with openat2(RESOLVE_IN_ROOT) relative to an O_PATH fd of
    // /proc/<pid>/root — symlinks, "..", and magic links cannot escape the
    // container root by construction. (A realpath-prefix check is wrong:
    // canonicalize resolves the /proc magic link away.)
    let path = match std::ffi::CString::new(path.as_str()) {
        Ok(p) => p,
        Err(_) => return Decision::Deny,
    };
    let root_path = std::ffi::CString::new(format!("/proc/{}/root", notif.pid))
        .expect("pid path is a valid CString");

    let root_fd = unsafe { libc::open(root_path.as_ptr(), libc::O_PATH | libc::O_CLOEXEC) };
    if root_fd < 0 {
        let e = std::io::Error::last_os_error();
        tracing::info!(pid = notif.pid, "broker: denied (no root fd: {e})");
        return Decision::Deny;
    }
    let root_fd = unsafe { OwnedFd::from_raw_fd(root_fd) };

    // open_how { flags, mode, resolve } — RESOLVE_IN_ROOT | RESOLVE_NO_MAGICLINKS
    #[repr(C)]
    struct OpenHow {
        flags: u64,
        mode: u64,
        resolve: u64,
    }
    const RESOLVE_NO_MAGICLINKS: u64 = 0x2;
    const RESOLVE_IN_ROOT: u64 = 0x10;
    let how = OpenHow {
        flags: (libc::O_RDONLY | libc::O_CLOEXEC) as u64,
        mode: 0,
        resolve: RESOLVE_IN_ROOT | RESOLVE_NO_MAGICLINKS,
    };

    let fd = unsafe {
        libc::syscall(
            libc::SYS_openat2,
            root_fd.as_raw_fd(),
            path.as_ptr(),
            &how as *const OpenHow,
            std::mem::size_of::<OpenHow>(),
        )
    };
    match fd {
        raw if raw >= 0 => {
            let file = unsafe { OwnedFd::from_raw_fd(raw as libc::c_int) };
            tracing::info!(
                pid = notif.pid,
                "broker: granted read-only fd (openat2 in-root)"
            );
            Decision::InjectFd(std::fs::File::from(file))
        }
        err => {
            let e = std::io::Error::from_raw_os_error(-(err as i32));
            tracing::info!(pid = notif.pid, "broker: denied (openat2: {e})");
            Decision::Deny
        }
    }
}

enum Decision {
    Deny,
    InjectFd(std::fs::File),
}

/// Read a NUL-terminated path from the target's memory at `ptr`.
fn read_path(pid: u32, ptr: u64) -> Option<String> {
    use std::os::unix::fs::FileExt;
    let mem = std::fs::File::open(format!("/proc/{pid}/mem")).ok()?;
    let mut buf = vec![0u8; MAX_PATH];
    let mut len = 0usize;
    loop {
        let n = mem.read_at(&mut buf[len..], ptr + len as u64).ok()?;
        if n == 0 {
            return None;
        }
        len += n;
        if let Some(pos) = buf[..len].iter().position(|&b| b == 0) {
            return String::from_utf8(buf[..pos].to_vec()).ok();
        }
        if len == MAX_PATH {
            return None;
        }
    }
}

/// Send the response for one notification.
fn respond(fd: libc::c_int, notif: &SeccompNotif, decision: Decision) -> Result<()> {
    let mut resp = SeccompNotifResp {
        id: notif.id,
        val: 0,
        error: 0,
        flags: 0,
    };
    match decision {
        Decision::Deny => {
            resp.error = libc::EPERM;
        }
        Decision::InjectFd(file) => {
            let addfd = SeccompNotifAddfd {
                id: notif.id,
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
