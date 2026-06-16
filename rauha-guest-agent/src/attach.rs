//! PTY fork and vsock I/O relay for exec sessions in the guest agent.
//!
//! Mirrors rauha-shim/src/attach.rs but adapted for the VM environment:
//! - No sync pipe / cgroup enrollment (VM is the isolation boundary)
//! - Vsock listener instead of Unix socket listener
//! - Chroot into virtiofs-mounted rootfs at /mnt/rauha/containers/{id}/...

#[cfg(target_os = "linux")]
use std::collections::HashMap;
use std::path::Path;
use std::sync::atomic::{AtomicU32, Ordering};
#[cfg(target_os = "linux")]
use std::sync::{LazyLock, Mutex};

/// Next available vsock port for exec sessions. Starts at 6000 to avoid
/// conflict with the control port (5123).
static NEXT_SESSION_PORT: AtomicU32 = AtomicU32::new(6000);

#[cfg(target_os = "linux")]
static PTY_SESSIONS: LazyLock<Mutex<HashMap<String, i32>>> =
    LazyLock::new(|| Mutex::new(HashMap::new()));

/// Allocate a unique vsock port for an exec session.
pub fn allocate_session_port() -> u32 {
    NEXT_SESSION_PORT.fetch_add(1, Ordering::Relaxed)
}

/// Allocate a PTY pair and fork+exec a command inside a container's rootfs.
///
/// Returns (master_fd, child_pid). The caller owns master_fd and is
/// responsible for closing it when the session ends.
#[cfg(target_os = "linux")]
pub fn fork_and_exec_pty(
    rootfs_root: &Path,
    container_id: &str,
    command: &[String],
    env: &[String],
) -> anyhow::Result<(i32, u32)> {
    use nix::pty::openpty;
    use nix::unistd::{self, ForkResult};
    use std::ffi::CString;
    use std::os::fd::AsRawFd;

    if command.is_empty() {
        anyhow::bail!("exec command is empty");
    }

    let container_dir = rootfs_root.join("containers").join(container_id);
    let rootfs = {
        let merged = container_dir.join("merged");
        let legacy = container_dir.join("rootfs");
        if merged.exists() {
            merged
        } else if legacy.exists() {
            legacy
        } else {
            anyhow::bail!("rootfs not found for container {container_id}");
        }
    };

    let pty = openpty(None, None)?;
    let master_fd = pty.master.as_raw_fd();
    let slave_fd = pty.slave.as_raw_fd();

    let c_args = cstring_vec(command, "exec.command")?;

    let c_env = cstring_vec(env, "exec.env")?;

    // Pre-allocate the TERM fallback before fork so the child can putenv it
    // without allocating. Only use it if the caller didn't already provide TERM.
    let has_term = env.iter().any(|e| e.starts_with("TERM="));
    let term_fallback: Option<CString> = if !has_term {
        Some(CString::new("TERM=xterm-256color")?)
    } else {
        None
    };

    match unsafe { unistd::fork() }? {
        ForkResult::Child => {
            drop(pty.master);

            // New session + controlling terminal.
            let _ = nix::unistd::setsid();

            // Dup slave fd to stdin/stdout/stderr.
            let _ = nix::unistd::dup2(slave_fd, 0);
            let _ = nix::unistd::dup2(slave_fd, 1);
            let _ = nix::unistd::dup2(slave_fd, 2);
            if slave_fd > 2 {
                drop(pty.slave);
            }

            // Set controlling terminal.
            unsafe { libc::ioctl(0, libc::TIOCSCTTY, 0) };

            // Chroot into container rootfs.
            if let Err(e) = nix::unistd::chroot(&rootfs) {
                let msg = format!("chroot failed: {e}\n");
                unsafe {
                    let _ = libc::write(2, msg.as_ptr() as _, msg.len());
                    libc::_exit(1);
                }
            }
            let _ = nix::unistd::chdir("/");

            // Set environment using libc directly — std::env::* are NOT
            // async-signal-safe (they hold a global mutex that may be held
            // by another thread in the parent process after fork).
            unsafe {
                libc::clearenv();
                for var in &c_env {
                    libc::putenv(var.as_ptr() as *mut libc::c_char);
                }
                if let Some(ref t) = term_fallback {
                    libc::putenv(t.as_ptr() as *mut libc::c_char);
                }
            }

            let err = nix::unistd::execvp(&c_args[0], &c_args);
            let msg = format!("execvp failed: {err:?}\n");
            unsafe {
                let _ = libc::write(2, msg.as_ptr() as _, msg.len());
                libc::_exit(127);
            }
        }
        ForkResult::Parent { child } => {
            drop(pty.slave);

            let child_pid = child.as_raw() as u32;

            // No cgroup enrollment needed — the VM is the boundary.
            // Prevent Rust from closing master_fd — the relay thread owns it.
            std::mem::forget(pty.master);

            tracing::info!(
                pid = child_pid,
                container = container_id,
                "exec process forked with PTY"
            );
            Ok((master_fd, child_pid))
        }
    }
}

#[cfg(target_os = "linux")]
fn cstring_vec(values: &[String], field: &str) -> anyhow::Result<Vec<std::ffi::CString>> {
    values
        .iter()
        .enumerate()
        .map(|(idx, value)| {
            std::ffi::CString::new(value.as_str())
                .map_err(|_| anyhow::anyhow!("{field}[{idx}] contains an interior NUL byte"))
        })
        .collect()
}

#[cfg(all(test, target_os = "linux"))]
mod tests {
    use super::cstring_vec;

    #[test]
    fn rejects_interior_nul_in_exec_command() {
        let err = cstring_vec(&["/bin/echo\0bad".to_string()], "exec.command")
            .expect_err("interior NUL must be rejected");

        assert!(err.to_string().contains("exec.command[0]"));
    }
}

/// Spawn a thread that listens on a vsock port, accepts one connection,
/// and relays data between the connection and a PTY master fd.
///
/// The thread closes the PTY master fd when the session ends.
#[cfg(target_os = "linux")]
pub fn serve_vsock_session(
    session_id: &str,
    pty_master_fd: i32,
    vsock_port: u32,
) -> anyhow::Result<()> {
    use nix::poll::{poll, PollFd, PollFlags, PollTimeout};
    use std::os::fd::BorrowedFd;

    const AF_VSOCK: i32 = 40;
    const VMADDR_CID_ANY: u32 = 0xFFFFFFFF;

    #[repr(C)]
    struct SockaddrVm {
        svm_family: u16,
        svm_reserved1: u16,
        svm_port: u32,
        svm_cid: u32,
        svm_zero: [u8; 4],
    }

    // Create and bind the vsock listener before spawning the thread,
    // so the port is ready before we return ExecReady to the host.
    let listen_fd = unsafe { libc::socket(AF_VSOCK, libc::SOCK_STREAM, 0) };
    if listen_fd < 0 {
        anyhow::bail!(
            "failed to create vsock socket: {}",
            std::io::Error::last_os_error()
        );
    }

    let addr = SockaddrVm {
        svm_family: AF_VSOCK as u16,
        svm_reserved1: 0,
        svm_port: vsock_port,
        svm_cid: VMADDR_CID_ANY,
        svm_zero: [0; 4],
    };

    let ret = unsafe {
        libc::bind(
            listen_fd,
            &addr as *const _ as *const libc::sockaddr,
            std::mem::size_of::<SockaddrVm>() as u32,
        )
    };
    if ret < 0 {
        unsafe {
            libc::close(listen_fd);
        }
        anyhow::bail!(
            "failed to bind vsock port {vsock_port}: {}",
            std::io::Error::last_os_error()
        );
    }

    let ret = unsafe { libc::listen(listen_fd, 1) };
    if ret < 0 {
        unsafe {
            libc::close(listen_fd);
        }
        anyhow::bail!(
            "failed to listen on vsock port {vsock_port}: {}",
            std::io::Error::last_os_error()
        );
    }

    // Set listener to nonblocking so we can poll with a timeout before accept.
    let flags = unsafe { libc::fcntl(listen_fd, libc::F_GETFL) };
    if flags >= 0 {
        unsafe { libc::fcntl(listen_fd, libc::F_SETFL, flags | libc::O_NONBLOCK) };
    }

    tracing::info!(port = vsock_port, "exec session vsock listening");
    let session_key = session_id.to_string();

    PTY_SESSIONS
        .lock()
        .map_err(|_| anyhow::anyhow!("PTY session registry is poisoned"))?
        .insert(session_key.clone(), pty_master_fd);

    // Spawn relay thread.
    std::thread::spawn(move || {
        // Accept with a 30s timeout to avoid leaking the PTY if the host
        // never connects (client crash, vsock failure, etc.).
        const ACCEPT_TIMEOUT_MS: i32 = 30_000;

        let conn_fd = loop {
            let mut poll_fds = [PollFd::new(
                unsafe { BorrowedFd::borrow_raw(listen_fd) },
                PollFlags::POLLIN,
            )];

            match poll(&mut poll_fds, PollTimeout::from(ACCEPT_TIMEOUT_MS as u16)) {
                Ok(0) => {
                    tracing::warn!(
                        port = vsock_port,
                        "exec session vsock accept timed out; closing PTY"
                    );
                    if let Ok(mut sessions) = PTY_SESSIONS.lock() {
                        sessions.remove(&session_key);
                    }
                    unsafe {
                        libc::close(pty_master_fd);
                        libc::close(listen_fd);
                    }
                    return;
                }
                Ok(_) => {}
                Err(nix::errno::Errno::EINTR) => continue,
                Err(e) => {
                    tracing::error!(%e, "exec session vsock poll failed");
                    if let Ok(mut sessions) = PTY_SESSIONS.lock() {
                        sessions.remove(&session_key);
                    }
                    unsafe {
                        libc::close(pty_master_fd);
                        libc::close(listen_fd);
                    }
                    return;
                }
            }

            let fd = unsafe { libc::accept(listen_fd, std::ptr::null_mut(), std::ptr::null_mut()) };
            if fd >= 0 {
                break fd;
            }
            let err = std::io::Error::last_os_error();
            if err.kind() == std::io::ErrorKind::WouldBlock {
                continue;
            }
            tracing::error!(%err, "exec session vsock accept failed");
            if let Ok(mut sessions) = PTY_SESSIONS.lock() {
                sessions.remove(&session_key);
            }
            unsafe {
                libc::close(pty_master_fd);
                libc::close(listen_fd);
            }
            return;
        };

        unsafe {
            libc::close(listen_fd);
        }

        // Set send/receive timeouts on the vsock connection to prevent
        // indefinite blocking if the peer stops reading or writing.
        let timeout = libc::timeval {
            tv_sec: 30,
            tv_usec: 0,
        };
        unsafe {
            libc::setsockopt(
                conn_fd,
                libc::SOL_SOCKET,
                libc::SO_SNDTIMEO,
                &timeout as *const _ as *const libc::c_void,
                std::mem::size_of::<libc::timeval>() as u32,
            );
            libc::setsockopt(
                conn_fd,
                libc::SOL_SOCKET,
                libc::SO_RCVTIMEO,
                &timeout as *const _ as *const libc::c_void,
                std::mem::size_of::<libc::timeval>() as u32,
            );
        }

        // Relay loop using poll(2): PTY master <-> vsock connection.
        let mut buf = [0u8; 4096];
        loop {
            let poll_fds = &mut [
                PollFd::new(
                    unsafe { BorrowedFd::borrow_raw(pty_master_fd) },
                    PollFlags::POLLIN,
                ),
                PollFd::new(
                    unsafe { BorrowedFd::borrow_raw(conn_fd) },
                    PollFlags::POLLIN,
                ),
            ];

            match poll(poll_fds, PollTimeout::from(500u16)) {
                Ok(0) => continue,
                Ok(_) => {}
                Err(nix::errno::Errno::EINTR) => continue,
                Err(e) => {
                    tracing::debug!(%e, "poll error, ending exec session");
                    break;
                }
            }

            // PTY master → vsock (container output → host).
            if let Some(revents) = poll_fds[0].revents() {
                if revents.contains(PollFlags::POLLIN) {
                    match nix::unistd::read(pty_master_fd, &mut buf) {
                        Ok(0) | Err(_) => break,
                        Ok(n) => {
                            if write_all_fd(conn_fd, &buf[..n]).is_err() {
                                break;
                            }
                        }
                    }
                }
                if revents.contains(PollFlags::POLLHUP) || revents.contains(PollFlags::POLLERR) {
                    break;
                }
            }

            // Vsock → PTY master (host input → container).
            if let Some(revents) = poll_fds[1].revents() {
                if revents.contains(PollFlags::POLLIN) {
                    match nix::unistd::read(conn_fd, &mut buf) {
                        Ok(0) | Err(_) => break,
                        Ok(n) => {
                            if write_all_fd(pty_master_fd, &buf[..n]).is_err() {
                                break;
                            }
                        }
                    }
                }
                if revents.contains(PollFlags::POLLHUP) || revents.contains(PollFlags::POLLERR) {
                    break;
                }
            }
        }

        if let Ok(mut sessions) = PTY_SESSIONS.lock() {
            sessions.remove(&session_key);
        }
        unsafe {
            libc::close(pty_master_fd);
            libc::close(conn_fd);
        }
        tracing::debug!(port = vsock_port, "exec session ended");
    });

    Ok(())
}

#[cfg(target_os = "linux")]
pub fn resize_pty(session_id: &str, rows: u32, cols: u32) -> anyhow::Result<()> {
    if rows == 0 || cols == 0 || rows > u16::MAX as u32 || cols > u16::MAX as u32 {
        anyhow::bail!("invalid PTY size {rows}x{cols}");
    }

    let pty_master_fd = *PTY_SESSIONS
        .lock()
        .map_err(|_| anyhow::anyhow!("PTY session registry is poisoned"))?
        .get(session_id)
        .ok_or_else(|| anyhow::anyhow!("PTY session {session_id} not found"))?;

    let winsize = libc::winsize {
        ws_row: rows as u16,
        ws_col: cols as u16,
        ws_xpixel: 0,
        ws_ypixel: 0,
    };

    let ret = unsafe { libc::ioctl(pty_master_fd, libc::TIOCSWINSZ, &winsize) };
    if ret < 0 {
        anyhow::bail!("TIOCSWINSZ failed: {}", std::io::Error::last_os_error());
    }

    Ok(())
}

#[cfg(target_os = "linux")]
fn write_all_fd(fd: i32, mut data: &[u8]) -> Result<(), ()> {
    while !data.is_empty() {
        match nix::unistd::write(unsafe { std::os::fd::BorrowedFd::borrow_raw(fd) }, data) {
            Ok(n) => data = &data[n..],
            Err(_) => return Err(()),
        }
    }
    Ok(())
}

// Non-Linux stubs: the guest agent only runs inside Linux VMs,
// but the crate must compile on macOS for workspace checks.

#[cfg(not(target_os = "linux"))]
pub fn fork_and_exec_pty(
    _rootfs_root: &Path,
    _container_id: &str,
    _command: &[String],
    _env: &[String],
) -> anyhow::Result<(i32, u32)> {
    anyhow::bail!("PTY exec is only supported inside Linux VMs")
}

#[cfg(not(target_os = "linux"))]
pub fn serve_vsock_session(
    _session_id: &str,
    _pty_master_fd: i32,
    _vsock_port: u32,
) -> anyhow::Result<()> {
    anyhow::bail!("vsock sessions are only supported inside Linux VMs")
}

#[cfg(not(target_os = "linux"))]
pub fn resize_pty(_session_id: &str, _rows: u32, _cols: u32) -> anyhow::Result<()> {
    anyhow::bail!("PTY resize is only supported inside Linux VMs")
}
