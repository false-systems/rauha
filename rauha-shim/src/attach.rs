//! Attach session I/O relay.
//!
//! Each attach/exec session gets its own Unix socket. A dedicated thread
//! runs `poll(2)` to multiplex between the PTY master fd and the socket,
//! relaying data bidirectionally.
//!
//! The socket path is returned to the daemon, which bridges it to the
//! gRPC stream.

use std::path::Path;

/// Create an attach session socket and spawn a relay thread.
///
/// Returns the socket path. The caller (daemon) connects to this socket
/// for bidirectional I/O with the container PTY.
///
/// On Linux, this allocates a PTY pair and relays between them.
/// On non-Linux, returns an error.
#[cfg(target_os = "linux")]
pub fn serve_attach_session(
    container_id: &str,
    session_id: &str,
    pty_master_fd: i32,
) -> anyhow::Result<String> {
    use nix::poll::{poll, PollFd, PollFlags, PollTimeout};
    use std::os::fd::BorrowedFd;
    use std::os::unix::io::AsRawFd;
    use std::os::unix::net::UnixListener;
    use std::path::PathBuf;

    let socket_dir = PathBuf::from("/run/rauha/containers").join(container_id);
    std::fs::create_dir_all(&socket_dir)?;
    let socket_path = socket_dir.join(format!("attach-{session_id}.sock"));

    // Remove stale socket.
    let _ = std::fs::remove_file(&socket_path);

    let listener = UnixListener::bind(&socket_path)?;
    let path_str = socket_path.to_string_lossy().to_string();

    // Spawn a dedicated thread for this attach session.
    std::thread::spawn(move || {
        // Accept exactly one connection.
        let stream = match listener.accept() {
            Ok((stream, _)) => stream,
            Err(e) => {
                tracing::error!(%e, "attach session accept failed");
                return;
            }
        };

        stream.set_nonblocking(true).ok();

        let stream_fd = stream.as_raw_fd();

        // Relay loop using poll(2).
        let mut buf = [0u8; 4096];
        loop {
            let poll_fds = &mut [
                PollFd::new(
                    unsafe { BorrowedFd::borrow_raw(pty_master_fd) },
                    PollFlags::POLLIN,
                ),
                PollFd::new(
                    unsafe { BorrowedFd::borrow_raw(stream_fd) },
                    PollFlags::POLLIN,
                ),
            ];

            match poll(poll_fds, PollTimeout::from(500u16)) {
                Ok(0) => continue, // timeout
                Ok(_) => {}
                Err(nix::errno::Errno::EINTR) => continue,
                Err(e) => {
                    tracing::debug!(%e, "poll error, ending attach session");
                    break;
                }
            }

            // PTY master → socket (container output → client).
            if let Some(revents) = poll_fds[0].revents() {
                if revents.contains(PollFlags::POLLIN) {
                    match nix::unistd::read(pty_master_fd, &mut buf) {
                        Ok(0) | Err(_) => break, // PTY closed
                        Ok(n) => {
                            tracing::debug!(bytes = n, "relay: PTY → socket");
                            if write_all_fd(stream_fd, &buf[..n]).is_err() {
                                break; // client disconnected
                            }
                        }
                    }
                }
                // Read any remaining data before checking POLLHUP.
                // POLLIN and POLLHUP can arrive together — always drain first.
                if revents.contains(PollFlags::POLLHUP) || revents.contains(PollFlags::POLLERR) {
                    // One last read attempt to drain buffered data.
                    while let Ok(n) = nix::unistd::read(pty_master_fd, &mut buf) {
                        if n == 0 {
                            break;
                        }
                        tracing::debug!(bytes = n, "relay: PTY → socket (drain)");
                        if write_all_fd(stream_fd, &buf[..n]).is_err() {
                            break;
                        }
                    }
                    break;
                }
            }

            // Socket → PTY master (client input → container).
            if let Some(revents) = poll_fds[1].revents() {
                if revents.contains(PollFlags::POLLIN) {
                    match nix::unistd::read(stream_fd, &mut buf) {
                        Ok(0) | Err(_) => break, // client disconnected
                        Ok(n) => {
                            if write_all_fd(pty_master_fd, &buf[..n]).is_err() {
                                break; // PTY write failed
                            }
                        }
                    }
                }
                if revents.contains(PollFlags::POLLHUP) || revents.contains(PollFlags::POLLERR) {
                    break;
                }
            }
        }

        // Close PTY master fd now that the relay is done.
        unsafe {
            libc::close(pty_master_fd);
        }

        // Clean up socket.
        let _ = std::fs::remove_file(&socket_path);
        tracing::debug!("attach session ended");
    });

    Ok(path_str)
}

/// Write all bytes to a raw fd.
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

/// Allocate a PTY pair and fork+exec a command, returning (master_fd, child_pid).
#[cfg(target_os = "linux")]
pub fn fork_and_exec_pty(
    zone_name: &str,
    container_id: &str,
    command: &[String],
    env: &[String],
    rootfs_root: &Path,
) -> anyhow::Result<(i32, u32)> {
    use nix::pty::openpty;
    use nix::unistd::{self, ForkResult};
    use std::ffi::CString;
    use std::os::fd::{AsRawFd, BorrowedFd};

    if command.is_empty() {
        anyhow::bail!("exec command is empty");
    }

    // Check rootfs exists (merged or legacy).
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
    let term = CString::new("TERM=xterm-256color")?;

    // Sync pipe for cgroup enrollment.
    let (pipe_rd, pipe_wr) = nix::unistd::pipe()?;
    let rd_raw = pipe_rd.as_raw_fd();
    let wr_raw = pipe_wr.as_raw_fd();

    match unsafe { unistd::fork() }? {
        ForkResult::Child => {
            drop(pipe_wr);
            drop(pty.master);

            // Wait for cgroup enrollment.
            let mut buf = [0u8; 1];
            let _ = nix::unistd::read(rd_raw, &mut buf);
            drop(pipe_rd);

            // New session + set controlling terminal.
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

            // Set environment using libc directly — Rust's std::env functions
            // are NOT async-signal-safe (they hold a global mutex that may be
            // held by another thread in the parent process after fork).
            unsafe {
                libc::clearenv();
                for var in &c_env {
                    libc::putenv(var.as_ptr() as *mut libc::c_char);
                }
                // Set TERM if not already in env.
                libc::putenv(term.as_ptr() as *mut libc::c_char);
            }

            let err = nix::unistd::execvp(&c_args[0], &c_args);
            let msg = format!("execvp failed: {err:?}\n");
            unsafe {
                let _ = libc::write(2, msg.as_ptr() as _, msg.len());
                libc::_exit(127);
            }
        }
        ForkResult::Parent { child } => {
            drop(pipe_rd);
            drop(pty.slave);

            let child_pid = child.as_raw() as u32;

            // Enroll child in zone cgroup.
            let cgroup_path = format!("/sys/fs/cgroup/rauha.slice/zone-{zone_name}/cgroup.procs");
            if let Err(e) = std::fs::write(&cgroup_path, child_pid.to_string()) {
                tracing::warn!(%e, cgroup = cgroup_path, "failed to enroll exec child in cgroup");
            }

            // Signal child to proceed.
            let _ = nix::unistd::write(unsafe { BorrowedFd::borrow_raw(wr_raw) }, &[1u8]);
            drop(pipe_wr);

            // Prevent Rust from closing master_fd when pty.master drops —
            // the relay thread owns the fd and closes it via libc::close()
            // when the session ends (see serve_attach_session).
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
    fn rejects_interior_nul_in_exec_env() {
        let err = cstring_vec(&["KEY=value\0tail".to_string()], "exec.env")
            .expect_err("interior NUL must be rejected");

        assert!(err.to_string().contains("exec.env[0]"));
    }
}

/// Non-Linux stub.
#[cfg(not(target_os = "linux"))]
pub fn serve_attach_session(
    _container_id: &str,
    _session_id: &str,
    _pty_master_fd: i32,
) -> anyhow::Result<String> {
    anyhow::bail!("attach sessions are only supported on Linux")
}

/// Non-Linux stub.
#[cfg(not(target_os = "linux"))]
pub fn fork_and_exec_pty(
    _zone_name: &str,
    _container_id: &str,
    _command: &[String],
    _env: &[String],
    _rootfs_root: &Path,
) -> anyhow::Result<(i32, u32)> {
    anyhow::bail!("PTY exec is only supported on Linux")
}
