//! Attach session I/O relay.
//!
//! Each attach/exec session gets its own Unix socket. A dedicated thread
//! runs `poll(2)` to multiplex between the PTY master fd and the socket,
//! relaying data bidirectionally.
//!
//! The socket path is returned to the daemon, which bridges it to the
//! gRPC stream.

#[cfg(target_os = "linux")]
use std::collections::HashMap;
#[cfg(target_os = "linux")]
use std::sync::{LazyLock, Mutex};

#[cfg(target_os = "linux")]
static PTY_SESSIONS: LazyLock<Mutex<HashMap<String, i32>>> =
    LazyLock::new(|| Mutex::new(HashMap::new()));

/// Only signals on disconnect; ShimState remains the sole waitpid owner.
#[cfg(target_os = "linux")]
struct DisconnectProcess(std::fs::File);
#[cfg(target_os = "linux")]
impl Drop for DisconnectProcess {
    fn drop(&mut self) {
        use std::os::fd::AsRawFd;
        unsafe {
            libc::syscall(
                libc::SYS_pidfd_send_signal,
                self.0.as_raw_fd(),
                libc::SIGKILL,
                std::ptr::null::<libc::siginfo_t>(),
                0,
            );
        }
    }
}

/// Create an attach session socket and spawn a relay thread.
///
/// Returns the socket path. The caller (daemon) connects to this socket
/// for bidirectional I/O with the container PTY.
///
/// On Linux, this allocates a PTY pair and relays between them.
/// On non-Linux, returns an error.
#[cfg(target_os = "linux")]
pub fn serve_attach_session(
    _container_id: &str,
    session_id: &str,
    master: std::fs::File,
    signal: std::fs::File,
) -> anyhow::Result<String> {
    use nix::poll::{poll, PollFd, PollFlags, PollTimeout};
    use std::os::fd::BorrowedFd;
    use std::os::unix::fs::PermissionsExt;
    use std::os::unix::io::AsRawFd;
    use std::os::unix::net::UnixListener;

    let disconnect = DisconnectProcess(signal);
    let pty_master_fd = master.as_raw_fd();
    let socket_dir = tempfile::Builder::new()
        .prefix("rauha-attach-")
        .permissions(std::fs::Permissions::from_mode(0o700))
        .tempdir_in("/tmp")?;
    let socket_path = socket_dir.path().join("attach.sock");

    let listener = UnixListener::bind(&socket_path)?;
    listener.set_nonblocking(true)?;
    let path_str = socket_path.to_string_lossy().to_string();
    let session_key = session_id.to_string();

    PTY_SESSIONS
        .lock()
        .map_err(|_| anyhow::anyhow!("PTY session registry is poisoned"))?
        .insert(session_key.clone(), pty_master_fd);

    // Spawn a dedicated thread for this attach session.
    let cleanup_path = socket_path.clone();
    let cleanup_key = session_key.clone();
    let relay = std::thread::Builder::new()
        .name("interactive-io".into())
        .spawn(move || {
            let _disconnect = disconnect;
            let _socket_dir = socket_dir;
            // Accept exactly one connection.
            let deadline = std::time::Instant::now() + std::time::Duration::from_secs(30);
            let stream = loop {
                match listener.accept() {
                    Ok((stream, _)) => break stream,
                    Err(e)
                        if e.kind() == std::io::ErrorKind::WouldBlock
                            && std::time::Instant::now() < deadline =>
                    {
                        std::thread::sleep(std::time::Duration::from_millis(10));
                        continue;
                    }
                    Err(e) => {
                        tracing::error!(%e, "attach session accept failed");
                        if let Ok(mut sessions) = PTY_SESSIONS.lock() {
                            sessions.remove(&session_key);
                        }
                        drop(master);
                        let _ = std::fs::remove_file(&socket_path);
                        return;
                    }
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
                    if revents.contains(PollFlags::POLLHUP) || revents.contains(PollFlags::POLLERR)
                    {
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
                    if revents.contains(PollFlags::POLLHUP) || revents.contains(PollFlags::POLLERR)
                    {
                        break;
                    }
                }
            }

            if let Ok(mut sessions) = PTY_SESSIONS.lock() {
                sessions.remove(&session_key);
            }

            // Close PTY master fd now that the relay is done.
            drop(master);

            // Clean up socket.
            let _ = std::fs::remove_file(&socket_path);
            tracing::debug!("attach session ended");
        });

    if let Err(error) = relay {
        if let Ok(mut sessions) = PTY_SESSIONS.lock() {
            sessions.remove(&cleanup_key);
        }
        let _ = std::fs::remove_file(cleanup_path);
        return Err(error.into());
    }

    Ok(path_str)
}

#[cfg(target_os = "linux")]
pub fn resize_pty(session_id: &str, rows: u32, cols: u32) -> anyhow::Result<()> {
    if rows == 0 || cols == 0 || rows > u16::MAX as u32 || cols > u16::MAX as u32 {
        anyhow::bail!("invalid PTY size {rows}x{cols}");
    }

    let sessions = PTY_SESSIONS
        .lock()
        .map_err(|_| anyhow::anyhow!("PTY session registry is poisoned"))?;
    let pty_master_fd = *sessions
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

/// Write all bytes to a raw fd.
#[cfg(target_os = "linux")]
fn write_all_fd(fd: i32, mut data: &[u8]) -> Result<(), ()> {
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(30);
    while !data.is_empty() {
        match nix::unistd::write(unsafe { std::os::fd::BorrowedFd::borrow_raw(fd) }, data) {
            Ok(0) => return Err(()),
            Ok(n) => data = &data[n..],
            Err(nix::errno::Errno::EINTR) => continue,
            Err(nix::errno::Errno::EAGAIN) if std::time::Instant::now() < deadline => {
                std::thread::sleep(std::time::Duration::from_millis(10))
            }
            Err(_) => return Err(()),
        }
    }
    Ok(())
}

/// Non-Linux stub.
#[cfg(not(target_os = "linux"))]
pub fn serve_attach_session(
    _container_id: &str,
    _session_id: &str,
    _master: std::fs::File,
    _signal: std::fs::File,
) -> anyhow::Result<String> {
    anyhow::bail!("attach sessions are only supported on Linux")
}

#[cfg(not(target_os = "linux"))]
pub fn resize_pty(_session_id: &str, _rows: u32, _cols: u32) -> anyhow::Result<()> {
    anyhow::bail!("PTY resize is only supported on Linux")
}
