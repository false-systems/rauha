//! Attach session I/O relay.
//!
//! Each attach/exec session gets its own Unix socket. A dedicated thread
//! runs `poll(2)` to multiplex between the PTY master fd and the socket,
//! relaying data bidirectionally.
//!
//! The socket path is returned to the daemon, which bridges it to the
//! gRPC stream.

use std::path::Path;

#[cfg(target_os = "linux")]
use std::collections::HashMap;
#[cfg(target_os = "linux")]
use std::sync::{LazyLock, Mutex};

#[cfg(target_os = "linux")]
static PTY_SESSIONS: LazyLock<Mutex<HashMap<String, i32>>> =
    LazyLock::new(|| Mutex::new(HashMap::new()));

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

    let socket_dir = crate::container::run_dir()
        .join("containers")
        .join(container_id);
    std::fs::create_dir_all(&socket_dir)?;
    let socket_path = socket_dir.join(format!("attach-{session_id}.sock"));

    // Remove stale socket.
    let _ = std::fs::remove_file(&socket_path);

    let listener = UnixListener::bind(&socket_path)?;
    let path_str = socket_path.to_string_lossy().to_string();
    let session_key = session_id.to_string();

    PTY_SESSIONS
        .lock()
        .map_err(|_| anyhow::anyhow!("PTY session registry is poisoned"))?
        .insert(session_key.clone(), pty_master_fd);

    // Spawn a dedicated thread for this attach session.
    std::thread::spawn(move || {
        // Accept exactly one connection.
        let stream = match listener.accept() {
            Ok((stream, _)) => stream,
            Err(e) => {
                tracing::error!(%e, "attach session accept failed");
                if let Ok(mut sessions) = PTY_SESSIONS.lock() {
                    sessions.remove(&session_key);
                }
                unsafe {
                    libc::close(pty_master_fd);
                }
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

        if let Ok(mut sessions) = PTY_SESSIONS.lock() {
            sessions.remove(&session_key);
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

#[cfg(target_os = "linux")]
struct ContainerNamespaces {
    root: std::fs::File,
    mount: std::fs::File,
    uts: std::fs::File,
    ipc: std::fs::File,
    network: std::fs::File,
    pid: std::fs::File,
}

#[cfg(target_os = "linux")]
impl ContainerNamespaces {
    fn open(pid: u32) -> anyhow::Result<Self> {
        let proc = std::path::PathBuf::from(format!("/proc/{pid}"));
        Ok(Self {
            root: std::fs::File::open(proc.join("root"))?,
            mount: std::fs::File::open(proc.join("ns/mnt"))?,
            uts: std::fs::File::open(proc.join("ns/uts"))?,
            ipc: std::fs::File::open(proc.join("ns/ipc"))?,
            network: std::fs::File::open(proc.join("ns/net"))?,
            pid: std::fs::File::open(proc.join("ns/pid"))?,
        })
    }

    /// Enter all non-user namespaces. PID membership takes effect for the next
    /// child, which fork_and_exec_pty creates immediately afterward.
    fn enter(&self) -> bool {
        [
            (&self.mount, nix::sched::CloneFlags::CLONE_NEWNS),
            (&self.uts, nix::sched::CloneFlags::CLONE_NEWUTS),
            (&self.ipc, nix::sched::CloneFlags::CLONE_NEWIPC),
            (&self.network, nix::sched::CloneFlags::CLONE_NEWNET),
            (&self.pid, nix::sched::CloneFlags::CLONE_NEWPID),
        ]
        .into_iter()
        .all(|(namespace, flag)| nix::sched::setns(namespace, flag).is_ok())
    }
}

#[cfg(target_os = "linux")]
#[allow(clippy::too_many_arguments)]
fn exec_child(
    namespaces: ContainerNamespaces,
    pty_slave: std::os::fd::OwnedFd,
    setup_wr: std::os::fd::OwnedFd,
    ready_wr: std::os::fd::OwnedFd,
    go_rd: std::os::fd::OwnedFd,
    slave_fd: i32,
    go_rd_raw: i32,
    process_security: crate::container::ProcessSecurity,
    cap_last_cap: u32,
    args: &[std::ffi::CString],
    env: &[std::ffi::CString],
    term: &std::ffi::CString,
) -> ! {
    use std::os::fd::AsRawFd;

    drop(setup_wr);
    let _ = nix::unistd::setsid();
    let _ = nix::unistd::dup2(slave_fd, 0);
    let _ = nix::unistd::dup2(slave_fd, 1);
    let _ = nix::unistd::dup2(slave_fd, 2);
    if slave_fd > 2 {
        drop(pty_slave);
    }
    unsafe {
        libc::ioctl(0, libc::TIOCSCTTY, 0);
    }

    let root_ok = unsafe {
        libc::fchdir(namespaces.root.as_raw_fd()) == 0
            && libc::chroot(c".".as_ptr()) == 0
            && libc::chdir(c"/".as_ptr()) == 0
    };
    drop(namespaces);
    if !root_ok {
        unsafe {
            let msg = b"rauha-shim: exec root entry failed\n";
            let _ = libc::write(2, msg.as_ptr() as _, msg.len());
            libc::_exit(1);
        }
    }

    if crate::container::apply_process_security(process_security, cap_last_cap).is_err() {
        unsafe {
            let msg = b"rauha-shim: exec process security failed\n";
            let _ = libc::write(2, msg.as_ptr() as _, msg.len());
            libc::_exit(1);
        }
    }

    let _ = nix::unistd::write(&ready_wr, &[1u8]);
    drop(ready_wr);
    let mut buf = [0u8; 1];
    let enrolled = matches!(nix::unistd::read(go_rd_raw, &mut buf), Ok(1));
    drop(go_rd);
    if !enrolled {
        unsafe {
            let msg = b"rauha-shim: exec cgroup enrollment failed\n";
            let _ = libc::write(2, msg.as_ptr() as _, msg.len());
            libc::_exit(125);
        }
    }

    unsafe {
        libc::clearenv();
        for var in env {
            libc::putenv(var.as_ptr() as *mut libc::c_char);
        }
        libc::putenv(term.as_ptr() as *mut libc::c_char);
    }
    let _ = nix::unistd::execvp(&args[0], args);
    unsafe {
        let msg = b"rauha-shim: execvp failed\n";
        let _ = libc::write(2, msg.as_ptr() as _, msg.len());
        libc::_exit(127);
    }
}

/// Allocate a PTY pair and fork+exec a command, returning (master_fd, child_pid).
#[cfg(target_os = "linux")]
pub fn fork_and_exec_pty(
    zone_name: &str,
    container_id: &str,
    init_pid: u32,
    command: &[String],
    env: &[String],
    spec_json: &str,
    rootfs_root: &Path,
) -> anyhow::Result<(i32, u32)> {
    use nix::pty::openpty;
    use nix::unistd::{self, ForkResult};
    use std::ffi::CString;
    use std::os::fd::{AsRawFd, BorrowedFd};

    if command.is_empty() {
        anyhow::bail!("exec command is empty");
    }

    if init_pid == 0 {
        anyhow::bail!("container {container_id} is not running");
    }

    // Check rootfs exists (merged or legacy).
    let container_dir = rootfs_root.join("containers").join(container_id);
    if !container_dir.join("merged").exists() && !container_dir.join("rootfs").exists() {
        anyhow::bail!("rootfs not found for container {container_id}");
    }
    let namespaces = ContainerNamespaces::open(init_pid)?;

    let pty = openpty(None, None)?;
    let master_fd = pty.master.as_raw_fd();
    let slave_fd = pty.slave.as_raw_fd();

    let c_args = cstring_vec(command, "exec.command")?;

    let c_env = cstring_vec(env, "exec.env")?;
    let term = CString::new("TERM=xterm-256color")?;
    let spec: oci_spec::runtime::Spec = serde_json::from_str(spec_json)?;
    if spec
        .linux()
        .as_ref()
        .is_some_and(|linux| linux.seccomp().is_some())
    {
        anyhow::bail!("interactive exec is disabled for seccomp-filtered containers");
    }
    let process = spec
        .process()
        .as_ref()
        .ok_or_else(|| anyhow::anyhow!("spec missing process"))?;
    let process_security = crate::container::ProcessSecurity::from_process(process)?;
    let cap_last_cap = std::fs::read_to_string("/proc/sys/kernel/cap_last_cap")?
        .trim()
        .parse::<u32>()?
        .min(63);

    // Two-phase handshake: trusted chroot and privilege drop happen before
    // enrollment; image code starts only after enrollment succeeds.
    let (setup_rd, setup_wr) = nix::unistd::pipe()?;
    let (go_rd, go_wr) = nix::unistd::pipe()?;
    let (ready_rd, ready_wr) = nix::unistd::pipe()?;
    let setup_rd_raw = setup_rd.as_raw_fd();
    let setup_wr_raw = setup_wr.as_raw_fd();
    let go_rd_raw = go_rd.as_raw_fd();
    let go_wr_raw = go_wr.as_raw_fd();

    match unsafe { unistd::fork() }? {
        ForkResult::Child => {
            drop(setup_rd);
            drop(go_wr);
            drop(pty.master);
            if !namespaces.enter() {
                unsafe {
                    let msg = b"rauha-shim: exec namespace entry failed\n";
                    let _ = libc::write(2, msg.as_ptr() as _, msg.len());
                    libc::_exit(1);
                }
            }

            // setns(CLONE_NEWPID) applies to the next child, so a second clone
            // is required for the exec process itself to enter the container's
            // PID namespace.
            match crate::container::clone_process(0) {
                Ok(ForkResult::Child) => exec_child(
                    namespaces,
                    pty.slave,
                    setup_wr,
                    ready_wr,
                    go_rd,
                    slave_fd,
                    go_rd_raw,
                    process_security,
                    cap_last_cap,
                    &c_args,
                    &c_env,
                    &term,
                ),
                Ok(ForkResult::Parent { child: exec_child }) => unsafe {
                    drop(namespaces);
                    drop(pty.slave);
                    drop(go_rd);
                    drop(ready_wr);
                    let mut ready = [0u8; 1];
                    let is_ready =
                        matches!(nix::unistd::read(ready_rd.as_raw_fd(), &mut ready), Ok(1));
                    drop(ready_rd);
                    if is_ready {
                        let pid = exec_child.as_raw().to_ne_bytes();
                        let _ = libc::write(setup_wr_raw, pid.as_ptr() as _, pid.len());
                    }
                    drop(setup_wr);
                    let mut status = 0;
                    let _ = libc::waitpid(exec_child.as_raw(), &mut status, 0);
                    if libc::WIFEXITED(status) {
                        libc::_exit(libc::WEXITSTATUS(status));
                    }
                    if libc::WIFSIGNALED(status) {
                        libc::_exit(128 + libc::WTERMSIG(status));
                    }
                    libc::_exit(125);
                },
                Err(_) => unsafe {
                    let msg = b"rauha-shim: exec namespace clone failed\n";
                    let _ = libc::write(2, msg.as_ptr() as _, msg.len());
                    libc::_exit(1);
                },
            }
        }
        ForkResult::Parent { child } => {
            drop(setup_wr);
            drop(go_rd);
            drop(pty.slave);
            drop(ready_rd);
            drop(ready_wr);
            drop(namespaces);

            let mut buf = [0u8; std::mem::size_of::<libc::pid_t>()];
            let setup_ok =
                matches!(nix::unistd::read(setup_rd_raw, &mut buf), Ok(n) if n == buf.len());
            drop(setup_rd);
            if !setup_ok {
                drop(go_wr);
                let _ = nix::sys::wait::waitpid(child, None);
                anyhow::bail!("exec child failed during trusted setup");
            }
            let child_pid = i32::from_ne_bytes(buf) as u32;
            let exec_pid = nix::unistd::Pid::from_raw(child_pid as i32);

            // Enroll child in zone cgroup.
            let cgroup_path = format!("/sys/fs/cgroup/rauha.slice/zone-{zone_name}/cgroup.procs");
            if let Err(e) = std::fs::write(&cgroup_path, child_pid.to_string()) {
                let _ = nix::sys::signal::kill(exec_pid, nix::sys::signal::Signal::SIGKILL);
                let _ = nix::sys::wait::waitpid(child, None);
                drop(go_wr);
                anyhow::bail!("failed to enroll exec child in zone cgroup {cgroup_path}: {e}");
            }

            // Signal child to proceed.
            let signaled = nix::unistd::write(unsafe { BorrowedFd::borrow_raw(go_wr_raw) }, &[1u8]);
            drop(go_wr);
            if !matches!(signaled, Ok(1)) {
                let _ = nix::sys::signal::kill(exec_pid, nix::sys::signal::Signal::SIGKILL);
                let _ = nix::sys::wait::waitpid(child, None);
                anyhow::bail!("exec child exited before workload start");
            }

            // Prevent Rust from closing master_fd when pty.master drops —
            // the relay thread owns the fd and closes it via libc::close()
            // when the session ends (see serve_attach_session).
            std::mem::forget(pty.master);
            std::thread::spawn(move || {
                let _ = nix::sys::wait::waitpid(child, None);
            });

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

#[cfg(not(target_os = "linux"))]
pub fn resize_pty(_session_id: &str, _rows: u32, _cols: u32) -> anyhow::Result<()> {
    anyhow::bail!("PTY resize is only supported on Linux")
}

/// Non-Linux stub.
#[cfg(not(target_os = "linux"))]
pub fn fork_and_exec_pty(
    _zone_name: &str,
    _container_id: &str,
    _init_pid: u32,
    _command: &[String],
    _env: &[String],
    _spec_json: &str,
    _rootfs_root: &Path,
) -> anyhow::Result<(i32, u32)> {
    anyhow::bail!("PTY exec is only supported on Linux")
}
