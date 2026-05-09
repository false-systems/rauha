use std::path::Path;

/// Fork a child process, set up rootfs, and run the container workload.
///
/// Flow:
/// 1. Create sync pipe
/// 2. fork()
/// 3. Child: block on pipe -> pivot_root -> execvp
/// 4. Parent: write child PID to zone cgroup -> signal pipe -> return PID
///
/// Note: This uses execvp (not shell exec) - no shell injection possible.
/// The child process image is replaced entirely by the container command.
#[cfg(target_os = "linux")]
pub fn fork_and_exec(
    zone_name: &str,
    container_id: &str,
    spec_json: &str,
    rootfs_root: &Path,
) -> anyhow::Result<u32> {
    use nix::unistd::{self, ForkResult};
    use oci_spec::runtime::Spec;
    use std::ffi::CString;
    use std::os::fd::{AsRawFd, BorrowedFd};
    use std::path::PathBuf;

    let spec: Spec = serde_json::from_str(spec_json)?;

    let process = spec
        .process()
        .as_ref()
        .ok_or_else(|| anyhow::anyhow!("spec missing process"))?;
    let args = process
        .args()
        .as_ref()
        .ok_or_else(|| anyhow::anyhow!("spec missing process.args"))?;
    if args.is_empty() {
        anyhow::bail!("process.args is empty");
    }

    // Check both overlayfs (merged/) and legacy (rootfs/) paths.
    let container_dir = rootfs_root.join("containers").join(container_id);
    let rootfs = {
        let merged = container_dir.join("merged");
        let legacy = container_dir.join("rootfs");
        if merged.exists() {
            merged
        } else if legacy.exists() {
            legacy
        } else {
            anyhow::bail!(
                "rootfs not found: checked {} and {}",
                merged.display(),
                legacy.display()
            );
        }
    };

    // Set up stdio log directory.
    let log_dir = PathBuf::from("/run/rauha/containers").join(container_id);
    std::fs::create_dir_all(&log_dir)?;

    // Create sync pipe. OwnedFd closes automatically on drop.
    let (pipe_rd, pipe_wr) = nix::unistd::pipe()?;

    // Prepare C strings before fork (allocation not async-signal-safe after fork).
    let c_args: Vec<CString> = args
        .iter()
        .map(|a| CString::new(a.as_str()).unwrap())
        .collect();

    let env_vars: Vec<CString> = process
        .env()
        .as_ref()
        .map(|vars| {
            vars.iter()
                .map(|e| CString::new(e.as_str()).unwrap())
                .collect::<Vec<CString>>()
        })
        .unwrap_or_default();

    let cwd = process.cwd().to_string_lossy().to_string();
    let cwd_cstr = CString::new(cwd.as_str())?;

    let hostname = spec.hostname().clone();

    // Pre-allocate log file paths as CStrings for signal-safe use after fork.
    let stdout_log = std::ffi::CString::new(
        log_dir.join("stdout.log").to_string_lossy().as_bytes(),
    ).unwrap_or_default();
    let stderr_log = std::ffi::CString::new(
        log_dir.join("stderr.log").to_string_lossy().as_bytes(),
    ).unwrap_or_default();

    // Convert OwnedFd to raw fds for use across fork.
    // We manage lifetime manually after fork (child/parent each close their end).
    let rd_raw = pipe_rd.as_raw_fd();
    let wr_raw = pipe_wr.as_raw_fd();

    // Fork.
    match unsafe { unistd::fork() }? {
        ForkResult::Child => {
            // Drop the write end (closes it).
            drop(pipe_wr);

            // Block until parent confirms cgroup enrollment.
            let mut buf = [0u8; 1];
            let _ = nix::unistd::read(rd_raw, &mut buf);
            // Drop the read end.
            drop(pipe_rd);

            // New session.
            let _ = nix::unistd::setsid();

            // Redirect stdout/stderr to log files.
            // Uses raw open() with pre-allocated CStrings — async-signal-safe.
            redirect_stdio_raw(&stdout_log, &stderr_log);

            // Enter a new mount namespace and make all mounts private.
            // pivot_root requires: (1) own mount namespace, (2) private root mount.
            // Without MS_PRIVATE|MS_REC, inherited shared mounts cause EINVAL.
            if let Err(e) = nix::sched::unshare(nix::sched::CloneFlags::CLONE_NEWNS) {
                let msg = format!("unshare(CLONE_NEWNS) failed: {e}\n");
                unsafe {
                    let _ = libc::write(2, msg.as_ptr() as _, msg.len());
                    libc::_exit(1);
                }
            }
            // Make all mounts private — required for pivot_root to work.
            if let Err(e) = nix::mount::mount(
                None::<&str>,
                "/",
                None::<&str>,
                nix::mount::MsFlags::MS_PRIVATE | nix::mount::MsFlags::MS_REC,
                None::<&str>,
            ) {
                let msg = format!("mount(MS_PRIVATE) failed: {e}\n");
                unsafe {
                    let _ = libc::write(2, msg.as_ptr() as _, msg.len());
                    libc::_exit(1);
                }
            }

            // pivot_root into the container rootfs.
            if let Err(e) = do_pivot_root(&rootfs) {
                let msg = format!("pivot_root failed: {e}\n");
                unsafe {
                    let _ = libc::write(2, msg.as_ptr() as _, msg.len());
                    libc::_exit(1);
                }
            }

            // Set hostname.
            if let Some(ref h) = hostname {
                let _ = nix::unistd::sethostname(h);
            }

            // Set environment using libc directly — bypasses Rust's env mutex.
            // std::env::set_var/remove_var are NOT async-signal-safe (they hold
            // a global lock that may be held by the parent process's other threads).
            unsafe {
                libc::clearenv();
                for var in &env_vars {
                    // CString is pre-allocated before fork — no allocation here.
                    libc::putenv(var.as_ptr() as *mut libc::c_char);
                }
            }

            // chdir.
            let _ = nix::unistd::chdir(cwd_cstr.as_c_str());

            // Replace process with container command (execvp, no shell involved).
            let err = nix::unistd::execvp(&c_args[0], &c_args);
            let msg = format!("execvp failed: {err:?}\n");
            unsafe {
                let _ = libc::write(2, msg.as_ptr() as _, msg.len());
                libc::_exit(127);
            }
        }
        ForkResult::Parent { child } => {
            // Drop read end (closes it).
            drop(pipe_rd);

            let child_pid = child.as_raw() as u32;

            // Enroll child in zone cgroup.
            let cgroup_path = format!(
                "/sys/fs/cgroup/rauha.slice/zone-{zone_name}/cgroup.procs"
            );
            if let Err(e) = std::fs::write(&cgroup_path, child_pid.to_string()) {
                tracing::warn!(%e, cgroup = cgroup_path, "failed to enroll child in cgroup");
            }

            // Signal child to proceed (unblock from sync pipe).
            let _ = nix::unistd::write(unsafe { BorrowedFd::borrow_raw(wr_raw) }, &[1u8]);
            // Drop write end (closes it).
            drop(pipe_wr);

            tracing::info!(pid = child_pid, container = container_id, "child forked");
            Ok(child_pid)
        }
    }
}

/// Non-Linux stub.
#[cfg(not(target_os = "linux"))]
pub fn fork_and_exec(
    _zone_name: &str,
    _container_id: &str,
    _spec_json: &str,
    _rootfs_root: &Path,
) -> anyhow::Result<u32> {
    anyhow::bail!("fork_and_exec is only supported on Linux")
}

/// Send a signal to a process.
pub fn send_signal(pid: u32, signal: i32) -> anyhow::Result<()> {
    #[cfg(target_os = "linux")]
    {
        use nix::sys::signal::{self, Signal};
        use nix::unistd::Pid;

        let sig = Signal::try_from(signal)?;
        signal::kill(Pid::from_raw(pid as i32), sig)?;
        Ok(())
    }

    #[cfg(not(target_os = "linux"))]
    {
        let _ = (pid, signal);
        anyhow::bail!("signal not supported on this platform")
    }
}

/// Try to reap a child process (non-blocking). Returns exit code if exited.
pub fn try_wait(pid: u32) -> Option<i32> {
    #[cfg(target_os = "linux")]
    {
        use nix::sys::wait::{waitpid, WaitPidFlag, WaitStatus};
        use nix::unistd::Pid;

        match waitpid(Pid::from_raw(pid as i32), Some(WaitPidFlag::WNOHANG)) {
            Ok(WaitStatus::Exited(_, code)) => Some(code),
            Ok(WaitStatus::Signaled(_, sig, _)) => Some(128 + sig as i32),
            _ => None,
        }
    }

    #[cfg(not(target_os = "linux"))]
    {
        let _ = pid;
        None
    }
}

/// Perform pivot_root to change the container's root filesystem.
#[cfg(target_os = "linux")]
fn do_pivot_root(new_root: &Path) -> anyhow::Result<()> {
    use nix::mount::{mount, umount2, MntFlags, MsFlags};

    // Bind-mount new_root onto itself (required by pivot_root).
    mount(
        Some(new_root),
        new_root,
        None::<&str>,
        MsFlags::MS_BIND | MsFlags::MS_REC,
        None::<&str>,
    )?;

    let old_root = new_root.join(".pivot_old");
    std::fs::create_dir_all(&old_root)?;

    nix::unistd::pivot_root(new_root, &old_root)?;
    nix::unistd::chdir("/")?;

    // Unmount old root.
    umount2("/.pivot_old", MntFlags::MNT_DETACH)?;
    std::fs::remove_dir("/.pivot_old").ok();

    Ok(())
}

/// Redirect stdout and stderr to log files.
#[cfg(target_os = "linux")]
/// Redirect stdout/stderr to log files using raw open() syscall.
///
/// Async-signal-safe: uses pre-allocated CStrings and libc::open directly.
/// No Rust allocation, no File::create, no global locks.
fn redirect_stdio_raw(stdout_path: &std::ffi::CStr, stderr_path: &std::ffi::CStr) {
    unsafe {
        let fd = libc::open(
            stdout_path.as_ptr(),
            libc::O_WRONLY | libc::O_CREAT | libc::O_TRUNC,
            0o644,
        );
        if fd >= 0 {
            libc::dup2(fd, 1);
            libc::close(fd);
        }

        let fd = libc::open(
            stderr_path.as_ptr(),
            libc::O_WRONLY | libc::O_CREAT | libc::O_TRUNC,
            0o644,
        );
        if fd >= 0 {
            libc::dup2(fd, 2);
            libc::close(fd);
        }
    }
}
