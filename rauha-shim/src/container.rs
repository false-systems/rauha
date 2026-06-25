use std::path::Path;

/// Fork a child process, set up rootfs, and run the container workload.
///
/// Flow (two-phase handshake):
/// 1. Create two sync pipes (setup: child->parent, go: parent->child)
/// 2. fork()
/// 3. Child: privileged setup (unshare/mount/pivot_root) -> signal "setup done"
///    -> block on "go" -> execvp the workload
/// 4. Parent: wait for "setup done" -> enroll child PID in zone cgroup
///    -> signal "go" -> return PID
///
/// The privileged bootstrap runs *before* cgroup enrollment, so the eBPF
/// `capable` hook does not judge rauha's own CAP_SYS_ADMIN setup against the
/// workload's policy. The untrusted workload (`execvp`) is started only after
/// enrollment is confirmed, so the TOCTOU enforcement boundary still holds:
/// no image code ever runs outside the zone. Enrollment failure is fatal —
/// the workload is never started unenforced (fail closed).
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

    // Two sync pipes for the two-phase handshake. OwnedFd closes on drop.
    //   setup pipe: child -> parent ("privileged setup done, safe to enroll")
    //   go pipe:    parent -> child ("enrolled, proceed to exec the workload")
    let (setup_rd, setup_wr) = nix::unistd::pipe()?;
    let (go_rd, go_wr) = nix::unistd::pipe()?;

    // Prepare C strings before fork (allocation not async-signal-safe after fork).
    let c_args = cstring_vec(args, "process.args")?;

    let env_vars = process
        .env()
        .as_ref()
        .map(|vars| cstring_vec(vars, "process.env"))
        .transpose()?
        .unwrap_or_default();

    let cwd = process.cwd().to_string_lossy().to_string();
    let cwd_cstr = CString::new(cwd.as_str())?;

    let hostname = spec.hostname().clone();

    // Pre-allocate log file paths as CStrings for signal-safe use after fork.
    let stdout_log =
        std::ffi::CString::new(log_dir.join("stdout.log").to_string_lossy().as_bytes())
            .unwrap_or_default();
    let stderr_log =
        std::ffi::CString::new(log_dir.join("stderr.log").to_string_lossy().as_bytes())
            .unwrap_or_default();

    // Convert OwnedFds to raw fds for use across fork.
    // We manage lifetime manually after fork (each side closes the ends it
    // does not use, by dropping the corresponding OwnedFd).
    let setup_rd_raw = setup_rd.as_raw_fd();
    let setup_wr_raw = setup_wr.as_raw_fd();
    let go_rd_raw = go_rd.as_raw_fd();
    let go_wr_raw = go_wr.as_raw_fd();

    // Fork.
    match unsafe { unistd::fork() }? {
        ForkResult::Child => {
            // Close the pipe ends this process does not use.
            drop(setup_rd);
            drop(go_wr);

            // New session.
            let _ = nix::unistd::setsid();

            // Redirect stdout/stderr to log files. Must happen before pivot_root
            // while /run/rauha/... is still reachable on the host filesystem.
            // Uses raw open() with pre-allocated CStrings — async-signal-safe.
            redirect_stdio_raw(&stdout_log, &stderr_log);

            // --- Privileged container bootstrap, BEFORE cgroup enrollment ---
            // The child is not yet a zone member here, so the eBPF `capable`
            // hook sees no zone (lookup_caller_zone -> None -> allow) and does
            // not judge these CAP_SYS_ADMIN operations against the workload's
            // policy. No image code runs in this window — only this fixed,
            // trusted setup sequence, after which we block until enrolled.

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

            // Signal the parent that privileged setup is complete and it is
            // safe to enroll us in the zone cgroup.
            let _ = nix::unistd::write(unsafe { BorrowedFd::borrow_raw(setup_wr_raw) }, &[1u8]);
            drop(setup_wr);

            // Block until the parent confirms cgroup enrollment. From here on
            // the process is inside the enforcement boundary, so the workload
            // exec below is fully subject to zone policy.
            let mut buf = [0u8; 1];
            let n = nix::unistd::read(go_rd_raw, &mut buf);
            drop(go_rd);
            // The "go" pipe closing without a byte means the parent could not
            // enroll us — refuse to run the workload unenforced (fail closed).
            if !matches!(n, Ok(1)) {
                let msg = b"cgroup enrollment failed; refusing to start workload unenforced\n";
                unsafe {
                    let _ = libc::write(2, msg.as_ptr() as _, msg.len());
                    libc::_exit(125);
                }
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
            // Close the pipe ends this process does not use.
            drop(setup_wr);
            drop(go_rd);

            let child_pid = child.as_raw() as u32;
            let child_p = nix::unistd::Pid::from_raw(child_pid as i32);

            // Wait for the child to finish privileged setup before enrolling it,
            // so its CAP_SYS_ADMIN bootstrap is not judged against zone policy.
            // A read of 1 byte means setup succeeded; EOF (0) means the child
            // died during setup (it already wrote its own error to stderr).
            let mut buf = [0u8; 1];
            let setup_ok = matches!(nix::unistd::read(setup_rd_raw, &mut buf), Ok(1));
            drop(setup_rd);
            if !setup_ok {
                drop(go_wr);
                let _ = nix::sys::wait::waitpid(child_p, None);
                anyhow::bail!(
                    "container {container_id} failed during pre-enrollment setup \
                     (see container stderr)"
                );
            }

            // Enroll child in zone cgroup. This MUST succeed: a workload running
            // outside the cgroup gets no eBPF enforcement. On failure, kill the
            // child and report the error rather than signaling "go" — fail closed.
            let cgroup_path = format!("/sys/fs/cgroup/rauha.slice/zone-{zone_name}/cgroup.procs");
            if let Err(e) = std::fs::write(&cgroup_path, child_pid.to_string()) {
                let _ = nix::sys::signal::kill(child_p, nix::sys::signal::Signal::SIGKILL);
                let _ = nix::sys::wait::waitpid(child_p, None);
                drop(go_wr);
                anyhow::bail!(
                    "failed to enroll container {container_id} in zone cgroup \
                     {cgroup_path}: {e}; refusing to start workload unenforced"
                );
            }

            // Signal the child to proceed to exec — it is now inside the boundary.
            let _ = nix::unistd::write(unsafe { BorrowedFd::borrow_raw(go_wr_raw) }, &[1u8]);
            drop(go_wr);

            tracing::info!(pid = child_pid, container = container_id, "child forked");
            Ok(child_pid)
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
    fn rejects_interior_nul_in_process_args() {
        let err = cstring_vec(&["/bin/sh\0bad".to_string()], "process.args")
            .expect_err("interior NUL must be rejected");

        assert!(err.to_string().contains("process.args[0]"));
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
