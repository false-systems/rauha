//! Container lifecycle inside the VM guest.
//!
//! Simpler than rauha-shim: no cgroup enrollment (the VM is the resource
//! boundary) and no setns (already in the right namespace).
//!
//! This code only runs inside a Linux VM, but the crate is checked on macOS
//! during workspace builds, so Linux-only APIs are cfg-gated.

use std::path::Path;

/// Fork a child process, set up rootfs, and exec the container workload.
#[cfg(target_os = "linux")]
pub fn fork_and_exec(
    container_id: &str,
    spec_json: &str,
    rootfs_root: &Path,
) -> anyhow::Result<u32> {
    use nix::unistd::{self, ForkResult};
    use oci_spec::runtime::Spec;
    use std::ffi::CString;
    use std::os::fd::AsRawFd;
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

    let log_dir = PathBuf::from("/run/rauha/containers").join(container_id);
    std::fs::create_dir_all(&log_dir)?;

    let (pipe_rd, pipe_wr) = nix::unistd::pipe()?;

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

    match unsafe { unistd::fork() }? {
        ForkResult::Child => {
            drop(pipe_wr);
            let mut buf = [0u8; 1];
            let _ = nix::unistd::read(pipe_rd.as_raw_fd(), &mut buf);
            drop(pipe_rd);

            let _ = nix::unistd::setsid();
            redirect_stdio(&log_dir);

            if let Err(e) = do_pivot_root(&rootfs) {
                let msg = format!("pivot_root failed: {e}\n");
                unsafe {
                    let _ = libc::write(2, msg.as_ptr() as _, msg.len());
                    libc::_exit(1);
                }
            }

            if let Some(ref h) = hostname {
                let _ = nix::unistd::sethostname(h);
            }

            // Set environment using libc directly — std::env::* are NOT
            // async-signal-safe (they hold a global mutex that may be held
            // by another thread in the parent process after fork).
            unsafe {
                libc::clearenv();
                for var in &env_vars {
                    libc::putenv(var.as_ptr() as *mut libc::c_char);
                }
            }

            let _ = nix::unistd::chdir(cwd_cstr.as_c_str());

            let err = nix::unistd::execvp(&c_args[0], &c_args);
            let msg = format!("execvp failed: {err:?}\n");
            unsafe {
                let _ = libc::write(2, msg.as_ptr() as _, msg.len());
                libc::_exit(127);
            }
        }
        ForkResult::Parent { child } => {
            drop(pipe_rd);
            let child_pid = child.as_raw() as u32;
            let _ = nix::unistd::write(&pipe_wr, &[1u8]);
            drop(pipe_wr);
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
    fn rejects_interior_nul_in_process_env() {
        let err = cstring_vec(&["PATH=/bin\0extra".to_string()], "process.env")
            .expect_err("interior NUL must be rejected");

        assert!(err.to_string().contains("process.env[0]"));
    }
}

#[cfg(not(target_os = "linux"))]
pub fn fork_and_exec(
    _container_id: &str,
    _spec_json: &str,
    _rootfs_root: &Path,
) -> anyhow::Result<u32> {
    anyhow::bail!("fork_and_exec is only supported on Linux (inside VM)")
}

/// Send a signal to a container process.
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

/// Non-blocking waitpid. Returns exit code if the child has exited.
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

#[cfg(target_os = "linux")]
fn do_pivot_root(new_root: &Path) -> anyhow::Result<()> {
    use nix::mount::{mount, umount2, MntFlags, MsFlags};

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

    umount2("/.pivot_old", MntFlags::MNT_DETACH)?;
    std::fs::remove_dir("/.pivot_old").ok();

    Ok(())
}

#[cfg(target_os = "linux")]
fn redirect_stdio(log_dir: &Path) {
    use std::os::unix::io::AsRawFd;

    let stdout_path = log_dir.join("stdout.log");
    let stderr_path = log_dir.join("stderr.log");

    if let Ok(f) = std::fs::File::create(&stdout_path) {
        let _ = nix::unistd::dup2(f.as_raw_fd(), 1);
    }
    if let Ok(f) = std::fs::File::create(&stderr_path) {
        let _ = nix::unistd::dup2(f.as_raw_fd(), 2);
    }
}

/// Collect resource usage stats for all processes in this VM.
pub fn collect_stats() -> (u64, u64, u32, u64, u64) {
    let cpu_usage_ns = read_proc_stat_cpu_ns().unwrap_or(0);
    let memory_bytes = read_meminfo_used().unwrap_or(0);
    let pids = count_pids().unwrap_or(0);
    let (network_rx_bytes, network_tx_bytes) = read_network_bytes().unwrap_or((0, 0));
    (
        cpu_usage_ns,
        memory_bytes,
        pids,
        network_rx_bytes,
        network_tx_bytes,
    )
}

fn read_proc_stat_cpu_ns() -> Option<u64> {
    let data = std::fs::read_to_string("/proc/stat").ok()?;
    let cpu_line = data.lines().next()?;
    let fields: Vec<&str> = cpu_line.split_whitespace().collect();
    if fields.len() < 5 || fields[0] != "cpu" {
        return None;
    }
    let user: u64 = fields[1].parse().ok()?;
    let nice: u64 = fields[2].parse().ok()?;
    let system: u64 = fields[3].parse().ok()?;
    Some((user + nice + system) * 10_000_000)
}

fn read_meminfo_used() -> Option<u64> {
    let data = std::fs::read_to_string("/proc/meminfo").ok()?;
    let mut total = 0u64;
    let mut available = 0u64;
    for line in data.lines() {
        if let Some(rest) = line.strip_prefix("MemTotal:") {
            total = parse_meminfo_kb(rest)?;
        } else if let Some(rest) = line.strip_prefix("MemAvailable:") {
            available = parse_meminfo_kb(rest)?;
        }
    }
    Some(total.saturating_sub(available) * 1024)
}

fn parse_meminfo_kb(s: &str) -> Option<u64> {
    s.trim().trim_end_matches("kB").trim().parse().ok()
}

fn count_pids() -> Option<u32> {
    let mut count = 0u32;
    for entry in (std::fs::read_dir("/proc").ok()?).flatten() {
        if entry
            .file_name()
            .to_string_lossy()
            .chars()
            .all(|c| c.is_ascii_digit())
        {
            count += 1;
        }
    }
    Some(count)
}

fn read_network_bytes() -> Option<(u64, u64)> {
    let data = std::fs::read_to_string("/proc/net/dev").ok()?;
    let mut rx = 0u64;
    let mut tx = 0u64;

    for line in data.lines().skip(2) {
        let Some((iface, counters)) = line.split_once(':') else {
            continue;
        };
        let iface = iface.trim();
        if iface == "lo" {
            continue;
        }

        let fields: Vec<&str> = counters.split_whitespace().collect();
        if fields.len() < 16 {
            continue;
        }

        rx = rx.saturating_add(fields[0].parse::<u64>().unwrap_or(0));
        tx = tx.saturating_add(fields[8].parse::<u64>().unwrap_or(0));
    }

    Some((rx, tx))
}
