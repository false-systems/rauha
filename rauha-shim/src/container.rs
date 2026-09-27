#[cfg(any(target_os = "linux", test))]
use std::ffi::OsString;
#[cfg(target_os = "linux")]
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::path::{Path, PathBuf};
use std::process::Command;
#[cfg(target_os = "linux")]
use std::process::Stdio;
use std::time::{Duration, Instant};

/// Resolve the crun binary, once per process. The daemon passes its
/// configured `[executor] crun` value via `RAUHA_CRUN`: "auto" (default)
/// searches PATH and known locations, or an absolute path is used directly.
/// Never a hardcoded single path — see the never-hardcode convention.
/// Cached: crun invocations are frequent (create, start, exec, delete) and
/// the search walks PATH only once.
pub fn crun_path() -> anyhow::Result<&'static PathBuf> {
    static CRUN: std::sync::LazyLock<Result<PathBuf, String>> = std::sync::LazyLock::new(|| {
        if let Ok(configured) = std::env::var("RAUHA_CRUN") {
            if configured != "auto" {
                let path = PathBuf::from(&configured);
                if !path.is_file() {
                    return Err(format!("configured OCI runtime is missing: {configured}"));
                }
                return Ok(path);
            }
        }

        let mut candidates: Vec<PathBuf> = std::env::var("PATH")
            .map(|p| {
                std::env::split_paths(&p)
                    .map(|dir| dir.join("crun"))
                    .collect()
            })
            .unwrap_or_default();
        candidates.push(PathBuf::from("/usr/local/bin/crun"));
        candidates.push(PathBuf::from("/usr/bin/crun"));
        candidates.push(PathBuf::from("/bin/crun"));

        candidates.into_iter().find(|c| c.is_file()).ok_or_else(|| {
            "crun not found: install crun, or set executor.crun in rauha.toml \
                 (passed to the shim as RAUHA_CRUN)"
                .to_string()
        })
    });
    CRUN.as_ref().map_err(|e| anyhow::anyhow!("{e}"))
}

/// An OCI init process supervised by the zone shim.
pub struct RuntimeProcess {
    #[cfg(target_os = "linux")]
    pidfd: OwnedFd,
    #[cfg(target_os = "linux")]
    pid: libc::pid_t,
    runtime_root: PathBuf,
    id: String,
    cleaned: bool,
}

impl RuntimeProcess {
    pub fn signal(&self, signal: i32) -> anyhow::Result<()> {
        #[cfg(target_os = "linux")]
        {
            let rc = unsafe {
                libc::syscall(
                    libc::SYS_pidfd_send_signal,
                    self.pidfd.as_raw_fd(),
                    signal,
                    std::ptr::null::<libc::siginfo_t>(),
                    0,
                )
            };
            if rc == 0 {
                Ok(())
            } else {
                Err(std::io::Error::last_os_error().into())
            }
        }
        #[cfg(not(target_os = "linux"))]
        {
            let _ = signal;
            anyhow::bail!("pidfd signaling is only supported on Linux")
        }
    }

    /// Return the workload exit code once init exits and clean its runtime state.
    pub fn try_wait(&mut self) -> Option<i32> {
        #[cfg(target_os = "linux")]
        {
            let mut pollfd = libc::pollfd {
                fd: self.pidfd.as_raw_fd(),
                events: libc::POLLIN,
                revents: 0,
            };
            if unsafe { libc::poll(&mut pollfd, 1, 0) } <= 0 {
                return None;
            }
            let mut status = 0;
            let waited = unsafe { libc::waitpid(self.pid, &mut status, libc::WNOHANG) };
            let exit_code = if waited == self.pid && libc::WIFEXITED(status) {
                libc::WEXITSTATUS(status)
            } else if waited == self.pid && libc::WIFSIGNALED(status) {
                128 + libc::WTERMSIG(status)
            } else {
                125
            };
            self.delete();
            Some(exit_code)
        }
        #[cfg(not(target_os = "linux"))]
        None
    }

    /// Wait up to `grace` for init to exit, then SIGKILL it and wait again.
    ///
    /// Init is PID 1 of its own pid namespace, where a signal with default
    /// disposition (SIGTERM to `sleep`, say) is silently discarded — so a
    /// delivered stop signal proves nothing until the pidfd reports exit.
    pub fn wait_or_kill(&mut self, grace: Duration) -> i32 {
        if let Some(exit_code) = self.wait_until(Instant::now() + grace) {
            return exit_code;
        }
        let _ = self.signal(9);
        let exit_code = self
            .wait_until(Instant::now() + Duration::from_secs(5))
            .unwrap_or(128 + 9);
        self.delete();
        exit_code
    }

    fn wait_until(&mut self, deadline: Instant) -> Option<i32> {
        loop {
            if let Some(exit_code) = self.try_wait() {
                return Some(exit_code);
            }
            if Instant::now() >= deadline {
                return None;
            }
            std::thread::sleep(Duration::from_millis(10));
        }
    }

    pub fn stop_and_delete(&mut self) {
        self.wait_or_kill(Duration::ZERO);
    }

    fn delete(&mut self) {
        if self.cleaned {
            return;
        }
        let _ = runtime_command(&self.runtime_root)
            .args(["delete", "--force", &self.id])
            .status();
        self.cleaned = true;
    }
}

/// Start an OCI bundle with crun while the shim remains its foreground supervisor.
pub fn start_with_crun(
    zone_name: &str,
    container_id: &str,
    spec_json: &str,
    rootfs_root: &Path,
) -> anyhow::Result<(RuntimeProcess, u32)> {
    #[cfg(not(target_os = "linux"))]
    {
        let _ = (zone_name, container_id, spec_json, rootfs_root);
        anyhow::bail!("crun execution is only supported on Linux")
    }

    #[cfg(target_os = "linux")]
    {
        // Fail fast if the OCI runtime is missing; runtime_command resolves
        // the same path when building each crun invocation.
        crun_path()?;
        if unsafe { libc::prctl(libc::PR_SET_CHILD_SUBREAPER, 1, 0, 0, 0) } != 0 {
            return Err(std::io::Error::last_os_error().into());
        }

        let bundle = rootfs_root.join("containers").join(container_id);
        if !bundle.join("merged").is_dir() && !bundle.join("rootfs").is_dir() {
            anyhow::bail!("rootfs not found for container {container_id}");
        }

        let runtime_root = rootfs_root.join("runtime");
        std::fs::create_dir_all(&runtime_root)?;
        std::fs::write(bundle.join("config.json"), spec_json)?;

        let pid_file = bundle.join("init.pid");
        let _ = std::fs::remove_file(&pid_file);
        let log_dir = run_dir().join("containers").join(container_id);
        std::fs::create_dir_all(&log_dir)?;

        let status = runtime_command(&runtime_root)
            .args(crun_create_args(&bundle, &pid_file, container_id))
            .stdin(Stdio::null())
            .stdout(Stdio::from(std::fs::File::create(
                log_dir.join("stdout.log"),
            )?))
            .stderr(Stdio::from(std::fs::File::create(
                log_dir.join("stderr.log"),
            )?))
            .status()?;
        if !status.success() {
            let error = std::fs::read_to_string(log_dir.join("stderr.log")).unwrap_or_default();
            let _ = runtime_command(&runtime_root)
                .args(["delete", "--force", container_id])
                .status();
            anyhow::bail!("crun create failed: {}", error.trim());
        }

        let pid = match std::fs::read_to_string(&pid_file)
            .and_then(|pid| pid.trim().parse::<u32>().map_err(std::io::Error::other))
        {
            Ok(pid) => pid,
            Err(error) => {
                let _ = runtime_command(&runtime_root)
                    .args(["delete", "--force", container_id])
                    .status();
                return Err(error.into());
            }
        };
        let pidfd = unsafe { libc::syscall(libc::SYS_pidfd_open, pid, 0) };
        if pidfd < 0 {
            let error = std::io::Error::last_os_error();
            let _ = runtime_command(&runtime_root)
                .args(["delete", "--force", container_id])
                .status();
            return Err(error.into());
        }
        let pidfd = unsafe { OwnedFd::from_raw_fd(pidfd as i32) };

        let cgroup = format!("/sys/fs/cgroup/rauha.slice/zone-{zone_name}/cgroup.procs");
        if let Err(error) = std::fs::write(&cgroup, pid.to_string()) {
            let _ = runtime_command(&runtime_root)
                .args(["delete", "--force", container_id])
                .status();
            anyhow::bail!("failed to enroll OCI init in {cgroup}: {error}");
        }

        let output = match runtime_command(&runtime_root)
            .args(["start", container_id])
            .output()
        {
            Ok(output) => output,
            Err(error) => {
                let _ = runtime_command(&runtime_root)
                    .args(["delete", "--force", container_id])
                    .status();
                return Err(error.into());
            }
        };
        if !output.status.success() {
            let _ = runtime_command(&runtime_root)
                .args(["delete", "--force", container_id])
                .status();
            anyhow::bail!(
                "crun start failed: {}",
                String::from_utf8_lossy(&output.stderr).trim()
            );
        }

        Ok((
            RuntimeProcess {
                pidfd,
                pid: pid as libc::pid_t,
                runtime_root,
                id: container_id.to_string(),
                cleaned: false,
            },
            pid,
        ))
    }
}

/// Runtime dir for sockets and container logs. The daemon passes its
/// configured `[paths] run_dir` via `RAUHA_RUN_DIR` (default `/run/rauha`).
#[cfg(target_os = "linux")]
pub(crate) fn run_dir() -> PathBuf {
    PathBuf::from(std::env::var("RAUHA_RUN_DIR").unwrap_or_else(|_| "/run/rauha".into()))
}

fn runtime_command(runtime_root: &Path) -> Command {
    let mut command = Command::new(
        crun_path()
            .cloned()
            .unwrap_or_else(|_| PathBuf::from("crun")),
    );
    command
        .arg("--root")
        .arg(runtime_root)
        .arg("--cgroup-manager=disabled");
    command
}

#[cfg(any(target_os = "linux", test))]
fn crun_create_args(bundle: &Path, pid_file: &Path, container_id: &str) -> Vec<OsString> {
    vec![
        "create".into(),
        "--bundle".into(),
        bundle.as_os_str().into(),
        "--pid-file".into(),
        pid_file.as_os_str().into(),
        container_id.into(),
    ]
}

#[cfg(target_os = "linux")]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(crate) struct ProcessSecurity {
    bounding: u64,
    effective: u64,
    inheritable: u64,
    permitted: u64,
    ambient: u64,
    no_new_privileges: bool,
}

#[cfg(target_os = "linux")]
impl ProcessSecurity {
    pub(crate) fn from_process(process: &oci_spec::runtime::Process) -> anyhow::Result<Self> {
        let capabilities = process
            .capabilities()
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("process.capabilities is required"))?;

        Ok(Self {
            bounding: capability_mask(capabilities.bounding().as_ref())?,
            effective: capability_mask(capabilities.effective().as_ref())?,
            inheritable: capability_mask(capabilities.inheritable().as_ref())?,
            permitted: capability_mask(capabilities.permitted().as_ref())?,
            ambient: capability_mask(capabilities.ambient().as_ref())?,
            no_new_privileges: process.no_new_privileges().unwrap_or(false),
        })
    }
}

#[cfg(target_os = "linux")]
fn capability_mask(capabilities: Option<&oci_spec::runtime::Capabilities>) -> anyhow::Result<u64> {
    capabilities
        .into_iter()
        .flatten()
        .try_fold(0u64, |mask, capability| {
            let name = capability.to_string();
            let bit = rauha_common::zone::linux_capability_bit(&name)
                .ok_or_else(|| anyhow::anyhow!("unsupported OCI capability: {name}"))?;
            Ok(mask | (1u64 << bit))
        })
}

#[cfg(target_os = "linux")]
pub(crate) fn apply_process_security(
    security: ProcessSecurity,
    cap_last_cap: u32,
) -> anyhow::Result<()> {
    #[repr(C)]
    struct UserCapHeader {
        version: u32,
        pid: i32,
    }
    #[repr(C)]
    #[derive(Clone, Copy)]
    struct UserCapData {
        effective: u32,
        permitted: u32,
        inheritable: u32,
    }

    for capability in 0..=cap_last_cap {
        if security.bounding & (1u64 << capability) == 0 {
            let rc = unsafe { libc::prctl(libc::PR_CAPBSET_DROP, capability, 0, 0, 0) };
            if rc != 0 {
                return Err(std::io::Error::last_os_error().into());
            }
        }
    }

    let header = UserCapHeader {
        version: 0x2008_0522,
        pid: 0,
    };
    let data = [
        UserCapData {
            effective: security.effective as u32,
            permitted: security.permitted as u32,
            inheritable: security.inheritable as u32,
        },
        UserCapData {
            effective: (security.effective >> 32) as u32,
            permitted: (security.permitted >> 32) as u32,
            inheritable: (security.inheritable >> 32) as u32,
        },
    ];
    let rc = unsafe { libc::syscall(libc::SYS_capset, &header, data.as_ptr()) };
    if rc != 0 {
        return Err(std::io::Error::last_os_error().into());
    }

    let rc = unsafe {
        libc::prctl(
            libc::PR_CAP_AMBIENT,
            libc::PR_CAP_AMBIENT_CLEAR_ALL,
            0,
            0,
            0,
        )
    };
    if rc != 0 {
        return Err(std::io::Error::last_os_error().into());
    }
    for capability in 0..=cap_last_cap {
        if security.ambient & (1u64 << capability) != 0 {
            let rc = unsafe {
                libc::prctl(
                    libc::PR_CAP_AMBIENT,
                    libc::PR_CAP_AMBIENT_RAISE,
                    capability,
                    0,
                    0,
                )
            };
            if rc != 0 {
                return Err(std::io::Error::last_os_error().into());
            }
        }
    }

    if security.no_new_privileges {
        let rc = unsafe { libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) };
        if rc != 0 {
            return Err(std::io::Error::last_os_error().into());
        }
    }
    Ok(())
}

/// fork(2)-equivalent clone3 used only by interactive exec.
#[cfg(target_os = "linux")]
pub(crate) fn clone_process(flags: u64) -> nix::Result<nix::unistd::ForkResult> {
    #[repr(C)]
    #[derive(Default)]
    struct CloneArgs {
        flags: u64,
        pidfd: u64,
        child_tid: u64,
        parent_tid: u64,
        exit_signal: u64,
        stack: u64,
        stack_size: u64,
        tls: u64,
        set_tid: u64,
        set_tid_size: u64,
        cgroup: u64,
    }

    let args = CloneArgs {
        flags,
        exit_signal: libc::SIGCHLD as u64,
        ..Default::default()
    };
    let pid = unsafe {
        libc::syscall(
            libc::SYS_clone3,
            &args as *const CloneArgs,
            std::mem::size_of::<CloneArgs>(),
        )
    };
    if pid < 0 {
        Err(nix::errno::Errno::last())
    } else if pid == 0 {
        Ok(nix::unistd::ForkResult::Child)
    } else {
        Ok(nix::unistd::ForkResult::Parent {
            child: nix::unistd::Pid::from_raw(pid as i32),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::crun_create_args;
    use std::path::Path;

    #[test]
    fn crun_creates_the_bundle_with_a_pid_file_before_start() {
        assert_eq!(
            crun_create_args(Path::new("/bundle"), Path::new("/bundle/init.pid"), "c1"),
            Vec::<std::ffi::OsString>::from(
                [
                    "create",
                    "--bundle",
                    "/bundle",
                    "--pid-file",
                    "/bundle/init.pid",
                    "c1"
                ]
                .map(std::ffi::OsString::from)
            )
        );
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn empty_oci_capabilities_mean_zero_process_capabilities() {
        use super::ProcessSecurity;
        use oci_spec::runtime::{Capabilities, LinuxCapabilitiesBuilder, ProcessBuilder};

        let capabilities = LinuxCapabilitiesBuilder::default()
            .bounding(Capabilities::default())
            .effective(Capabilities::default())
            .inheritable(Capabilities::default())
            .permitted(Capabilities::default())
            .ambient(Capabilities::default())
            .build()
            .unwrap();
        let process = ProcessBuilder::default()
            .capabilities(capabilities)
            .no_new_privileges(true)
            .build()
            .unwrap();

        assert_eq!(
            ProcessSecurity::from_process(&process).unwrap(),
            ProcessSecurity {
                no_new_privileges: true,
                ..Default::default()
            }
        );
    }
}
