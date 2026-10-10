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
    exit_code: Option<i32>,
    is_init: bool,
    #[cfg(target_os = "linux")]
    io: Option<crate::process_io::IoSession>,
    #[cfg(target_os = "linux")]
    captures: Vec<crate::output::Capture>,
    #[cfg(target_os = "linux")]
    broker: Option<crate::broker::Broker>,
    #[cfg(target_os = "linux")]
    exec_cgroup: Option<crate::exec_cgroup::ExecCgroup>,
}

impl RuntimeProcess {
    pub fn termination_handle(&self) -> anyhow::Result<std::fs::File> {
        #[cfg(target_os = "linux")]
        {
            Ok(std::fs::File::from(self.pidfd.try_clone()?))
        }
        #[cfg(not(target_os = "linux"))]
        {
            anyhow::bail!("pidfd signaling requires Linux")
        }
    }
    pub fn signal_all(&self, signal: i32) -> anyhow::Result<()> {
        anyhow::ensure!(self.is_init, "all-process signaling requires the init task");
        let output = runtime_command(&self.runtime_root)
            .args(["kill", "--all", &self.id, &signal.to_string()])
            .output()?;
        anyhow::ensure!(
            output.status.success(),
            "crun kill failed: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        Ok(())
    }

    pub fn set_paused(&self, paused: bool) -> anyhow::Result<()> {
        let output = runtime_command(&self.runtime_root)
            .args([if paused { "pause" } else { "resume" }, &self.id])
            .output()?;
        anyhow::ensure!(
            output.status.success(),
            "crun pause/resume failed: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        Ok(())
    }

    pub fn update_resources(&self, resources: &str, bundle: &Path) -> anyhow::Result<()> {
        let value: serde_json::Value = serde_json::from_str(resources)?;
        let spec: serde_json::Value =
            serde_json::from_slice(&std::fs::read(bundle.join("config.json"))?)?;
        if let Some(devices) = value.get("devices") {
            anyhow::ensure!(
                Some(devices) == spec.pointer("/linux/resources/devices"),
                "resource updates cannot change zone device admission"
            );
        }
        let path = bundle.join("resources.json");
        std::fs::write(&path, serde_json::to_vec(&value)?)?;
        let output = runtime_command(&self.runtime_root)
            .arg("update")
            .arg("--resources")
            .arg(path)
            .arg(&self.id)
            .output()?;
        anyhow::ensure!(
            output.status.success(),
            "crun resource update failed; container remains paused: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        Ok(())
    }

    pub fn close_stdin(&self) -> anyhow::Result<()> {
        #[cfg(target_os = "linux")]
        if let Some(io) = &self.io {
            io.close_stdin();
        }
        Ok(())
    }

    pub fn resize(&self, rows: u16, cols: u16) -> anyhow::Result<()> {
        #[cfg(target_os = "linux")]
        {
            self.io
                .as_ref()
                .ok_or_else(|| anyhow::anyhow!("process has no terminal"))?
                .resize(rows, cols)
        }
        #[cfg(not(target_os = "linux"))]
        {
            let _ = (rows, cols);
            anyhow::bail!("terminal resize requires Linux")
        }
    }

    pub fn start(&self) -> anyhow::Result<()> {
        let output = runtime_command(&self.runtime_root)
            .args(["start", &self.id])
            .output()?;
        anyhow::ensure!(
            output.status.success(),
            "crun start failed: {}",
            String::from_utf8_lossy(&output.stderr).trim()
        );
        Ok(())
    }

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
    pub fn try_wait(&mut self) -> anyhow::Result<Option<i32>> {
        if self.exit_code.is_some() {
            return Ok(self.exit_code);
        }
        #[cfg(target_os = "linux")]
        {
            let mut pollfd = libc::pollfd {
                fd: self.pidfd.as_raw_fd(),
                events: libc::POLLIN,
                revents: 0,
            };
            let ready = unsafe { libc::poll(&mut pollfd, 1, 0) };
            if ready < 0 {
                let error = std::io::Error::last_os_error();
                if error.kind() == std::io::ErrorKind::Interrupted {
                    return Ok(None);
                }
                return Err(error.into());
            }
            if ready == 0 {
                return Ok(None);
            }
            anyhow::ensure!(
                pollfd.revents & libc::POLLNVAL == 0,
                "invalid process descriptor"
            );
            let mut status = 0;
            let waited = unsafe { libc::waitpid(self.pid, &mut status, libc::WNOHANG) };
            if waited == 0 {
                return Ok(None);
            }
            if waited < 0 {
                let error = std::io::Error::last_os_error();
                if error.kind() == std::io::ErrorKind::Interrupted {
                    return Ok(None);
                }
                return Err(anyhow::anyhow!("workload exit status unavailable: {error}"));
            }
            let exit_code = if waited == self.pid && libc::WIFEXITED(status) {
                libc::WEXITSTATUS(status)
            } else if waited == self.pid && libc::WIFSIGNALED(status) {
                128 + libc::WTERMSIG(status)
            } else {
                return Err(anyhow::anyhow!(
                    "runtime returned a nonterminal process status"
                ));
            };
            self.exit_code = Some(exit_code);
            self.captures.clear();
            Ok(Some(exit_code))
        }
        #[cfg(not(target_os = "linux"))]
        Ok(None)
    }

    /// Wait up to `grace` for init to exit, then SIGKILL it and wait again.
    ///
    /// Init is PID 1 of its own pid namespace, where a signal with default
    /// disposition (SIGTERM to `sleep`, say) is silently discarded — so a
    /// delivered stop signal proves nothing until the pidfd reports exit.
    pub fn wait_or_kill(&mut self, grace: Duration) -> anyhow::Result<i32> {
        if let Some(exit_code) = self.wait_until(Instant::now() + grace)? {
            return Ok(exit_code);
        }
        let _ = self.signal(9);
        let exit_code = self
            .wait_until(Instant::now() + Duration::from_secs(5))?
            .ok_or_else(|| anyhow::anyhow!("container {} has not exited after SIGKILL", self.id))?;
        Ok(exit_code)
    }

    fn wait_until(&mut self, deadline: Instant) -> anyhow::Result<Option<i32>> {
        loop {
            if let Some(exit_code) = self.try_wait()? {
                return Ok(Some(exit_code));
            }
            if Instant::now() >= deadline {
                return Ok(None);
            }
            std::thread::sleep(Duration::from_millis(10));
        }
    }

    pub fn stop_and_delete(&mut self) -> anyhow::Result<()> {
        #[cfg(target_os = "linux")]
        if let Some(group) = &self.exec_cgroup {
            group.terminate()?;
        }
        self.wait_or_kill(Duration::ZERO)?;
        self.delete()
    }

    fn delete(&mut self) -> anyhow::Result<()> {
        if self.is_init && !self.cleaned {
            let output = runtime_command(&self.runtime_root)
                .args(["delete", "--force", &self.id])
                .output()?;
            anyhow::ensure!(
                output.status.success(),
                "crun delete failed: {}",
                String::from_utf8_lossy(&output.stderr).trim()
            );
        }
        self.cleaned = true;
        #[cfg(target_os = "linux")]
        {
            self.captures.clear();
            if let Some(io) = &mut self.io {
                io.finish()?;
            }
            self.io.take();
            self.broker.take();
            if let Some(group) = &mut self.exec_cgroup {
                group.cleanup()?;
            }
            self.exec_cgroup.take();
        }
        Ok(())
    }
}

/// Create an OCI init process; it remains suspended until `RuntimeProcess::start`.
pub fn create_with_crun(
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
        crun_path()?;
        if unsafe { libc::prctl(libc::PR_SET_CHILD_SUBREAPER, 1, 0, 0, 0) } != 0 {
            return Err(std::io::Error::last_os_error().into());
        }
        let bundle = rootfs_root.join("containers").join(container_id);
        anyhow::ensure!(
            bundle.join("merged").is_dir() || bundle.join("rootfs").is_dir(),
            "container rootfs is missing"
        );
        let runtime_root = rootfs_root.join("runtime");
        std::fs::create_dir_all(&runtime_root)?;
        let mut spec: serde_json::Value = serde_json::from_str(spec_json)?;
        spec["linux"]["cgroupsPath"] =
            format!("/rauha.slice/zone-{zone_name}/{container_id}").into();
        std::fs::write(bundle.join("config.json"), serde_json::to_vec(&spec)?)?;
        let pid_file = bundle.join("init.pid");
        let _ = std::fs::remove_file(&pid_file);
        let log_dir = run_dir().join("containers").join(container_id);
        use std::os::unix::fs::DirBuilderExt;
        std::fs::DirBuilder::new()
            .mode(0o700)
            .recursive(true)
            .create(&log_dir)?;
        let mut captures = Vec::new();
        let mut imported_io = if spec["annotations"]["io.rauha.containerd.io"] == "fifo" {
            let stream = |name: &str| {
                spec["annotations"][format!("io.rauha.containerd.{name}")]
                    .as_str()
                    .unwrap_or("")
                    .to_owned()
            };
            Some(crate::process_io::PreparedIo::new(
                &rauha_common::shim::ProcessIo {
                    stdin: stream("stdin"),
                    stdout: stream("stdout"),
                    stderr: stream("stderr"),
                    terminal: spec["process"]["terminal"].as_bool().unwrap_or(false),
                },
                &bundle,
            )?)
        } else {
            None
        };
        let (stdin, stdout, stderr) = if let Some(io) = imported_io.as_mut() {
            (
                std::mem::replace(&mut io.stdin, Stdio::null()),
                std::mem::replace(&mut io.stdout, Stdio::null()),
                std::mem::replace(&mut io.stderr, Stdio::null()),
            )
        } else {
            let limit = crate::output::max_bytes()?;
            let (out_capture, out) =
                crate::output::Capture::start(&log_dir.join("stdout.log"), limit)?;
            let (err_capture, err) =
                crate::output::Capture::start(&log_dir.join("stderr.log"), limit)?;
            captures.extend([out_capture, err_capture]);
            (
                Stdio::null(),
                Stdio::from(OwnedFd::from(out)),
                Stdio::from(OwnedFd::from(err)),
            )
        };
        let args = crun_create_args(&bundle, &pid_file, container_id);
        let broker = broker_listener_path(spec_json)
            .map(|path| crate::broker::Broker::start(&path, &log_dir.join("broker.log")))
            .transpose()?;
        let runtime_log = tempfile::NamedTempFile::new_in(&bundle)?;
        let mut command = runtime_command(&runtime_root);
        command.arg("--log").arg(runtime_log.path());
        command.args(&args[..args.len() - 1]);
        if let Some(path) = imported_io.as_ref().and_then(|io| io.console_path()) {
            command.arg("--console-socket").arg(path);
        }
        command
            .arg(container_id)
            .stdin(stdin)
            .stdout(stdout)
            .stderr(stderr);
        let creation = (|| -> anyhow::Result<(OwnedFd, u32)> {
            let status = command.status()?;
            if !status.success() {
                use std::io::Read;
                let mut diagnostic = String::new();
                std::fs::File::open(runtime_log.path())?
                    .take(64 * 1024)
                    .read_to_string(&mut diagnostic)?;
                anyhow::bail!(
                    "crun create rejected OCI version {} ({status}): {}",
                    spec["ociVersion"],
                    diagnostic.trim()
                );
            }
            if let Some(io) = imported_io.as_mut() {
                io.receive_console()?;
            }
            read_pidfd(&pid_file)
        })();
        let (pidfd, pid) = match creation {
            Ok(process) => process,
            Err(error) => {
                let cleanup = runtime_command(&runtime_root)
                    .args(["delete", "--force", container_id])
                    .output()?;
                anyhow::ensure!(
                    cleanup.status.success(),
                    "{error}; runtime cleanup failed: {}",
                    String::from_utf8_lossy(&cleanup.stderr)
                );
                return Err(error);
            }
        };
        Ok((
            RuntimeProcess {
                pidfd,
                pid: pid as libc::pid_t,
                runtime_root,
                id: container_id.to_owned(),
                cleaned: false,
                exit_code: None,
                is_init: true,
                io: imported_io.as_mut().map(|io| io.take_session()),
                captures,
                broker,
                exec_cgroup: None,
            },
            pid,
        ))
    }
}

#[cfg(target_os = "linux")]
fn read_pidfd(path: &Path) -> anyhow::Result<(OwnedFd, u32)> {
    let pid = std::fs::read_to_string(path)?.trim().parse::<u32>()?;
    anyhow::ensure!(pid > 0, "runtime returned invalid PID");
    let fd = unsafe { libc::syscall(libc::SYS_pidfd_open, pid, 0) };
    if fd < 0 {
        return Err(std::io::Error::last_os_error().into());
    }
    Ok((unsafe { OwnedFd::from_raw_fd(fd as i32) }, pid))
}

pub fn exec_with_crun(
    container_id: &str,
    exec_id: &str,
    process_json: &str,
    io: &rauha_common::shim::ProcessIo,
    rootfs_root: &Path,
) -> anyhow::Result<(RuntimeProcess, u32)> {
    let (runtime, pid, _) =
        exec_with_console(container_id, exec_id, process_json, io, rootfs_root, false)?;
    Ok((runtime, pid))
}

pub fn exec_with_console(
    container_id: &str,
    exec_id: &str,
    process_json: &str,
    io: &rauha_common::shim::ProcessIo,
    rootfs_root: &Path,
    direct: bool,
) -> anyhow::Result<(RuntimeProcess, u32, Option<std::fs::File>)> {
    #[cfg(not(target_os = "linux"))]
    {
        let _ = (container_id, exec_id, process_json, io, rootfs_root, direct);
        anyhow::bail!("crun exec requires Linux")
    }
    #[cfg(target_os = "linux")]
    {
        let bundle = rootfs_root.join("containers").join(container_id);
        let runtime_root = rootfs_root.join("runtime");
        let process_file = bundle.join(format!("exec-{exec_id}.json"));
        let pid_file = bundle.join(format!("exec-{exec_id}.pid"));
        std::fs::write(&process_file, process_json)?;
        let mut io = crate::process_io::PreparedIo::new(io, &bundle)?;
        let runtime_log = tempfile::NamedTempFile::new_in(&bundle)?;
        let mut exec_cgroup =
            crate::exec_cgroup::ExecCgroup::create(&bundle, container_id, exec_id)?;
        let mut command = runtime_command(&runtime_root);
        command
            .arg("--log")
            .arg(runtime_log.path())
            .arg("exec")
            .arg("--detach")
            .arg("--cgroup")
            .arg(exec_cgroup.name())
            .arg("--process")
            .arg(&process_file)
            .arg("--pid-file")
            .arg(&pid_file);
        if let Some(path) = io.console_path() {
            command.arg("--console-socket").arg(path);
        }
        let output = command
            .arg(container_id)
            .stdin(std::mem::replace(&mut io.stdin, Stdio::null()))
            .stdout(std::mem::replace(&mut io.stdout, Stdio::null()))
            .stderr(std::mem::replace(&mut io.stderr, Stdio::null()))
            .status();
        let output = match output {
            Ok(output) => output,
            Err(error) => {
                exec_cgroup.terminate()?;
                exec_cgroup.cleanup()?;
                return Err(error.into());
            }
        };
        if !output.success() {
            exec_cgroup.terminate()?;
            use std::io::Read;
            let mut diagnostic = String::new();
            std::fs::File::open(runtime_log.path())?
                .take(64 * 1024)
                .read_to_string(&mut diagnostic)?;
            exec_cgroup.cleanup()?;
            anyhow::bail!("crun exec failed ({output}): {}", diagnostic.trim());
        }
        let (pidfd, pid) = match read_pidfd(&pid_file) {
            Ok(process) => process,
            Err(error) => {
                exec_cgroup.terminate()?;
                exec_cgroup.cleanup()?;
                return Err(error);
            }
        };
        let mut process = RuntimeProcess {
            pidfd,
            pid: pid as libc::pid_t,
            runtime_root,
            id: container_id.to_owned(),
            cleaned: false,
            exit_code: None,
            is_init: false,
            io: None,
            captures: Vec::new(),
            broker: None,
            exec_cgroup: Some(exec_cgroup),
        };
        if let Err(error) = process
            .exec_cgroup
            .as_ref()
            .unwrap()
            .verify_workload_boundary()
        {
            process.stop_and_delete()?;
            return Err(error);
        }
        let console = if direct {
            io.receive_direct_console().map(Some)
        } else {
            io.receive_console().map(|()| None)
        };
        let console = match console {
            Ok(console) => console,
            Err(error) => {
                process.stop_and_delete()?;
                return Err(error);
            }
        };
        process.io = Some(io.take_session());
        Ok((process, pid, console))
    }
}

/// Runtime dir for sockets and container logs. The daemon passes its
/// configured `[paths] run_dir` via `RAUHA_RUN_DIR` (default `/run/rauha`).
#[cfg(target_os = "linux")]
pub(crate) fn run_dir() -> PathBuf {
    PathBuf::from(std::env::var("RAUHA_RUN_DIR").unwrap_or_else(|_| "/run/rauha".into()))
}

/// Extract `linux.seccomp.listenerPath` from the OCI spec, if present.
#[cfg(target_os = "linux")]
fn broker_listener_path(spec_json: &str) -> Option<std::path::PathBuf> {
    let spec: serde_json::Value = serde_json::from_str(spec_json).ok()?;
    let path = spec.pointer("/linux/seccomp/listenerPath")?.as_str()?;
    Some(std::path::PathBuf::from(path))
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
        .arg("--cgroup-manager=cgroupfs");
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

#[cfg(test)]
mod tests {
    #[cfg(target_os = "linux")]
    #[test]
    #[allow(clippy::zombie_processes)] // RuntimeProcess deliberately owns waitpid in the first branch.
    fn process_wait_preserves_exit_status_and_refuses_missing_status() {
        use super::*;
        for already_reaped in [false, true] {
            let mut child = Command::new("/bin/sh")
                .args(["-c", "exit 7"])
                .spawn()
                .unwrap();
            let fd = unsafe { libc::syscall(libc::SYS_pidfd_open, child.id(), 0) };
            assert!(fd >= 0);
            let mut process = RuntimeProcess {
                pidfd: unsafe { OwnedFd::from_raw_fd(fd as i32) },
                pid: child.id() as i32,
                runtime_root: PathBuf::new(),
                id: "test".into(),
                cleaned: false,
                exit_code: None,
                is_init: false,
                io: None,
                captures: Vec::new(),
                broker: None,
                exec_cgroup: None,
            };
            if already_reaped {
                assert_eq!(child.wait().unwrap().code(), Some(7));
                assert!(process
                    .try_wait()
                    .unwrap_err()
                    .to_string()
                    .contains("exit status unavailable"));
            } else {
                assert_eq!(
                    process
                        .wait_until(Instant::now() + Duration::from_secs(5))
                        .unwrap(),
                    Some(7)
                );
                assert_eq!(process.try_wait().unwrap(), Some(7));
            }
        }
    }
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
    fn container_logs_and_their_directory_are_root_only() {
        use std::os::unix::fs::{DirBuilderExt, PermissionsExt};

        let base = std::env::temp_dir().join(format!("rauha-log-mode-{}", std::process::id()));
        let log_dir = base.join("run").join("containers").join("c1");
        std::fs::DirBuilder::new()
            .mode(0o700)
            .recursive(true)
            .create(&log_dir)
            .unwrap();
        let (capture, writer) =
            crate::output::Capture::start(&log_dir.join("stdout.log"), 1024).unwrap();
        drop(writer);
        drop(capture);
        let dir_mode = std::fs::metadata(&log_dir).unwrap().permissions().mode();
        assert_eq!(
            dir_mode & 0o777,
            0o700,
            "container log dir must be root-only"
        );
        let file_mode = std::fs::metadata(log_dir.join("stdout.log"))
            .unwrap()
            .permissions()
            .mode();
        assert_eq!(
            file_mode & 0o777,
            0o600,
            "container log file must be root-only"
        );
        std::fs::remove_dir_all(&base).ok();
    }
}
