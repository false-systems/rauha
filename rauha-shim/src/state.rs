use std::collections::HashMap;
use std::path::PathBuf;

use crate::container;
use rauha_common::shim::{ProcessIo, ProcessOperation, ShimResponse};

/// Tracks container processes within this zone shim.
pub struct ShimState {
    zone_name: String,
    rootfs_root: PathBuf,
    containers: HashMap<String, ContainerProcess>,
    execs: HashMap<(String, String), ContainerProcess>,
    shutdown: bool,
}

/// A container process tracked by the shim.
struct ContainerProcess {
    /// OCI init PID (0 if only created, not started).
    pid: u32,
    /// Current status.
    status: ContainerStatus,
    /// Exit code reported by the foreground OCI runtime.
    exit_code: Option<i32>,
    /// OCI runtime spec JSON (saved at create time, used at start time).
    spec_json: String,
    /// OCI init process supervised by this shim.
    runtime: Option<container::RuntimeProcess>,
    io: Option<ProcessIo>,
    finished_at: String,
    paused: bool,
    wait_error: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq)]
enum ContainerStatus {
    Created,
    Running,
    Stopped,
}

impl std::fmt::Display for ContainerStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Created => write!(f, "created"),
            Self::Running => write!(f, "running"),
            Self::Stopped => write!(f, "stopped"),
        }
    }
}

impl ShimState {
    pub fn interactive_exec(
        &mut self,
        id: &str,
        session: &str,
        command: &[String],
        env: &[String],
    ) -> anyhow::Result<String> {
        self.reap_children();
        let init = self
            .containers
            .get(id)
            .ok_or_else(|| anyhow::anyhow!("container not found"))?;
        anyhow::ensure!(
            init.status == ContainerStatus::Running && !init.paused,
            "container is not running"
        );
        let spec: serde_json::Value = serde_json::from_str(&init.spec_json)?;
        let mut process = spec["process"].clone();
        process["args"] = serde_json::to_value(command)?;
        if !env.is_empty() {
            process["env"] = serde_json::to_value(env)?;
        }
        let spec_json = admit_exec(&serde_json::to_string(&process)?, &init.spec_json, true)?;
        let io = ProcessIo {
            terminal: true,
            stdin: String::new(),
            stdout: String::new(),
            stderr: String::new(),
        };
        let (runtime, pid, master) =
            container::exec_with_console(id, session, &spec_json, &io, &self.rootfs_root, true)?;
        let key = (id.to_owned(), session.to_owned());
        self.execs.insert(
            key.clone(),
            ContainerProcess {
                pid,
                status: ContainerStatus::Running,
                exit_code: None,
                spec_json,
                runtime: Some(runtime),
                io: None,
                finished_at: String::new(),
                paused: false,
                wait_error: None,
            },
        );
        let result = (|| {
            let master = master.ok_or_else(|| anyhow::anyhow!("runtime omitted console"))?;
            let signal = self.execs[&key]
                .runtime
                .as_ref()
                .unwrap()
                .termination_handle()?;
            crate::attach::serve_attach_session(id, session, master, signal)
        })();
        if result.is_err() {
            self.execs
                .get_mut(&key)
                .unwrap()
                .runtime
                .as_mut()
                .unwrap()
                .stop_and_delete()?;
        }
        result
    }

    pub fn process_operation(
        &mut self,
        id: &str,
        exec_id: &str,
        operation: ProcessOperation,
    ) -> anyhow::Result<ShimResponse> {
        self.reap_children();
        let init = self
            .containers
            .get(id)
            .ok_or_else(|| anyhow::anyhow!("container not found"))?;
        let key = (id.to_owned(), exec_id.to_owned());
        if let ProcessOperation::Create { process_json, io } = operation {
            anyhow::ensure!(
                !exec_id.is_empty()
                    && exec_id.len() <= 128
                    && exec_id
                        .bytes()
                        .all(|b| b.is_ascii_alphanumeric() || b"_.-".contains(&b))
                    && exec_id != "."
                    && exec_id != "..",
                "invalid exec ID"
            );
            anyhow::ensure!(
                init.status == ContainerStatus::Running,
                "container is not running"
            );
            anyhow::ensure!(!self.execs.contains_key(&key), "exec already exists");
            let spec_json = admit_exec(&process_json, &init.spec_json, io.terminal)?;
            let process = ContainerProcess {
                pid: 0,
                status: ContainerStatus::Created,
                exit_code: None,
                spec_json,
                runtime: None,
                io: Some(io),
                finished_at: String::new(),
                paused: false,
                wait_error: None,
            };
            let response = process.info();
            self.execs.insert(key, process);
            return Ok(response);
        }
        if matches!(operation, ProcessOperation::Start) {
            anyhow::ensure!(
                !exec_id.is_empty() && init.status == ContainerStatus::Running && !init.paused,
                "exec requires a running container"
            );
            let process = self
                .execs
                .get_mut(&key)
                .ok_or_else(|| anyhow::anyhow!("exec not found"))?;
            anyhow::ensure!(
                process.status == ContainerStatus::Created,
                "exec has already started"
            );
            let (runtime, pid) = container::exec_with_crun(
                id,
                exec_id,
                &process.spec_json,
                process.io.as_ref().unwrap(),
                &self.rootfs_root,
            )?;
            process.pid = pid;
            process.runtime = Some(runtime);
            process.status = ContainerStatus::Running;
            return Ok(process.info());
        }
        let process = if exec_id.is_empty() {
            self.containers.get_mut(id)
        } else {
            self.execs.get_mut(&key)
        }
        .ok_or_else(|| anyhow::anyhow!("process not found"))?;
        if matches!(operation, ProcessOperation::State) {
            return Ok(process.info());
        }
        if matches!(operation, ProcessOperation::Delete) {
            anyhow::ensure!(!exec_id.is_empty(), "init deletion uses DeleteContainer");
            anyhow::ensure!(
                process.status != ContainerStatus::Running,
                "exec is still running"
            );
            if let Some(runtime) = &mut process.runtime {
                runtime.stop_and_delete()?;
            }
            remove_exec_files(&self.rootfs_root.join("containers").join(id), exec_id)?;
            let response = process.info();
            self.execs.remove(&key);
            return Ok(response);
        }
        let runtime = process
            .runtime
            .as_mut()
            .ok_or_else(|| anyhow::anyhow!("process has not started"))?;
        match operation {
            ProcessOperation::Signal { signal, all } => {
                anyhow::ensure!((0..=64).contains(&signal), "invalid signal");
                if all {
                    anyhow::ensure!(exec_id.is_empty(), "all-process signal requires init");
                    runtime.signal_all(signal)?;
                } else {
                    anyhow::ensure!(
                        process.status != ContainerStatus::Stopped,
                        "process has exited"
                    );
                    runtime.signal(signal)?;
                }
            }
            ProcessOperation::Resize { rows, cols } => {
                anyhow::ensure!(rows > 0 && cols > 0, "terminal dimensions must be positive");
                runtime.resize(rows, cols)?;
            }
            ProcessOperation::CloseIo => runtime.close_stdin()?,
            ProcessOperation::Pause { paused } => {
                anyhow::ensure!(
                    exec_id.is_empty() && process.status == ContainerStatus::Running,
                    "pause requires a running init task"
                );
                if process.paused != paused {
                    runtime.set_paused(paused)?;
                    process.paused = paused;
                }
            }
            ProcessOperation::UpdateResources { resources_json } => {
                anyhow::ensure!(
                    exec_id.is_empty() && process.status == ContainerStatus::Running,
                    "resource update requires a running init task"
                );
                let was_paused = process.paused;
                if !was_paused {
                    runtime.set_paused(true)?;
                    process.paused = true;
                }
                runtime.update_resources(
                    &resources_json,
                    &self.rootfs_root.join("containers").join(id),
                )?;
                if !was_paused {
                    runtime.set_paused(false)?;
                    process.paused = false;
                }
            }
            ProcessOperation::Stats => {
                anyhow::ensure!(exec_id.is_empty(), "statistics apply to a container");
                #[cfg(target_os = "linux")]
                {
                    return crate::resources::stats(&crate::resources::path(&self.zone_name, id));
                }
                #[cfg(not(target_os = "linux"))]
                anyhow::bail!("cgroup statistics require Linux");
            }
            _ => unreachable!("handled above"),
        }
        Ok(process.info())
    }

    pub fn new(zone_name: String, rootfs_root: PathBuf) -> Self {
        Self {
            zone_name,
            rootfs_root,
            containers: HashMap::new(),
            execs: HashMap::new(),
            shutdown: false,
        }
    }

    /// Create the OCI init process without starting the workload.
    pub fn create_container(&mut self, id: &str, spec_json: &str) -> anyhow::Result<u32> {
        if self.containers.contains_key(id) {
            anyhow::bail!("container {id} already exists");
        }

        let (runtime, pid) =
            container::create_with_crun(&self.zone_name, id, spec_json, &self.rootfs_root)?;
        self.containers.insert(
            id.to_string(),
            ContainerProcess {
                pid,
                status: ContainerStatus::Created,
                exit_code: None,
                spec_json: spec_json.to_string(),
                runtime: Some(runtime),
                io: None,
                finished_at: String::new(),
                paused: false,
                wait_error: None,
            },
        );

        Ok(pid)
    }

    /// Start a previously created container through crun.
    pub fn start_container(&mut self, id: &str) -> anyhow::Result<u32> {
        let proc = self
            .containers
            .get(id)
            .ok_or_else(|| anyhow::anyhow!("container {id} not found"))?;

        if proc.status != ContainerStatus::Created {
            anyhow::bail!("container {id} is {}, cannot start", proc.status);
        }

        proc.runtime
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("container {id} has no OCI runtime"))?
            .start()?;
        let pid = proc.pid;

        let proc = self
            .containers
            .get_mut(id)
            .ok_or_else(|| anyhow::anyhow!("container {id} not found after OCI start"))?;
        proc.pid = pid;
        proc.status = ContainerStatus::Running;

        tracing::info!(container = id, pid, "container started");
        Ok(pid)
    }

    /// Stop a container: deliver `signal`, then escalate to SIGKILL if init
    /// has not exited within the grace period. Returns only once init is gone.
    pub fn stop_container(&mut self, id: &str, signal: i32) -> anyhow::Result<()> {
        const GRACE: std::time::Duration = std::time::Duration::from_secs(5);

        self.reap_children();
        let proc = self
            .containers
            .get_mut(id)
            .ok_or_else(|| anyhow::anyhow!("container {id} not found"))?;
        if proc.status == ContainerStatus::Stopped {
            return Ok(());
        }
        anyhow::ensure!(
            proc.status == ContainerStatus::Running,
            "container {id} is not running"
        );
        let runtime = proc
            .runtime
            .as_mut()
            .ok_or_else(|| anyhow::anyhow!("container {id} has no OCI runtime"))?;
        if proc.paused {
            runtime.set_paused(false)?;
            proc.paused = false;
        }
        // Detached execs are adopted by this shim, not reaped by namespace
        // PID 1. Reap them before waiting for init's namespace teardown.
        for ((container, _), process) in &mut self.execs {
            if container == id {
                stop_exec_process(process)?;
            }
        }
        runtime.signal(signal)?;
        let exit_code = runtime.wait_or_kill(GRACE)?;
        tracing::info!(
            container = id,
            pid = proc.pid,
            exit_code,
            "container stopped"
        );
        proc.status = ContainerStatus::Stopped;
        proc.exit_code = Some(exit_code);
        proc.finished_at = chrono::Utc::now().to_rfc3339();
        Ok(())
    }

    /// Send a signal to a container's process.
    pub fn signal_container(&mut self, id: &str, signal: i32) -> anyhow::Result<()> {
        let proc = self
            .containers
            .get(id)
            .ok_or_else(|| anyhow::anyhow!("container {id} not found"))?;

        if proc.status != ContainerStatus::Running || proc.pid == 0 {
            anyhow::bail!("container {id} is not running");
        }

        proc.runtime
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("container {id} has no OCI runtime"))?
            .signal(signal)?;
        Ok(())
    }

    /// Get the state of a container.
    pub fn delete_container(&mut self, id: &str) -> anyhow::Result<()> {
        self.reap_children();
        if self
            .containers
            .get(id)
            .is_some_and(|p| p.status == ContainerStatus::Running)
        {
            anyhow::bail!("container {id} is running");
        }
        for (_, process) in self
            .execs
            .iter_mut()
            .filter(|((container, _), _)| container == id)
        {
            stop_exec_process(process)?;
        }
        if let Some(runtime) = self.containers.get_mut(id).and_then(|p| p.runtime.as_mut()) {
            runtime.stop_and_delete()?;
        }
        self.execs.retain(|(container, _), _| container != id);
        self.containers.remove(id);
        Ok(())
    }

    /// Get the state of a container.
    pub fn get_state(&self, id: &str) -> anyhow::Result<Option<(u32, String, Option<i32>)>> {
        let Some(process) = self.containers.get(id) else {
            return Ok(None);
        };
        if let Some(error) = &process.wait_error {
            anyhow::bail!("{error}");
        }
        Ok(Some((
            process.pid,
            process.status_name(),
            process.exit_code,
        )))
    }

    /// Reap exited child processes.
    pub fn reap_children(&mut self) {
        for proc in self.execs.values_mut().chain(self.containers.values_mut()) {
            if proc.status == ContainerStatus::Stopped || proc.pid == 0 {
                continue;
            }
            let outcome = match proc
                .runtime
                .as_mut()
                .map(|runtime| runtime.try_wait())
                .transpose()
            {
                Ok(outcome) => outcome.flatten(),
                Err(error) => {
                    proc.wait_error = Some(error.to_string());
                    continue;
                }
            };
            if let Some(exit_code) = outcome {
                tracing::info!(pid = proc.pid, exit_code, "container exited");
                proc.status = ContainerStatus::Stopped;
                proc.exit_code = Some(exit_code);
                proc.finished_at = chrono::Utc::now().to_rfc3339();
            }
        }
        // Keep exec status until the daemon has drained the PTY, read the exit
        // status and issued DeleteExec. Parent deletion handles abandoned RPCs.
    }

    /// Return (running_pids_count, total_count) for stats.
    pub fn container_summary(&self) -> (u32, u32) {
        let running = self
            .containers
            .values()
            .filter(|p| p.status == ContainerStatus::Running && p.pid > 0)
            .count() as u32;
        (running, self.containers.len() as u32)
    }

    pub fn request_shutdown(&mut self) -> anyhow::Result<()> {
        for process in self.execs.values_mut().chain(self.containers.values_mut()) {
            if let Some(runtime) = process.runtime.as_mut() {
                runtime.stop_and_delete()?;
            }
        }
        self.shutdown = true;
        Ok(())
    }

    pub fn should_shutdown(&self) -> bool {
        self.shutdown
    }
}

fn stop_exec_process(process: &mut ContainerProcess) -> anyhow::Result<()> {
    if let Some(runtime) = &mut process.runtime {
        let cleanup = runtime.stop_and_delete();
        // Even when output cleanup needs a retry, retain the real exit status
        // for containerd Wait/Delete instead of inventing a successful exit.
        if let Some(code) = runtime.try_wait()? {
            process.status = ContainerStatus::Stopped;
            process.exit_code = Some(code);
            if process.finished_at.is_empty() {
                process.finished_at = chrono::Utc::now().to_rfc3339();
            }
            process.wait_error = None;
        }
        cleanup?;
    }
    Ok(())
}

impl ContainerProcess {
    fn status_name(&self) -> String {
        if self.paused && self.status == ContainerStatus::Running {
            "paused".into()
        } else {
            self.status.to_string()
        }
    }
    fn info(&self) -> ShimResponse {
        if let Some(error) = &self.wait_error {
            return ShimResponse::Error {
                message: error.clone(),
            };
        }
        ShimResponse::ProcessState {
            pid: self.pid,
            status: self.status_name(),
            exit_code: self.exit_code,
            finished_at: self.finished_at.clone(),
        }
    }
}

fn remove_exec_files(bundle: &std::path::Path, exec_id: &str) -> anyhow::Result<()> {
    for extension in ["json", "pid"] {
        match std::fs::remove_file(bundle.join(format!("exec-{exec_id}.{extension}"))) {
            Ok(()) => {}
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => return Err(error.into()),
        }
    }
    Ok(())
}

fn admit_exec(process: &str, init: &str, terminal: bool) -> anyhow::Result<String> {
    let mut process: serde_json::Value = serde_json::from_str(process)?;
    let init: serde_json::Value = serde_json::from_str(init)?;
    anyhow::ensure!(
        !init
            .pointer("/linux/seccomp/listenerPath")
            .and_then(|path| path.as_str())
            .is_some_and(|path| !path.is_empty()),
        "exec is not supported for seccomp notification broker containers"
    );
    anyhow::ensure!(process.is_object(), "exec process must be an OCI object");
    let _: oci_spec::runtime::Process = serde_json::from_value(process.clone())?;
    anyhow::ensure!(
        process["args"]
            .as_array()
            .is_some_and(|args| !args.is_empty()),
        "exec command is required"
    );
    process["terminal"] = terminal.into();
    for field in ["args", "env"] {
        if let Some(values) = process[field].as_array() {
            anyhow::ensure!(
                values
                    .iter()
                    .all(|value| value.as_str().is_some_and(|value| !value.contains('\0'))),
                "exec {field} contains an invalid string"
            );
        }
    }
    process["noNewPrivileges"] = true.into();
    if process.get("capabilities").is_none() {
        process["capabilities"] = init["process"]["capabilities"].clone();
    }
    for kind in [
        "bounding",
        "effective",
        "inheritable",
        "permitted",
        "ambient",
    ] {
        if let Some(caps) = process["capabilities"][kind].as_array_mut() {
            caps.retain(|cap| {
                init["process"]["capabilities"][kind]
                    .as_array()
                    .is_some_and(|allowed| allowed.contains(cap))
            });
        }
    }
    Ok(serde_json::to_string(&process)?)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn completed_interactive_exec_keeps_exit_status_until_explicit_delete() {
        let root = std::env::temp_dir().join(format!("rauha-exit-{}", uuid::Uuid::new_v4()));
        let mut state = ShimState::new("zone".into(), root);
        let completed = || ContainerProcess {
            pid: 0,
            status: ContainerStatus::Stopped,
            exit_code: Some(7),
            spec_json: "{}".into(),
            runtime: None,
            io: None,
            finished_at: "finished".into(),
            paused: false,
            wait_error: None,
        };
        state.containers.insert("container".into(), completed());
        let key = ("container".into(), "session".into());
        state.execs.insert(key.clone(), completed());
        state.reap_children();
        assert_eq!(state.execs[&key].exit_code, Some(7));
        let response = state
            .process_operation("container", "session", ProcessOperation::Delete)
            .unwrap();
        assert!(matches!(
            response,
            ShimResponse::ProcessState {
                exit_code: Some(7),
                ..
            }
        ));
        assert!(!state.execs.contains_key(&key));
    }

    #[test]
    fn exec_delete_retains_state_on_file_cleanup_failure_then_retries() {
        let root =
            std::env::temp_dir().join(format!("rauha-exec-cleanup-{}", uuid::Uuid::new_v4()));
        let bundle = root.join("containers/init");
        std::fs::create_dir_all(bundle.join("exec-extra.json")).unwrap();
        std::fs::write(bundle.join("exec-extra.pid"), b"123").unwrap();
        std::fs::write(bundle.join("config.json"), b"preserve").unwrap();
        let process = || ContainerProcess {
            wait_error: None,
            pid: 0,
            status: ContainerStatus::Created,
            exit_code: None,
            spec_json: "{}".into(),
            runtime: None,
            io: None,
            finished_at: String::new(),
            paused: false,
        };
        let mut state = ShimState::new("zone".into(), root.clone());
        state.containers.insert("init".into(), process());
        let key = ("init".into(), "extra".into());
        state.execs.insert(key.clone(), process());
        assert!(state
            .process_operation("init", "extra", ProcessOperation::Delete)
            .is_err());
        assert!(state.execs.contains_key(&key));
        std::fs::remove_dir(bundle.join("exec-extra.json")).unwrap();
        state
            .process_operation("init", "extra", ProcessOperation::Delete)
            .unwrap();
        assert!(!state.execs.contains_key(&key));
        assert!(!bundle.join("exec-extra.pid").exists());
        assert_eq!(
            std::fs::read(bundle.join("config.json")).unwrap(),
            b"preserve"
        );
        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn exec_rejects_notification_broker_and_interior_nul() {
        let process = r#"{"args":["/bin/sh"],"cwd":"/","user":{"uid":0,"gid":0}}"#;
        let init = r#"{"linux":{"seccomp":{"listenerPath":"/run/broker.sock"}}}"#;
        assert!(admit_exec(process, init, true)
            .unwrap_err()
            .to_string()
            .contains("notification broker"));
        let init = r#"{"linux":{"seccomp":{"defaultAction":"SCMP_ACT_ALLOW"}}}"#;
        assert!(admit_exec(process, init, true).is_ok());
        let mut process: serde_json::Value = serde_json::from_str(process).unwrap();
        process["env"] = serde_json::json!(["KEY=value\0tail"]);
        assert!(admit_exec(&process.to_string(), init, true)
            .unwrap_err()
            .to_string()
            .contains("invalid string"));
    }

    #[test]
    fn exec_cannot_regain_capabilities_and_preserves_user_and_command() {
        let process = r#"{"args":["/bin/sh","-c","exit 7"],"cwd":"/tmp","user":{"uid":123,"gid":456},"capabilities":{"bounding":["CAP_SYS_ADMIN","CAP_CHOWN"]},"noNewPrivileges":false}"#;
        let init = r#"{"process":{"capabilities":{"bounding":["CAP_CHOWN"]}}}"#;
        let admitted: serde_json::Value =
            serde_json::from_str(&admit_exec(process, init, false).unwrap()).unwrap();
        assert_eq!(
            admitted["capabilities"]["bounding"],
            serde_json::json!(["CAP_CHOWN"])
        );
        assert_eq!(admitted["user"]["uid"], 123);
        assert_eq!(admitted["cwd"], "/tmp");
        assert_eq!(admitted["noNewPrivileges"], true);
        assert_eq!(admitted["args"][2], "exit 7");
    }
}
