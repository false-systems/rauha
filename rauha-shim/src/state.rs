use std::collections::HashMap;
use std::path::PathBuf;

use crate::container;

/// Tracks container processes within this zone shim.
pub struct ShimState {
    zone_name: String,
    rootfs_root: PathBuf,
    containers: HashMap<String, ContainerProcess>,
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
    pub fn new(zone_name: String, rootfs_root: PathBuf) -> Self {
        Self {
            zone_name,
            rootfs_root,
            containers: HashMap::new(),
            shutdown: false,
        }
    }

    /// Create a container (save spec, don't fork yet).
    pub fn create_container(&mut self, id: &str, spec_json: &str) -> anyhow::Result<u32> {
        if self.containers.contains_key(id) {
            anyhow::bail!("container {id} already exists");
        }

        self.containers.insert(
            id.to_string(),
            ContainerProcess {
                pid: 0,
                status: ContainerStatus::Created,
                exit_code: None,
                spec_json: spec_json.to_string(),
                runtime: None,
            },
        );

        Ok(0) // No PID yet — will be assigned on start.
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

        let spec_json = proc.spec_json.clone();

        let (runtime, pid) =
            container::start_with_crun(&self.zone_name, id, &spec_json, &self.rootfs_root)?;

        let proc = self
            .containers
            .get_mut(id)
            .ok_or_else(|| anyhow::anyhow!("container {id} not found after OCI start"))?;
        proc.pid = pid;
        proc.status = ContainerStatus::Running;
        proc.runtime = Some(runtime);

        tracing::info!(container = id, pid, "container started");
        Ok(pid)
    }

    /// Stop a container: deliver `signal`, then escalate to SIGKILL if init
    /// has not exited within the grace period. Returns only once init is gone.
    pub fn stop_container(&mut self, id: &str, signal: i32) -> anyhow::Result<()> {
        const GRACE: std::time::Duration = std::time::Duration::from_secs(5);

        self.reap_children();
        self.signal_container(id, signal)?;
        let proc = self
            .containers
            .get_mut(id)
            .ok_or_else(|| anyhow::anyhow!("container {id} not found"))?;
        let runtime = proc
            .runtime
            .as_mut()
            .ok_or_else(|| anyhow::anyhow!("container {id} has no OCI runtime"))?;
        let exit_code = runtime.wait_or_kill(GRACE);
        tracing::info!(
            container = id,
            pid = proc.pid,
            exit_code,
            "container stopped"
        );
        proc.status = ContainerStatus::Stopped;
        proc.exit_code = Some(exit_code);
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
        self.containers.remove(id);
        Ok(())
    }

    /// Get the state of a container.
    pub fn get_state(&self, id: &str) -> Option<(u32, String, Option<i32>)> {
        self.containers
            .get(id)
            .map(|p| (p.pid, p.status.to_string(), p.exit_code))
    }

    pub fn spec_json(&self, id: &str) -> Option<&str> {
        self.containers
            .get(id)
            .map(|process| process.spec_json.as_str())
    }

    /// Reap exited child processes.
    pub fn reap_children(&mut self) {
        for proc in self.containers.values_mut() {
            if proc.status != ContainerStatus::Running || proc.pid == 0 {
                continue;
            }
            if let Some(exit_code) = proc.runtime.as_mut().and_then(|runtime| runtime.try_wait()) {
                tracing::info!(pid = proc.pid, exit_code, "container exited");
                proc.status = ContainerStatus::Stopped;
                proc.exit_code = Some(exit_code);
            }
        }
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

    pub fn request_shutdown(&mut self) {
        for process in self.containers.values_mut() {
            if let Some(runtime) = process.runtime.as_mut() {
                runtime.stop_and_delete();
            }
        }
        self.shutdown = true;
    }

    pub fn should_shutdown(&self) -> bool {
        self.shutdown
    }

    pub fn zone_name(&self) -> &str {
        &self.zone_name
    }

    pub fn rootfs_root(&self) -> &std::path::Path {
        &self.rootfs_root
    }
}
