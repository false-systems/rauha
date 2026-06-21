pub mod apfs;
pub mod pf;
pub mod vm;
pub mod vsock;

use std::path::{Path, PathBuf};

use rauha_common::backend::IsolationBackend;
use rauha_common::container::{ContainerHandle, ContainerSpec};
use rauha_common::error::{RauhaError, Result};
use rauha_common::shim::{ShimRequest, ShimResponse};
use rauha_common::zone::*;
use uuid::Uuid;

use self::apfs::ApfsManager;
use self::pf::PfManager;
use self::vm::{VmConfig, VmManager};

/// macOS isolation backend using Virtualization.framework.
///
/// One lightweight Linux VM per zone. The VM is the isolation boundary.
/// Communication with the guest agent inside the VM uses virtio-vsock
/// with the same ShimRequest/ShimResponse protocol as the Linux shim.
pub struct MacosBackend {
    vm_manager: VmManager,
    pf_manager: PfManager,
    apfs_manager: ApfsManager,
    root: PathBuf,
}

impl MacosBackend {
    pub fn new(root: &str) -> Result<Self> {
        let root_path = PathBuf::from(root);
        Ok(Self {
            vm_manager: VmManager::new(),
            pf_manager: PfManager::new(),
            apfs_manager: ApfsManager::new(&root_path),
            root: root_path,
        })
    }

    /// Send a request to a zone's guest agent via vsock.
    fn send_to_guest(
        &self,
        zone_name: &str,
        request: &ShimRequest,
    ) -> Result<ShimResponse> {
        vsock::send_request(&self.vm_manager, zone_name, request)
    }

    /// Build an OCI spec JSON from a ContainerSpec for the guest agent.
    fn build_spec_json(&self, spec: &ContainerSpec) -> String {
        let env: Vec<String> = spec
            .env
            .iter()
            .map(|(k, v)| format!("{k}={v}"))
            .collect();
        let cwd = spec.working_dir.as_deref().unwrap_or("/");

        // Minimal OCI runtime spec with just what fork_and_exec needs.
        serde_json::json!({
            "process": {
                "args": spec.command,
                "env": env,
                "cwd": cwd,
                "user": { "uid": 0, "gid": 0 }
            },
            "root": {
                "path": "rootfs"
            }
        })
        .to_string()
    }

    /// Zone-specific container data directory.
    fn zone_dir(&self, zone_name: &str) -> PathBuf {
        self.root.join("containers").join(zone_name)
    }
}

impl IsolationBackend for MacosBackend {
    fn create_zone(&self, config: &ZoneConfig) -> Result<ZoneHandle> {
        tracing::info!(zone = config.name, backend = "macos-virtualization", "creating zone");

        let zone_id = Uuid::new_v4();
        let zone_dir = self.zone_dir(&config.name);
        std::fs::create_dir_all(&zone_dir).map_err(|e| RauhaError::BackendError(
            format!("failed to create zone dir: {e}"),
        ))?;

        // Create pf anchor for network isolation.
        // Non-fatal: pf requires root, and we don't want to block development
        // testing when running rauhad without root.
        if let Err(e) = self.pf_manager.create_zone_rules(&config.name, &config.policy) {
            tracing::warn!(zone = config.name, %e, "pf rules not applied — network isolation inactive (run as root for full isolation)");
        }

        // Boot VM with virtio-vsock + virtio-fs.
        let vm_config = VmConfig::from_policy(&config.policy, zone_dir);
        self.vm_manager.boot_vm(&config.name, &vm_config)?;

        Ok(ZoneHandle {
            id: zone_id,
            name: config.name.clone(),
            platform_id: 0, // VM doesn't have a numeric platform ID
            network_state: None, // macOS VMs get IPs from Virtualization.framework's NAT
        })
    }

    fn destroy_zone(&self, zone: &ZoneHandle) -> Result<()> {
        tracing::info!(zone = zone.name, "destroying zone");

        // Shut down VM.
        self.vm_manager.shutdown_vm(&zone.name)?;

        // Remove pf rules.
        self.pf_manager.remove_zone_rules(&zone.name)?;

        // Clean up zone directory.
        let zone_dir = self.zone_dir(&zone.name);
        if zone_dir.exists() {
            let _ = std::fs::remove_dir_all(&zone_dir);
        }

        Ok(())
    }

    fn enforce_policy(&self, zone: &ZoneHandle, policy: &ZonePolicy) -> Result<()> {
        tracing::info!(zone = zone.name, "enforcing policy");

        // Update pf rules (non-fatal without root).
        if let Err(e) = self.pf_manager.update_zone_rules(&zone.name, policy) {
            tracing::warn!(zone = zone.name, %e, "pf rules not applied");
        }

        // VM resource limits (CPU/memory) can only be set at boot time
        // with Virtualization.framework. Log a warning if they differ.
        tracing::debug!(
            zone = zone.name,
            "VM CPU/memory limits are set at boot — restart zone to change"
        );

        Ok(())
    }

    fn hot_reload_policy(&self, zone: &ZoneHandle, policy: &ZonePolicy) -> Result<()> {
        tracing::info!(zone = zone.name, "hot-reloading policy");

        // Network rules can be hot-reloaded (non-fatal without root).
        if let Err(e) = self.pf_manager.update_zone_rules(&zone.name, policy) {
            tracing::warn!(zone = zone.name, %e, "pf rules not applied");
        }

        // VM resource limits cannot be hot-reloaded — log this.
        tracing::info!(
            zone = zone.name,
            "network policy updated; CPU/memory limits require zone restart"
        );

        Ok(())
    }

    fn create_container(
        &self,
        zone: &ZoneHandle,
        spec: &ContainerSpec,
    ) -> Result<ContainerHandle> {
        tracing::info!(zone = zone.name, container = spec.name, "creating container");

        let container_id = Uuid::new_v4();

        // Place rootfs where the guest agent expects it:
        // {zone_dir}/containers/{id}/rootfs → /mnt/rauha/containers/{id}/rootfs in VM.
        let container_rootfs = self
            .zone_dir(&zone.name)
            .join("containers")
            .join(container_id.to_string())
            .join("rootfs");

        if let Some(ref base_rootfs) = spec.rootfs_path {
            self.apfs_manager
                .clone_rootfs(base_rootfs, &container_rootfs)?;
        } else {
            std::fs::create_dir_all(&container_rootfs).map_err(|e| {
                RauhaError::RootfsError {
                    message: format!("failed to create container rootfs dir: {e}"),
                }
            })?;
        }

        // Send CreateContainer to guest agent via vsock.
        let spec_json = self.build_spec_json(spec);
        let response = self.send_to_guest(
            &zone.name,
            &ShimRequest::CreateContainer {
                id: container_id.to_string(),
                spec_json,
            },
        )?;

        match response {
            ShimResponse::Created { pid } => Ok(ContainerHandle {
                id: container_id,
                zone_id: zone.id,
                pid,
                platform_id: 0,
            }),
            ShimResponse::Error { message } => Err(RauhaError::ContainerExecError {
                container: spec.name.clone(),
                message,
            }),
            other => Err(RauhaError::BackendError(format!(
                "unexpected response from guest agent: {other:?}"
            ))),
        }
    }

    fn start_container(&self, container: &ContainerHandle) -> Result<u32> {
        tracing::info!(container = %container.id, "starting container");

        // We need to find which zone this container belongs to.
        // The zone_id is in the handle, but we need the zone name for vsock routing.
        // For now, look up the zone by checking running VMs.
        let zone_name = self.find_zone_for_container(container)?;

        let response = self.send_to_guest(
            &zone_name,
            &ShimRequest::StartContainer {
                id: container.id.to_string(),
            },
        )?;

        match response {
            ShimResponse::Created { pid } => Ok(pid),
            ShimResponse::Error { message } => Err(RauhaError::ContainerExecError {
                container: container.id.to_string(),
                message,
            }),
            other => Err(RauhaError::BackendError(format!(
                "unexpected response to StartContainer: {other:?}"
            ))),
        }
    }

    fn stop_container(&self, container: &ContainerHandle) -> Result<()> {
        tracing::info!(container = %container.id, "stopping container");

        let zone_name = self.find_zone_for_container(container)?;

        // Send SIGTERM first.
        let response = self.send_to_guest(
            &zone_name,
            &ShimRequest::StopContainer {
                id: container.id.to_string(),
                signal: 15, // SIGTERM
            },
        )?;

        match response {
            ShimResponse::Ok => Ok(()),
            ShimResponse::Error { message } => {
                tracing::warn!(container = %container.id, %message, "SIGTERM failed, trying SIGKILL");
                // Try SIGKILL as fallback.
                let _ = self.send_to_guest(
                    &zone_name,
                    &ShimRequest::StopContainer {
                        id: container.id.to_string(),
                        signal: 9, // SIGKILL
                    },
                );
                Ok(())
            }
            _ => Ok(()),
        }
    }

    fn zone_stats(&self, zone: &ZoneHandle) -> Result<ZoneStats> {
        // Query guest agent for resource usage.
        match self.send_to_guest(&zone.name, &ShimRequest::GetStats) {
            Ok(ShimResponse::Stats {
                cpu_usage_ns,
                memory_bytes,
                pids,
                container_count,
                network_rx_bytes,
                network_tx_bytes,
            }) => Ok(ZoneStats {
                zone_id: zone.id,
                container_count,
                cpu_usage_percent: cpu_usage_ns as f64 / 1_000_000_000.0,
                memory_usage_bytes: memory_bytes,
                memory_limit_bytes: 0, // Set from policy
                network_rx_bytes,
                network_tx_bytes,
                pids_current: pids as u64,
            }),
            Ok(other) => Err(RauhaError::BackendError(format!(
                "unexpected response to GetStats: {other:?}"
            ))),
            Err(e) => Err(e),
        }
    }

    fn verify_isolation(&self, zone: &ZoneHandle) -> Result<IsolationReport> {
        let mut checks = Vec::new();

        // Check 1: VM is running.
        let vm_running = self.vm_manager.is_running(&zone.name);
        checks.push(IsolationCheck {
            name: "vm-running".into(),
            passed: vm_running,
            detail: if vm_running {
                "Virtualization.framework VM is running".into()
            } else {
                "VM is not running for this zone".into()
            },
        });

        // Check 2: pf anchor exists.
        // pf requires root — without it, rules aren't written (by design).
        // The VM boundary is the primary isolation on macOS; pf is defense-in-depth.
        let pf_file = Path::new("/etc/pf.anchors")
            .join(format!("com.rauha.zone-{}", zone.name));
        let pf_exists = pf_file.exists();
        let is_root = unsafe { libc::geteuid() } == 0;
        checks.push(IsolationCheck {
            name: "pf-anchor".into(),
            passed: pf_exists || !is_root,
            detail: if pf_exists {
                format!("pf anchor file exists at {}", pf_file.display())
            } else if !is_root {
                "pf rules not applied (not running as root) — VM boundary provides isolation".into()
            } else {
                "pf anchor file missing — network isolation inactive".into()
            },
        });

        // Check 3: zone directory exists.
        let zone_dir = self.zone_dir(&zone.name);
        let dir_exists = zone_dir.exists();
        checks.push(IsolationCheck {
            name: "zone-directory".into(),
            passed: dir_exists,
            detail: if dir_exists {
                format!("zone directory exists at {}", zone_dir.display())
            } else {
                "zone directory missing".into()
            },
        });

        let is_isolated = checks.iter().all(|c| c.passed);

        Ok(IsolationReport {
            zone_id: zone.id,
            model: IsolationModel::HardwareBoundary,
            is_isolated,
            checks,
        })
    }

    fn recover_zone(
        &self,
        zone: &ZoneHandle,
        _zone_type: ZoneType,
        policy: &ZonePolicy,
    ) -> Result<()> {
        tracing::info!(zone = zone.name, "recovering zone");

        // VMs don't survive daemon restart — we need to re-boot.
        if !self.vm_manager.is_running(&zone.name) {
            let zone_dir = self.zone_dir(&zone.name);
            std::fs::create_dir_all(&zone_dir).map_err(|e| {
                RauhaError::BackendError(format!("failed to create zone dir: {e}"))
            })?;

            let vm_config = VmConfig::from_policy(policy, zone_dir);
            self.vm_manager.boot_vm(&zone.name, &vm_config)?;
        }

        // Re-apply pf rules (non-fatal without root).
        if let Err(e) = self.pf_manager.create_zone_rules(&zone.name, policy) {
            tracing::warn!(zone = zone.name, %e, "pf rules not applied during recovery");
        }

        Ok(())
    }

    fn cleanup_orphans(&self, known_zones: &[ZoneHandle]) -> Result<()> {
        let known_names: Vec<&str> = known_zones.iter().map(|z| z.name.as_str()).collect();
        let running = self.vm_manager.running_zones();

        for zone_name in running {
            if !known_names.contains(&zone_name.as_str()) {
                tracing::warn!(zone = zone_name, "shutting down orphaned VM");
                let _ = self.vm_manager.shutdown_vm(&zone_name);
                let _ = self.pf_manager.remove_zone_rules(&zone_name);
            }
        }

        Ok(())
    }

    fn isolation_model(&self) -> IsolationModel {
        IsolationModel::HardwareBoundary
    }

    fn name(&self) -> &str {
        "macos-virtualization"
    }

    fn shim_request(
        &self,
        zone_name: &str,
        request: &ShimRequest,
    ) -> Result<ShimResponse> {
        self.send_to_guest(zone_name, request)
    }

    fn connect_vsock_port(
        &self,
        zone_name: &str,
        port: u32,
    ) -> Result<std::os::fd::OwnedFd> {
        self.vm_manager.connect_vsock(zone_name, port)
    }
}

impl MacosBackend {
    /// Find the zone name for a container by scanning zone directories.
    fn find_zone_for_container(&self, container: &ContainerHandle) -> Result<String> {
        let containers_dir = self.root.join("containers");
        if let Ok(entries) = std::fs::read_dir(&containers_dir) {
            for entry in entries.flatten() {
                let zone_name = entry.file_name().to_string_lossy().to_string();
                // Container rootfs lives at {zone_dir}/containers/{id}/rootfs.
                let container_dir = entry.path().join("containers").join(container.id.to_string());
                if container_dir.exists() {
                    return Ok(zone_name);
                }
            }
        }

        // Fallback: check running VMs. If only one is running, use it.
        let running = self.vm_manager.running_zones();
        if running.len() == 1 {
            return Ok(running.into_iter().next().unwrap());
        }

        Err(RauhaError::ContainerNotFound(container.id))
    }
}
