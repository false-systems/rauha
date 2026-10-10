//! cgroup v2 management for zone isolation.
//!
//! Each zone gets a cgroup at `/sys/fs/cgroup/rauha.slice/zone-{name}/`.
//! Resource limits are applied by writing to cgroup control files.
//! The cgroup_id (inode number) identifies the zone in BPF maps.

use std::fs;
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};

use rauha_common::error::{RauhaError, Result};
use rauha_common::zone::{ResourcePolicy, ZoneStats};

const CGROUP_ROOT: &str = "/sys/fs/cgroup";
const RAUHA_SLICE: &str = "rauha.slice";

pub struct CgroupManager {
    /// Path to the rauha slice: /sys/fs/cgroup/rauha.slice
    slice_path: PathBuf,
}

impl CgroupManager {
    /// Create a new CgroupManager, ensuring the rauha.slice exists.
    pub fn new() -> Result<Self> {
        let slice_path = PathBuf::from(CGROUP_ROOT).join(RAUHA_SLICE);

        // Verify cgroup v2 is mounted.
        if !Path::new(CGROUP_ROOT).join("cgroup.controllers").exists() {
            return Err(RauhaError::CgroupError {
                message: "cgroup v2 not available".into(),
                hint: "mount cgroup2 at /sys/fs/cgroup or boot with systemd.unified_cgroup_hierarchy=1".into(),
            });
        }

        // Create our slice if it doesn't exist.
        if !slice_path.exists() {
            fs::create_dir_all(&slice_path).map_err(|e| RauhaError::CgroupError {
                message: format!("failed to create {}: {e}", slice_path.display()),
                hint: "run rauhad as root".into(),
            })?;
        }

        // Enable controllers for child cgroups (zones).
        // Without this, zone cgroups can't use cpu.weight, memory.max, etc.
        let subtree_control = slice_path.join("cgroup.subtree_control");
        if let Err(e) = fs::write(&subtree_control, "+cpu +memory +pids +io") {
            tracing::warn!(
                %e,
                "failed to enable cgroup controllers in rauha.slice — \
                 resource limits may not work. Check that parent cgroup has \
                 controllers delegated."
            );
        }

        Ok(Self { slice_path })
    }

    /// Create a cgroup for a zone. Returns the cgroup_id (inode number).
    pub fn create_zone_cgroup(&self, zone_name: &str) -> Result<u64> {
        let path = self.zone_path(zone_name);

        if path.exists() {
            return Err(RauhaError::CgroupError {
                message: format!("cgroup already exists: {}", path.display()),
                hint: format!("run: rmdir {}", path.display()),
            });
        }

        fs::create_dir(&path).map_err(|e| RauhaError::CgroupError {
            message: format!("failed to create cgroup {}: {e}", path.display()),
            hint: "run rauhad as root".into(),
        })?;

        self.cgroup_id(&path)
    }

    /// Destroy a zone's cgroup. The cgroup must be empty (no processes).
    pub fn destroy_zone_cgroup(&self, zone_name: &str) -> Result<()> {
        let path = self.zone_path(zone_name);

        if !path.exists() {
            return Ok(()); // Already gone, idempotent.
        }

        for (_, child) in self.container_cgroups(zone_name)? {
            fs::remove_dir(&child).map_err(|e| RauhaError::CgroupError {
                message: format!("failed to remove child cgroup {}: {e}", child.display()),
                hint: "stop all container processes and retry".into(),
            })?;
        }
        fs::remove_dir(&path).map_err(|e| RauhaError::CgroupError {
            message: format!("failed to remove cgroup {}: {e}", path.display()),
            hint: "ensure no processes remain in the zone (check cgroup.procs)".into(),
        })?;

        Ok(())
    }

    /// Apply resource limits to a zone's cgroup.
    pub fn apply_resources(&self, zone_name: &str, resources: &ResourcePolicy) -> Result<()> {
        let path = self.zone_path(zone_name);

        if !path.exists() {
            return Err(RauhaError::CgroupError {
                message: format!("cgroup does not exist: {}", path.display()),
                hint: "create the zone first".into(),
            });
        }

        // cpu.weight: 1-10000, default 100. cgroup v2 uses "weight" not "shares".
        // Convert cpu_shares (sysfs convention: 2-262144, default 1024) to weight (1-10000).
        let weight = shares_to_weight(resources.cpu_shares);
        write_cgroup_file(&path, "cpu.weight", &weight.to_string())?;

        // memory.max: bytes or "max" for unlimited.
        if resources.memory_limit == 0 || resources.memory_limit == u64::MAX {
            write_cgroup_file(&path, "memory.max", "max")?;
        } else {
            write_cgroup_file(&path, "memory.max", &resources.memory_limit.to_string())?;
        }

        // pids.max: count or "max".
        if resources.pids_max == 0 || resources.pids_max == u64::MAX {
            write_cgroup_file(&path, "pids.max", "max")?;
        } else {
            write_cgroup_file(&path, "pids.max", &resources.pids_max.to_string())?;
        }

        // io.weight: 1-10000, default 100.
        let io_weight = resources.io_weight.clamp(1, 10000);
        write_cgroup_file(&path, "io.weight", &format!("default {io_weight}"))?;

        Ok(())
    }

    /// Suspend survivors before loading fresh maps; only successful recovery thaws them.
    pub fn freeze_existing_zones(&self) -> Result<()> {
        let mut zones = Vec::new();
        for entry in fs::read_dir(&self.slice_path)? {
            let entry = entry?;
            if !entry.file_type()?.is_dir() {
                continue;
            }
            let name = entry.file_name();
            let name = name
                .to_str()
                .ok_or_else(|| RauhaError::BackendError("cgroup name is not UTF-8".into()))?;
            if let Some(zone) = name.strip_prefix("zone-") {
                zones.push(zone.to_owned());
            }
        }
        // Request all freezes even if one fails; never leave later zones running
        // solely because an earlier cgroup could not acknowledge suspension.
        let mut failed = None;
        for zone in &zones {
            if let Err(error) = write_cgroup_file(&self.zone_path(zone), "cgroup.freeze", "1") {
                failed.get_or_insert(error);
            }
        }
        if let Some(error) = failed {
            return Err(error);
        }
        for zone in zones {
            self.set_frozen(&zone, true)?;
        }
        Ok(())
    }

    /// Freeze or thaw the complete zone subtree and wait for kernel acknowledgement.
    pub fn set_frozen(&self, zone_name: &str, frozen: bool) -> Result<()> {
        let path = self.zone_path(zone_name);
        write_cgroup_file(&path, "cgroup.freeze", if frozen { "1" } else { "0" })?;
        for _ in 0..500 {
            let events = fs::read_to_string(path.join("cgroup.events"))?;
            if events
                .lines()
                .any(|line| line == if frozen { "frozen 1" } else { "frozen 0" })
            {
                return Ok(());
            }
            std::thread::sleep(std::time::Duration::from_millis(10));
        }
        Err(RauhaError::BackendError(format!(
            "zone {zone_name} did not acknowledge frozen={frozen}"
        )))
    }

    /// Read runtime stats from a zone's cgroup.
    pub fn read_stats(&self, zone_name: &str, zone_id: uuid::Uuid) -> Result<ZoneStats> {
        let path = self.zone_path(zone_name);

        if !path.exists() {
            return Err(RauhaError::CgroupError {
                message: format!("cgroup does not exist: {}", path.display()),
                hint: "create the zone first".into(),
            });
        }

        let memory_current = read_cgroup_u64(&path, "memory.current").unwrap_or(0);
        let memory_limit = read_cgroup_u64(&path, "memory.max").unwrap_or(0);
        let pids_current = read_cgroup_u64(&path, "pids.current").unwrap_or(0);
        let cpu_usage = read_cpu_usage(&path).unwrap_or(0.0);

        Ok(ZoneStats {
            zone_id,
            container_count: 0, // Filled by caller.
            cpu_usage_percent: cpu_usage,
            memory_usage_bytes: memory_current,
            memory_limit_bytes: memory_limit,
            network_rx_bytes: 0, // Requires netns stats — Phase 2.10.
            network_tx_bytes: 0,
            pids_current,
        })
    }

    /// Get the cgroup_id (inode number) for a zone's cgroup.
    pub fn cgroup_id_for_zone(&self, zone_name: &str) -> Result<u64> {
        let path = self.zone_path(zone_name);
        self.cgroup_id(&path)
    }

    /// Check if a zone's cgroup exists.
    pub fn zone_cgroup_exists(&self, zone_name: &str) -> bool {
        self.zone_path(zone_name).exists()
    }

    pub fn zone_has_processes(&self, zone_name: &str) -> Result<bool> {
        let path = self.zone_path(zone_name).join("cgroup.events");
        let processes = fs::read_to_string(&path).map_err(|e| RauhaError::CgroupError {
            message: format!("failed to read {}: {e}", path.display()),
            hint: "retain kernel membership until cgroup state is readable".into(),
        })?;
        Ok(processes.lines().any(|line| line == "populated 1"))
    }

    /// Children first, so teardown never removes a parent before its descendants.
    pub fn container_cgroups(&self, zone_name: &str) -> Result<Vec<(u64, PathBuf)>> {
        fn visit(path: &Path, children: &mut Vec<(u64, PathBuf)>) -> std::io::Result<()> {
            for entry in fs::read_dir(path)? {
                let entry = entry?;
                if entry.file_type()?.is_dir() {
                    visit(&entry.path(), children)?;
                    children.push((entry.metadata()?.ino(), entry.path()));
                }
            }
            Ok(())
        }
        let mut children = Vec::new();
        let path = self.zone_path(zone_name);
        if path.exists() {
            visit(&path, &mut children).map_err(|e| RauhaError::CgroupError {
                message: format!("cannot enumerate container cgroups: {e}"),
                hint: "retain enforcement and retry".into(),
            })?;
        }
        Ok(children)
    }

    /// Kill every process in a zone and wait until the cgroup is empty.
    /// Enforcement must stay installed until this succeeds.
    pub fn drain_zone(&self, zone_name: &str) -> Result<()> {
        let path = self.zone_path(zone_name);
        if !path.exists() || !self.zone_has_processes(zone_name)? {
            return Ok(());
        }

        let kill_path = path.join("cgroup.kill");
        let native_kill = kill_path.exists();
        if native_kill {
            fs::write(&kill_path, "1").map_err(|e| RauhaError::CgroupError {
                message: format!(
                    "failed to kill processes through {}: {e}",
                    kill_path.display()
                ),
                hint: "retain zone enforcement and retry teardown".into(),
            })?;
        }

        for _ in 0..100 {
            if !self.zone_has_processes(zone_name)? {
                return Ok(());
            }
            if !native_kill {
                // cgroup.kill arrived in Linux 5.14. Re-read while draining so
                // children forked during teardown cannot escape the snapshot.
                let mut groups = self.container_cgroups(zone_name)?;
                groups.push((0, path.clone()));
                for (_, group) in groups {
                    let procs_path = group.join("cgroup.procs");
                    let procs =
                        fs::read_to_string(&procs_path).map_err(|e| RauhaError::CgroupError {
                            message: format!("failed to read {}: {e}", procs_path.display()),
                            hint: "retain zone enforcement and retry teardown".into(),
                        })?;
                    for pid in procs.lines().filter_map(|pid| pid.parse::<i32>().ok()) {
                        unsafe {
                            libc::kill(pid, libc::SIGKILL);
                        }
                    }
                }
            }
            std::thread::sleep(std::time::Duration::from_millis(10));
        }

        Err(RauhaError::CgroupError {
            message: format!("zone {zone_name} cgroup still contains live processes"),
            hint: "enforcement was retained; inspect cgroup.procs and retry teardown".into(),
        })
    }

    pub(super) fn zone_path(&self, zone_name: &str) -> PathBuf {
        self.slice_path.join(format!("zone-{zone_name}"))
    }

    fn cgroup_id(&self, path: &Path) -> Result<u64> {
        let meta = fs::metadata(path).map_err(|e| RauhaError::CgroupError {
            message: format!("failed to stat {}: {e}", path.display()),
            hint: "check cgroup filesystem is mounted".into(),
        })?;
        // On cgroupfs, st_ino is the cgroup_id used by bpf_get_current_cgroup_id().
        Ok(meta.ino())
    }
}

/// Convert Docker-style cpu_shares (2-262144, default 1024) to cgroup v2 weight (1-10000, default 100).
fn shares_to_weight(shares: u64) -> u64 {
    if shares == 0 {
        return 100; // default
    }
    // Linear mapping: shares/1024 * 100, clamped to [1, 10000].
    let weight = (shares * 100) / 1024;
    weight.clamp(1, 10000)
}

fn write_cgroup_file(cgroup_path: &Path, filename: &str, value: &str) -> Result<()> {
    let file_path = cgroup_path.join(filename);
    fs::write(&file_path, value).map_err(|e| RauhaError::CgroupError {
        message: format!("failed to write {} to {}: {e}", value, file_path.display()),
        hint: format!(
            "check that {} controller is enabled in the parent cgroup",
            filename.split('.').next().unwrap_or("unknown")
        ),
    })?;
    Ok(())
}

fn read_cgroup_u64(cgroup_path: &Path, filename: &str) -> Option<u64> {
    let content = fs::read_to_string(cgroup_path.join(filename)).ok()?;
    let trimmed = content.trim();
    if trimmed == "max" {
        return Some(u64::MAX);
    }
    trimmed.parse().ok()
}

/// Read cumulative CPU usage from cgroup cpu.stat.
///
/// Returns cumulative CPU seconds (NOT a percentage). The field is named
/// `cpu_usage_percent` in the proto for historical reasons but contains
/// cumulative seconds. Callers computing real utilization need two samples
/// and the elapsed wall time: `(sample2 - sample1) / elapsed * 100`.
fn read_cpu_usage(cgroup_path: &Path) -> Option<f64> {
    let content = fs::read_to_string(cgroup_path.join("cpu.stat")).ok()?;
    for line in content.lines() {
        if let Some(value) = line.strip_prefix("usage_usec ") {
            let usec: u64 = value.trim().parse().ok()?;
            return Some(usec as f64 / 1_000_000.0);
        }
    }
    Some(0.0)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn teardown_enumerates_nested_container_groups_children_first() {
        let dir = tempfile::tempdir().unwrap();
        let manager = CgroupManager {
            slice_path: dir.path().to_owned(),
        };
        let child = manager.zone_path("test").join("container");
        let nested = child.join("nested");
        fs::create_dir_all(&nested).unwrap();
        fs::write(child.join("cgroup.procs"), "").unwrap();
        let groups = manager.container_cgroups("test").unwrap();
        assert_eq!(
            groups.iter().map(|(_, path)| path).collect::<Vec<_>>(),
            vec![&nested, &child]
        );
        assert!(groups
            .iter()
            .all(|(id, path)| *id == fs::metadata(path).unwrap().ino()));
    }

    #[test]
    fn startup_requests_every_zone_freeze_and_does_not_thaw_on_failure() {
        let dir = tempfile::tempdir().unwrap();
        let manager = CgroupManager {
            slice_path: dir.path().to_owned(),
        };
        for zone in ["a", "b", "c"] {
            fs::create_dir(manager.zone_path(zone)).unwrap();
            fs::write(
                manager.zone_path(zone).join("cgroup.events"),
                "populated 1\nfrozen 1\n",
            )
            .unwrap();
            fs::write(manager.zone_path(zone).join("cgroup.freeze"), "0").unwrap();
        }
        fs::create_dir(dir.path().join("unrelated")).unwrap();
        manager.freeze_existing_zones().unwrap();
        for zone in ["a", "b", "c"] {
            assert_eq!(
                fs::read_to_string(manager.zone_path(zone).join("cgroup.freeze")).unwrap(),
                "1"
            );
        }
        assert!(!dir.path().join("unrelated/cgroup.freeze").exists());
        let broken = manager.zone_path("b").join("cgroup.freeze");
        fs::remove_file(&broken).unwrap();
        fs::create_dir(&broken).unwrap();
        for zone in ["a", "c"] {
            fs::write(manager.zone_path(zone).join("cgroup.freeze"), "0").unwrap();
        }
        assert!(manager.freeze_existing_zones().is_err());
        for zone in ["a", "c"] {
            assert_eq!(
                fs::read_to_string(manager.zone_path(zone).join("cgroup.freeze")).unwrap(),
                "1"
            );
        }
    }

    #[test]
    fn test_shares_to_weight() {
        assert_eq!(shares_to_weight(1024), 100); // default
        assert_eq!(shares_to_weight(512), 50);
        assert_eq!(shares_to_weight(2048), 200);
        assert_eq!(shares_to_weight(0), 100); // zero → default
        assert_eq!(shares_to_weight(1), 1); // minimum clamp
    }
}
