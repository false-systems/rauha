//! A private, single-use runtime setup cgroup for each native exec.
use aya::maps::{HashMap, Map, MapData, MapError, MapType};
use rauha_ebpf_common::{ZoneInfoKernel, ZONE_FLAG_GLOBAL, ZONE_FLAG_RUNTIME_SETUP};
use std::{
    os::{fd::OwnedFd, unix::fs::MetadataExt},
    path::{Path, PathBuf},
    sync::{Mutex, OnceLock},
};

type Membership = HashMap<MapData, u64, ZoneInfoKernel>;
static MEMBERSHIP: OnceLock<Mutex<Membership>> = OnceLock::new();

pub fn install_membership_map(fd: OwnedFd) -> anyhow::Result<()> {
    let data = MapData::from_fd(fd)?;
    let info = data.info()?;
    anyhow::ensure!(
        info.map_type()? == MapType::Hash
            && info.key_size() == 8
            && info.value_size() == 8
            && info.name_as_str() == Some("ZONE_MEMBERSHIP"),
        "invalid inherited zone membership map"
    );
    let map = Membership::try_from(Map::HashMap(data))?;
    if let Some(existing) = MEMBERSHIP.get() {
        *existing
            .lock()
            .map_err(|_| anyhow::anyhow!("zone membership map lock poisoned"))? = map;
        return Ok(());
    }
    MEMBERSHIP
        .set(Mutex::new(map))
        .map_err(|_| anyhow::anyhow!("membership map already installed"))
}

fn membership() -> anyhow::Result<std::sync::MutexGuard<'static, Membership>> {
    MEMBERSHIP
        .get()
        .ok_or_else(|| anyhow::anyhow!("zone membership map was not inherited"))?
        .lock()
        .map_err(|_| anyhow::anyhow!("zone membership map lock poisoned"))
}

fn parent_path(cgroups_path: &str, container_id: &str) -> anyhow::Result<PathBuf> {
    let parts: Vec<_> = cgroups_path.split('/').collect();
    anyhow::ensure!(
        parts.len() == 4
            && parts[0].is_empty()
            && parts[1] == "rauha.slice"
            && parts[2].starts_with("zone-")
            && parts[2].len() > 5
            && parts[3] == container_id
            && !container_id.is_empty()
            && container_id != "."
            && container_id != "..",
        "container cgroup is outside its zone"
    );
    Ok(Path::new("/sys/fs/cgroup").join(cgroups_path.trim_start_matches('/')))
}

fn setup_membership(mut parent: ZoneInfoKernel) -> anyhow::Result<ZoneInfoKernel> {
    anyhow::ensure!(
        parent.flags & ZONE_FLAG_RUNTIME_SETUP == 0,
        "exec cannot inherit a runtime setup membership"
    );
    if parent.flags & ZONE_FLAG_GLOBAL == 0 {
        parent.flags |= ZONE_FLAG_RUNTIME_SETUP;
    }
    Ok(parent)
}

pub struct ExecCgroup {
    path: PathBuf,
    id: u64,
    name: String,
    cleaned: bool,
}

impl ExecCgroup {
    pub fn create(bundle: &Path, container_id: &str, exec_id: &str) -> anyhow::Result<Self> {
        anyhow::ensure!(
            !exec_id.is_empty()
                && exec_id.len() <= 128
                && exec_id
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b"_.-".contains(&b)),
            "invalid exec cgroup ID"
        );
        let spec: serde_json::Value =
            serde_json::from_slice(&std::fs::read(bundle.join("config.json"))?)?;
        let parent = parent_path(
            spec.pointer("/linux/cgroupsPath")
                .and_then(|v| v.as_str())
                .ok_or_else(|| anyhow::anyhow!("missing container cgroup"))?,
            container_id,
        )?;
        let mut map = membership()?;
        let info = setup_membership(map.get(&parent.metadata()?.ino(), 0)?)?;
        let name = format!("exec-{exec_id}");
        let path = parent.join(&name);
        std::fs::create_dir(&path)?;
        let id = match path.metadata() {
            Ok(metadata) => metadata.ino(),
            Err(error) => {
                let _ = std::fs::remove_dir(&path);
                return Err(error.into());
            }
        };
        if let Err(error) = map.insert(id, info, 1) {
            let _ = std::fs::remove_dir(&path);
            return Err(error.into());
        }
        Ok(Self {
            path,
            id,
            name,
            cleaned: false,
        })
    }

    pub fn name(&self) -> &str {
        &self.name
    }

    pub fn verify_workload_boundary(&self) -> anyhow::Result<()> {
        anyhow::ensure!(
            membership()?.get(&self.id, 0)?.flags & ZONE_FLAG_RUNTIME_SETUP == 0,
            "runtime setup permission was not consumed before workload exec"
        );
        Ok(())
    }

    pub fn terminate(&self) -> anyhow::Result<()> {
        match std::fs::write(self.path.join("cgroup.kill"), "1") {
            Ok(()) => {}
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(()),
            Err(error) => return Err(error.into()),
        }
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
        loop {
            match std::fs::read_to_string(self.path.join("cgroup.events")) {
                Ok(events) if events.lines().any(|line| line == "populated 0") => return Ok(()),
                Ok(_) => {}
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(()),
                Err(error) => return Err(error.into()),
            }
            anyhow::ensure!(
                std::time::Instant::now() < deadline,
                "exec cgroup did not stop after kill; retaining enforcement"
            );
            std::thread::sleep(std::time::Duration::from_millis(10));
        }
    }

    pub fn cleanup(&mut self) -> anyhow::Result<()> {
        if self.cleaned {
            return Ok(());
        }
        match std::fs::read_to_string(self.path.join("cgroup.events")) {
            Ok(events) => anyhow::ensure!(
                events.lines().any(|line| line == "populated 0"),
                "exec cgroup still contains processes; retaining enforcement"
            ),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => return Err(error.into()),
        }
        match std::fs::remove_dir(&self.path) {
            Ok(()) => {}
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => return Err(error.into()),
        }
        let mut map = membership()?;
        match map.get(&self.id, 0) {
            Ok(_) => map.remove(&self.id)?,
            Err(MapError::KeyNotFound) => {}
            Err(error) => return Err(error.into()),
        }
        self.cleaned = true;
        Ok(())
    }
}

impl Drop for ExecCgroup {
    fn drop(&mut self) {
        if let Err(error) = self.cleanup() {
            tracing::error!(%error, path = %self.path.display(), "exec cgroup retained for recovery");
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn ordinary_descriptor_cannot_replace_the_membership_map() {
        let file = std::fs::File::open("/dev/null").unwrap();
        assert!(install_membership_map(file.into()).is_err());
    }
    #[test]
    fn exec_setup_is_scoped_and_cannot_rearm_an_existing_setup_parent() {
        let parent = ZoneInfoKernel {
            zone_id: 42,
            flags: 0,
        };
        let setup = setup_membership(parent).unwrap();
        assert_eq!(setup.zone_id, 42);
        assert_eq!(setup.flags, ZONE_FLAG_RUNTIME_SETUP);
        assert_eq!(parent.flags, 0);
        assert!(setup_membership(setup).is_err());
        assert_eq!(
            setup_membership(ZoneInfoKernel {
                zone_id: 42,
                flags: ZONE_FLAG_GLOBAL
            })
            .unwrap()
            .flags,
            ZONE_FLAG_GLOBAL
        );
    }
    #[test]
    fn exec_cgroup_parent_rejects_traversal_and_other_containers() {
        assert_eq!(
            parent_path("/rauha.slice/zone-a/container", "container").unwrap(),
            Path::new("/sys/fs/cgroup/rauha.slice/zone-a/container")
        );
        for path in [
            "/rauha.slice/zone-a/other",
            "/rauha.slice/zone-a/../container",
            "rauha.slice/zone-a/container",
            "/other/zone-a/container",
        ] {
            assert!(parent_path(path, "container").is_err());
        }
    }
}
