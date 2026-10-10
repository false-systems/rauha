//! Per-container cgroup v2 counters; OCI resource changes are handled by crun.
use rauha_common::shim::ShimResponse;
use std::path::{Path, PathBuf};

pub fn path(zone: &str, id: &str) -> PathBuf {
    PathBuf::from("/sys/fs/cgroup/rauha.slice")
        .join(format!("zone-{zone}"))
        .join(id)
}

pub fn stats(path: &Path) -> anyhow::Result<ShimResponse> {
    let cpu = std::fs::read_to_string(path.join("cpu.stat"))?;
    let counter = |key: &str| -> anyhow::Result<u64> {
        cpu.lines()
            .find_map(|line| {
                line.split_once(' ')
                    .filter(|(k, _)| *k == key)
                    .map(|(_, v)| v.parse::<u64>())
            })
            .ok_or_else(|| anyhow::anyhow!("missing cpu counter {key}"))?
            .map_err(Into::into)
    };
    let read = |file: &str| -> anyhow::Result<u64> {
        let text = std::fs::read_to_string(path.join(file))?;
        if text.trim() == "max" {
            Ok(u64::MAX)
        } else {
            Ok(text.trim().parse()?)
        }
    };
    let process_ids = process_ids(path)?;
    Ok(ShimResponse::ContainerStats {
        cpu_usage_usec: counter("usage_usec")?,
        cpu_user_usec: counter("user_usec")?,
        cpu_system_usec: counter("system_usec")?,
        memory_usage_bytes: read("memory.current")?,
        memory_limit_bytes: read("memory.max")?,
        pids_current: read("pids.current")?,
        pids_limit: read("pids.max")?,
        process_ids,
    })
}

fn process_ids(path: &Path) -> anyhow::Result<Vec<u32>> {
    let mut pending = vec![path.to_path_buf()];
    let mut ids = std::collections::BTreeSet::new();
    while let Some(path) = pending.pop() {
        let text = match std::fs::read_to_string(path.join("cgroup.procs")) {
            Ok(text) => text,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => continue,
            Err(error) => return Err(error.into()),
        };
        for id in text.lines() {
            ids.insert(id.parse::<u32>()?);
        }
        let entries = match std::fs::read_dir(path) {
            Ok(entries) => entries,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => continue,
            Err(error) => return Err(error.into()),
        };
        for entry in entries {
            let entry = entry?;
            if entry.file_type()?.is_dir() {
                pending.push(entry.path());
            }
        }
    }
    Ok(ids.into_iter().collect())
}

#[cfg(test)]
mod tests {
    #[test]
    fn process_list_includes_exec_children_without_following_symlinks() {
        let directory = tempfile::tempdir().unwrap();
        let child = directory.path().join("exec-one");
        std::fs::create_dir(&child).unwrap();
        std::fs::write(directory.path().join("cgroup.procs"), "10\n").unwrap();
        std::fs::write(child.join("cgroup.procs"), "20\n10\n").unwrap();
        std::os::unix::fs::symlink(directory.path(), child.join("loop")).unwrap();
        assert_eq!(super::process_ids(directory.path()).unwrap(), [10, 20]);
    }
    #[test]
    fn exec_enrollment_is_beneath_the_container_not_only_the_zone() {
        assert_eq!(
            super::path("zone", "container").join("cgroup.procs"),
            std::path::Path::new("/sys/fs/cgroup/rauha.slice/zone-zone/container/cgroup.procs")
        );
    }
}
