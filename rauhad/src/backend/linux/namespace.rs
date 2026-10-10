//! Network namespace management for zone isolation.
//!
//! Each zone gets its own network namespace, providing full network
//! stack isolation. The daemon creates/destroys netns as zones come and go.

use std::fs;
use std::os::{fd::AsRawFd, unix::fs::MetadataExt};
use std::path::PathBuf;
use std::process::Command;

use rauha_common::error::{RauhaError, Result};

/// Create a network namespace for a zone.
///
/// Uses `ip netns add` to create a named namespace that persists
/// in the netns dir and can be entered by other processes.
pub fn create_netns(zone_name: &str, netns_dir: &str) -> Result<()> {
    let ns_name = netns_name(zone_name);

    // Ensure the netns dir exists.
    fs::create_dir_all(netns_dir).map_err(|e| RauhaError::NamespaceError {
        message: format!("failed to create {netns_dir}: {e}"),
        hint: "run rauhad as root".into(),
    })?;

    let output = Command::new("ip")
        .args(["netns", "add", &ns_name])
        .output()
        .map_err(|e| RauhaError::NamespaceError {
            message: format!("failed to run `ip netns add {ns_name}`: {e}"),
            hint: "ensure iproute2 is installed".into(),
        })?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        // Idempotent: if netns already exists, that's fine.
        if !stderr.contains("File exists") {
            return Err(RauhaError::NamespaceError {
                message: format!("ip netns add {ns_name} failed: {stderr}"),
                hint: "run rauhad as root".into(),
            });
        }
    }

    tracing::info!(namespace = ns_name, "created network namespace");
    Ok(())
}

/// Destroy a zone's network namespace.
pub fn destroy_netns(zone_name: &str, netns_dir: &str) -> Result<()> {
    let ns_name = netns_name(zone_name);
    let ns_path = PathBuf::from(netns_dir).join(&ns_name);

    if !ns_path.exists() {
        return Ok(()); // Already gone.
    }

    use std::os::unix::ffi::OsStrExt;
    let path = std::ffi::CString::new(ns_path.as_os_str().as_bytes()).map_err(|e| {
        RauhaError::NamespaceError {
            message: e.to_string(),
            hint: "configure a valid namespace directory".into(),
        }
    })?;
    if unsafe { libc::umount(path.as_ptr()) } != 0 {
        let error = std::io::Error::last_os_error();
        if !matches!(error.raw_os_error(), Some(libc::EINVAL | libc::ENOENT)) {
            return Err(RauhaError::NamespaceError {
                message: format!("unmount namespace {ns_name}: {error}"),
                hint: "stop namespace users and retry cleanup".into(),
            });
        }
    }
    fs::remove_file(&ns_path).map_err(|e| RauhaError::NamespaceError {
        message: format!("remove namespace pin {ns_name}: {e}"),
        hint: "retry cleanup".into(),
    })?;

    tracing::info!(namespace = ns_name, "destroyed network namespace");
    Ok(())
}

/// Check if a zone's network namespace exists.
pub fn netns_exists(zone_name: &str, netns_dir: &str) -> bool {
    PathBuf::from(netns_dir)
        .join(netns_name(zone_name))
        .exists()
}

/// Absolute path of a zone's named network namespace (for OCI spec
/// `linux.namespaces[].path`).
pub fn netns_path(zone_name: &str, netns_dir: &str) -> PathBuf {
    PathBuf::from(netns_dir).join(netns_name(zone_name))
}

fn netns_name(zone_name: &str) -> String {
    format!("rauha-{zone_name}")
}

/// Pin an orchestrator-owned namespace without trusting its path after admission.
pub fn import_netns(zone_name: &str, netns_dir: &str, source: &str) -> Result<()> {
    let fail = |error: String| RauhaError::NamespaceError {
        message: error,
        hint: "provide a unique, non-host CNI network namespace".into(),
    };
    let file = fs::File::open(source).map_err(|e| fail(e.to_string()))?;
    // NS_GET_NSTYPE proves this is a network namespace, not an arbitrary bind source.
    if unsafe { libc::ioctl(file.as_raw_fd(), 0xb703) } != libc::CLONE_NEWNET {
        return Err(fail("source is not a network namespace".into()));
    }
    let identity = file.metadata().map_err(|e| fail(e.to_string()))?;
    for path in ["/proc/1/ns/net", "/proc/self/ns/net"] {
        let host = fs::metadata(path).map_err(|e| fail(e.to_string()))?;
        if identity.dev() == host.dev() && identity.ino() == host.ino() {
            return Err(fail(
                "host or daemon network namespace cannot be imported".into(),
            ));
        }
    }
    fs::create_dir_all(netns_dir).map_err(|e| fail(e.to_string()))?;
    for entry in fs::read_dir(netns_dir).map_err(|e| fail(e.to_string()))? {
        let entry = entry.map_err(|e| fail(e.to_string()))?;
        if entry.file_name().to_string_lossy().starts_with("rauha-") {
            let metadata = fs::metadata(entry.path()).map_err(|e| fail(e.to_string()))?;
            if metadata.dev() == identity.dev() && metadata.ino() == identity.ino() {
                return Err(fail("namespace already belongs to another zone".into()));
            }
        }
    }
    let target = netns_path(zone_name, netns_dir);
    fs::File::options()
        .write(true)
        .create_new(true)
        .open(&target)
        .map_err(|e| fail(e.to_string()))?;
    let source = std::ffi::CString::new(format!("/proc/self/fd/{}", file.as_raw_fd())).unwrap();
    use std::os::unix::ffi::OsStrExt;
    let destination =
        std::ffi::CString::new(target.as_os_str().as_bytes()).map_err(|e| fail(e.to_string()))?;
    if unsafe {
        libc::mount(
            source.as_ptr(),
            destination.as_ptr(),
            std::ptr::null(),
            libc::MS_BIND,
            std::ptr::null(),
        )
    } != 0
    {
        let error = std::io::Error::last_os_error();
        let _ = fs::remove_file(target);
        return Err(fail(format!("pinning network namespace failed: {error}")));
    }
    Ok(())
}

pub fn verify_imported_netns(zone_name: &str, netns_dir: &str) -> Result<()> {
    let file = fs::File::open(netns_path(zone_name, netns_dir)).map_err(|e| {
        RauhaError::NamespaceError {
            message: format!("external namespace pin is missing: {e}"),
            hint: "recreate the containerd pod; an external namespace is never silently replaced"
                .into(),
        }
    })?;
    if unsafe { libc::ioctl(file.as_raw_fd(), 0xb703) } != libc::CLONE_NEWNET {
        return Err(RauhaError::NamespaceError {
            message: "external namespace pin is invalid".into(),
            hint: "recreate the containerd pod".into(),
        });
    }
    Ok(())
}

/// Resolve shared pod namespaces through a pinned /proc directory, then pin the namespace itself.
pub fn pin_pod_namespaces(
    spec: &mut serde_json::Value,
    enforced: &mut serde_json::Value,
    zone_cgroup: &std::path::Path,
    container_root: &std::path::Path,
) -> Result<()> {
    use std::os::unix::{ffi::OsStrExt, fs::OpenOptionsExt};
    let refuse = |message: String| RauhaError::InvalidPolicy(format!("pod namespace: {message}"));
    let expected = zone_cgroup
        .strip_prefix("/sys/fs/cgroup")
        .map_err(|e| refuse(e.to_string()))?;
    let expected = format!("/{}", expected.display());
    let Some(namespaces) = spec["linux"]["namespaces"].as_array_mut() else {
        return Ok(());
    };
    for ns in namespaces {
        let Some(path) = ns["path"].as_str().filter(|path| !path.is_empty()) else {
            continue;
        };
        let (kind, flag) = match ns["type"].as_str() {
            Some("ipc") => ("ipc", libc::CLONE_NEWIPC),
            Some("uts") => ("uts", libc::CLONE_NEWUTS),
            Some("pid") => ("pid", libc::CLONE_NEWPID),
            _ => continue,
        };
        let fields = path.split('/').collect::<Vec<_>>();
        if fields.len() != 5
            || !fields[0].is_empty()
            || fields[1] != "proc"
            || fields[3] != "ns"
            || fields[4] != kind
            || fields[2]
                .parse::<u32>()
                .ok()
                .filter(|pid| *pid > 0)
                .is_none()
        {
            return Err(refuse(
                "shared IPC/UTS/PID namespaces must identify a live same-zone process".into(),
            ));
        }
        let process = fs::OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW)
            .open(format!("/proc/{}", fields[2]))
            .map_err(|e| refuse(e.to_string()))?;
        let process_path = format!("/proc/self/fd/{}", process.as_raw_fd());
        let cgroup = fs::read_to_string(format!("{process_path}/cgroup"))
            .map_err(|e| refuse(e.to_string()))?;
        let member = cgroup
            .lines()
            .find_map(|line| line.strip_prefix("0::"))
            .is_some_and(|actual| {
                actual == expected
                    || actual
                        .strip_prefix(&expected)
                        .is_some_and(|tail| tail.starts_with('/'))
            });
        if !member {
            return Err(refuse(
                "shared namespace owner does not belong to this zone".into(),
            ));
        }
        let descriptor = fs::File::open(format!("{process_path}/ns/{kind}"))
            .map_err(|e| refuse(e.to_string()))?;
        if unsafe { libc::ioctl(descriptor.as_raw_fd(), 0xb703) } != flag {
            return Err(refuse("namespace type does not match OCI request".into()));
        }
        let directory = container_root.join("namespaces");
        fs::create_dir_all(&directory).map_err(|e| refuse(e.to_string()))?;
        let pin = directory.join(kind);
        fs::File::options()
            .write(true)
            .create_new(true)
            .open(&pin)
            .map_err(|e| refuse(e.to_string()))?;
        let source =
            std::ffi::CString::new(format!("/proc/self/fd/{}", descriptor.as_raw_fd())).unwrap();
        let target = std::ffi::CString::new(pin.as_os_str().as_bytes())
            .map_err(|e| refuse(e.to_string()))?;
        if unsafe {
            libc::mount(
                source.as_ptr(),
                target.as_ptr(),
                std::ptr::null(),
                libc::MS_BIND,
                std::ptr::null(),
            )
        } != 0
        {
            return Err(refuse(format!(
                "pinning {kind} namespace: {}",
                std::io::Error::last_os_error()
            )));
        }
        ns["path"] = pin.to_string_lossy().into_owned().into();
        let admitted = enforced["linux"]["namespaces"].as_array_mut().unwrap();
        let entry = admitted
            .iter_mut()
            .find(|entry| entry["type"] == kind)
            .ok_or_else(|| refuse(format!("zone has no {kind} namespace")))?;
        entry["path"] = ns["path"].clone();
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn external_namespace_cannot_be_the_host_daemon_or_a_regular_file() {
        let directory = tempfile::tempdir().unwrap();
        let ordinary = directory.path().join("ordinary");
        fs::write(&ordinary, b"not a namespace").unwrap();
        for path in [
            "/proc/1/ns/net",
            "/proc/self/ns/net",
            ordinary.to_str().unwrap(),
        ] {
            assert!(import_netns("rejected", directory.path().to_str().unwrap(), path).is_err());
            assert!(!netns_path("rejected", directory.path().to_str().unwrap()).exists());
        }
    }
}
