//! Network namespace management for zone isolation.
//!
//! Each zone gets its own network namespace, providing full network
//! stack isolation. The daemon creates/destroys netns as zones come and go.

use std::fs;
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

    let output = Command::new("ip")
        .args(["netns", "delete", &ns_name])
        .output()
        .map_err(|e| RauhaError::NamespaceError {
            message: format!("failed to run `ip netns delete {ns_name}`: {e}"),
            hint: "ensure iproute2 is installed".into(),
        })?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        if !stderr.contains("No such file") {
            return Err(RauhaError::NamespaceError {
                message: format!("ip netns delete {ns_name} failed: {stderr}"),
                hint: "check if processes are still running in the namespace".into(),
            });
        }
    }

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
