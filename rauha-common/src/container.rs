use std::path::PathBuf;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Container {
    pub id: Uuid,
    pub name: String,
    pub zone_id: Uuid,
    pub image: String,
    pub state: ContainerState,
    pub pid: Option<u32>,
    pub created_at: DateTime<Utc>,
    pub started_at: Option<DateTime<Utc>>,
    pub finished_at: Option<DateTime<Utc>>,
    pub exit_code: Option<i32>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ContainerState {
    Created,
    Running,
    Stopped,
    Paused,
}

/// Handle to a running container, used by the isolation backend.
#[derive(Debug, Clone)]
pub struct ContainerHandle {
    pub id: Uuid,
    pub zone_id: Uuid,
    pub pid: u32,
    pub platform_id: u64,
}

/// Spec for creating a container (simplified OCI-compatible spec).
#[derive(Debug, Clone)]
pub struct ContainerSpec {
    pub name: String,
    pub image: String,
    pub command: Vec<String>,
    pub env: Vec<(String, String)>,
    pub working_dir: Option<String>,
    /// Prepared base rootfs path (set by orchestration layer after image extraction).
    /// Used as fallback when overlayfs is not available.
    pub rootfs_path: Option<PathBuf>,
    /// Pre-extracted layer paths for overlayfs mount (set by orchestration layer).
    /// When present, the backend mounts an overlay instead of copying the rootfs.
    pub overlay_layers: Option<Vec<PathBuf>>,
    /// A containerd OCI bundle, admitted against the zone policy by the backend.
    pub oci_spec_json: Option<String>,
}
