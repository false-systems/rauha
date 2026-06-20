//! Structured results for agent sandbox execution.
//!
//! Rauha's sandbox command is a task-level wrapper around zones: create or
//! select a zone, run one command, collect outputs and events, then clean up
//! according to policy. This module defines the stable result shape that
//! CLI/API surfaces use without depending on Linux-specific enforcement.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

/// Result of one sandboxed task execution.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SandboxExecResult {
    pub task_id: String,
    pub zone_id: String,
    pub command: Vec<String>,
    pub status: SandboxStatus,
    pub exit_code: Option<i32>,
    pub stdout: String,
    pub stderr: String,
    pub duration_ms: u64,
    pub started_at: Option<DateTime<Utc>>,
    pub finished_at: Option<DateTime<Utc>>,
    pub events: Vec<SandboxEventSummary>,
    pub enforcement_events: Vec<EnforcementEventSummary>,
}

impl SandboxExecResult {
    /// Build an empty runtime-error result for command paths that cannot start.
    pub fn runtime_error(
        task_id: impl Into<String>,
        zone_id: impl Into<String>,
        command: Vec<String>,
        message: impl Into<String>,
    ) -> Self {
        Self {
            task_id: task_id.into(),
            zone_id: zone_id.into(),
            command,
            status: SandboxStatus::RuntimeError,
            exit_code: None,
            stdout: String::new(),
            stderr: message.into(),
            duration_ms: 0,
            started_at: None,
            finished_at: None,
            events: Vec::new(),
            enforcement_events: Vec::new(),
        }
    }
}

/// High-level outcome of one sandboxed task.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SandboxStatus {
    Succeeded,
    Failed,
    TimedOut,
    RuntimeError,
}

/// Small user-facing event summary attached to a sandbox result.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SandboxEventSummary {
    pub timestamp: Option<DateTime<Utc>>,
    pub kind: String,
    pub message: String,
}

/// Kernel enforcement event summary attached to a sandbox result.
///
/// This intentionally does not expose raw BPF map/ring-buffer structures.
/// Enforcement capture is best-effort: backend absence or broadcast lag can
/// yield an empty or partial list, so this field is not an audit-complete log.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct EnforcementEventSummary {
    pub timestamp: Option<DateTime<Utc>>,
    pub hook: String,
    pub action: String,
    pub decision: String,
    pub message: String,
    pub pid: Option<u32>,
    pub source_zone: Option<String>,
    pub target_zone: Option<String>,
    pub object: Option<String>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sandbox_status_serializes_as_snake_case() {
        let value = serde_json::to_value(SandboxStatus::RuntimeError).unwrap();
        assert_eq!(value, serde_json::json!("runtime_error"));
    }

    #[test]
    fn sandbox_result_serializes_with_empty_enforcement_events() {
        let result = SandboxExecResult {
            task_id: "task-1".into(),
            zone_id: "zone-1".into(),
            command: vec!["echo".into(), "hello".into()],
            status: SandboxStatus::Succeeded,
            exit_code: Some(0),
            stdout: "hello\n".into(),
            stderr: String::new(),
            duration_ms: 12,
            started_at: None,
            finished_at: None,
            events: Vec::new(),
            enforcement_events: Vec::new(),
        };

        let value = serde_json::to_value(&result).unwrap();
        assert_eq!(value["status"], "succeeded");
        assert_eq!(value["enforcement_events"], serde_json::json!([]));
    }

    #[test]
    fn runtime_error_result_has_no_exit_code_or_events() {
        let result = SandboxExecResult::runtime_error(
            "task-1",
            "zone-1",
            vec!["pytest".into()],
            "sandbox runtime is not available",
        );

        assert_eq!(result.status, SandboxStatus::RuntimeError);
        assert_eq!(result.exit_code, None);
        assert_eq!(result.stderr, "sandbox runtime is not available");
        assert!(result.events.is_empty());
        assert!(result.enforcement_events.is_empty());
    }
}
