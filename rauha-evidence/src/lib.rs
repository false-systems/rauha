//! Evidence-grade observability schema and projections for Rauha.
//!
//! Ownership reading: Syva is the Linux eBPF LSM enforcer. This crate is the
//! Rauha evidence surface: it consumes raw Syva/backend records plus Rauha
//! lifecycle events, normalizes them into one schema, and owns projections and
//! sinks. It does not enforce policy.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt::Write as _;
use std::fs::{File, OpenOptions};
use std::io::Write;
use std::path::Path;
use std::sync::Mutex;

use chrono::{DateTime, SecondsFormat, Utc};
use serde::{Deserialize, Serialize};
use thiserror::Error;

pub mod event_name {
    pub const DAEMON_START: &str = "rauha.daemon.start";
    pub const DAEMON_READY: &str = "rauha.daemon.ready";
    pub const DAEMON_SHUTDOWN: &str = "rauha.daemon.shutdown";
    pub const BACKEND_SELECTED: &str = "rauha.backend.selected";
    pub const BACKEND_CAPABILITY_DETECTED: &str = "rauha.backend.capability_detected";
    pub const BACKEND_CAPABILITY_MISSING: &str = "rauha.backend.capability_missing";
    pub const BACKEND_DEGRADED: &str = "rauha.backend.degraded";
    pub const ENFORCER_SELECTED: &str = "rauha.enforcer.selected";
    pub const ENFORCER_CONFORMANCE_CHECKED: &str = "rauha.enforcer.conformance.checked";
    pub const ENFORCER_UNAVAILABLE: &str = "rauha.enforcer.unavailable";
    pub const ENFORCER_NOOP_ENABLED: &str = "rauha.enforcer.noop.enabled";
    pub const RAUHA_ZONE_CREATE_STARTED: &str = "rauha.zone.create.started";
    pub const RAUHA_ZONE_CREATE_SUCCEEDED: &str = "rauha.zone.create.succeeded";
    pub const RAUHA_ZONE_CREATE_FAILED: &str = "rauha.zone.create.failed";
    pub const RAUHA_ZONE_RESTORE_STARTED: &str = "rauha.zone.restore.started";
    pub const RAUHA_ZONE_RESTORE_SUCCEEDED: &str = "rauha.zone.restore.succeeded";
    pub const RAUHA_ZONE_RESTORE_FAILED: &str = "rauha.zone.restore.failed";
    pub const RAUHA_ZONE_DELETE_STARTED: &str = "rauha.zone.delete.started";
    pub const RAUHA_ZONE_DELETE_SUCCEEDED: &str = "rauha.zone.delete.succeeded";
    pub const RAUHA_ZONE_DELETE_FAILED: &str = "rauha.zone.delete.failed";
    pub const RAUHA_ZONE_CLEANUP_STARTED: &str = "rauha.zone.cleanup.started";
    pub const RAUHA_ZONE_CLEANUP_SUCCEEDED: &str = "rauha.zone.cleanup.succeeded";
    pub const RAUHA_ZONE_CLEANUP_PARTIAL: &str = "rauha.zone.cleanup.partial";
    pub const RAUHA_ZONE_CLEANUP_FAILED: &str = "rauha.zone.cleanup.failed";
    pub const POLICY_LOAD_STARTED: &str = "rauha.policy.load.started";
    pub const POLICY_LOAD_SUCCEEDED: &str = "rauha.policy.load.succeeded";
    pub const POLICY_LOAD_FAILED: &str = "rauha.policy.load.failed";
    pub const POLICY_VALIDATE_SUCCEEDED: &str = "rauha.policy.validate.succeeded";
    pub const POLICY_VALIDATE_FAILED: &str = "rauha.policy.validate.failed";
    pub const POLICY_APPLY_STARTED: &str = "rauha.policy.apply.started";
    pub const POLICY_APPLY_SUCCEEDED: &str = "rauha.policy.apply.succeeded";
    pub const POLICY_APPLY_FAILED: &str = "rauha.policy.apply.failed";
    pub const POLICY_AMBIGUOUS_INPUT_REJECTED: &str = "rauha.policy.ambiguous_input.rejected";
    pub const SANDBOX_RUN_STARTED: &str = "rauha.sandbox.run.started";
    pub const SANDBOX_ZONE_ALLOCATED: &str = "rauha.sandbox.zone.allocated";
    pub const SANDBOX_CONTAINER_STARTED: &str = "rauha.sandbox.container.started";
    pub const SANDBOX_COMMAND_STARTED: &str = "rauha.sandbox.command.started";
    pub const SANDBOX_COMMAND_EXITED: &str = "rauha.sandbox.command.exited";
    pub const SANDBOX_COMMAND_TIMED_OUT: &str = "rauha.sandbox.command.timed_out";
    pub const SANDBOX_COMMAND_CANCELLED: &str = "rauha.sandbox.command.cancelled";
    pub const SANDBOX_STDOUT_CAPTURED: &str = "rauha.sandbox.stdout.captured";
    pub const SANDBOX_STDERR_CAPTURED: &str = "rauha.sandbox.stderr.captured";
    pub const SANDBOX_RESULT_BUILT: &str = "rauha.sandbox.result.built";
    pub const SANDBOX_CLEANUP_SUCCEEDED: &str = "rauha.sandbox.cleanup.succeeded";
    pub const SANDBOX_CLEANUP_PARTIAL: &str = "rauha.sandbox.cleanup.partial";
    pub const SANDBOX_RUN_SUCCEEDED: &str = "rauha.sandbox.run.succeeded";
    pub const SANDBOX_RUN_FAILED: &str = "rauha.sandbox.run.failed";
    pub const FS_ROOTFS_PREPARE_STARTED: &str = "rauha.fs.rootfs.prepare.started";
    pub const FS_ROOTFS_PREPARE_SUCCEEDED: &str = "rauha.fs.rootfs.prepare.succeeded";
    pub const FS_ROOTFS_PREPARE_FAILED: &str = "rauha.fs.rootfs.prepare.failed";
    pub const FS_MOUNT_VISIBLE: &str = "rauha.fs.mount.visible";
    pub const FS_POLICY_APPLIED: &str = "rauha.fs.policy.applied";
    pub const FS_ACCESS_DENIED: &str = "rauha.fs.access.denied";
    pub const FS_ACCESS_AUDIT: &str = "rauha.fs.access.audit";
    pub const NETWORK_NAMESPACE_CREATED: &str = "rauha.network.namespace.created";
    pub const NETWORK_BRIDGE_CONFIGURED: &str = "rauha.network.bridge.configured";
    pub const NETWORK_EGRESS_POLICY_APPLIED: &str = "rauha.network.egress.policy.applied";
    pub const NETWORK_EGRESS_DENIED: &str = "rauha.network.egress.denied";
    pub const NETWORK_EGRESS_AUDIT: &str = "rauha.network.egress.audit";
    pub const NETWORK_MODE_AUDIT_ONLY: &str = "rauha.network.mode.audit_only";
    pub const NETWORK_CLEANUP_SUCCEEDED: &str = "rauha.network.cleanup.succeeded";
    pub const NETWORK_CLEANUP_FAILED: &str = "rauha.network.cleanup.failed";
    pub const RESOURCE_CGROUP_CREATED: &str = "rauha.resource.cgroup.created";
    pub const RESOURCE_LIMIT_APPLIED: &str = "rauha.resource.limit.applied";
    pub const RESOURCE_LIMIT_FAILED: &str = "rauha.resource.limit.failed";
    pub const RESOURCE_SAMPLE: &str = "rauha.resource.sample";
    pub const RESOURCE_PRESSURE_DETECTED: &str = "rauha.resource.pressure.detected";
    pub const RESOURCE_OOM_DETECTED: &str = "rauha.resource.oom.detected";
    pub const ENFORCEMENT_POLICY_LOADED: &str = "rauha.enforcement.policy.loaded";
    pub const ENFORCEMENT_MAP_UPDATED: &str = "rauha.enforcement.map.updated";
    pub const ENFORCEMENT_EVENT_RECEIVED: &str = "rauha.enforcement.event.received";
    pub const ENFORCEMENT_DENY: &str = "rauha.enforcement.deny";
    pub const ENFORCEMENT_AUDIT: &str = "rauha.enforcement.audit";
    pub const ENFORCEMENT_COUNTER_UPDATED: &str = "rauha.enforcement.counter.updated";
    pub const ENFORCEMENT_BROADCAST_LAG_DETECTED: &str = "rauha.enforcement.broadcast.lag_detected";
    pub const ENFORCEMENT_CAPTURE_BEST_EFFORT: &str = "rauha.enforcement.capture.best_effort";
    pub const ENFORCEMENT_CAPTURE_INCOMPLETE: &str = "rauha.enforcement.capture.incomplete";
    pub const CONTAINERD_TASK_CREATE_STARTED: &str = "rauha.containerd.task.create.started";
    pub const CONTAINERD_TASK_CREATE_SUCCEEDED: &str = "rauha.containerd.task.create.succeeded";
    pub const CONTAINERD_TASK_CREATE_FAILED: &str = "rauha.containerd.task.create.failed";
    pub const K8S_RUNTIMECLASS_ZONE_MAPPED: &str = "rauha.k8s.runtimeclass.zone.mapped";
    pub const K8S_POD_SANDBOX_MAPPED: &str = "rauha.k8s.pod.sandbox.mapped";
    pub const K8S_IDENTITY_MISSING: &str = "rauha.k8s.identity.missing";
    pub const K8S_IDENTITY_RESOLVED: &str = "rauha.k8s.identity.resolved";

    pub const ZONE_FILE_DENIED: &str = "zone.file.denied";
    pub const ZONE_FILE_ALLOWED: &str = "zone.file.allowed";
    pub const ZONE_EXEC_DENIED: &str = "zone.exec.denied";
    pub const ZONE_PTRACE_DENIED: &str = "zone.ptrace.denied";
    pub const ZONE_SIGNAL_DENIED: &str = "zone.signal.denied";
    pub const ZONE_MOUNT_DENIED: &str = "zone.mount.denied";
    pub const ZONE_IPC_DENIED: &str = "zone.ipc.denied";
    pub const ZONE_ESCAPE_CGROUP_ATTACH: &str = "zone.escape.cgroup_attach";
    pub const ZONE_NET_DENIED: &str = "zone.net.denied";
    pub const ZONE_PROC_FILTERED: &str = "zone.proc.filtered";
    pub const ZONE_CREATED: &str = "zone.created";
    pub const ZONE_STARTED: &str = "zone.started";
    pub const ZONE_STOPPED: &str = "zone.stopped";
    pub const ZONE_DELETED: &str = "zone.deleted";
    pub const ZONE_VERIFY_PASSED: &str = "zone.verify.passed";
    pub const ZONE_VERIFY_FAILED: &str = "zone.verify.failed";
    pub const POLICY_LOADED: &str = "policy.loaded";
    pub const POLICY_REJECTED: &str = "policy.rejected";
    pub const CONTAINER_STARTED: &str = "container.started";
    pub const CONTAINER_EXITED: &str = "container.exited";
    pub const IMAGE_PULLED: &str = "image.pulled";
    pub const TASK_STARTED: &str = "task.started";
    pub const TASK_SUCCEEDED: &str = "task.succeeded";
    pub const TASK_FAILED: &str = "task.failed";
    pub const RINGBUF_DROP: &str = "ringbuf.drop";
    pub const PIPELINE_SHED: &str = "pipeline.shed";
}

pub const BACKEND_LINUX_EBPF: &str = "linux-ebpf";
pub const BACKEND_MACOS_VM: &str = "macos-vm";

const MAX_FIELD_CHARS: usize = 4096;
pub const RUNTIME_EVENT_VERSION: u32 = 1;

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EventKind {
    Lifecycle,
    Policy,
    Execution,
    Filesystem,
    Network,
    Resource,
    Enforcement,
    Audit,
    Cleanup,
    Backend,
    Error,
}

impl EventKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Lifecycle => "lifecycle",
            Self::Policy => "policy",
            Self::Execution => "execution",
            Self::Filesystem => "filesystem",
            Self::Network => "network",
            Self::Resource => "resource",
            Self::Enforcement => "enforcement",
            Self::Audit => "audit",
            Self::Cleanup => "cleanup",
            Self::Backend => "backend",
            Self::Error => "error",
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EventOutcome {
    Started,
    Succeeded,
    Failed,
    Denied,
    Allowed,
    Skipped,
    Degraded,
    TimedOut,
    Cancelled,
}

impl EventOutcome {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Started => "started",
            Self::Succeeded => "succeeded",
            Self::Failed => "failed",
            Self::Denied => "denied",
            Self::Allowed => "allowed",
            Self::Skipped => "skipped",
            Self::Degraded => "degraded",
            Self::TimedOut => "timed_out",
            Self::Cancelled => "cancelled",
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TrustLevel {
    Complete,
    Partial,
    BestEffort,
    Unavailable,
}

impl TrustLevel {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Complete => "complete",
            Self::Partial => "partial",
            Self::BestEffort => "best_effort",
            Self::Unavailable => "unavailable",
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EnforcementMode {
    Enforcing,
    AuditOnly,
    Noop,
    Unavailable,
}

impl EnforcementMode {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Enforcing => "enforcing",
            Self::AuditOnly => "audit_only",
            Self::Noop => "noop",
            Self::Unavailable => "unavailable",
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct RuntimeEvent {
    pub timestamp: String,
    pub level: Severity,
    #[serde(rename = "event.name")]
    pub event_name: String,
    #[serde(rename = "event.version")]
    pub event_version: u32,
    #[serde(rename = "event.kind")]
    pub event_kind: EventKind,
    #[serde(rename = "event.outcome")]
    pub event_outcome: EventOutcome,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub task_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub zone_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub zone_name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub container_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sandbox_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub command_hash: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub command_argv_safe: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub image_ref: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub repo_path_safe: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub repo_hash: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub policy_name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub policy_hash: Option<String>,
    #[serde(rename = "backend.name", skip_serializing_if = "Option::is_none")]
    pub backend_name: Option<String>,
    #[serde(rename = "backend.platform", skip_serializing_if = "Option::is_none")]
    pub backend_platform: Option<String>,
    #[serde(
        rename = "backend.enforcement_mode",
        skip_serializing_if = "Option::is_none"
    )]
    pub backend_enforcement_mode: Option<EnforcementMode>,
    #[serde(rename = "enforcer.backend", skip_serializing_if = "Option::is_none")]
    pub enforcer_backend: Option<String>,
    #[serde(
        rename = "enforcer.capabilities",
        skip_serializing_if = "Option::is_none"
    )]
    pub enforcer_capabilities: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub request_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub trace_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub correlation_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub parent_span_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub span_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub duration_ms: Option<u64>,
    #[serde(rename = "error.code", skip_serializing_if = "Option::is_none")]
    pub error_code: Option<String>,
    #[serde(rename = "error.kind", skip_serializing_if = "Option::is_none")]
    pub error_kind: Option<String>,
    #[serde(rename = "error.message", skip_serializing_if = "Option::is_none")]
    pub error_message: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub degraded_reason: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub trust_level: Option<TrustLevel>,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub fields: BTreeMap<String, FieldValue>,
}

impl RuntimeEvent {
    pub fn machine_json(&self) -> Result<String, EvidenceError> {
        serde_json::to_string(self).map_err(EvidenceError::Serialize)
    }

    pub fn emit_tracing(&self) {
        match self.level {
            Severity::Trace => self.emit_trace(),
            Severity::Info => self.emit_info(),
            Severity::Warn => self.emit_warn(),
            Severity::Error => self.emit_error(),
        }
    }

    fn emit_trace(&self) {
        tracing::trace!(
            event.name = %self.event_name,
            event.version = self.event_version,
            event.kind = %self.event_kind.as_str(),
            event.outcome = %self.event_outcome.as_str(),
            task_id = self.task_id.as_deref().unwrap_or(""),
            zone_id = self.zone_id.as_deref().unwrap_or(""),
            zone_name = self.zone_name.as_deref().unwrap_or(""),
            container_id = self.container_id.as_deref().unwrap_or(""),
            backend.name = self.backend_name.as_deref().unwrap_or(""),
            backend.platform = self.backend_platform.as_deref().unwrap_or(""),
            backend.enforcement_mode = self.backend_enforcement_mode.map(EnforcementMode::as_str).unwrap_or(""),
            enforcer.backend = self.enforcer_backend.as_deref().unwrap_or(""),
            correlation_id = self.correlation_id.as_deref().unwrap_or(""),
            request_id = self.request_id.as_deref().unwrap_or(""),
            trust_level = self.trust_level.map(TrustLevel::as_str).unwrap_or(""),
            error.code = self.error_code.as_deref().unwrap_or(""),
            error.kind = self.error_kind.as_deref().unwrap_or(""),
            degraded_reason = self.degraded_reason.as_deref().unwrap_or(""),
            "rauha.evidence"
        );
    }

    fn emit_info(&self) {
        tracing::info!(
            event.name = %self.event_name,
            event.version = self.event_version,
            event.kind = %self.event_kind.as_str(),
            event.outcome = %self.event_outcome.as_str(),
            task_id = self.task_id.as_deref().unwrap_or(""),
            zone_id = self.zone_id.as_deref().unwrap_or(""),
            zone_name = self.zone_name.as_deref().unwrap_or(""),
            container_id = self.container_id.as_deref().unwrap_or(""),
            backend.name = self.backend_name.as_deref().unwrap_or(""),
            backend.platform = self.backend_platform.as_deref().unwrap_or(""),
            backend.enforcement_mode = self.backend_enforcement_mode.map(EnforcementMode::as_str).unwrap_or(""),
            enforcer.backend = self.enforcer_backend.as_deref().unwrap_or(""),
            correlation_id = self.correlation_id.as_deref().unwrap_or(""),
            request_id = self.request_id.as_deref().unwrap_or(""),
            trust_level = self.trust_level.map(TrustLevel::as_str).unwrap_or(""),
            error.code = self.error_code.as_deref().unwrap_or(""),
            error.kind = self.error_kind.as_deref().unwrap_or(""),
            degraded_reason = self.degraded_reason.as_deref().unwrap_or(""),
            "rauha.evidence"
        );
    }

    fn emit_warn(&self) {
        tracing::warn!(
            event.name = %self.event_name,
            event.version = self.event_version,
            event.kind = %self.event_kind.as_str(),
            event.outcome = %self.event_outcome.as_str(),
            task_id = self.task_id.as_deref().unwrap_or(""),
            zone_id = self.zone_id.as_deref().unwrap_or(""),
            zone_name = self.zone_name.as_deref().unwrap_or(""),
            container_id = self.container_id.as_deref().unwrap_or(""),
            backend.name = self.backend_name.as_deref().unwrap_or(""),
            backend.platform = self.backend_platform.as_deref().unwrap_or(""),
            backend.enforcement_mode = self.backend_enforcement_mode.map(EnforcementMode::as_str).unwrap_or(""),
            enforcer.backend = self.enforcer_backend.as_deref().unwrap_or(""),
            correlation_id = self.correlation_id.as_deref().unwrap_or(""),
            request_id = self.request_id.as_deref().unwrap_or(""),
            trust_level = self.trust_level.map(TrustLevel::as_str).unwrap_or(""),
            error.code = self.error_code.as_deref().unwrap_or(""),
            error.kind = self.error_kind.as_deref().unwrap_or(""),
            degraded_reason = self.degraded_reason.as_deref().unwrap_or(""),
            "rauha.evidence"
        );
    }

    fn emit_error(&self) {
        tracing::error!(
            event.name = %self.event_name,
            event.version = self.event_version,
            event.kind = %self.event_kind.as_str(),
            event.outcome = %self.event_outcome.as_str(),
            task_id = self.task_id.as_deref().unwrap_or(""),
            zone_id = self.zone_id.as_deref().unwrap_or(""),
            zone_name = self.zone_name.as_deref().unwrap_or(""),
            container_id = self.container_id.as_deref().unwrap_or(""),
            backend.name = self.backend_name.as_deref().unwrap_or(""),
            backend.platform = self.backend_platform.as_deref().unwrap_or(""),
            backend.enforcement_mode = self.backend_enforcement_mode.map(EnforcementMode::as_str).unwrap_or(""),
            enforcer.backend = self.enforcer_backend.as_deref().unwrap_or(""),
            correlation_id = self.correlation_id.as_deref().unwrap_or(""),
            request_id = self.request_id.as_deref().unwrap_or(""),
            trust_level = self.trust_level.map(TrustLevel::as_str).unwrap_or(""),
            error.code = self.error_code.as_deref().unwrap_or(""),
            error.kind = self.error_kind.as_deref().unwrap_or(""),
            degraded_reason = self.degraded_reason.as_deref().unwrap_or(""),
            "rauha.evidence"
        );
    }
}

pub struct RuntimeEventBuilder {
    event: RuntimeEvent,
}

impl RuntimeEventBuilder {
    pub fn new(name: impl Into<String>, kind: EventKind, outcome: EventOutcome) -> Self {
        Self {
            event: RuntimeEvent {
                timestamp: now_rfc3339(),
                level: Severity::Info,
                event_name: name.into(),
                event_version: RUNTIME_EVENT_VERSION,
                event_kind: kind,
                event_outcome: outcome,
                task_id: None,
                zone_id: None,
                zone_name: None,
                container_id: None,
                sandbox_id: None,
                command_hash: None,
                command_argv_safe: None,
                image_ref: None,
                repo_path_safe: None,
                repo_hash: None,
                policy_name: None,
                policy_hash: None,
                backend_name: None,
                backend_platform: None,
                backend_enforcement_mode: None,
                enforcer_backend: None,
                enforcer_capabilities: None,
                request_id: None,
                trace_id: None,
                correlation_id: None,
                parent_span_id: None,
                span_id: None,
                duration_ms: None,
                error_code: None,
                error_kind: None,
                error_message: None,
                degraded_reason: None,
                trust_level: None,
                fields: BTreeMap::new(),
            },
        }
    }

    pub fn level(mut self, level: Severity) -> Self {
        self.event.level = level;
        self
    }

    pub fn task_id(mut self, value: impl Into<String>) -> Self {
        self.event.task_id = Some(bound_string(&value.into()));
        self
    }

    pub fn zone_id(mut self, value: impl Into<String>) -> Self {
        self.event.zone_id = Some(bound_string(&value.into()));
        self
    }

    pub fn zone_name(mut self, value: impl Into<String>) -> Self {
        self.event.zone_name = Some(bound_string(&value.into()));
        self
    }

    pub fn container_id(mut self, value: impl Into<String>) -> Self {
        self.event.container_id = Some(bound_string(&value.into()));
        self
    }

    pub fn command_hash(mut self, value: impl Into<String>) -> Self {
        self.event.command_hash = Some(bound_string(&value.into()));
        self
    }

    pub fn command_argv_safe(mut self, value: Vec<String>) -> Self {
        self.event.command_argv_safe = Some(value.into_iter().map(|s| bound_string(&s)).collect());
        self
    }

    pub fn image_ref(mut self, value: impl Into<String>) -> Self {
        self.event.image_ref = Some(redact_and_bound(&value.into()));
        self
    }

    pub fn repo_path_safe(mut self, value: impl Into<String>) -> Self {
        self.event.repo_path_safe = Some(redact_and_bound(&value.into()));
        self
    }

    pub fn policy_hash(mut self, value: impl Into<String>) -> Self {
        self.event.policy_hash = Some(bound_string(&value.into()));
        self
    }

    pub fn backend(
        mut self,
        name: impl Into<String>,
        platform: impl Into<String>,
        mode: EnforcementMode,
    ) -> Self {
        self.event.backend_name = Some(bound_string(&name.into()));
        self.event.backend_platform = Some(bound_string(&platform.into()));
        self.event.backend_enforcement_mode = Some(mode);
        self
    }

    pub fn enforcer_backend(mut self, value: impl Into<String>) -> Self {
        self.event.enforcer_backend = Some(bound_string(&value.into()));
        self
    }

    pub fn correlation_id(mut self, value: impl Into<String>) -> Self {
        self.event.correlation_id = Some(bound_string(&value.into()));
        self
    }

    pub fn request_id(mut self, value: impl Into<String>) -> Self {
        self.event.request_id = Some(bound_string(&value.into()));
        self
    }

    pub fn duration_ms(mut self, value: u64) -> Self {
        self.event.duration_ms = Some(value);
        self
    }

    pub fn error(
        mut self,
        code: impl Into<String>,
        kind: impl Into<String>,
        message: impl Into<String>,
    ) -> Self {
        self.event.error_code = Some(bound_string(&code.into()));
        self.event.error_kind = Some(bound_string(&kind.into()));
        self.event.error_message = Some(redact_and_bound(&message.into()));
        self
    }

    pub fn degraded_reason(mut self, value: impl Into<String>) -> Self {
        self.event.degraded_reason = Some(bound_string(&value.into()));
        self
    }

    pub fn trust_level(mut self, value: TrustLevel) -> Self {
        self.event.trust_level = Some(value);
        self
    }

    pub fn field(mut self, key: impl Into<String>, value: FieldValue) -> Self {
        self.event.fields.insert(key.into(), value.bounded());
        self
    }

    pub fn build(self) -> RuntimeEvent {
        self.event
    }

    pub fn emit(self) -> RuntimeEvent {
        let event = self.build();
        event.emit_tracing();
        event
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "UPPERCASE")]
pub enum Severity {
    Trace,
    Info,
    Warn,
    Error,
}

impl Severity {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Trace => "TRACE",
            Self::Info => "INFO",
            Self::Warn => "WARN",
            Self::Error => "ERROR",
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct ZoneIdentity {
    pub id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct ActorIdentity {
    pub id: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub delegation: Vec<String>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct ResourceAttrs {
    pub backend: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub host: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub node: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub container_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub kernel_version: Option<String>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct FalseNarrative {
    pub what_failed: String,
    pub why_it_matters: String,
    pub possible_causes: Vec<String>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct OTelMapping {
    pub log_body: String,
    pub severity_text: String,
    pub resource_attributes: Vec<String>,
    pub event_attributes: Vec<String>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct FalseEvent {
    pub ts: String,
    pub level: Severity,
    pub event: String,
    pub zone: ZoneIdentity,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub actor: Option<ActorIdentity>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub resource: Option<String>,
    pub backend: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub trace_id: Option<String>,
    pub what_failed: String,
    pub why_it_matters: String,
    pub possible_causes: Vec<String>,
    pub resource_attributes: ResourceAttrs,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub fields: BTreeMap<String, FieldValue>,
    pub otel: OTelMapping,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(untagged)]
pub enum FieldValue {
    String(String),
    U64(u64),
    I64(i64),
    Bool(bool),
    StringList(Vec<String>),
}

impl FieldValue {
    fn bounded(self) -> Self {
        match self {
            Self::String(s) => Self::String(bound_string(&s)),
            Self::StringList(values) => {
                Self::StringList(values.into_iter().map(|s| bound_string(&s)).collect())
            }
            other => other,
        }
    }
}

#[derive(Default)]
pub struct FalseEventBuilder {
    event: Option<String>,
    level: Option<Severity>,
    zone: Option<ZoneIdentity>,
    actor: Option<ActorIdentity>,
    resource: Option<String>,
    resource_attributes: Option<ResourceAttrs>,
    trace_id: Option<String>,
    fields: BTreeMap<String, FieldValue>,
}

impl FalseEventBuilder {
    pub fn new(event: impl Into<String>) -> Self {
        Self {
            event: Some(event.into()),
            ..Self::default()
        }
    }

    pub fn level(mut self, level: Severity) -> Self {
        self.level = Some(level);
        self
    }

    pub fn zone(mut self, id: impl Into<String>, name: Option<String>) -> Self {
        self.zone = Some(ZoneIdentity {
            id: id.into(),
            name: name.map(|s| bound_string(&s)),
        });
        self
    }

    pub fn actor(mut self, id: impl Into<String>, delegation: Vec<String>) -> Self {
        self.actor = Some(ActorIdentity {
            id: bound_string(&id.into()),
            delegation: delegation.into_iter().map(|s| bound_string(&s)).collect(),
        });
        self
    }

    pub fn resource(mut self, resource: impl Into<String>) -> Self {
        self.resource = Some(redact_and_bound(&resource.into()));
        self
    }

    pub fn resource_attributes(mut self, attrs: ResourceAttrs) -> Self {
        self.resource_attributes = Some(attrs);
        self
    }

    pub fn trace_id(mut self, trace_id: impl Into<String>) -> Self {
        self.trace_id = Some(bound_string(&trace_id.into()));
        self
    }

    pub fn field(mut self, key: impl Into<String>, value: FieldValue) -> Self {
        self.fields.insert(key.into(), value.bounded());
        self
    }

    pub fn build(self) -> Result<FalseEvent, EvidenceError> {
        let event = self.event.ok_or(EvidenceError::MissingField("event"))?;
        let level = self.level.unwrap_or_else(|| default_severity(&event));
        let zone = self.zone.ok_or(EvidenceError::MissingField("zone"))?;
        let resource_attributes = self
            .resource_attributes
            .unwrap_or_else(|| ResourceAttrs::new(BACKEND_LINUX_EBPF));
        let narrative = narrative_for(&event);
        let field_keys = self.fields.keys().cloned().collect::<Vec<_>>();

        Ok(FalseEvent {
            ts: now_rfc3339(),
            level,
            event: event.clone(),
            zone,
            actor: self.actor,
            resource: self.resource,
            backend: resource_attributes.backend.clone(),
            trace_id: self.trace_id,
            what_failed: narrative.what_failed,
            why_it_matters: narrative.why_it_matters,
            possible_causes: narrative.possible_causes,
            otel: OTelMapping {
                log_body: event,
                severity_text: level.as_str().to_string(),
                resource_attributes: vec![
                    "service.name=rauhad".to_string(),
                    "backend".to_string(),
                    "host".to_string(),
                    "node".to_string(),
                    "container.id".to_string(),
                    "kernel.version".to_string(),
                ],
                event_attributes: field_keys,
            },
            resource_attributes,
            fields: self.fields,
        })
    }
}

impl ResourceAttrs {
    pub fn new(backend: impl Into<String>) -> Self {
        Self {
            backend: backend.into(),
            host: std::env::var("HOSTNAME").ok(),
            node: None,
            container_id: None,
            kernel_version: None,
        }
    }
}

pub fn pipeline_shed_event(reason: impl Into<String>, backend: impl Into<String>) -> FalseEvent {
    let reason = bound_string(&reason.into());
    let resource_attributes = ResourceAttrs::new(backend);
    let narrative = narrative_for(event_name::PIPELINE_SHED);
    let mut fields = BTreeMap::new();
    fields.insert("reason".to_string(), FieldValue::String(reason));

    FalseEvent {
        ts: now_rfc3339(),
        level: Severity::Warn,
        event: event_name::PIPELINE_SHED.to_string(),
        zone: ZoneIdentity {
            id: "zone-unknown".to_string(),
            name: None,
        },
        actor: None,
        resource: None,
        backend: resource_attributes.backend.clone(),
        trace_id: None,
        what_failed: narrative.what_failed,
        why_it_matters: narrative.why_it_matters,
        possible_causes: narrative.possible_causes,
        resource_attributes,
        fields,
        otel: OTelMapping {
            log_body: event_name::PIPELINE_SHED.to_string(),
            severity_text: Severity::Warn.as_str().to_string(),
            resource_attributes: vec![
                "service.name=rauhad".to_string(),
                "backend".to_string(),
                "host".to_string(),
                "node".to_string(),
                "container.id".to_string(),
                "kernel.version".to_string(),
            ],
            event_attributes: vec!["reason".to_string()],
        },
    }
}

impl FalseEvent {
    pub fn machine_json(&self) -> Result<String, EvidenceError> {
        serde_json::to_string(self).map_err(EvidenceError::Serialize)
    }

    pub fn compact_human(&self) -> String {
        let mut line = String::new();
        let time = self.ts.get(11..19).unwrap_or(&self.ts);
        let actor = self
            .actor
            .as_ref()
            .map(|a| a.id.as_str())
            .unwrap_or("unknown-actor");
        let resource = self.resource.as_deref().unwrap_or("-");
        let _ = write!(
            line,
            "{time}  {:<5}  {:<26} {}/{} -> {}\n                {} · {}",
            self.level.as_str(),
            self.event,
            self.zone.id,
            actor,
            resource,
            self.what_failed,
            self.why_it_matters
        );
        line
    }

    pub fn expanded_human(&self) -> String {
        let mut out = String::new();
        let time = self.ts.get(11..19).unwrap_or(&self.ts);
        let _ = writeln!(out, "{time}  {}  {}", self.level.as_str(), self.event);
        let _ = writeln!(out, "  zone          {}", self.zone.id);
        if let Some(actor) = &self.actor {
            let _ = writeln!(out, "  actor         {}", actor.id);
            if !actor.delegation.is_empty() {
                let _ = writeln!(out, "  delegation    {}", actor.delegation.join(" -> "));
            }
        }
        if let Some(resource) = &self.resource {
            let _ = writeln!(
                out,
                "  resource      {}   backend  {}",
                resource, self.backend
            );
        } else {
            let _ = writeln!(out, "  backend       {}", self.backend);
        }
        let _ = writeln!(out, "  why           {}", self.why_it_matters);
        for (key, value) in &self.fields {
            let _ = writeln!(out, "  {key:<13} {}", display_field(value));
        }
        out
    }

    pub fn emit_tracing(&self) {
        match self.level {
            Severity::Trace => tracing::trace!(
                event = %self.event,
                zone.id = %self.zone.id,
                actor.id = self.actor.as_ref().map(|a| a.id.as_str()).unwrap_or(""),
                backend = %self.backend,
                what_failed = %self.what_failed,
                why_it_matters = %self.why_it_matters,
                "rauha.evidence"
            ),
            Severity::Info => tracing::info!(
                event = %self.event,
                zone.id = %self.zone.id,
                actor.id = self.actor.as_ref().map(|a| a.id.as_str()).unwrap_or(""),
                backend = %self.backend,
                what_failed = %self.what_failed,
                why_it_matters = %self.why_it_matters,
                "rauha.evidence"
            ),
            Severity::Warn => tracing::warn!(
                event = %self.event,
                zone.id = %self.zone.id,
                actor.id = self.actor.as_ref().map(|a| a.id.as_str()).unwrap_or(""),
                backend = %self.backend,
                what_failed = %self.what_failed,
                why_it_matters = %self.why_it_matters,
                "rauha.evidence"
            ),
            Severity::Error => tracing::error!(
                event = %self.event,
                zone.id = %self.zone.id,
                actor.id = self.actor.as_ref().map(|a| a.id.as_str()).unwrap_or(""),
                backend = %self.backend,
                what_failed = %self.what_failed,
                why_it_matters = %self.why_it_matters,
                "rauha.evidence"
            ),
        }
    }
}

pub fn validate_metric_labels(labels: &[&str]) -> Result<(), EvidenceError> {
    let forbidden = [
        "zone.id",
        "container.id",
        "actor.id",
        "inode",
        "pid",
        "connection.id",
        "trace_id",
    ];
    for label in labels {
        if forbidden.contains(label) {
            return Err(EvidenceError::HighCardinalityMetricLabel(
                (*label).to_string(),
            ));
        }
    }
    Ok(())
}

pub fn metric_label_set(labels: &[&str]) -> Result<BTreeSet<String>, EvidenceError> {
    validate_metric_labels(labels)?;
    Ok(labels.iter().map(|label| (*label).to_string()).collect())
}

pub trait EventSink: Send + Sync {
    fn emit(&self, event: &FalseEvent) -> Result<(), SinkError>;
    fn flush(&self) -> Result<(), SinkError>;
}

#[derive(Debug, Error)]
pub enum SinkError {
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
    #[error("serialization error: {0}")]
    Serialize(#[from] serde_json::Error),
    #[error("evidence error: {0}")]
    Evidence(#[from] EvidenceError),
    #[error("sink unsupported: {0}")]
    Unsupported(&'static str),
    #[error("sink lock poisoned")]
    Poisoned,
}

pub struct StdoutSink;

impl EventSink for StdoutSink {
    fn emit(&self, event: &FalseEvent) -> Result<(), SinkError> {
        println!("{}", event.machine_json()?);
        Ok(())
    }

    fn flush(&self) -> Result<(), SinkError> {
        std::io::stdout().flush().map_err(SinkError::Io)
    }
}

pub struct FileSink {
    file: Mutex<File>,
}

impl FileSink {
    pub fn append(path: &Path) -> Result<Self, SinkError> {
        let file = OpenOptions::new().create(true).append(true).open(path)?;
        Ok(Self {
            file: Mutex::new(file),
        })
    }
}

impl EventSink for FileSink {
    fn emit(&self, event: &FalseEvent) -> Result<(), SinkError> {
        let mut file = self.file.lock().map_err(|_| SinkError::Poisoned)?;
        writeln!(file, "{}", event.machine_json()?)?;
        Ok(())
    }

    fn flush(&self) -> Result<(), SinkError> {
        self.file.lock().map_err(|_| SinkError::Poisoned)?.flush()?;
        Ok(())
    }
}

pub struct OtlpSink;

impl EventSink for OtlpSink {
    fn emit(&self, _event: &FalseEvent) -> Result<(), SinkError> {
        Err(SinkError::Unsupported(
            "OTLP transport is declared but not wired in this observe-only pass",
        ))
    }

    fn flush(&self) -> Result<(), SinkError> {
        Ok(())
    }
}

#[derive(Clone)]
pub struct GrpcWatchSink {
    tx: tokio::sync::broadcast::Sender<FalseEvent>,
}

impl GrpcWatchSink {
    pub fn new(tx: tokio::sync::broadcast::Sender<FalseEvent>) -> Self {
        Self { tx }
    }

    pub fn sender(&self) -> tokio::sync::broadcast::Sender<FalseEvent> {
        self.tx.clone()
    }
}

impl EventSink for GrpcWatchSink {
    fn emit(&self, event: &FalseEvent) -> Result<(), SinkError> {
        let _ = self.tx.send(event.clone());
        Ok(())
    }

    fn flush(&self) -> Result<(), SinkError> {
        Ok(())
    }
}

#[derive(Debug, Error)]
pub enum EvidenceError {
    #[error("missing evidence field: {0}")]
    MissingField(&'static str),
    #[error("serialization error: {0}")]
    Serialize(#[from] serde_json::Error),
    #[error("high-cardinality field is forbidden as a metric label: {0}")]
    HighCardinalityMetricLabel(String),
}

fn narrative_for(event: &str) -> FalseNarrative {
    use event_name::*;
    match event {
        ZONE_FILE_DENIED => FalseNarrative {
            what_failed: "cross-zone file_open".into(),
            why_it_matters: "file inode belongs to a different zone than the caller".into(),
            possible_causes: causes(&["policy drift", "mislabeled mount", "escape attempt"]),
        },
        ZONE_EXEC_DENIED => FalseNarrative {
            what_failed: "cross-zone exec".into(),
            why_it_matters: "executable inode belongs to a different zone than the caller".into(),
            possible_causes: causes(&["policy drift", "mislabeled image layer", "escape attempt"]),
        },
        ZONE_PTRACE_DENIED => FalseNarrative {
            what_failed: "cross-zone ptrace".into(),
            why_it_matters: "caller attempted to inspect or control a process outside its zone"
                .into(),
            possible_causes: causes(&[
                "debug tool in wrong zone",
                "credential misuse",
                "escape attempt",
            ]),
        },
        ZONE_SIGNAL_DENIED => FalseNarrative {
            what_failed: "cross-zone signal".into(),
            why_it_matters: "caller attempted to signal a process outside its zone".into(),
            possible_causes: causes(&[
                "stale process target",
                "orchestrator drift",
                "escape attempt",
            ]),
        },
        ZONE_ESCAPE_CGROUP_ATTACH => FalseNarrative {
            what_failed: "cross-zone cgroup attach".into(),
            why_it_matters: "moving tasks across zone cgroups would break the isolation boundary"
                .into(),
            possible_causes: causes(&["runtime bug", "manual cgroup mutation", "escape attempt"]),
        },
        ZONE_NET_DENIED => FalseNarrative {
            what_failed: "cross-zone network access".into(),
            why_it_matters: "network policy does not allow this zone-to-zone path".into(),
            possible_causes: causes(&[
                "policy drift",
                "unexpected service dependency",
                "escape attempt",
            ]),
        },
        ZONE_MOUNT_DENIED => FalseNarrative {
            what_failed: "zone mount denied".into(),
            why_it_matters: "mount operations can change the filesystem boundary".into(),
            possible_causes: causes(&["unexpected privilege", "bad OCI spec", "escape attempt"]),
        },
        ZONE_IPC_DENIED => FalseNarrative {
            what_failed: "cross-zone IPC denied".into(),
            why_it_matters: "IPC target belongs to a different zone than the caller".into(),
            possible_causes: causes(&[
                "shared namespace drift",
                "bad workload placement",
                "escape attempt",
            ]),
        },
        ZONE_PROC_FILTERED => FalseNarrative {
            what_failed: "proc entry filtered".into(),
            why_it_matters: "process listing was restricted to preserve zone visibility".into(),
            possible_causes: causes(&["normal isolation behavior"]),
        },
        RINGBUF_DROP => FalseNarrative {
            what_failed: "ring buffer event dropped".into(),
            why_it_matters: "evidence may be incomplete for the affected interval".into(),
            possible_causes: causes(&["burst exceeded ring buffer", "userspace reader lagged"]),
        },
        PIPELINE_SHED => FalseNarrative {
            what_failed: "evidence pipeline shed event".into(),
            why_it_matters: "downstream consumers may be missing telemetry".into(),
            possible_causes: causes(&["slow sink", "subscriber lag", "bounded queue full"]),
        },
        _ => FalseNarrative {
            what_failed: event.replace('.', " "),
            why_it_matters: "event records a zone lifecycle or evidence state transition".into(),
            possible_causes: causes(&["normal runtime activity"]),
        },
    }
}

fn default_severity(event: &str) -> Severity {
    use event_name::*;
    match event {
        ZONE_ESCAPE_CGROUP_ATTACH | RINGBUF_DROP => Severity::Error,
        ZONE_FILE_DENIED | ZONE_EXEC_DENIED | ZONE_PTRACE_DENIED | ZONE_SIGNAL_DENIED
        | ZONE_MOUNT_DENIED | ZONE_IPC_DENIED | ZONE_NET_DENIED | PIPELINE_SHED => Severity::Warn,
        ZONE_FILE_ALLOWED | ZONE_PROC_FILTERED => Severity::Trace,
        _ => Severity::Info,
    }
}

fn causes(values: &[&str]) -> Vec<String> {
    values.iter().map(|v| (*v).to_string()).collect()
}

fn now_rfc3339() -> String {
    DateTime::<Utc>::from(std::time::SystemTime::now()).to_rfc3339_opts(SecondsFormat::Millis, true)
}

fn redact_and_bound(value: &str) -> String {
    let lower = value.to_ascii_lowercase();
    if lower.contains("secret") || lower.contains("password") || lower.contains("token") {
        return "[redacted]".into();
    }
    bound_string(value)
}

fn bound_string(value: &str) -> String {
    if value.chars().count() <= MAX_FIELD_CHARS {
        return value.to_string();
    }
    let mut truncated = value.chars().take(MAX_FIELD_CHARS).collect::<String>();
    truncated.push_str("...[truncated]");
    truncated
}

fn display_field(value: &FieldValue) -> String {
    match value {
        FieldValue::String(value) => value.clone(),
        FieldValue::U64(value) => value.to_string(),
        FieldValue::I64(value) => value.to_string(),
        FieldValue::Bool(value) => value.to_string(),
        FieldValue::StringList(values) => values.join(","),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn metric_labels_reject_high_cardinality() {
        assert!(validate_metric_labels(&["event", "zone.bucket"]).is_ok());
        assert!(validate_metric_labels(&["event", "zone.id"]).is_err());
    }

    #[test]
    fn renders_machine_and_human_projection() {
        let event = FalseEventBuilder::new(event_name::ZONE_FILE_DENIED)
            .zone("zone-7", None)
            .actor("pid:42", vec!["svc:builder".into()])
            .resource("inode:99")
            .resource_attributes(ResourceAttrs::new(BACKEND_LINUX_EBPF))
            .field("pid", FieldValue::U64(42))
            .field("inode", FieldValue::U64(99))
            .build()
            .unwrap();

        assert!(event.machine_json().unwrap().contains("zone.file.denied"));
        assert!(event.compact_human().contains("zone.file.denied"));
        assert!(event.expanded_human().contains("delegation"));
    }

    #[test]
    fn runtime_event_uses_stable_evidence_fields() {
        let event = RuntimeEventBuilder::new(
            event_name::SANDBOX_RUN_STARTED,
            EventKind::Execution,
            EventOutcome::Started,
        )
        .task_id("task-123")
        .zone_id("zone-456")
        .zone_name("sandbox-zone")
        .backend("linux-ebpf", "linux", EnforcementMode::Enforcing)
        .correlation_id("task-123")
        .trust_level(TrustLevel::BestEffort)
        .degraded_reason("enforcement_capture_status_reported_separately")
        .build();

        let value: serde_json::Value =
            serde_json::from_str(&event.machine_json().unwrap()).unwrap();
        assert_eq!(value["event.name"], event_name::SANDBOX_RUN_STARTED);
        assert_eq!(value["event.version"], RUNTIME_EVENT_VERSION);
        assert_eq!(value["event.kind"], "execution");
        assert_eq!(value["event.outcome"], "started");
        assert_eq!(value["backend.enforcement_mode"], "enforcing");
        assert_eq!(value["trust_level"], "best_effort");
        assert_eq!(value["correlation_id"], "task-123");
    }

    #[test]
    fn runtime_event_redacts_sensitive_fields() {
        let event = RuntimeEventBuilder::new(
            event_name::SANDBOX_RUN_STARTED,
            EventKind::Execution,
            EventOutcome::Started,
        )
        .image_ref("registry.example/app:token=secret")
        .error("bad", "secret_error", "password=abc123")
        .build();

        let json = event.machine_json().unwrap();
        assert!(json.contains("[redacted]"));
        assert!(!json.contains("abc123"));
    }
}
