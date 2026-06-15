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
}
