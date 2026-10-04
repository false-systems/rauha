//! Local task lifecycle: validate -> commit journal -> publish state/action.
//! This deliberately grants no ownership epochs or external-effect authority.

use super::*;
use anyhow::{ensure, Context};
use rauha_common::run::{reduce, Emitter, RunState};
use rauha_evidence::journal::Journal;
use rauha_evidence::receipt::{sha256_bytes, JournalCommitment, SignedExecutionReceipt};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::fs::{DirBuilder, File};
use std::os::unix::fs::DirBuilderExt;
use std::path::{Path, PathBuf};

#[derive(Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Manifest {
    task_id: String,
    zone_id: String,
    inputs_sha256: String,
    policy_sha256: String,
}

impl From<&RecoveryRecord> for Manifest {
    fn from(record: &RecoveryRecord) -> Self {
        Self {
            task_id: record.receipt.task_id.clone(),
            zone_id: record.receipt.zone_id.clone(),
            inputs_sha256: record.receipt.inputs_sha256.clone(),
            policy_sha256: record.receipt.policy_sha256.clone(),
        }
    }
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Body {
    emitter: Emitter,
    data: Value,
}

pub(crate) struct TaskRun {
    journal: Journal,
    state: Option<RunState>,
    sealed_result: Option<String>,
    sealed_prefix: Option<JournalCommitment>,
}

pub(super) fn path(root: &str, id: &str) -> anyhow::Result<PathBuf> {
    ensure!(valid_task_id(id), "invalid Run task identity");
    Ok(Path::new(root).join("runs").join(id))
}

/// Caller holds the daemon's active-task mutex and excludes pending recovery.
/// Keep the result reservation until this returns: it prevents ID reuse while
/// a crash-interrupted deletion is retried. Never repair a live journal.
pub(super) fn discard(root: &str, id: &str) -> anyhow::Result<()> {
    let path = path(root, id)?;
    let pending = path.with_file_name(format!(".deleting-{id}"));
    let parent = path.parent().unwrap();
    let pending_exists = match std::fs::symlink_metadata(&pending) {
        Ok(meta) => {
            ensure!(meta.is_dir(), "invalid journal deletion directory");
            true
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => false,
        Err(e) => return Err(e.into()),
    };
    let journal = match std::fs::symlink_metadata(&path) {
        Ok(_) => {
            ensure!(!pending_exists, "conflicting journal deletion state");
            let journal = Journal::open(&path)?;
            std::fs::rename(&path, &pending)?;
            Some(journal)
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => None,
        Err(e) => return Err(e.into()),
    };
    if journal.is_some() || pending_exists {
        ensure!(
            std::fs::symlink_metadata(&pending)?.is_dir(),
            "invalid journal deletion directory"
        );
        // Sync even on retry: the first writer may have died just after rename.
        File::open(parent)?.sync_all()?;
        std::fs::remove_dir_all(&pending)?;
        File::open(parent)?.sync_all()?;
    } else if parent.try_exists()? {
        // A previous attempt may have unlinked the directory but not synced it.
        File::open(parent)?.sync_all()?;
    }
    drop(journal);
    Ok(())
}

impl TaskRun {
    pub(crate) fn create(root: &str, record: &RecoveryRecord) -> anyhow::Result<Self> {
        let path = path(root, &record.receipt.task_id)?;
        let parent = path.parent().unwrap();
        match DirBuilder::new().mode(0o700).create(parent) {
            Ok(()) => File::open(root)?.sync_all()?,
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {
                ensure!(
                    std::fs::symlink_metadata(parent)?.is_dir(),
                    "Run parent is not a directory"
                );
            }
            Err(e) => return Err(e.into()),
        }
        let mut run = Self {
            journal: Journal::create(&path, serde_json::to_value(Manifest::from(record))?)?,
            state: None,
            sealed_result: None,
            sealed_prefix: None,
        };
        run.append(
            "run.created",
            Emitter::Supervisor,
            json!({"task_id": record.receipt.task_id}),
        )?;
        Ok(run)
    }

    pub(super) fn open(root: &str, id: &str) -> anyhow::Result<Self> {
        let journal = Journal::open(&path(root, id)?)?;
        let manifest: Manifest = serde_json::from_value(journal.manifest().clone())?;
        ensure!(manifest.task_id == id, "Run manifest identity mismatch");
        let mut state = None;
        let mut sealed_result = None;
        let mut sealed_prefix = None;
        let mut failure = None;
        journal.replay(|entry| {
            if failure.is_some() {
                return;
            }
            let apply = || -> anyhow::Result<_> {
                ensure!(
                    entry.epoch == 0,
                    "local task Run cannot claim an ownership epoch"
                );
                ensure!(sealed_result.is_none(), "event after task result seal");
                let body: Body = serde_json::from_value(entry.body.clone())?;
                validate_body(&manifest, &entry.kind, &body.data)?;
                let reduced = reduce(state, &entry.kind, body.emitter)?;
                if entry.kind == "receipt.sealed" {
                    ensure!(
                        matches!(state, Some(RunState::Waiting | RunState::Frozen)),
                        "cannot seal an active task"
                    );
                }
                ensure!(
                    reduced.unknown_event.is_none(),
                    "unsupported local task event"
                );
                Ok((reduced.state, body))
            };
            match apply() {
                Ok((next, body)) => {
                    if entry.kind == "receipt.sealed" {
                        sealed_prefix = Some(
                            commitment(
                                state,
                                &journal.head().manifest_sha256,
                                entry.seq - 1,
                                &entry.prev,
                            )
                            .unwrap(),
                        );
                        sealed_result =
                            Some(body.data["result_sha256"].as_str().unwrap().to_owned());
                    }
                    state = next;
                }
                Err(e) => failure = Some(e),
            }
        })?;
        if let Some(error) = failure {
            return Err(error);
        }
        ensure!(state.is_some(), "Run has no committed creation event");
        Ok(Self {
            journal,
            state,
            sealed_result,
            sealed_prefix,
        })
    }

    pub(super) fn verify_context(&self, record: &RecoveryRecord) -> anyhow::Result<()> {
        let manifest: Manifest = serde_json::from_value(self.journal.manifest().clone())?;
        ensure!(
            manifest == Manifest::from(record),
            "Run/recovery identity or input commitment mismatch"
        );
        Ok(())
    }

    fn append(&mut self, kind: &str, emitter: Emitter, data: Value) -> anyhow::Result<()> {
        ensure!(
            self.sealed_result.is_none(),
            "task result is already sealed"
        );
        let manifest: Manifest = serde_json::from_value(self.journal.manifest().clone())?;
        validate_body(&manifest, kind, &data)?;
        let next = reduce(self.state, kind, emitter)?;
        ensure!(next.unknown_event.is_none(), "unsupported local task event");
        self.journal
            .append(kind, 0, serde_json::to_value(Body { emitter, data })?)?;
        self.state = next.state;
        Ok(())
    }

    pub(super) fn ready(&mut self, record: &RecoveryRecord) -> anyhow::Result<()> {
        self.verify_context(record)?;
        self.append(
            "sandbox.ready",
            Emitter::Custodian,
            json!({
                "container_id": record.container_id.context("ready without container")?,
                "image": record.receipt.image,
            }),
        )
    }

    pub(super) fn finish(&mut self, freeze_reason: Option<&str>) -> anyhow::Result<()> {
        if self.state == Some(RunState::Frozen) {
            return Ok(());
        }
        if freeze_reason.is_some() || self.state == Some(RunState::Preparing) {
            self.append(
                "run.frozen",
                Emitter::Custodian,
                json!({"reason": freeze_reason.unwrap_or("execution_not_started")}),
            )
        } else {
            self.append(
                "run.waiting",
                Emitter::Supervisor,
                json!({"reason": "result_ready"}),
            )
        }
    }

    pub(super) fn commitment(&self) -> anyhow::Result<JournalCommitment> {
        let head = self.journal.head();
        commitment(
            self.state,
            &head.manifest_sha256,
            head.sequence,
            &head.journal_root,
        )
    }

    /// Bind the already-persisted signed result to the exact lifecycle prefix.
    /// Idempotent across a crash after either result commit or seal append.
    pub(super) fn seal_result(
        &mut self,
        result: &pb::sandbox::SandboxResult,
    ) -> anyhow::Result<()> {
        self.verify_result(result, false)?;
        if self.sealed_result.is_some() {
            return Ok(());
        }
        let prefix = self.commitment()?;
        let hash = sha256_bytes(&result.encode_to_vec());
        self.append(
            "receipt.sealed",
            Emitter::Custodian,
            json!({"result_sha256": hash}),
        )?;
        self.sealed_result = Some(hash);
        self.sealed_prefix = Some(prefix);
        Ok(())
    }

    pub(super) fn verify_result(
        &self,
        result: &pb::sandbox::SandboxResult,
        require_seal: bool,
    ) -> anyhow::Result<()> {
        ensure!(
            matches!(self.state, Some(RunState::Waiting | RunState::Frozen)),
            "cannot seal an active task"
        );
        let receipt: SignedExecutionReceipt = serde_json::from_str(&result.receipt_json)?;
        receipt.verify().map_err(anyhow::Error::msg)?;
        let manifest: Manifest = serde_json::from_value(self.journal.manifest().clone())?;
        ensure!(
            receipt.payload.task_id == manifest.task_id
                && result.task_id == manifest.task_id
                && receipt.payload.zone_id == manifest.zone_id
                && result.zone_id == manifest.zone_id
                && receipt.payload.inputs_sha256 == manifest.inputs_sha256
                && receipt.payload.policy_sha256 == manifest.policy_sha256,
            "result identity differs from Run"
        );
        ensure!(
            self.journal.uncommitted_bytes() == 0,
            "Run tail requires explicit repair"
        );
        let prefix = self.sealed_prefix.clone().unwrap_or(self.commitment()?);
        ensure!(
            receipt.payload.journal.as_ref() == Some(&prefix),
            "receipt does not cover Run lifecycle prefix"
        );
        match &self.sealed_result {
            Some(hash) => ensure!(
                *hash == sha256_bytes(&result.encode_to_vec()),
                "saved result differs from journal seal"
            ),
            None => ensure!(!require_seal, "Run result seal is pending recovery"),
        }
        Ok(())
    }
}

fn commitment(
    state: Option<RunState>,
    manifest: &str,
    sequence: u64,
    root: &str,
) -> anyhow::Result<JournalCommitment> {
    let state = serde_json::to_value(state.context("Run has no state")?)?
        .as_str()
        .unwrap()
        .to_owned();
    Ok(JournalCommitment {
        state,
        manifest_sha256: manifest.into(),
        sequence,
        journal_root: root.into(),
    })
}

fn validate_body(manifest: &Manifest, kind: &str, data: &Value) -> anyhow::Result<()> {
    ensure!(data.is_object(), "event data must be an object");
    match kind {
        "run.created" => ensure!(
            data["task_id"].as_str() == Some(&manifest.task_id),
            "creation identity mismatch"
        ),
        "sandbox.ready" => {
            uuid::Uuid::parse_str(
                data["container_id"]
                    .as_str()
                    .context("missing container identity")?,
            )?;
            let _: ImageAdmission = serde_json::from_value(data["image"].clone())?;
        }
        "run.waiting" => ensure!(data["reason"] == "result_ready", "unknown wait reason"),
        "run.frozen" => ensure!(
            matches!(
                data["reason"].as_str(),
                Some(
                    "daemon_interrupted"
                        | "execution_not_started"
                        | "execution_failed"
                        | "execution_timeout"
                )
            ),
            "unknown freeze reason"
        ),
        "receipt.sealed" => {
            let hash = data["result_sha256"]
                .as_str()
                .context("missing result hash")?;
            ensure!(
                hash.strip_prefix("sha256:").is_some_and(|v| v.len() == 64
                    && v.bytes()
                        .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))),
                "invalid result hash"
            );
        }
        _ => anyhow::bail!("unsupported local task event: {kind}"),
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    #[test]
    fn discard_retries_each_directory_removal_boundary() {
        for boundary in ["before_rename", "renamed", "partial_unlink", "unlinked"] {
            let tmp = tempfile::tempdir().unwrap();
            let root = tmp.path().to_str().unwrap();
            let record = record();
            let id = &record.receipt.task_id;
            drop(TaskRun::create(root, &record).unwrap());
            let live = path(root, id).unwrap();
            let pending = live.with_file_name(format!(".deleting-{id}"));
            if boundary != "before_rename" {
                std::fs::rename(&live, &pending).unwrap();
            }
            if boundary == "partial_unlink" {
                std::fs::remove_file(pending.join("head")).unwrap();
            }
            if boundary == "unlinked" {
                std::fs::remove_dir_all(&pending).unwrap();
            }
            discard(root, id).unwrap();
            discard(root, id).unwrap();
            assert!(!live.exists() && !pending.exists(), "{boundary}");
        }
    }

    fn record() -> RecoveryRecord {
        let id = format!("task-{}", uuid::Uuid::new_v4());
        let zone = uuid::Uuid::new_v4().to_string();
        RecoveryRecord {
            journaled: true,
            zone_name: "test".into(),
            container_id: Some(uuid::Uuid::new_v4()),
            cleanup_zone: true,
            command: vec!["true".into()],
            admission: rauha_common::zone::PolicyAdmission::Audit,
            receipt: recovery_receipt(
                &id,
                &zone,
                &pb::sandbox::RunSandboxRequest {
                    image: "alpine".into(),
                    command: vec!["true".into()],
                    ..Default::default()
                },
                &Default::default(),
                vec![],
            )
            .unwrap(),
        }
    }

    #[test]
    fn result_commit_and_journal_seal_recover_independently() {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path().to_str().unwrap();
        let record = record();
        let id = &record.receipt.task_id;
        let signer = ReceiptSigner::load_or_create(&tmp.path().join("key")).unwrap();
        let mut run = TaskRun::create(root, &record).unwrap();
        assert_eq!(run.commitment().unwrap().state, "preparing");
        let before = run.commitment().unwrap();
        assert!(run
            .append(
                "sandbox.ready",
                Emitter::Supervisor,
                json!({"container_id":record.container_id,"image":record.receipt.image})
            )
            .is_err());
        assert_eq!(run.commitment().unwrap(), before);
        run.ready(&record).unwrap();
        assert_eq!(run.commitment().unwrap().state, "running");
        run.finish(None).unwrap();
        let mut payload = record.receipt.clone();
        payload.journal = Some(run.commitment().unwrap());
        let result = seal_bounded_result(
            pb::sandbox::SandboxResult {
                task_id: id.clone(),
                zone_id: record.receipt.zone_id.clone(),
                status: "succeeded".into(),
                exit_code: Some(0),
                ..Default::default()
            },
            payload,
            &signer,
        )
        .unwrap();
        drop(run); // Crash after result commit, before receipt.sealed.
        let mut run = TaskRun::open(root, id).unwrap();
        assert!(run.verify_result(&result, true).is_err());
        run.seal_result(&result).unwrap();
        let bytes = std::fs::read(path(root, id).unwrap().join("journal.jsonl")).unwrap();
        drop(run);
        for _ in 0..3 {
            let mut run = TaskRun::open(root, id).unwrap();
            run.seal_result(&result).unwrap();
            run.verify_result(&result, true).unwrap();
            assert_eq!(run.state, Some(RunState::Waiting));
            assert_eq!(
                std::fs::read(path(root, id).unwrap().join("journal.jsonl")).unwrap(),
                bytes
            );
            let mut altered = result.clone();
            altered.stdout.push_str("changed");
            assert!(run.verify_result(&altered, true).is_err());
        }
    }

    #[test]
    fn interrupted_states_freeze_and_tails_never_advance_state() {
        for initial in [RunState::Preparing, RunState::Running, RunState::Waiting] {
            let tmp = tempfile::tempdir().unwrap();
            let root = tmp.path().to_str().unwrap();
            let record = record();
            let id = &record.receipt.task_id;
            let mut run = TaskRun::create(root, &record).unwrap();
            if initial != RunState::Preparing {
                run.ready(&record).unwrap();
            }
            if initial == RunState::Waiting {
                run.finish(None).unwrap();
            }
            drop(run);
            let mut run = TaskRun::open(root, id).unwrap();
            run.finish(Some("daemon_interrupted")).unwrap();
            let frozen = run.commitment().unwrap();
            assert_eq!(frozen.state, "frozen");
            drop(run);
            let mut run = TaskRun::open(root, id).unwrap();
            run.finish(Some("daemon_interrupted")).unwrap();
            assert_eq!(run.commitment().unwrap(), frozen);
        }
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path().to_str().unwrap();
        let record = record();
        let id = &record.receipt.task_id;
        let original = TaskRun::create(root, &record)
            .unwrap()
            .commitment()
            .unwrap();
        let log = path(root, id).unwrap().join("journal.jsonl");
        std::fs::OpenOptions::new()
            .append(true)
            .open(&log)
            .unwrap()
            .write_all(b"torn")
            .unwrap();
        let bytes = std::fs::read(&log).unwrap();
        let mut run = TaskRun::open(root, id).unwrap();
        assert!(run.ready(&record).is_err());
        assert!(run.finish(Some("daemon_interrupted")).is_err());
        assert_eq!(run.commitment().unwrap(), original);
        assert_eq!(std::fs::read(&log).unwrap(), bytes);
    }

    #[test]
    fn replay_refuses_wrong_emitter_epoch_body_and_identity() {
        for damage in [
            "emitter",
            "epoch",
            "body",
            "identity",
            "unknown",
            "active_seal",
        ] {
            let tmp = tempfile::tempdir().unwrap();
            let root = tmp.path().to_str().unwrap();
            let record = record();
            let id = &record.receipt.task_id;
            drop(TaskRun::create(root, &record).unwrap());
            let mut journal = Journal::open(&path(root, id).unwrap()).unwrap();
            let (kind, emitter, data) = match damage {
                "emitter" => (
                    "sandbox.ready",
                    Emitter::Supervisor,
                    json!({"container_id":record.container_id,"image":record.receipt.image}),
                ),
                "body" => (
                    "run.frozen",
                    Emitter::Custodian,
                    json!({"reason":"invented"}),
                ),
                "identity" => (
                    "run.created",
                    Emitter::Supervisor,
                    json!({"task_id":"other"}),
                ),
                "unknown" => ("run.future", Emitter::Supervisor, json!({})),
                "active_seal" => (
                    "receipt.sealed",
                    Emitter::Custodian,
                    json!({"result_sha256":sha256_bytes(b"fake")}),
                ),
                _ => (
                    "run.frozen",
                    Emitter::Custodian,
                    json!({"reason":"daemon_interrupted"}),
                ),
            };
            journal
                .append(
                    kind,
                    if damage == "epoch" { 1 } else { 0 },
                    serde_json::to_value(Body { emitter, data }).unwrap(),
                )
                .unwrap();
            drop(journal);
            assert!(TaskRun::open(root, id).is_err(), "{damage}");
        }
    }
}
