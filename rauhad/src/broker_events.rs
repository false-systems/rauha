//! Broker decision ingestion — the rauha side of the shim's `broker.log`.
//!
//! The zone shim's seccomp broker records every judgment as one JSON line
//! in `/run/rauha/containers/<id>/broker.log` (see
//! `rauha-shim/src/broker/decision.rs` — the schema is pinned there by
//! test). This module is the daemon's projection of that record into the
//! evidence schema:
//!
//! - [`read_decisions_capped`]: one-shot read at sandbox result time —
//!   the ordered capture for the task's result, with storage and parse loss
//!   reported explicitly (broadcast races can also drop live events).
//! - [`spawn_broker_tailer`]: a follow tailer for live streaming — each
//!   new decision is normalized and broadcast on the daemon-wide event
//!   channel, so broker decisions ride `rauha events` like kernel
//!   enforcement events do. Spawned only for zones whose policy brokers
//!   syscalls; self-terminates when the container is gone.

use std::io::Read;
use std::path::PathBuf;

use rauha_evidence::BrokerDecision;
use uuid::Uuid;

/// One-shot read of a container's broker decisions, byte-capped like the
/// stdout/stderr capture. A missing file is an empty vec — a container
/// whose zone does not broker syscalls never writes one. Malformed lines
/// are skipped and counted once in a warning: one bad line must not
/// discard the rest of the evidence.
pub(crate) fn read_decisions_capped(
    container_id: &Uuid,
    run_dir: &str,
    max_bytes: usize,
    issues: &mut Vec<String>,
) -> Vec<BrokerDecision> {
    let path = broker_log_path(run_dir, container_id);
    if path.with_extension("incomplete").exists() {
        issues.push("broker.storage_incomplete".into());
    }
    let Ok(file) = std::fs::File::open(&path) else {
        return Vec::new();
    };
    let mut bytes = Vec::with_capacity(4096);
    // Read one byte past the cap so truncation is detectable.
    let mut limited = file.take(max_bytes.saturating_add(1) as u64);
    if limited.read_to_end(&mut bytes).is_err() {
        issues.push("broker.read_failed".into());
        return Vec::new();
    }
    let truncated = bytes.len() > max_bytes;
    if truncated {
        issues.push("broker.preview_truncated".into());
        bytes.truncate(max_bytes);
    }
    let text = String::from_utf8_lossy(&bytes);
    let mut decisions = Vec::new();
    let mut malformed = 0usize;
    for line in text.lines().filter(|l| !l.is_empty()) {
        match serde_json::from_str::<BrokerDecision>(line) {
            Ok(decision) => decisions.push(decision),
            Err(_) => malformed += 1,
        }
    }
    if malformed > 0 {
        issues.push("broker.malformed_records".into());
        tracing::warn!(
            container = %container_id,
            malformed,
            truncated,
            "broker.log: skipped malformed decision lines"
        );
    }
    decisions
}

fn broker_log_path(run_dir: &str, container_id: &Uuid) -> PathBuf {
    PathBuf::from(run_dir)
        .join("containers")
        .join(container_id.to_string())
        .join("broker.log")
}

/// Spawn the live tailer for a container's broker decisions, if its zone
/// brokers syscalls at all. No-op otherwise — nothing to follow, nothing
/// to log. The task resolves the zone once, then polls the file until the
/// container is gone from the registry.
/// Containers that already have a live tailer. StartContainer can be
/// retried (the containerd shim retries RPCs); without the guard, a
/// retry would double every decision on the event stream. Idempotent by
/// UUID: a new container never collides with an old one.
#[cfg(target_os = "linux")]
static TAILED: std::sync::OnceLock<std::sync::Mutex<std::collections::HashSet<Uuid>>> =
    std::sync::OnceLock::new();

#[cfg(target_os = "linux")]
fn claim_tailer(container_id: &Uuid) -> bool {
    let set = TAILED.get_or_init(Default::default);
    let mut guard = set.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
    guard.insert(*container_id)
}

#[cfg(target_os = "linux")]
fn release_tailer(container_id: &Uuid) {
    let set = TAILED.get_or_init(Default::default);
    let mut guard = set.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
    guard.remove(container_id);
}

#[cfg(target_os = "linux")]
pub(crate) async fn spawn_broker_tailer(
    registry: std::sync::Arc<crate::zone::registry::ZoneRegistry>,
    event_tx: tokio::sync::broadcast::Sender<rauha_evidence::FalseEvent>,
    container_id: Uuid,
) {
    /// Poll interval — same cadence as container log tailing
    /// (`rauhad/src/logs.rs`).
    const TAIL_POLL_MS: u64 = 200;
    /// The tailer checks container existence every 25 polls (~5s) and
    /// exits once the container is gone; between checks it only reads.
    const CONTAINER_CHECK_INTERVAL: u32 = 25;
    use std::io::{Read, Seek, SeekFrom};

    use rauha_evidence::broker_decision_event;

    if !claim_tailer(&container_id) {
        // A tailer is already live for this container — a retried
        // StartContainer must not duplicate the stream.
        tracing::debug!(container = %container_id, "broker decision tailer already running");
        return;
    }
    let Ok(container) = registry.get_container(&container_id) else {
        release_tailer(&container_id);
        return;
    };
    let Some(zone_name) = registry.zone_name_for_container(&container.zone_id).await else {
        release_tailer(&container_id);
        return;
    };
    let Ok(zone) = registry.get_zone(&zone_name).await else {
        release_tailer(&container_id);
        return;
    };
    if zone.policy.syscalls.broker.is_empty() {
        release_tailer(&container_id);
        return;
    }
    // Identity label: the compact kernel zone id matches how eBPF
    // enforcement events label zones; fall back to the zone's UUID.
    let kernel_zone_id = registry.kernel_zone_id(&zone_name).await;
    let zone_label = match kernel_zone_id {
        Some(id) => format!("zone-{id}"),
        None => zone.id.to_string(),
    };
    let path = broker_log_path(&registry.config().paths.run_dir, &container_id);

    tokio::spawn(async move {
        let mut reader: Option<(std::fs::File, u64)> = None;
        let mut malformed = 0usize;
        let mut tick: u32 = 0;
        tracing::debug!(container = %container_id, "broker decision tailer started");
        loop {
            // Open (or keep) the file and read everything past the last
            // offset. Tiny synchronous reads on a 200ms cadence — the
            // container log tailer does the same.
            if reader.is_none() {
                if let Ok(file) = std::fs::File::open(&path) {
                    reader = Some((file, 0));
                }
            }
            if let Some((file, offset)) = reader.as_mut() {
                let mut chunk = String::new();
                let read_ok = file
                    .seek(SeekFrom::Start(*offset))
                    .and_then(|_| file.take(1024 * 1024).read_to_string(&mut chunk))
                    .is_ok();
                // Consume only complete, newline-terminated lines: a
                // tailer must not assume the writer's write granularity.
                // If a torn line is ever observed, its bytes stay
                // unconsumed and the next poll re-reads them whole.
                if read_ok {
                    if let Some(consumed) = chunk.rfind('\n').map(|i| i + 1) {
                        for line in chunk[..consumed].lines().filter(|l| !l.is_empty()) {
                            match serde_json::from_str::<BrokerDecision>(line) {
                                Ok(decision) => {
                                    let event = broker_decision_event(
                                        &decision,
                                        &zone_label,
                                        kernel_zone_id.unwrap_or(0),
                                    );
                                    // No receivers is fine — WatchEvents
                                    // subscribers come and go; the file keeps
                                    // the record regardless.
                                    let _ = event_tx.send(event);
                                }
                                Err(_) => malformed += 1,
                            }
                        }
                        *offset += consumed as u64;
                    }
                }
            }
            if malformed > 0 {
                tracing::warn!(container = %container_id, malformed, "broker.log: malformed lines in tailer");
                malformed = 0;
            }
            tick = tick.wrapping_add(1);
            if tick.is_multiple_of(CONTAINER_CHECK_INTERVAL)
                && registry.get_container(&container_id).is_err()
            {
                tracing::debug!(container = %container_id, "broker decision tailer stopped");
                release_tailer(&container_id);
                return;
            }
            tokio::time::sleep(std::time::Duration::from_millis(TAIL_POLL_MS)).await;
        }
    });
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reads_decisions_in_file_order_and_skips_malformed_lines() {
        let dir = tempfile::tempdir().unwrap();
        let run_dir = dir.path().to_str().unwrap().to_string();
        let id = Uuid::new_v4();
        let log_dir = dir.path().join("containers").join(id.to_string());
        std::fs::create_dir_all(&log_dir).unwrap();
        std::fs::write(
            log_dir.join("broker.log"),
            concat!(
                r#"{"seq":1,"ts_ms":1,"notif_id":1,"tid":10,"syscall":"openat","path":"/a","decision":"granted","errno":0,"reason":null}"#,
                "\nnot json at all\n",
                r#"{"seq":2,"ts_ms":2,"notif_id":2,"tid":11,"syscall":"openat","path":"/b","decision":"denied","errno":1,"reason":"not read-only"}"#,
                "\n"
            ),
        )
        .unwrap();

        let mut issues = Vec::new();
        let decisions = read_decisions_capped(&id, &run_dir, 64 * 1024, &mut issues);
        assert_eq!(issues, ["broker.malformed_records"]);
        assert_eq!(decisions.len(), 2, "malformed line skipped, rest kept");
        assert_eq!(decisions[0].seq, 1);
        assert_eq!(decisions[1].path, "/b");
        assert!(!decisions[1].granted());
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn tailer_claim_is_idempotent_until_released() {
        // A retried StartContainer must not double the event stream.
        let id = Uuid::new_v4();
        assert!(claim_tailer(&id), "first claim wins");
        assert!(
            !claim_tailer(&id),
            "second claim for the same container is refused"
        );
        release_tailer(&id);
        assert!(claim_tailer(&id), "release re-arms the claim");
        release_tailer(&id);
    }

    #[test]
    fn missing_log_is_empty_not_an_error() {
        let decisions = read_decisions_capped(
            &Uuid::new_v4(),
            "/nonexistent-run-dir",
            1024,
            &mut Vec::new(),
        );
        assert!(decisions.is_empty());
    }

    #[test]
    fn cap_truncates_instead_of_reading_unbounded() {
        let dir = tempfile::tempdir().unwrap();
        let run_dir = dir.path().to_str().unwrap().to_string();
        let id = Uuid::new_v4();
        let log_dir = dir.path().join("containers").join(id.to_string());
        std::fs::create_dir_all(&log_dir).unwrap();
        let line = concat!(
            r#"{"seq":1,"ts_ms":1,"notif_id":1,"tid":10,"syscall":"openat","path":"/a","decision":"granted","errno":0,"reason":null}"#,
            "\n"
        );
        // Two lines, capped to less than two: at most one survives whole.
        std::fs::write(log_dir.join("broker.log"), line.repeat(2)).unwrap();
        let mut issues = Vec::new();
        let decisions = read_decisions_capped(&id, &run_dir, line.len() + 10, &mut issues);
        assert!(issues.contains(&"broker.preview_truncated".to_string()));
        assert!(decisions.len() <= 2);
        assert!(!decisions.is_empty());
    }
}
