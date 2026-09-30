//! The decision record: what the judge decided, and the append-only JSON
//! Lines log that makes every decision evidence-grade.

use std::io::Write;
use std::os::unix::fs::OpenOptionsExt;
use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};

pub(crate) enum Decision {
    Deny {
        errno: i32,
        reason: String,
    },
    /// Open succeeded on the workload's behalf; `cloexec` mirrors the
    /// caller's O_CLOEXEC onto the injected descriptor.
    InjectFd {
        file: std::fs::File,
        cloexec: bool,
    },
}

impl Decision {
    /// A denied call. `errno` is the positive errno; `respond` handles the
    /// sign the kernel wants on the wire.
    pub(crate) fn deny(errno: i32, reason: impl Into<String>) -> Self {
        Decision::Deny {
            errno,
            reason: reason.into(),
        }
    }
}

/// One line of `broker.log`, serialized directly to the file — no JSON
/// value tree on the hot path. Field names are the stable schema
/// (grep-matched by tests/integration/test-broker.sh).
#[derive(serde::Serialize)]
struct Record<'a> {
    seq: u64,
    ts_ms: u64,
    notif_id: u64,
    tid: u32,
    syscall: &'a str,
    path: std::borrow::Cow<'a, str>,
    decision: &'a str,
    errno: i32,
    reason: Option<&'a str>,
}

/// Append-only JSON Lines record of every decision: the seed for evidence
/// projection. One line per judged notification, final outcome only, in
/// judgment order. Thread-safe behind a mutex in the judge pool: the lock
/// covers one small write, never a judgment. A missing or unwritable log
/// degrades to tracing only, and a persistently failing log disables
/// itself after the first error — it must never affect the decision
/// itself, and never spam.
pub(crate) struct DecisionLog {
    file: Option<std::fs::File>,
    seq: u64,
    disabled: bool,
}

impl DecisionLog {
    pub(crate) fn open(path: &Path) -> Self {
        // Close-on-exec: the shim forks and execs helpers; a container's
        // decision log is not theirs to write.
        let file = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            // Root-only: the decision log records every path a workload
            // opened — workload activity is not for other local users.
            .mode(0o600)
            .custom_flags(libc::O_CLOEXEC)
            .open(path);
        match file {
            Ok(file) => Self {
                file: Some(file),
                seq: 0,
                disabled: false,
            },
            Err(e) => {
                tracing::warn!(
                    path = %path.display(),
                    %e,
                    "broker: decision log unavailable — decisions will not be recorded"
                );
                Self {
                    file: None,
                    seq: 0,
                    disabled: false,
                }
            }
        }
    }

    /// Record the final outcome of one judged notification.
    pub(crate) fn record(
        &mut self,
        id: u64,
        syscall: &str,
        tid: u32,
        path: &[u8],
        errno: i32,
        reason: Option<&str>,
    ) {
        let Some(file) = &mut self.file else { return };
        if self.disabled {
            return;
        }
        self.seq += 1;
        let ts_ms = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_millis() as u64)
            .unwrap_or(0);
        let record = Record {
            seq: self.seq,
            ts_ms,
            notif_id: id,
            tid,
            syscall,
            path: String::from_utf8_lossy(path),
            decision: if reason.is_some() {
                "denied"
            } else {
                "granted"
            },
            errno,
            reason,
        };
        let mut line = serde_json::to_string(&record).unwrap_or_else(|_| "{}".into());
        line.push('\n');
        if let Err(e) = file.write_all(line.as_bytes()) {
            tracing::warn!(%e, "broker: cannot write decision log — disabling it");
            self.disabled = true;
        }
    }

    #[cfg(test)]
    fn disabled(&self) -> bool {
        self.disabled
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn decision_log_records_grants_and_denials_in_order() {
        let dir = std::env::temp_dir().join(format!("rauha-broker-log-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("broker.log");
        let mut log = DecisionLog::open(&path);
        log.record(
            7,
            "openat",
            42,
            b"/etc/hostname",
            libc::EPERM,
            Some("not read-only"),
        );
        log.record(8, "openat", 42, b"/etc/hostname", 0, None);
        let content = std::fs::read_to_string(&path).unwrap();
        let lines: Vec<&str> = content.lines().collect();
        assert_eq!(lines.len(), 2);
        assert!(lines[0].contains("\"seq\":1"));
        assert!(lines[0].contains("\"decision\":\"denied\""));
        assert!(lines[0].contains("\"errno\":1"));
        assert!(lines[0].contains("\"reason\":\"not read-only\""));
        assert!(lines[0].contains("\"path\":\"/etc/hostname\""));
        assert!(lines[1].contains("\"seq\":2"));
        assert!(lines[1].contains("\"decision\":\"granted\""));
        assert!(lines[1].contains("\"reason\":null"));
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn record_schema_is_stable() {
        // The exact line shape, byte for byte — integration tests and
        // evidence consumers grep these fields.
        let record = Record {
            seq: 1,
            ts_ms: 0,
            notif_id: 9,
            tid: 5,
            syscall: "openat",
            path: "/x".into(),
            decision: "denied",
            errno: 1,
            reason: Some("r"),
        };
        assert_eq!(
            serde_json::to_string(&record).unwrap(),
            "{\"seq\":1,\"ts_ms\":0,\"notif_id\":9,\"tid\":5,\"syscall\":\"openat\",\"path\":\"/x\",\"decision\":\"denied\",\"errno\":1,\"reason\":\"r\"}"
        );
    }

    #[test]
    fn a_failing_log_disables_itself_instead_of_spamming() {
        // /dev/full: opens fine, every write fails ENOSPC. After the first
        // failure the log must go quiet, not warn per decision.
        let mut log = DecisionLog::open(Path::new("/dev/full"));
        log.record(1, "openat", 1, b"/x", libc::EPERM, Some("not read-only"));
        assert!(log.disabled(), "first write failure must disable the log");
        log.record(2, "openat", 1, b"/x", libc::EPERM, Some("not read-only"));
    }

    #[test]
    fn the_decision_log_is_root_only() {
        // The log records every path a workload opened — mode 0600, not
        // for other local users (flagged in the #73 review).
        use std::os::unix::fs::PermissionsExt;
        let dir = std::env::temp_dir().join(format!("rauha-broker-mode-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("broker.log");
        let _log = DecisionLog::open(&path);
        let mode = std::fs::metadata(&path).unwrap().permissions().mode();
        assert_eq!(mode & 0o777, 0o600, "decision log must be root-only");
        std::fs::remove_dir_all(&dir).ok();
    }
}
