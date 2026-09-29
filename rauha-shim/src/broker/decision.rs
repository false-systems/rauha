//! The decision record: what the judge decided, and the append-only JSON
//! Lines log that makes every decision evidence-grade.

use std::io::Write;
use std::os::unix::fs::OpenOptionsExt;
use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};

/// What the judge decided, plus the context the decision log needs.
pub(crate) struct Judged {
    pub syscall: &'static str,
    pub tid: u32,
    pub path: Vec<u8>,
    pub decision: Decision,
}

impl Judged {
    /// A denied call. `errno` is the positive errno; `respond` handles the
    /// sign the kernel wants on the wire.
    pub(crate) fn deny(
        syscall: &'static str,
        tid: u32,
        path: Vec<u8>,
        errno: i32,
        reason: impl Into<String>,
    ) -> Self {
        Self {
            syscall,
            tid,
            path,
            decision: Decision::Deny {
                errno,
                reason: reason.into(),
            },
        }
    }

    /// The judge panicked: deny without trusting any partial state.
    pub(crate) fn panic(reason: &str) -> Self {
        Self::deny(
            "unknown",
            0,
            Vec::new(),
            libc::EPERM,
            format!("judge panicked: {reason}"),
        )
    }
}

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

/// Append-only JSON Lines record of every decision: the seed for evidence
/// projection. One line per judged notification, final outcome only, in
/// judgment order. A missing/unwritable log degrades to tracing only, and
/// a persistently failing log disables itself after the first error — it
/// must never affect the decision itself, and never spam.
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
        let line = serde_json::json!({
            "seq": self.seq,
            "ts_ms": ts_ms,
            "notif_id": id,
            "tid": tid,
            "syscall": syscall,
            "path": String::from_utf8_lossy(path),
            "decision": if reason.is_some() { "denied" } else { "granted" },
            "errno": errno,
            "reason": reason,
        });
        if let Err(e) = writeln!(file, "{line}") {
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
        assert!(lines[1].contains("\"seq\":2"));
        assert!(lines[1].contains("\"decision\":\"granted\""));
        std::fs::remove_dir_all(&dir).ok();
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
}
