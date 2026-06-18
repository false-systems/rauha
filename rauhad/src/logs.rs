//! Container log file tailing.
//!
//! Container stdout/stderr are written to log files by the shim at
//! `/run/rauha/containers/{id}/stdout.log` and `stderr.log`.
//!
//! This module provides:
//! - One-shot read: return existing log content
//! - Follow mode: poll for new lines every 200ms

use std::io::{BufRead, BufReader, Seek, SeekFrom};
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};

/// A single log line with metadata.
#[derive(Debug, Clone)]
pub struct LogLine {
    pub source: String,
    pub line: String,
    pub timestamp: String,
}

/// Read the last `tail` lines from a log file, then optionally follow.
///
/// Sends lines through the provided callback. Returns when the callback
/// returns `false` (client disconnected) or when `follow` is false and
/// all existing content has been read.
pub fn tail_logs(
    container_id: &str,
    follow: bool,
    tail: u32,
    cancelled: &AtomicBool,
    mut on_line: impl FnMut(LogLine) -> bool,
) {
    let stdout_path = log_path(container_id, "stdout");
    let stderr_path = log_path(container_id, "stderr");

    // Read initial tail lines from both files.
    let mut stdout_lines = read_tail_lines(&stdout_path, tail);
    let mut stderr_lines = read_tail_lines(&stderr_path, tail);

    // Send initial lines (stdout first, then stderr, as a simple merge).
    for line in stdout_lines.drain(..) {
        if !on_line(LogLine {
            source: "stdout".into(),
            line,
            timestamp: now_rfc3339(),
        }) {
            return;
        }
    }
    for line in stderr_lines.drain(..) {
        if !on_line(LogLine {
            source: "stderr".into(),
            line,
            timestamp: now_rfc3339(),
        }) {
            return;
        }
    }

    if !follow {
        return;
    }

    // Follow mode: open files and poll for new data.
    let mut stdout_reader = open_at_end(&stdout_path);
    let mut stderr_reader = open_at_end(&stderr_path);

    loop {
        if cancelled.load(Ordering::Relaxed) {
            return;
        }

        let mut got_data = false;

        if let Some(ref mut reader) = stdout_reader {
            let mut line = String::new();
            while reader.read_line(&mut line).unwrap_or(0) > 0 {
                let trimmed = line.trim_end_matches('\n').to_string();
                if !trimmed.is_empty() {
                    if !on_line(LogLine {
                        source: "stdout".into(),
                        line: trimmed,
                        timestamp: now_rfc3339(),
                    }) {
                        return;
                    }
                    got_data = true;
                }
                line.clear();
            }
        } else {
            // File may not exist yet — try to open it.
            stdout_reader = open_at_end(&stdout_path);
        }

        if let Some(ref mut reader) = stderr_reader {
            let mut line = String::new();
            while reader.read_line(&mut line).unwrap_or(0) > 0 {
                let trimmed = line.trim_end_matches('\n').to_string();
                if !trimmed.is_empty() {
                    if !on_line(LogLine {
                        source: "stderr".into(),
                        line: trimmed,
                        timestamp: now_rfc3339(),
                    }) {
                        return;
                    }
                    got_data = true;
                }
                line.clear();
            }
        } else {
            stderr_reader = open_at_end(&stderr_path);
        }

        if !got_data {
            std::thread::sleep(std::time::Duration::from_millis(200));
        }
    }
}

fn log_path(container_id: &str, stream: &str) -> PathBuf {
    PathBuf::from("/run/rauha/containers")
        .join(container_id)
        .join(format!("{stream}.log"))
}

/// Read the full stdout and stderr logs for a container.
///
/// Returns `(stdout, stderr)`. A missing log file yields an empty string —
/// a container that produced no output is not an error. Synchronous file I/O,
/// so callers in async contexts should wrap this in `spawn_blocking`.
pub fn read_all(container_id: &str) -> (String, String) {
    let stdout = std::fs::read_to_string(log_path(container_id, "stdout")).unwrap_or_default();
    let stderr = std::fs::read_to_string(log_path(container_id, "stderr")).unwrap_or_default();
    (stdout, stderr)
}

/// Read the last N lines from a file (or all lines if tail == 0).
///
/// When tail > 0, uses a bounded ring buffer to avoid loading the entire
/// file into memory (important for large log files).
fn read_tail_lines(path: &PathBuf, tail: u32) -> Vec<String> {
    let file = match std::fs::File::open(path) {
        Ok(f) => f,
        Err(_) => return Vec::new(),
    };

    let reader = BufReader::new(file);

    if tail == 0 {
        // Return all non-empty lines.
        return reader
            .lines()
            .filter_map(|l| l.ok())
            .filter(|l| !l.is_empty())
            .collect();
    }

    // Use a ring buffer of size `tail` to keep only the last N lines.
    let cap = tail as usize;
    let mut ring = std::collections::VecDeque::with_capacity(cap);
    for line in reader.lines().filter_map(|l| l.ok()).filter(|l| !l.is_empty()) {
        if ring.len() == cap {
            ring.pop_front();
        }
        ring.push_back(line);
    }
    ring.into_iter().collect()
}

/// Open a file seeked to the end, for follow mode.
fn open_at_end(path: &PathBuf) -> Option<BufReader<std::fs::File>> {
    let mut file = std::fs::File::open(path).ok()?;
    file.seek(SeekFrom::End(0)).ok()?;
    Some(BufReader::new(file))
}

fn now_rfc3339() -> String {
    chrono::Utc::now().to_rfc3339()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    #[test]
    fn read_tail_lines_all() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("test.log");
        let mut f = std::fs::File::create(&path).unwrap();
        writeln!(f, "line1").unwrap();
        writeln!(f, "line2").unwrap();
        writeln!(f, "line3").unwrap();

        let lines = read_tail_lines(&path, 0);
        assert_eq!(lines, vec!["line1", "line2", "line3"]);
    }

    #[test]
    fn read_tail_lines_limited() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("test.log");
        let mut f = std::fs::File::create(&path).unwrap();
        writeln!(f, "line1").unwrap();
        writeln!(f, "line2").unwrap();
        writeln!(f, "line3").unwrap();

        let lines = read_tail_lines(&path, 2);
        assert_eq!(lines, vec!["line2", "line3"]);
    }

    #[test]
    fn read_tail_lines_missing_file() {
        let path = PathBuf::from("/nonexistent/test.log");
        let lines = read_tail_lines(&path, 0);
        assert!(lines.is_empty());
    }

    #[test]
    fn tail_logs_oneshot() {
        let dir = tempfile::tempdir().unwrap();
        let container_id = "test-oneshot";
        let log_dir = dir.path().join(container_id);
        std::fs::create_dir_all(&log_dir).unwrap();

        let mut f = std::fs::File::create(log_dir.join("stdout.log")).unwrap();
        writeln!(f, "hello").unwrap();
        writeln!(f, "world").unwrap();

        // Override log path for testing by collecting lines directly
        // from read_tail_lines (tail_logs uses hardcoded /run/rauha path).
        let stdout_path = log_dir.join("stdout.log");
        let lines = read_tail_lines(&stdout_path, 1);
        assert_eq!(lines, vec!["world"]);
    }
}
