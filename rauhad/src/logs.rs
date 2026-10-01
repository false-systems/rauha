//! Container log file tailing.
//!
//! Container stdout/stderr are written to log files by the shim at
//! `/run/rauha/containers/{id}/stdout.log` and `stderr.log`.
//!
//! This module provides:
//! - One-shot read: return existing log content
//! - Follow mode: poll for new lines every 200ms

use std::io::{BufRead, BufReader, Read, Seek, SeekFrom};
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};

/// A single log line with metadata.
#[derive(Debug, Clone)]
pub struct LogLine {
    pub source: String,
    pub line: String,
    pub timestamp: String,
}

#[derive(Default)]
pub struct CapturedLogs {
    pub stdout: String,
    pub stderr: String,
    pub issues: Vec<String>,
}

/// Read the last `tail` lines from a log file, then optionally follow.
///
/// Sends lines through the provided callback. Returns when the callback
/// returns `false` (client disconnected) or when `follow` is false and
/// all existing content has been read.
pub fn tail_logs(
    container_id: &str,
    run_dir: &str,
    follow: bool,
    tail: u32,
    cancelled: &AtomicBool,
    mut on_line: impl FnMut(LogLine) -> bool,
) {
    let stdout_path = log_path(run_dir, container_id, "stdout");
    let stderr_path = log_path(run_dir, container_id, "stderr");

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
            while let Some(line) = read_log_chunk(reader) {
                if cancelled.load(Ordering::Relaxed) {
                    return;
                }
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
            }
        } else {
            // File may not exist yet — try to open it.
            stdout_reader = open_at_end(&stdout_path);
        }

        if let Some(ref mut reader) = stderr_reader {
            while let Some(line) = read_log_chunk(reader) {
                if cancelled.load(Ordering::Relaxed) {
                    return;
                }
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
            }
        } else {
            stderr_reader = open_at_end(&stderr_path);
        }

        if !got_data {
            std::thread::sleep(std::time::Duration::from_millis(200));
        }
    }
}

fn log_path(run_dir: &str, container_id: &str, stream: &str) -> PathBuf {
    PathBuf::from(run_dir)
        .join("containers")
        .join(container_id)
        .join(format!("{stream}.log"))
}

/// Read stdout and stderr logs for a container, capped per stream.
///
/// Missing, partial and lossy captures are explicit issues. Synchronous file I/O,
/// so callers in async contexts should wrap this in `spawn_blocking`.
pub fn read_all_capped(
    container_id: &str,
    run_dir: &str,
    max_bytes_per_stream: usize,
) -> CapturedLogs {
    let mut issues = Vec::new();
    let stdout = read_text_capped(
        &log_path(run_dir, container_id, "stdout"),
        "stdout",
        max_bytes_per_stream,
        &mut issues,
    );
    let stderr = read_text_capped(
        &log_path(run_dir, container_id, "stderr"),
        "stderr",
        max_bytes_per_stream,
        &mut issues,
    );
    CapturedLogs {
        stdout,
        stderr,
        issues,
    }
}

fn read_text_capped(
    path: &PathBuf,
    stream: &str,
    max_bytes: usize,
    issues: &mut Vec<String>,
) -> String {
    if path.with_extension("incomplete").exists() {
        issues.push(format!("{stream}.storage_incomplete"));
    }
    let file = match std::fs::File::open(path) {
        Ok(file) => file,
        Err(_) => {
            issues.push(format!("{stream}.unavailable"));
            return String::new();
        }
    };

    let mut bytes = Vec::with_capacity(max_bytes.saturating_add(1));
    let mut limited = file.take(max_bytes.saturating_add(1) as u64);
    if limited.read_to_end(&mut bytes).is_err() {
        issues.push(format!("{stream}.read_failed"));
        return String::new();
    }

    let truncated = bytes.len() > max_bytes;
    if truncated {
        bytes.truncate(max_bytes);
    }

    let decoded = String::from_utf8_lossy(&bytes);
    if matches!(decoded, std::borrow::Cow::Owned(_)) {
        issues.push(format!("{stream}.invalid_utf8"));
    }
    let mut text = decoded.into_owned();
    if truncated || text.len() > max_bytes {
        issues.push(format!("{stream}.preview_truncated"));
        let marker = format!("\n[rauha: {stream} truncated after {max_bytes} bytes]\n");
        truncate_utf8(&mut text, max_bytes.saturating_sub(marker.len()));
        if marker.len() <= max_bytes {
            text.push_str(&marker);
        }
    }
    text
}

pub(crate) fn truncate_utf8(text: &mut String, max_bytes: usize) {
    let mut end = text.len().min(max_bytes);
    while !text.is_char_boundary(end) {
        end -= 1;
    }
    text.truncate(end);
}

/// Read the last N lines from a file (or all lines if tail == 0).
///
/// When tail > 0, uses a bounded ring buffer to avoid loading the entire
/// file into memory (important for large log files).
fn read_tail_lines(path: &PathBuf, tail: u32) -> Vec<String> {
    let mut file = match std::fs::File::open(path) {
        Ok(f) => f,
        Err(_) => return Vec::new(),
    };

    // Bound bytes as well as line count, including legacy unbounded files.
    const WINDOW: u64 = 1024 * 1024;
    let size = file.metadata().map(|m| m.len()).unwrap_or(0);
    if file
        .seek(SeekFrom::Start(size.saturating_sub(WINDOW)))
        .is_err()
    {
        return Vec::new();
    }
    let mut reader = BufReader::new(file.take(WINDOW));
    let mut ring = std::collections::VecDeque::new();
    while let Some(line) = read_log_chunk(&mut reader) {
        let line = line.trim_end_matches('\n').to_string();
        if line.is_empty() {
            continue;
        }
        if tail > 0 && ring.len() == tail as usize {
            ring.pop_front();
        }
        ring.push_back(line);
    }
    if size > WINDOW {
        ring.push_front("[rauha: log preview limited to last 1 MiB]".into());
    }
    ring.into_iter().collect()
}

/// Split oversized lines; invalid bytes remain visible as replacement characters.
fn read_log_chunk(reader: &mut impl BufRead) -> Option<String> {
    let mut bytes = Vec::new();
    match reader.take(64 * 1024).read_until(b'\n', &mut bytes) {
        Ok(0) | Err(_) => None,
        Ok(_) => Some(String::from_utf8_lossy(&bytes).into_owned()),
    }
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
    fn huge_binary_line_and_untrusted_tail_count_stay_bounded() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("stdout.log");
        std::fs::write(&path, vec![0xff; 2 * 1024 * 1024]).unwrap();
        let lines = read_tail_lines(&path, u32::MAX);
        assert!(lines[0].contains("limited"));
        assert!(lines.iter().all(|line| line.len() <= 3 * 64 * 1024));
        assert!(lines.iter().map(String::len).sum::<usize>() < 4 * 1024 * 1024);
    }

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
    fn read_text_capped_appends_truncation_marker() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("stdout.log");
        std::fs::write(&path, b"abcdef").unwrap();

        let mut issues = Vec::new();
        let text = read_text_capped(&path, "stdout", 3, &mut issues);
        assert!(text.len() <= 3);
        assert_eq!(issues, ["stdout.preview_truncated"]);
        std::fs::write(&path, [0xff; 1024]).unwrap();
        issues.clear();
        let text = read_text_capped(&path, "stdout", 1024, &mut issues);
        assert!(text.len() <= 1024);
        assert!(text.contains("truncated"));
        assert_eq!(issues, ["stdout.invalid_utf8", "stdout.preview_truncated"]);
    }

    #[test]
    fn read_text_capped_missing_file_is_empty() {
        let path = PathBuf::from("/nonexistent/test.log");
        let mut issues = Vec::new();
        assert_eq!(read_text_capped(&path, "stderr", 3, &mut issues), "");
        assert_eq!(issues, ["stderr.unavailable"]);
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
