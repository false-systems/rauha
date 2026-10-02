//! Drain workload output continuously, keeping only a bounded prefix on disk.
use std::fs::{File, OpenOptions};
use std::io::{Read, Write};
use std::os::unix::fs::OpenOptionsExt;
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::sync::{
    atomic::{AtomicBool, Ordering},
    Arc,
};
use std::thread::JoinHandle;
use std::time::Duration;

pub fn max_bytes() -> anyhow::Result<usize> {
    let value = std::env::var("RAUHA_LOG_MAX_BYTES")
        .unwrap_or_else(|_| (1024 * 1024).to_string())
        .parse::<usize>()?;
    anyhow::ensure!(value > 0, "RAUHA_LOG_MAX_BYTES must be positive");
    Ok(value)
}

pub struct BoundedLog {
    pub(crate) file: File,
    marker: PathBuf,
    remaining: usize,
    incomplete: bool,
}

impl BoundedLog {
    pub fn open(path: &Path, limit: usize) -> std::io::Result<Self> {
        let marker = path.with_extension("incomplete");
        // Missing clean completion must remain visible even if the shim crashes.
        OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .mode(0o600)
            .open(&marker)?;
        let file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(path)?;
        Ok(Self {
            file,
            marker,
            remaining: limit,
            incomplete: false,
        })
    }

    pub fn write(&mut self, bytes: &[u8], whole_record: bool) -> std::io::Result<()> {
        let count = if whole_record && bytes.len() > self.remaining {
            self.remaining = 0;
            0
        } else {
            bytes.len().min(self.remaining)
        };
        if count < bytes.len() {
            self.incomplete = true;
        }
        if let Err(error) = self.file.write_all(&bytes[..count]) {
            self.incomplete = true;
            self.remaining = 0;
            return Err(error);
        }
        self.remaining -= count;
        Ok(())
    }

    pub fn finish(&mut self) -> std::io::Result<()> {
        self.file.sync_all()?;
        if !self.incomplete {
            std::fs::remove_file(&self.marker)?;
        }
        Ok(())
    }
}

pub struct Capture {
    stop: Arc<AtomicBool>,
    thread: Option<JoinHandle<()>>,
}

impl Capture {
    pub fn start(path: &Path, limit: usize) -> std::io::Result<(Self, UnixStream)> {
        let mut log = BoundedLog::open(path, limit)?;
        let (mut reader, writer) = UnixStream::pair()?;
        reader.set_read_timeout(Some(Duration::from_millis(200)))?;
        let stop = Arc::new(AtomicBool::new(false));
        let stopping = stop.clone();
        let thread = std::thread::Builder::new()
            .name("output-capture".into())
            .spawn(move || {
                let mut buffer = [0u8; 8192];
                let mut stop_at = None;
                loop {
                    if stopping.load(Ordering::Acquire) {
                        let deadline = stop_at.get_or_insert_with(|| {
                            std::time::Instant::now() + Duration::from_millis(200)
                        });
                        if std::time::Instant::now() >= *deadline {
                            return;
                        }
                    }
                    match reader.read(&mut buffer) {
                        Ok(0) => {
                            let _ = log.finish();
                            return;
                        }
                        Ok(count) => {
                            let _ = log.write(&buffer[..count], false);
                        }
                        Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
                        Err(e)
                            if matches!(
                                e.kind(),
                                std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
                            ) =>
                        {
                            if stopping.load(Ordering::Acquire) {
                                return;
                            }
                        }
                        Err(_) => return,
                    }
                }
            })?;
        Ok((
            Self {
                stop,
                thread: Some(thread),
            },
            writer,
        ))
    }
}

impl Drop for Capture {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Release);
        if let Some(thread) = self.thread.take() {
            let _ = thread.join();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn drains_overflow_and_marks_loss_but_preserves_complete_output() {
        let dir = std::env::temp_dir().join(format!("rauha-output-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir(&dir).unwrap();
        for (name, size) in [("short", 12), ("exact", 1024), ("long", 1024 * 1024)] {
            let path = dir.join(format!("{name}.log"));
            let (capture, mut writer) = Capture::start(&path, 1024).unwrap();
            writer.write_all(&vec![0xff; size]).unwrap();
            drop(writer);
            drop(capture);
            assert_eq!(
                std::fs::metadata(&path).unwrap().len(),
                size.min(1024) as u64
            );
            assert_eq!(path.with_extension("incomplete").exists(), size > 1024);
        }
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn abandoned_writer_cannot_hang_cleanup_or_claim_complete_capture() {
        let dir = std::env::temp_dir().join(format!("rauha-output-abort-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir(&dir).unwrap();
        let path = dir.join("stdout.log");
        let (capture, writer) = Capture::start(&path, 1024).unwrap();
        let start = std::time::Instant::now();
        drop(capture);
        assert!(start.elapsed() < Duration::from_secs(2));
        assert!(path.with_extension("incomplete").exists());
        drop(writer);
        std::fs::remove_dir_all(dir).unwrap();
    }
}
