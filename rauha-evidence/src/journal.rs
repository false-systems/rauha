//! Local Run journal storage. No lifecycle decisions or execution occur here.
//! The caller owns the parent directory and authenticates event origins/epochs.
//! A committed prefix is immutable; an uncommitted tail is preserved and blocks
//! appends. This storage head is not the full ownership-bearing RunHead.

use std::fs::{DirBuilder, File, OpenOptions};
use std::io::{BufRead, BufReader, Read, Write};
use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt};
use std::path::{Path, PathBuf};

use chrono::{DateTime, Utc};
use serde::{de::DeserializeOwned, Deserialize, Serialize};
use serde_json::Value;

/// Bounds each manifest, head and journal entry, including its newline.
pub const MAX_RECORD_BYTES: u64 = 1024 * 1024;

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error(transparent)]
    Io(#[from] std::io::Error),
    #[error(transparent)]
    Json(#[from] serde_json::Error),
    #[error("journal already has a writer")]
    Busy,
    #[error("invalid journal: {0}")]
    Invalid(&'static str),
    #[error("uncommitted journal bytes require explicit repair")]
    UncommittedTail,
    #[error("previous write failed; close and reopen to determine the committed head")]
    ReopenRequired,
}

pub type Result<T> = std::result::Result<T, Error>;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct JournalHead {
    pub manifest_sha256: String,
    pub sequence: u64,
    pub journal_root: String,
    pub journal_bytes: u64,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Entry {
    pub seq: u64,
    pub ts: DateTime<Utc>,
    pub kind: String,
    pub epoch: u64,
    pub prev: String,
    pub body: Value,
}

pub struct Journal {
    path: PathBuf,
    // Never unlink the lock file: another opener must lock the same inode.
    _lock: File,
    directory: File,
    log: File,
    manifest: Value,
    head: JournalHead,
    tail_bytes: u64,
    write_failed: bool,
}

impl Journal {
    /// Create a new private Run directory beneath an existing trusted parent.
    /// Incomplete creation is left intact and never mistaken for an empty Run.
    pub fn create(path: &Path, manifest: Value) -> Result<Self> {
        if !manifest.is_object() {
            return Err(Error::Invalid("manifest must be an object"));
        }
        let bytes = record(&manifest)?;
        let parent = path
            .parent()
            .filter(|p| !p.as_os_str().is_empty())
            .unwrap_or_else(|| Path::new("."));
        DirBuilder::new().mode(0o700).create(path)?;
        File::open(parent)?.sync_all()?;
        boundary("directory_created");
        let lock = lock(path)?;
        let directory = File::open(path)?;
        let mut file = new_file(&path.join("manifest.json"))?;
        file.write_all(&bytes)?;
        file.sync_all()?;
        boundary("manifest_synced");
        let log = new_file(&path.join("journal.jsonl"))?;
        log.sync_all()?;
        directory.sync_all()?;
        boundary("journal_created");
        let root = digest(&manifest)?;
        let head = JournalHead {
            manifest_sha256: root.clone(),
            sequence: 0,
            journal_root: root,
            journal_bytes: 0,
        };
        publish_head(path, &directory, &head)?;
        Ok(Self {
            path: path.into(),
            _lock: lock,
            directory,
            log,
            manifest,
            head,
            tail_bytes: 0,
            write_failed: false,
        })
    }

    /// Verify the manifest and every committed entry before returning a handle.
    /// Bytes beyond the head are not parsed, promoted, truncated or overwritten.
    pub fn open(path: &Path) -> Result<Self> {
        if !std::fs::symlink_metadata(path)?.is_dir() {
            return Err(Error::Invalid("Run path is not a directory"));
        }
        let lock = lock(path)?;
        let manifest: Value = read_record_file(&path.join("manifest.json"))?;
        if !manifest.is_object() {
            return Err(Error::Invalid("manifest must be an object"));
        }
        let head: JournalHead = read_record_file(&path.join("head"))?;
        if digest(&manifest)? != head.manifest_sha256 {
            return Err(Error::Invalid("manifest digest mismatch"));
        }
        let log = open_file(&path.join("journal.jsonl"), true)?;
        let tail_bytes = log
            .metadata()?
            .len()
            .checked_sub(head.journal_bytes)
            .ok_or(Error::Invalid("journal shorter than committed head"))?;
        let journal = Self {
            path: path.into(),
            _lock: lock,
            directory: File::open(path)?,
            log,
            manifest,
            head,
            tail_bytes,
            write_failed: false,
        };
        journal.scan(|_| {})?;
        Ok(journal)
    }

    pub fn head(&self) -> &JournalHead {
        &self.head
    }
    pub fn manifest(&self) -> &Value {
        &self.manifest
    }
    pub fn uncommitted_bytes(&self) -> u64 {
        self.tail_bytes
    }

    /// Stream the verified prefix, with memory bounded by one record.
    /// The visitor sees records only after a full verification pass succeeds.
    pub fn replay(&self, visitor: impl FnMut(&Entry)) -> Result<()> {
        self.scan(|_| {})?;
        self.scan(visitor)
    }

    /// Append, sync, replace head, sync directory. An error after writing starts
    /// poisons this handle: reopening is required even if rename had succeeded.
    pub fn append(&mut self, kind: &str, epoch: u64, body: Value) -> Result<Entry> {
        if self.write_failed {
            return Err(Error::ReopenRequired);
        }
        if self.tail_bytes != 0 {
            return Err(Error::UncommittedTail);
        }
        if !valid_kind(kind) || !body.is_object() {
            return Err(Error::Invalid(
                "event needs a namespaced kind and object body",
            ));
        }
        let entry = Entry {
            seq: self
                .head
                .sequence
                .checked_add(1)
                .ok_or(Error::Invalid("sequence overflow"))?,
            ts: Utc::now(),
            kind: kind.into(),
            epoch,
            prev: self.head.journal_root.clone(),
            body,
        };
        let bytes = record(&entry)?;
        let next = JournalHead {
            manifest_sha256: self.head.manifest_sha256.clone(),
            sequence: entry.seq,
            journal_root: digest(&entry)?,
            journal_bytes: self
                .head
                .journal_bytes
                .checked_add(bytes.len() as u64)
                .ok_or(Error::Invalid("journal size overflow"))?,
        };
        self.write_failed = true;
        boundary("before_append");
        // Splitting the write also exercises a genuine torn JSON line in tests.
        let split = bytes.len() / 2;
        self.log.write_all(&bytes[..split])?;
        boundary("partial_append");
        self.log.write_all(&bytes[split..])?;
        boundary("append_written");
        self.log.sync_all()?;
        boundary("append_synced");
        publish_head(&self.path, &self.directory, &next)?;
        self.head = next;
        self.write_failed = false;
        Ok(entry)
    }

    fn scan(&self, mut visitor: impl FnMut(&Entry)) -> Result<()> {
        let file = open_file(&self.path.join("journal.jsonl"), false)?;
        let mut reader = BufReader::new(file.take(self.head.journal_bytes));
        let mut seq = 0u64;
        let mut root = self.head.manifest_sha256.clone();
        let mut consumed = 0u64;
        loop {
            let bytes = read_line(&mut reader)?;
            if bytes.is_empty() {
                break;
            }
            consumed += bytes.len() as u64;
            let entry: Entry = parse_record(&bytes)?;
            seq = seq
                .checked_add(1)
                .ok_or(Error::Invalid("sequence overflow"))?;
            if entry.seq != seq || entry.prev != root {
                return Err(Error::Invalid("sequence or hash chain mismatch"));
            }
            if !valid_kind(&entry.kind) || !entry.body.is_object() {
                return Err(Error::Invalid("invalid event kind or body"));
            }
            root = digest(&entry)?;
            visitor(&entry);
        }
        if seq != self.head.sequence
            || root != self.head.journal_root
            || consumed != self.head.journal_bytes
        {
            return Err(Error::Invalid("committed head does not match journal"));
        }
        Ok(())
    }
}

fn valid_kind(kind: &str) -> bool {
    kind.contains('.')
        && kind.split('.').all(|part| {
            !part.is_empty()
                && part
                    .bytes()
                    .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'_')
        })
}

fn canonical<T: Serialize>(value: &T) -> Result<Value> {
    let mut value = serde_json::to_value(value)?;
    value.sort_all_objects();
    Ok(value)
}

fn digest<T: Serialize>(value: &T) -> Result<String> {
    Ok(crate::receipt::sha256_json(&canonical(value)?)?)
}

fn record<T: Serialize>(value: &T) -> Result<Vec<u8>> {
    let mut bytes = serde_json::to_vec(&canonical(value)?)?;
    bytes.push(b'\n');
    if bytes.len() as u64 > MAX_RECORD_BYTES {
        return Err(Error::Invalid("record exceeds 1 MiB"));
    }
    // A constructed Value can exceed the reader's nesting limit. Refuse it
    // before writing, otherwise a successful append could poison reopening.
    let _: Value = serde_json::from_slice(&bytes)?;
    Ok(bytes)
}

fn parse_record<T: DeserializeOwned + Serialize>(bytes: &[u8]) -> Result<T> {
    let value: T = serde_json::from_slice(bytes)?;
    // A single representation also rejects duplicate keys and ignored fields.
    if record(&value)? != bytes {
        return Err(Error::Invalid("record is not canonical JSON plus newline"));
    }
    Ok(value)
}

fn read_line(reader: &mut impl BufRead) -> Result<Vec<u8>> {
    let mut bytes = Vec::new();
    reader
        .take(MAX_RECORD_BYTES + 1)
        .read_until(b'\n', &mut bytes)?;
    if bytes.len() as u64 > MAX_RECORD_BYTES {
        return Err(Error::Invalid("record exceeds 1 MiB"));
    }
    Ok(bytes)
}

fn read_record_file<T: DeserializeOwned + Serialize>(path: &Path) -> Result<T> {
    let mut bytes = Vec::new();
    open_file(path, false)?
        .take(MAX_RECORD_BYTES + 1)
        .read_to_end(&mut bytes)?;
    if bytes.len() as u64 > MAX_RECORD_BYTES {
        return Err(Error::Invalid("record exceeds 1 MiB"));
    }
    parse_record(&bytes)
}

fn open_file(path: &Path, append: bool) -> Result<File> {
    let file = OpenOptions::new()
        .read(true)
        .append(append)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open(path)?;
    if !file.metadata()?.is_file() {
        return Err(Error::Invalid("not a regular file"));
    }
    Ok(file)
}

fn new_file(path: &Path) -> Result<File> {
    Ok(OpenOptions::new()
        .read(true)
        .append(true)
        .create_new(true)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW)
        .open(path)?)
}

fn lock(path: &Path) -> Result<File> {
    let lock = OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open(path.join(".writer.lock"))?;
    if !lock.metadata()?.is_file() {
        return Err(Error::Invalid("lock is not a regular file"));
    }
    lock.try_lock().map_err(|error| match error {
        std::fs::TryLockError::WouldBlock => Error::Busy,
        std::fs::TryLockError::Error(error) => Error::Io(error),
    })?;
    Ok(lock)
}

fn publish_head(path: &Path, directory: &File, head: &JournalHead) -> Result<()> {
    let mut file = new_file(&path.join("head.next"))?;
    boundary("head_created");
    file.write_all(&record(head)?)?;
    boundary("head_written");
    file.sync_all()?;
    boundary("head_synced");
    std::fs::rename(path.join("head.next"), path.join("head"))?;
    boundary("head_renamed");
    directory.sync_all()?;
    boundary("head_committed");
    Ok(())
}

#[cfg(not(test))]
fn boundary(_: &str) {}

#[cfg(test)]
fn boundary(stage: &str) {
    if std::env::var("RAUHA_JOURNAL_CRASH_AT").as_deref() == Ok(stage) {
        std::fs::write(
            std::env::var_os("RAUHA_JOURNAL_CRASH_MARKER").unwrap(),
            stage,
        )
        .unwrap();
        loop {
            std::thread::park();
        }
    }
}

#[cfg(test)]
mod tests;
