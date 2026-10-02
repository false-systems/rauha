//! Local Run journal storage. No lifecycle decisions or execution occur here.
//! The caller owns the parent directory and authenticates event origins/epochs.
//! A committed prefix is immutable; an uncommitted tail is preserved and blocks
//! appends. This storage head is not the full ownership-bearing RunHead.

use std::ffi::CStr;
use std::fs::{DirBuilder, File, OpenOptions};
use std::io::{BufRead, BufReader, Read, Write};
use std::os::fd::{AsRawFd, FromRawFd};
use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt};
use std::path::Path;

use chrono::{DateTime, Utc};
use serde::{de::DeserializeOwned, Deserialize, Serialize};
use serde_json::Value;

/// Bounds each manifest, head and journal entry, including its newline.
pub const MAX_RECORD_BYTES: u64 = 1024 * 1024;
/// Leaves room for the entry envelope beneath serde_json's reader limit.
pub const MAX_INPUT_DEPTH: usize = 120;

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
    // Never unlink the lock file: another opener must lock the same inode.
    _lock: WriterLock,
    directory: File,
    log: File,
    manifest: Value,
    head: JournalHead,
    tail_bytes: u64,
    write_failed: bool,
}

struct WriterLock(File);

impl Drop for WriterLock {
    fn drop(&mut self) {
        // Closing alone leaves flock held by descriptors briefly inherited by
        // another thread's fork/exec. Release on every exit, including failed
        // open/create, before closing our descriptor.
        let _ = self.0.unlock();
    }
}

impl Journal {
    /// Create a new private Run directory beneath an existing trusted parent.
    /// Incomplete creation is left intact and never mistaken for an empty Run.
    pub fn create(path: &Path, manifest: Value) -> Result<Self> {
        let manifest = bounded_input(manifest)?;
        if !manifest.is_object() {
            return Err(Error::Invalid("manifest must be an object"));
        }
        let bytes = record(&manifest)?;
        let path = std::path::absolute(path)?;
        let parent = path
            .parent()
            .filter(|p| !p.as_os_str().is_empty())
            .unwrap_or_else(|| Path::new("."));
        DirBuilder::new().mode(0o700).create(&path)?;
        File::open(parent)?.sync_all()?;
        boundary("directory_created");
        let directory = open_directory(&path)?;
        let lock = lock(&directory)?;
        let mut file = new_file(&directory, c"manifest.json")?;
        file.write_all(&bytes)?;
        file.sync_all()?;
        boundary("manifest_synced");
        let log = new_file(&directory, c"journal.jsonl")?;
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
        publish_head(&directory, &head)?;
        Ok(Self {
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
        let directory = open_directory(path)?;
        let lock = lock(&directory)?;
        let manifest: Value = read_record_file(open_file(&directory, c"manifest.json", false)?)?;
        if !manifest.is_object() {
            return Err(Error::Invalid("manifest must be an object"));
        }
        let head: JournalHead = read_record_file(open_file(&directory, c"head", false)?)?;
        if digest(&manifest)? != head.manifest_sha256 {
            return Err(Error::Invalid("manifest digest mismatch"));
        }
        let log = open_file(&directory, c"journal.jsonl", true)?;
        let tail_bytes = log
            .metadata()?
            .len()
            .checked_sub(head.journal_bytes)
            .ok_or(Error::Invalid("journal shorter than committed head"))?;
        let journal = Self {
            _lock: lock,
            directory,
            log,
            manifest,
            head,
            tail_bytes,
            write_failed: false,
        };
        journal.scan(|_| {})?;
        boundary("recovery_verified");
        // A killed writer may have renamed a synced head without syncing its
        // directory. Make that verified head durable before exposing it.
        journal.directory.sync_all()?;
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
        let body = bounded_input(body)?;
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
        publish_head(&self.directory, &next)?;
        self.head = next;
        self.write_failed = false;
        Ok(entry)
    }

    fn scan(&self, mut visitor: impl FnMut(&Entry)) -> Result<()> {
        let file = open_file(&self.directory, c"journal.jsonl", false)?;
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

fn bounded_input(value: Value) -> Result<Value> {
    // Recursion is bounded before entering serde's recursive clone/sort/write.
    fn fits(value: &Value, remaining: usize) -> bool {
        match value {
            Value::Array(values) => remaining > 0 && values.iter().all(|v| fits(v, remaining - 1)),
            Value::Object(values) => {
                remaining > 0 && values.values().all(|v| fits(v, remaining - 1))
            }
            _ => true,
        }
    }
    if fits(&value, MAX_INPUT_DEPTH) {
        return Ok(value);
    }
    // Rejecting an owned Value must not recursively drop its unbounded tree.
    let mut pending = vec![value];
    while let Some(value) = pending.pop() {
        match value {
            Value::Array(values) => pending.extend(values),
            Value::Object(values) => pending.extend(values.into_values()),
            _ => {}
        }
    }
    Err(Error::Invalid("input exceeds maximum JSON depth"))
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

fn read_record_file<T: DeserializeOwned + Serialize>(file: File) -> Result<T> {
    let mut bytes = Vec::new();
    file.take(MAX_RECORD_BYTES + 1).read_to_end(&mut bytes)?;
    if bytes.len() as u64 > MAX_RECORD_BYTES {
        return Err(Error::Invalid("record exceeds 1 MiB"));
    }
    parse_record(&bytes)
}

fn open_directory(path: &Path) -> Result<File> {
    Ok(OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW)
        .open(path)?)
}

// All child names are fixed single components, resolved against this handle's
// directory even if the caller changes cwd or renames the Run directory.
fn open_at(directory: &File, name: &CStr, flags: libc::c_int) -> Result<File> {
    // SAFETY: directory is live, name is NUL-terminated, and mode is supplied
    // for O_CREAT. A successful descriptor is transferred exactly once to File.
    let fd = unsafe {
        libc::openat(
            directory.as_raw_fd(),
            name.as_ptr(),
            flags | libc::O_CLOEXEC | libc::O_NOFOLLOW | libc::O_NONBLOCK,
            0o600,
        )
    };
    if fd < 0 {
        return Err(std::io::Error::last_os_error().into());
    }
    let file = unsafe { File::from_raw_fd(fd) };
    if !file.metadata()?.is_file() {
        return Err(Error::Invalid("not a regular file"));
    }
    Ok(file)
}

fn open_file(directory: &File, name: &CStr, append: bool) -> Result<File> {
    open_at(
        directory,
        name,
        if append {
            libc::O_RDWR | libc::O_APPEND
        } else {
            libc::O_RDONLY
        },
    )
}

fn new_file(directory: &File, name: &CStr) -> Result<File> {
    open_at(
        directory,
        name,
        libc::O_RDWR | libc::O_APPEND | libc::O_CREAT | libc::O_EXCL,
    )
}

fn lock(directory: &File) -> Result<WriterLock> {
    let lock = open_at(directory, c".writer.lock", libc::O_RDWR | libc::O_CREAT)?;
    lock.try_lock().map_err(|error| match error {
        std::fs::TryLockError::WouldBlock => Error::Busy,
        std::fs::TryLockError::Error(error) => Error::Io(error),
    })?;
    Ok(WriterLock(lock))
}

fn publish_head(directory: &File, head: &JournalHead) -> Result<()> {
    let mut file = new_file(directory, c"head.next")?;
    boundary("head_created");
    file.write_all(&record(head)?)?;
    boundary("head_written");
    file.sync_all()?;
    boundary("head_synced");
    // SAFETY: both names are fixed C strings and both descriptors stay live.
    if unsafe {
        libc::renameat(
            directory.as_raw_fd(),
            c"head.next".as_ptr(),
            directory.as_raw_fd(),
            c"head".as_ptr(),
        )
    } != 0
    {
        return Err(std::io::Error::last_os_error().into());
    }
    boundary("head_renamed");
    directory.sync_all()?;
    boundary("head_committed");
    Ok(())
}

#[cfg(not(test))]
fn boundary(_: &str) {}

#[cfg(test)]
fn boundary(stage: &str) {
    tests::faults::at_boundary(stage);
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
