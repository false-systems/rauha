use super::*;
use serde_json::json;
use std::os::unix::fs::{symlink, PermissionsExt};
use std::os::unix::process::ExitStatusExt;
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};
use tempfile::TempDir;

pub(super) mod faults;

fn seed(path: &Path) -> Journal {
    let mut journal = Journal::create(path, json!({"task": "test", "agent": ["true"]})).unwrap();
    journal
        .append("run.created", 1, json!({"task": "test"}))
        .unwrap();
    journal
}

fn entries(journal: &Journal) -> Vec<Entry> {
    let mut entries = Vec::new();
    journal.replay(|entry| entries.push(entry.clone())).unwrap();
    entries
}

#[test]
fn reopen_verifies_canonical_history_without_reordering_bodies() {
    let tmp = TempDir::new().unwrap();
    let path = tmp.path().join("run");
    let mut journal = seed(&path);
    let body = json!({"nested": {"z": 2, "a": 1}, "array": [3, 2, 1],
        "float": 0.8455124082255701, "negative_zero": -0.0, "unicode": "ä"});
    let entry = journal.append("future.event", 1, body.clone()).unwrap();
    assert_eq!(entry.prev, digest(&entries(&journal)[0]).unwrap());
    let head = journal.head().clone();
    drop(journal);
    let mut journal = Journal::open(&path).unwrap();
    assert_eq!(journal.head(), &head);
    assert_eq!(entries(&journal)[1].body, body);
    assert_eq!(journal.uncommitted_bytes(), 0);
    journal.append("run.waiting", 1, json!({})).unwrap();
    assert_eq!(entries(&journal).len(), 3);
    assert_eq!(
        std::fs::metadata(&path).unwrap().permissions().mode() & 0o777,
        0o700
    );
    for name in ["manifest.json", "journal.jsonl", "head", ".writer.lock"] {
        assert_eq!(
            std::fs::metadata(path.join(name))
                .unwrap()
                .permissions()
                .mode()
                & 0o777,
            0o600
        );
    }
}

#[test]
fn canonical_hash_sorts_nested_keys_and_rejects_ambiguous_records() {
    let a: Value = serde_json::from_str(r#"{"z":0,"a":{"y":2,"x":1}}"#).unwrap();
    let b: Value = serde_json::from_str(r#"{"a":{"x":1,"y":2},"z":0}"#).unwrap();
    assert_eq!(digest(&a).unwrap(), digest(&b).unwrap());
    assert_eq!(
        digest(&a).unwrap(),
        "sha256:6f6bf0a139e57b8a3e68d8ffadeb0444b132f8b40cfc1bd79b22d2dc730bb68e"
    );
    assert_eq!(record(&a).unwrap(), b"{\"a\":{\"x\":1,\"y\":2},\"z\":0}\n");
    assert!(parse_record::<Value>(b"{\"a\":1,\"a\":2}\n").is_err());
    assert!(parse_record::<Value>(b"{ \"a\": 1 }\n").is_err());
}

#[test]
fn corruption_in_committed_data_is_never_repaired_or_replayed() {
    for damage in [
        "manifest",
        "sequence",
        "prev",
        "body",
        "utf8",
        "truncated",
        "head_sequence",
        "head_root",
        "head_bytes",
        "missing_manifest",
        "oversized_head",
    ] {
        let tmp = TempDir::new().unwrap();
        let path = tmp.path().join("run");
        drop(seed(&path));
        match damage {
            "manifest" => std::fs::write(
                path.join("manifest.json"),
                record(&json!({"task": "changed"})).unwrap(),
            )
            .unwrap(),
            "sequence" | "prev" | "body" => {
                let mut entry: Entry =
                    read_record_file(File::open(path.join("journal.jsonl")).unwrap()).unwrap();
                match damage {
                    "sequence" => entry.seq = 2,
                    "prev" => entry.prev = "sha256:wrong".into(),
                    _ => entry.body = json!({"task": "evil"}),
                }
                std::fs::write(path.join("journal.jsonl"), record(&entry).unwrap()).unwrap();
            }
            "utf8" => std::fs::write(path.join("journal.jsonl"), [0xff, b'\n']).unwrap(),
            "truncated" => {
                OpenOptions::new()
                    .write(true)
                    .open(path.join("journal.jsonl"))
                    .unwrap()
                    .set_len(1)
                    .unwrap();
            }
            "missing_manifest" => std::fs::remove_file(path.join("manifest.json")).unwrap(),
            "oversized_head" => {
                std::fs::write(path.join("head"), vec![b' '; MAX_RECORD_BYTES as usize + 1])
                    .unwrap()
            }
            _ => {
                let mut head: JournalHead =
                    read_record_file(File::open(path.join("head")).unwrap()).unwrap();
                match damage {
                    "head_sequence" => head.sequence += 1,
                    "head_root" => head.journal_root = "sha256:wrong".into(),
                    _ => head.journal_bytes -= 1,
                }
                std::fs::write(path.join("head"), record(&head).unwrap()).unwrap();
            }
        }
        let before = std::fs::read(path.join("journal.jsonl")).unwrap();
        assert!(Journal::open(&path).is_err(), "accepted {damage}");
        assert_eq!(std::fs::read(path.join("journal.jsonl")).unwrap(), before);
    }
}

#[test]
fn tail_is_preserved_and_never_promoted_even_if_it_is_a_valid_entry() {
    for tail in [b"{broken".as_slice(), b"\xff\n", b"{\"seq\":2}\n"] {
        let tmp = TempDir::new().unwrap();
        let path = tmp.path().join("run");
        let original = seed(&path).head().clone();
        OpenOptions::new()
            .append(true)
            .open(path.join("journal.jsonl"))
            .unwrap()
            .write_all(tail)
            .unwrap();
        let mut journal = Journal::open(&path).unwrap();
        assert_eq!(journal.head(), &original);
        assert_eq!(journal.uncommitted_bytes(), tail.len() as u64);
        assert_eq!(entries(&journal).len(), 1);
        assert!(matches!(
            journal.append("run.waiting", 1, json!({})),
            Err(Error::UncommittedTail)
        ));
    }
    let tmp = TempDir::new().unwrap();
    let path = tmp.path().join("run");
    let mut journal = seed(&path);
    let old_head = record(journal.head()).unwrap();
    journal.append("run.waiting", 1, json!({})).unwrap();
    drop(journal);
    std::fs::write(path.join("head"), old_head).unwrap();
    let journal = Journal::open(&path).unwrap();
    assert_eq!(entries(&journal).len(), 1);
    assert!(journal.uncommitted_bytes() > 0);
}

#[test]
fn refuses_second_writer_symlinks_and_reuse_after_write_error() {
    let tmp = TempDir::new().unwrap();
    let path = tmp.path().join("run");
    let mut journal = seed(&path);
    assert!(matches!(Journal::open(&path), Err(Error::Busy)));
    assert!(Journal::create(&path, json!({})).is_err());
    let before = journal.head().clone();
    // An existing staging file must not be overwritten after an uncertain write.
    std::fs::write(path.join("head.next"), b"preserve").unwrap();
    assert!(journal.append("run.waiting", 1, json!({})).is_err());
    assert!(matches!(
        journal.append("run.waiting", 1, json!({})),
        Err(Error::ReopenRequired)
    ));
    assert_eq!(std::fs::read(path.join("head.next")).unwrap(), b"preserve");
    drop(journal);
    let journal = Journal::open(&path).unwrap();
    assert_eq!(journal.head(), &before);
    assert!(journal.uncommitted_bytes() > 0);
    drop(journal);
    std::fs::rename(path.join("manifest.json"), path.join("outside.json")).unwrap();
    symlink("outside.json", path.join("manifest.json")).unwrap();
    assert!(Journal::open(&path).is_err());
}

#[test]
fn invalid_and_oversized_events_leave_no_tail() {
    let tmp = TempDir::new().unwrap();
    let path = tmp.path().join("run");
    let mut journal = seed(&path);
    let head = journal.head().clone();
    assert!(journal.append("BAD", 1, json!({})).is_err());
    assert!(journal.append("run.waiting", 1, json!(null)).is_err());
    assert!(journal
        .append(
            "run.waiting",
            1,
            json!({"large": "x".repeat(MAX_RECORD_BYTES as usize)})
        )
        .is_err());
    let mut nested = json!({});
    for _ in 0..140 {
        nested = json!({"nested": nested});
    }
    assert!(journal.append("run.waiting", 1, nested).is_err());
    assert_eq!(journal.head(), &head);
    assert_eq!(
        std::fs::metadata(path.join("journal.jsonl")).unwrap().len(),
        head.journal_bytes
    );
    journal.append("run.waiting", 1, json!({})).unwrap();
}

#[test]
fn sequence_gaps_and_duplicates_are_corruption_even_with_valid_json() {
    for invalid_seq in [1, 3] {
        let tmp = TempDir::new().unwrap();
        let path = tmp.path().join("run");
        let mut journal = seed(&path);
        journal.append("run.waiting", 1, json!({})).unwrap();
        let mut committed = entries(&journal);
        drop(journal);
        committed[1].seq = invalid_seq;
        let bytes: Vec<_> = committed.iter().flat_map(|e| record(e).unwrap()).collect();
        std::fs::write(path.join("journal.jsonl"), &bytes).unwrap();
        let error = Journal::open(&path)
            .err()
            .expect("corrupt sequence was accepted");
        assert!(
            matches!(error, Error::Invalid("sequence or hash chain mismatch")),
            "{error:?}"
        );
        assert_eq!(std::fs::read(path.join("journal.jsonl")).unwrap(), bytes);
    }
}

#[test]
fn replay_checks_the_whole_prefix_before_calling_a_visitor() {
    let tmp = TempDir::new().unwrap();
    let path = tmp.path().join("run");
    let mut journal = seed(&path);
    journal
        .append("run.waiting", 1, json!({"reason": "pause"}))
        .unwrap();
    let original = std::fs::read_to_string(path.join("journal.jsonl")).unwrap();
    std::fs::write(
        path.join("journal.jsonl"),
        original.replace("pause", "error"),
    )
    .unwrap();
    let mut visited = 0;
    assert!(journal.replay(|_| visited += 1).is_err());
    assert_eq!(visited, 0);
}

struct KillOnDrop(Child);
impl Drop for KillOnDrop {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

#[test]
#[ignore = "subprocess helper invoked by crash tests"]
fn crash_child() {
    let path = PathBuf::from(std::env::var_os("RAUHA_JOURNAL_TEST_PATH").unwrap());
    if std::env::var("RAUHA_JOURNAL_TEST_MODE").as_deref() == Ok("create") {
        Journal::create(&path, json!({"task": "test"})).unwrap();
    } else {
        Journal::open(&path)
            .unwrap()
            .append("run.waiting", 1, json!({}))
            .unwrap();
    }
    panic!("crash boundary was not reached");
}

#[test]
#[ignore = "subprocess helper isolates process-wide cwd changes"]
fn directory_identity_child() {
    let tmp = TempDir::new().unwrap();
    let a = tmp.path().join("a");
    let b = tmp.path().join("b");
    std::fs::create_dir(&a).unwrap();
    std::fs::create_dir(&b).unwrap();
    std::env::set_current_dir(&a).unwrap();
    let mut journal = Journal::create(Path::new("run"), json!({})).unwrap();
    std::env::set_current_dir(&b).unwrap();
    let other = Journal::create(Path::new("run"), json!({})).unwrap();
    journal.append("run.created", 1, json!({})).unwrap();
    drop(journal);
    std::env::set_current_dir(&a).unwrap();
    let mut journal = Journal::open(Path::new("run")).unwrap();
    std::env::set_current_dir(&b).unwrap();
    let moved = a.join("moved");
    std::fs::rename(a.join("run"), &moved).unwrap();
    let replacement = Journal::create(&a.join("run"), json!({})).unwrap();
    journal.append("run.waiting", 1, json!({})).unwrap();
    assert_eq!(entries(&journal).len(), 2);
    assert!(matches!(Journal::open(&moved), Err(Error::Busy)));
    drop(journal);
    assert_eq!(Journal::open(&moved).unwrap().head().sequence, 2);
    for (path, untouched) in [(a.join("run"), replacement), (b.join("run"), other)] {
        let head = untouched.head().clone();
        drop(untouched);
        let reopened = Journal::open(&path).unwrap();
        assert_eq!(reopened.head(), &head);
        assert_eq!(reopened.uncommitted_bytes(), 0);
    }
    // Leave cwd before TempDir removes it.
    std::env::set_current_dir(tmp.path().parent().unwrap()).unwrap();
}

#[test]
fn directory_identity_survives_cwd_changes_and_rename() {
    assert!(Command::new(std::env::current_exe().unwrap())
        .args([
            "--exact",
            "journal::tests::directory_identity_child",
            "--ignored"
        ])
        .status()
        .unwrap()
        .success());
}

fn nested_value(depth: usize) -> Value {
    let mut value = Value::Null;
    for level in 0..depth {
        value = if level % 2 == 0 {
            Value::Array(vec![value])
        } else {
            let mut map = serde_json::Map::new();
            map.insert("x".into(), value);
            Value::Object(map)
        };
    }
    value
}

#[test]
#[ignore = "subprocess helper contains stack-overflow regressions"]
fn deep_input_child() {
    let tmp = TempDir::new().unwrap();
    let path = tmp.path().join("run");
    assert!(Journal::create(&path, nested_value(100_000)).is_err());
    assert!(!path.exists());
    let mut journal = seed(&path);
    let head = journal.head().clone();
    for kind in ["run.waiting", "BAD"] {
        assert!(journal.append(kind, 1, nested_value(100_000)).is_err());
    }
    assert_eq!(journal.head(), &head);
    assert_eq!(journal.log.metadata().unwrap().len(), head.journal_bytes);
    journal
        .append("run.waiting", 1, nested_value(MAX_INPUT_DEPTH))
        .unwrap();
    assert!(journal
        .append("run.waiting", 1, nested_value(MAX_INPUT_DEPTH + 2))
        .is_err());
    drop(journal);
    let journal = Journal::open(&path).unwrap();
    assert_eq!(entries(&journal).len(), 2);
    drop(journal);
    // Early refusal of an already damaged journal must also dispose safely.
    OpenOptions::new()
        .append(true)
        .open(path.join("journal.jsonl"))
        .unwrap()
        .write_all(b"tail")
        .unwrap();
    let mut journal = Journal::open(&path).unwrap();
    assert!(journal
        .append("run.waiting", 1, nested_value(100_000))
        .is_err());
    assert_eq!(journal.uncommitted_bytes(), 4);
    println!("PASS: 100,000-level owned input rejected and dropped safely; depth limit reopens");
}

#[test]
fn pathological_input_cannot_abort_the_writer() {
    assert!(Command::new(std::env::current_exe().unwrap())
        .args([
            "--exact",
            "journal::tests::deep_input_child",
            "--ignored",
            "--nocapture"
        ])
        .status()
        .unwrap()
        .success());
}

#[test]
#[ignore = "subprocess helper installs an irreversible fsync failure filter"]
fn recovery_sync_child() {
    let path = PathBuf::from(std::env::var_os("RAUHA_JOURNAL_TEST_PATH").unwrap());
    if std::env::var_os("RAUHA_JOURNAL_FAIL_SYNC").is_some() {
        faults::deny_syscall(libc::SYS_fsync, None, libc::EIO);
        assert!(
            matches!(Journal::open(&path), Err(Error::Io(e)) if e.raw_os_error() == Some(libc::EIO))
        );
        println!("PASS: recovery refused to expose a head when fsync returned EIO");
    } else {
        let journal = Journal::open(&path).unwrap();
        assert_eq!(journal.head().sequence, 2);
        assert_eq!(entries(&journal).len(), 2);
        println!("PASS: recovered renamed head verified and synced");
    }
}

#[test]
fn recovery_must_sync_before_exposing_a_renamed_head() {
    let tmp = TempDir::new().unwrap();
    let path = tmp.path().join("run");
    drop(seed(&path));
    crash(&path, "head_renamed", false);
    let before = std::fs::read(path.join("journal.jsonl")).unwrap();
    for fail in [true, false] {
        let mut command = Command::new(std::env::current_exe().unwrap());
        command
            .args([
                "--exact",
                "journal::tests::recovery_sync_child",
                "--ignored",
                "--nocapture",
            ])
            .env("RAUHA_JOURNAL_TEST_PATH", &path);
        if fail {
            command.env("RAUHA_JOURNAL_FAIL_SYNC", "1");
        }
        assert!(command.status().unwrap().success());
        assert_eq!(std::fs::read(path.join("journal.jsonl")).unwrap(), before);
    }
}

fn crash(path: &Path, stage: &str, create: bool) {
    let marker = path.with_extension("reached");
    if marker.exists() {
        std::fs::remove_file(&marker).unwrap();
    }
    let mut child = KillOnDrop(
        Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "journal::tests::crash_child",
                "--ignored",
                "--nocapture",
            ])
            .env("RAUHA_JOURNAL_TEST_PATH", path)
            .env(
                "RAUHA_JOURNAL_TEST_MODE",
                if create { "create" } else { "append" },
            )
            .env("RAUHA_JOURNAL_CRASH_AT", stage)
            .env("RAUHA_JOURNAL_CRASH_MARKER", &marker)
            .stdout(Stdio::null())
            .spawn()
            .unwrap(),
    );
    let deadline = Instant::now() + Duration::from_secs(20);
    while !marker.exists() {
        assert!(
            child.0.try_wait().unwrap().is_none(),
            "child exited before {stage}"
        );
        assert!(Instant::now() < deadline, "timed out at {stage}");
        std::thread::sleep(Duration::from_millis(10));
    }
    if !create {
        assert!(matches!(Journal::open(path), Err(Error::Busy)));
    }
    child.0.kill().unwrap();
    assert_eq!(child.0.wait().unwrap().signal(), Some(libc::SIGKILL));
}

#[test]
fn sigkill_at_every_append_boundary_recovers_only_the_committed_prefix() {
    for stage in [
        "before_append",
        "partial_append",
        "append_written",
        "append_synced",
        "head_created",
        "head_written",
        "head_synced",
        "head_renamed",
        "head_committed",
    ] {
        let tmp = TempDir::new().unwrap();
        let path = tmp.path().join("run");
        drop(seed(&path));
        crash(&path, stage, false);
        let bytes = std::fs::read(path.join("journal.jsonl")).unwrap();
        let mut journal = Journal::open(&path).unwrap();
        let published = matches!(stage, "head_renamed" | "head_committed");
        assert_eq!(
            journal.head().sequence,
            if published { 2 } else { 1 },
            "{stage}"
        );
        assert_eq!(entries(&journal).len() as u64, journal.head().sequence);
        assert_eq!(std::fs::read(path.join("journal.jsonl")).unwrap(), bytes);
        if published || stage == "before_append" {
            journal.append("run.waiting", 1, json!({})).unwrap();
        } else {
            assert!(journal.uncommitted_bytes() > 0, "{stage}");
            assert!(matches!(
                journal.append("run.waiting", 1, json!({})),
                Err(Error::UncommittedTail)
            ));
        }
        println!(
            "PASS SIGKILL {stage}: committed prefix verified, uncommitted bytes never promoted"
        );
    }
}

#[test]
fn interrupted_creation_is_never_reinitialized() {
    for stage in [
        "directory_created",
        "manifest_synced",
        "journal_created",
        "head_created",
        "head_written",
        "head_synced",
        "head_renamed",
        "head_committed",
    ] {
        let tmp = TempDir::new().unwrap();
        let path = tmp.path().join("run");
        crash(&path, stage, true);
        let recovered = Journal::open(&path);
        if matches!(stage, "head_renamed" | "head_committed") {
            assert_eq!(recovered.unwrap().head().sequence, 0);
        } else {
            assert!(recovered.is_err(), "{stage}");
        }
        assert!(Journal::create(&path, json!({"replacement": true})).is_err());
    }
}
