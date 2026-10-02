use super::*;

// These filters live only in disposable test subprocesses. They inject kernel
// errors into the actual file operations, without replacing the storage code.
pub(super) fn deny_syscall(syscall: libc::c_long, fd: Option<i32>, errno: i32) {
    let mut filter = vec![
        libc::sock_filter {
            code: (libc::BPF_LD | libc::BPF_W | libc::BPF_ABS) as u16,
            jt: 0,
            jf: 0,
            k: 0,
        },
        libc::sock_filter {
            code: (libc::BPF_JMP | libc::BPF_JEQ | libc::BPF_K) as u16,
            jt: 0,
            jf: if fd.is_some() { 3 } else { 1 },
            k: syscall as u32,
        },
    ];
    if let Some(fd) = fd {
        filter.extend([
            libc::sock_filter {
                code: (libc::BPF_LD | libc::BPF_W | libc::BPF_ABS) as u16,
                jt: 0,
                jf: 0,
                k: std::mem::offset_of!(libc::seccomp_data, args) as u32,
            },
            libc::sock_filter {
                code: (libc::BPF_JMP | libc::BPF_JEQ | libc::BPF_K) as u16,
                jt: 0,
                jf: 1,
                k: fd as u32,
            },
        ]);
    }
    filter.extend([
        libc::sock_filter {
            code: (libc::BPF_RET | libc::BPF_K) as u16,
            jt: 0,
            jf: 0,
            k: libc::SECCOMP_RET_ERRNO | errno as u32,
        },
        libc::sock_filter {
            code: (libc::BPF_RET | libc::BPF_K) as u16,
            jt: 0,
            jf: 0,
            k: libc::SECCOMP_RET_ALLOW,
        },
    ]);
    let program = libc::sock_fprog {
        len: filter.len() as u16,
        filter: filter.as_mut_ptr(),
    };
    // SAFETY: prctl copies the live program. The filter affects only this test
    // thread; the syscall argument comparison is for native Linux little endian.
    unsafe {
        assert_eq!(libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0), 0);
        assert_eq!(
            libc::prctl(libc::PR_SET_SECCOMP, libc::SECCOMP_MODE_FILTER, &program),
            0
        );
    }
}

// stage, syscall, target filename (empty means the Run directory)
fn fault(name: &str) -> (&'static str, libc::c_long, &'static str) {
    match name {
        "journal_write" => ("before_append", libc::SYS_write, "journal.jsonl"),
        "partial_write" => ("partial_append", libc::SYS_write, "journal.jsonl"),
        "journal_sync" => ("append_written", libc::SYS_fsync, "journal.jsonl"),
        "head_write" => ("head_created", libc::SYS_write, "head.next"),
        "head_sync" => ("head_written", libc::SYS_fsync, "head.next"),
        "head_rename" => ("head_synced", libc::SYS_renameat, ""),
        "directory_sync" => ("head_renamed", libc::SYS_fsync, ""),
        _ => panic!("unknown fault {name}"),
    }
}

pub(in crate::journal) fn at_boundary(stage: &str) {
    let Ok(name) = std::env::var("RAUHA_JOURNAL_FAULT") else {
        return;
    };
    let (target_stage, syscall, filename) = fault(&name);
    if stage != target_stage {
        return;
    }
    let path = PathBuf::from(std::env::var_os("RAUHA_JOURNAL_TEST_PATH").unwrap());
    let target = if filename.is_empty() {
        path
    } else {
        path.join(filename)
    };
    let fd = std::fs::read_dir("/proc/self/fd")
        .unwrap()
        .map(|entry| entry.unwrap().path())
        .find(|path| std::fs::read_link(path).ok().as_ref() == Some(&target))
        .unwrap();
    let fd = fd.file_name().unwrap().to_str().unwrap().parse().unwrap();
    let errno = std::env::var("RAUHA_JOURNAL_ERRNO")
        .unwrap()
        .parse()
        .unwrap();
    deny_syscall(syscall, Some(fd), errno);
}

#[test]
#[ignore = "subprocess helper installs irreversible I/O faults or file limits"]
fn io_fault_child() {
    let path = PathBuf::from(std::env::var_os("RAUHA_JOURNAL_TEST_PATH").unwrap());
    let mut journal = Journal::open(&path).unwrap();
    let before = journal.head().clone();
    let errno: i32 = std::env::var("RAUHA_JOURNAL_ERRNO")
        .unwrap()
        .parse()
        .unwrap();
    if std::env::var_os("RAUHA_JOURNAL_SHORT_WRITE").is_some() {
        // Linux writes the one remaining byte, then the retry fails EFBIG.
        let limit = libc::rlimit {
            rlim_cur: before.journal_bytes + 1,
            rlim_max: before.journal_bytes + 1,
        };
        unsafe {
            libc::signal(libc::SIGXFSZ, libc::SIG_IGN);
            assert_eq!(libc::setrlimit(libc::RLIMIT_FSIZE, &limit), 0);
        }
    }
    assert!(
        matches!(journal.append("run.waiting", 1, json!({})), Err(Error::Io(e)) if e.raw_os_error() == Some(errno))
    );
    assert_eq!(journal.head(), &before);
    assert!(matches!(
        journal.append("run.waiting", 1, json!({})),
        Err(Error::ReopenRequired)
    ));
}

#[test]
fn io_failures_never_acknowledge_or_overwrite_history() {
    for name in [
        "journal_write",
        "partial_write",
        "journal_sync",
        "head_write",
        "head_sync",
        "head_rename",
        "directory_sync",
        "short_write",
    ] {
        for errno in if name == "short_write" {
            vec![libc::EFBIG]
        } else {
            vec![libc::EIO, libc::ENOSPC]
        } {
            let tmp = TempDir::new().unwrap();
            let path = tmp.path().join("run");
            let original = seed(&path).head().clone();
            let prefix = std::fs::read(path.join("journal.jsonl")).unwrap();
            let mut command = Command::new(std::env::current_exe().unwrap());
            command
                .args([
                    "--exact",
                    "journal::tests::faults::io_fault_child",
                    "--ignored",
                ])
                .env("RAUHA_JOURNAL_TEST_PATH", &path)
                .env("RAUHA_JOURNAL_ERRNO", errno.to_string())
                .stdout(Stdio::null());
            if name == "short_write" {
                command.env("RAUHA_JOURNAL_SHORT_WRITE", "1");
            } else {
                command.env("RAUHA_JOURNAL_FAULT", name);
            }
            assert!(command.status().unwrap().success(), "{name}/{errno}");
            let bytes = std::fs::read(path.join("journal.jsonl")).unwrap();
            assert!(bytes.starts_with(&prefix));
            let staged = std::fs::read(path.join("head.next")).ok();
            for _ in 0..3 {
                let mut journal = Journal::open(&path).unwrap();
                let expected_seq = if name == "directory_sync" { 2 } else { 1 };
                assert_eq!(journal.head().sequence, expected_seq, "{name}");
                assert_eq!(entries(&journal).len() as u64, expected_seq);
                if name == "short_write" {
                    assert_eq!(journal.uncommitted_bytes(), 1);
                }
                if !matches!(name, "journal_write" | "directory_sync") {
                    assert_eq!(journal.head(), &original);
                    assert!(journal.uncommitted_bytes() > 0);
                    assert!(matches!(
                        journal.append("run.waiting", 1, json!({})),
                        Err(Error::UncommittedTail)
                    ));
                }
                assert_eq!(std::fs::read(path.join("journal.jsonl")).unwrap(), bytes);
                assert_eq!(std::fs::read(path.join("head.next")).ok(), staged);
            }
            if matches!(name, "journal_write" | "directory_sync") {
                Journal::open(&path)
                    .unwrap()
                    .append("run.waiting", 1, json!({}))
                    .unwrap();
            }
            println!("PASS I/O {name}/{errno}: no false success; committed prefix preserved");
        }
    }
}

#[test]
#[ignore = "subprocess helper contends for the real writer lock"]
fn contending_writer_child() {
    let path = PathBuf::from(std::env::var_os("RAUHA_JOURNAL_TEST_PATH").unwrap());
    let id: u64 = std::env::var("RAUHA_JOURNAL_WRITER")
        .unwrap()
        .parse()
        .unwrap();
    let deadline = Instant::now() + Duration::from_secs(30);
    let mut saw_busy = false;
    for n in 0..25 {
        loop {
            assert!(Instant::now() < deadline, "writer timed out");
            match Journal::open(&path) {
                Ok(mut journal) => {
                    assert!(saw_busy, "parent must hold lock until all writers contend");
                    journal
                        .append("run.waiting", 1, json!({"writer": id, "n": n}))
                        .unwrap();
                    break;
                }
                Err(Error::Busy) => {
                    if !saw_busy {
                        std::fs::write(path.with_extension(format!("ready-{id}")), b"busy")
                            .unwrap();
                        saw_busy = true;
                    }
                    std::thread::sleep(Duration::from_millis(1));
                }
                Err(e) => panic!("unexpected storage failure: {e}"),
            }
        }
    }
}

#[test]
fn competing_processes_commit_each_event_exactly_once() {
    let tmp = TempDir::new().unwrap();
    let path = tmp.path().join("run");
    let journal = seed(&path);
    let mut children: Vec<_> = (0..4)
        .map(|id| {
            KillOnDrop(
                Command::new(std::env::current_exe().unwrap())
                    .args([
                        "--exact",
                        "journal::tests::faults::contending_writer_child",
                        "--ignored",
                    ])
                    .env("RAUHA_JOURNAL_TEST_PATH", &path)
                    .env("RAUHA_JOURNAL_WRITER", id.to_string())
                    .stdout(Stdio::null())
                    .spawn()
                    .unwrap(),
            )
        })
        .collect();
    let deadline = Instant::now() + Duration::from_secs(20);
    while !(0..4).all(|id| path.with_extension(format!("ready-{id}")).exists()) {
        assert!(Instant::now() < deadline, "writers did not reach lock");
        for child in &mut children {
            assert!(child.0.try_wait().unwrap().is_none());
        }
        std::thread::sleep(Duration::from_millis(1));
    }
    drop(journal);
    for child in &mut children {
        assert!(child.0.wait().unwrap().success());
    }
    let journal = Journal::open(&path).unwrap();
    let committed = entries(&journal);
    assert_eq!(journal.head().sequence, 101);
    let actual: std::collections::BTreeSet<_> = committed[1..]
        .iter()
        .map(|entry| {
            (
                entry.body["writer"].as_u64().unwrap(),
                entry.body["n"].as_u64().unwrap(),
            )
        })
        .collect();
    let expected = (0..4)
        .flat_map(|id| (0..25).map(move |n| (id, n)))
        .collect();
    assert_eq!(actual, expected);
    assert_eq!(journal.uncommitted_bytes(), 0);
    println!("PASS contention: four processes, 100 unique commits, dense verified chain");
}

#[test]
fn closing_writer_releases_lock_even_while_a_fork_inherits_its_fd() {
    let tmp = TempDir::new().unwrap();
    let path = tmp.path().join("run");
    let journal = seed(&path);
    // SAFETY: the child executes only async-signal-safe libc calls; it never
    // accesses the inherited Rust handle. This models fork before exec closes
    // CLOEXEC descriptors in another thread's Command::spawn.
    let pid = unsafe { libc::fork() };
    assert!(pid >= 0);
    if pid == 0 {
        unsafe {
            loop {
                libc::pause();
            }
        }
    }
    drop(journal);
    let reopened = Journal::open(&path);
    // Reap before asserting so even the broken implementation leaves no child.
    unsafe {
        assert_eq!(libc::kill(pid, libc::SIGKILL), 0);
        assert_eq!(libc::waitpid(pid, std::ptr::null_mut(), 0), pid);
    }
    assert_eq!(reopened.unwrap().head().sequence, 1);
}

#[test]
fn repeated_crashes_and_recovery_preserve_one_history() {
    let tmp = TempDir::new().unwrap();
    let path = tmp.path().join("run");
    let mut expected = seed(&path).head().sequence;
    for _ in 0..8 {
        for stage in [
            "before_append",
            "head_renamed",
            "recovery_verified",
            "head_committed",
        ] {
            crash(&path, stage, false);
            if matches!(stage, "head_renamed" | "head_committed") {
                expected += 1;
            }
            let journal = Journal::open(&path).unwrap();
            assert_eq!(journal.head().sequence, expected);
            assert_eq!(entries(&journal).len() as u64, expected);
            assert_eq!(journal.uncommitted_bytes(), 0);
        }
    }
    crash(&path, "partial_append", false);
    let bytes = std::fs::read(path.join("journal.jsonl")).unwrap();
    for _ in 0..8 {
        crash(&path, "recovery_verified", false);
        let mut journal = Journal::open(&path).unwrap();
        assert_eq!(journal.head().sequence, expected);
        assert!(matches!(
            journal.append("run.waiting", 1, json!({})),
            Err(Error::UncommittedTail)
        ));
        assert_eq!(std::fs::read(path.join("journal.jsonl")).unwrap(), bytes);
    }
    println!("PASS repeated recovery: 41 SIGKILLs on one Run; tail never promoted");
}

#[test]
#[ignore = "manual power-cut probe: run only inside a disposable VM with an external head oracle"]
fn power_cut_child() {
    let path = PathBuf::from(std::env::var_os("RAUHA_JOURNAL_TEST_PATH").unwrap());
    let action = std::env::var("RAUHA_JOURNAL_POWER_ACTION").unwrap();
    match action.as_str() {
        "prepare" => {
            let journal = seed(&path);
            println!("ACK {}", serde_json::to_string(journal.head()).unwrap());
        }
        "append" => {
            let mut journal = Journal::open(&path).unwrap();
            journal
                .append("run.waiting", 1, json!({"power_cut": true}))
                .unwrap();
            println!("ACK {}", serde_json::to_string(journal.head()).unwrap());
            std::io::stdout().flush().unwrap();
            loop {
                std::thread::park();
            }
        }
        "verify" => {
            // The oracle is captured on the host before cutting the guest,
            // then copied back after restart. Never derive it from recovery.
            let oracle = std::env::var_os("RAUHA_JOURNAL_ORACLE").unwrap();
            let expected: JournalHead = read_record_file(File::open(oracle).unwrap()).unwrap();
            let mut journal = Journal::open(&path).unwrap();
            let events = entries(&journal);
            assert!(journal.head().sequence >= expected.sequence);
            assert!(journal.head().sequence <= expected.sequence + 1);
            assert_eq!(journal.head().manifest_sha256, expected.manifest_sha256);
            assert_eq!(
                digest(&events[expected.sequence as usize - 1]).unwrap(),
                expected.journal_root
            );
            let prefix_bytes: u64 = events[..expected.sequence as usize]
                .iter()
                .map(|entry| record(entry).unwrap().len() as u64)
                .sum();
            assert_eq!(prefix_bytes, expected.journal_bytes);
            if std::env::var_os("RAUHA_JOURNAL_REQUIRE_EXACT").is_some() {
                assert_eq!(journal.head(), &expected);
            }
            let tail = journal.uncommitted_bytes();
            if tail > 0 {
                let bytes = std::fs::read(path.join("journal.jsonl")).unwrap();
                assert!(matches!(
                    journal.append("run.waiting", 1, json!({})),
                    Err(Error::UncommittedTail)
                ));
                assert_eq!(std::fs::read(path.join("journal.jsonl")).unwrap(), bytes);
            }
            println!("PASS POWER CUT: acknowledged sequence {} preserved; recovered sequence {}; tail {tail}", expected.sequence, journal.head().sequence);
        }
        _ => panic!("unknown power probe action"),
    }
}
