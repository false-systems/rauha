//! Privileged scenarios. Workload shell snippets exercise the container's shell;
//! orchestration, assertions, fixtures and cleanup belong to this Rust harness.
use std::fs;
use std::io::{Read, Write};
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Output, Stdio};
use std::thread;
use std::time::{Duration, Instant};

use anyhow::{bail, ensure, Context, Result};
use base64::Engine;
use serde_json::Value;

pub const SCENARIOS: &[&str] = &[
    "broker",
    "cgroup-lock",
    "container-lifecycle",
    "exec",
    "host-boundaries",
    "image-pull",
    "logs",
    "sandbox",
    "zone-isolation",
    "zone-networking",
];

pub fn checked(command: &mut Command) -> Result<String> {
    let output = command
        .output()
        .with_context(|| format!("launch {command:?}"))?;
    ensure!(
        output.status.success(),
        "{command:?}: {}\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    Ok(String::from_utf8(output.stdout)?.trim().to_owned())
}

pub fn wait_for(mut predicate: impl FnMut() -> Result<bool>) -> Result<()> {
    let start = Instant::now();
    while !predicate()? {
        ensure!(
            start.elapsed() < Duration::from_secs(30),
            "condition did not become true within 30 seconds"
        );
        thread::sleep(Duration::from_millis(100));
    }
    Ok(())
}

pub struct Process(pub Child);
impl Drop for Process {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

pub struct Harness {
    pub binary: PathBuf,
    pub image: String,
    pub zones: Vec<String>,
    pub temporary: tempfile::TempDir,
}

impl Harness {
    pub fn new() -> Result<Self> {
        let binary = std::env::var_os("RAUHA_BIN")
            .map(PathBuf::from)
            .unwrap_or_else(|| {
                super::configured_target_dir(
                    &super::project_root(),
                    super::project_root().join("target"),
                )
                .join("debug/rauha")
            });
        Ok(Self {
            binary,
            image: std::env::var("TEST_IMAGE").unwrap_or_else(|_| "alpine:latest".into()),
            zones: Vec::new(),
            temporary: tempfile::tempdir()?,
        })
    }
    pub fn command(&self, args: &[&str]) -> Command {
        let mut command = Command::new(&self.binary);
        command.args(args).stdin(Stdio::null());
        command
    }
    pub fn cli(&self, args: &[&str]) -> Result<String> {
        checked(&mut self.command(args))
    }
    pub fn output(&self, args: &[&str]) -> Result<Output> {
        Ok(self.command(args).output()?)
    }
    pub fn json(&self, args: &[&str]) -> Result<Value> {
        let mut command = self.command(&["--json"]);
        command.args(args);
        Ok(serde_json::from_str(&checked(&mut command)?)?)
    }
    pub fn pull(&self) -> Result<()> {
        self.cli(&["image", "pull", &self.image])?;
        Ok(())
    }
    pub fn zone(&mut self, label: &str, policy: &Path) -> Result<String> {
        let zone = format!("test-{label}-{}", std::process::id());
        self.zones.push(zone.clone());
        self.cli(&[
            "zone",
            "create",
            "--name",
            &zone,
            "--policy",
            policy.to_str().context("policy path is not UTF-8")?,
        ])?;
        Ok(zone)
    }
    pub fn audit_zone(&mut self, label: &str) -> Result<String> {
        self.zone(label, &policy("audit"))
    }
    pub fn run(&self, zone: &str, args: &[&str]) -> Result<String> {
        let mut all = vec!["run", "--zone", zone, &self.image];
        all.extend_from_slice(args);
        let id = self.cli(&all)?;
        ensure!(!id.is_empty(), "run did not return a container ID");
        Ok(id)
    }
    pub fn sandbox(&self, zone: &str, args: &[&str]) -> Result<Output> {
        let mut all = vec![
            "sandbox",
            "--name",
            zone,
            "--image",
            &self.image,
            "--timeout",
            "30",
            "--",
        ];
        all.extend_from_slice(args);
        self.output(&all)
    }
    pub fn shell(&self, zone: &str, script: &str, success: bool) -> Result<()> {
        let output = self.sandbox(zone, &["/bin/sh", "-c", script])?;
        ensure!(
            output.status.success() == success,
            "workload {script:?}: {}\n{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
        Ok(())
    }
    pub fn stop_delete(&self, id: &str) -> Result<()> {
        self.cli(&["stop", id])?;
        self.cli(&["delete", id, "--force"])?;
        Ok(())
    }
    pub fn delete_zone(&self, zone: &str) -> Result<()> {
        self.cli(&["zone", "delete", zone, "--force"])?;
        Ok(())
    }
}
impl Drop for Harness {
    fn drop(&mut self) {
        for zone in &self.zones {
            if let Err(error) = self.delete_zone(zone) {
                eprintln!("cleanup {zone}: {error:#}");
            }
        }
    }
}

pub fn policy(name: &str) -> PathBuf {
    std::env::var_os(format!("RAUHA_TEST_{}_POLICY", name.to_uppercase()))
        .map(PathBuf::from)
        .unwrap_or_else(|| {
            super::project_root()
                .join("policies")
                .join(format!("{name}.toml"))
        })
}
pub fn cgroup(zone: &str) -> PathBuf {
    PathBuf::from(format!("/sys/fs/cgroup/rauha.slice/zone-{zone}"))
}
pub fn pids(zone: &str) -> Result<Vec<u32>> {
    fn visit(path: &Path, found: &mut Vec<u32>) -> Result<()> {
        found.extend(
            fs::read_to_string(path.join("cgroup.procs"))?
                .split_whitespace()
                .map(str::parse)
                .collect::<std::result::Result<Vec<u32>, _>>()?,
        );
        for entry in fs::read_dir(path)? {
            let entry = entry?;
            if entry.file_type()?.is_dir() {
                visit(&entry.path(), found)?;
            }
        }
        Ok(())
    }
    let mut found = Vec::new();
    visit(&cgroup(zone), &mut found)?;
    found.sort_unstable();
    found.dedup();
    Ok(found)
}
pub fn workload_cgroup(zone: &str) -> Result<PathBuf> {
    let membership = fs::read_to_string(format!("/proc/{}/cgroup", pid(zone)?))?;
    let relative = membership
        .lines()
        .find_map(|s| s.strip_prefix("0::/"))
        .context("cgroup v2 membership missing")?;
    let path = Path::new("/sys/fs/cgroup").join(relative);
    ensure!(
        path.starts_with(cgroup(zone)),
        "workload cgroup is outside its zone"
    );
    Ok(path)
}
pub fn pid(zone: &str) -> Result<u32> {
    let mut result = None;
    wait_for(|| {
        result = pids(zone)?.first().copied();
        Ok(result.is_some())
    })?;
    result.context("missing workload PID")
}
pub fn process_start(pid: u32) -> Result<String> {
    let stat = fs::read_to_string(format!("/proc/{pid}/stat"))?;
    stat.rsplit_once(") ")
        .and_then(|(_, tail)| tail.split_whitespace().nth(19))
        .map(str::to_owned)
        .context("invalid proc stat")
}
fn namespace(path: impl AsRef<Path>) -> Result<(u64, u64)> {
    let metadata = fs::metadata(path)?;
    Ok((metadata.dev(), metadata.ino()))
}

pub fn run(name: &str) -> Result<()> {
    ensure!(
        SCENARIOS.contains(&name),
        "unknown scenario {name:?}; choose one of {SCENARIOS:?}"
    );
    ensure!(
        cfg!(target_os = "linux"),
        "integration scenarios require Linux"
    );
    let mut h = Harness::new()?;
    h.pull()?;
    match name {
        "image-pull" => image_pull(&h)?,
        "container-lifecycle" => lifecycle(&mut h)?,
        "logs" => logs(&mut h)?,
        "sandbox" => sandbox(&mut h)?,
        "broker" => broker(&mut h)?,
        "exec" => exec(&mut h)?,
        "host-boundaries" => boundaries(&mut h)?,
        "zone-isolation" => isolation(&mut h)?,
        "zone-networking" => networking(&mut h)?,
        "cgroup-lock" => cgroup_lock(&mut h)?,
        _ => bail!("unknown scenario {name:?}; choose one of {SCENARIOS:?}"),
    }
    println!("PASS: {name}");
    Ok(())
}

fn image_pull(h: &Harness) -> Result<()> {
    h.cli(&["image", "ls"])?;
    h.cli(&["image", "inspect", &h.image])?;
    let root = PathBuf::from(std::env::var("RAUHA_ROOT")?);
    ensure!(
        fs::read_dir(root.join("content/blobs/sha256"))?.count() >= 2,
        "config and layer blobs missing"
    );
    let references = root.join("content/references-v2");
    let before = fs::read_dir(&references)?.count();
    ensure!(before > 0, "manifest references missing");
    h.cli(&["image", "remove", &h.image])?;
    ensure!(
        fs::read_dir(references)?.count() < before,
        "image reference not removed"
    );
    ensure!(
        fs::read_dir(root.join("content/blobs/sha256"))?.count() >= 2,
        "removing a reference removed shared blobs"
    );
    Ok(())
}

fn lifecycle(h: &mut Harness) -> Result<()> {
    let zone = h.audit_zone("lifecycle")?;
    ensure!(
        h.cli(&["zone", "list"])?.contains(&zone),
        "zone missing from list"
    );
    let id = h.run(&zone, &["/bin/echo", "hello"])?;
    wait_for(|| Ok(h.cli(&["logs", &id])?.contains("hello")))?;
    ensure!(
        h.cli(&["ps", "--zone", &zone])?.contains(&id),
        "container missing from ps"
    );
    ensure!(
        Path::new(&format!("/run/rauha/shim-{zone}.sock")).exists(),
        "shim socket missing"
    );
    h.stop_delete(&id)?;
    let id = h.run(&zone, &["/bin/sleep", "120"])?;
    let pid = self::pid(&zone)?;
    let start = process_start(pid)?;
    h.cli(&["stop", &id])?;
    ensure!(
        process_start(pid).ok().as_ref() != Some(&start),
        "stop left original workload alive"
    );
    let ps = h.cli(&["ps", "--zone", &zone])?;
    ensure!(
        !ps.lines()
            .any(|line| line.contains(&id) && line.to_lowercase().contains("running")),
        "stopped workload still reported running"
    );
    h.cli(&["delete", &id, "--force"])?;
    h.run(&zone, &["/bin/sleep", "120"])?;
    let pid = self::pid(&zone)?;
    let start = process_start(pid)?;
    h.delete_zone(&zone)?;
    h.zones.retain(|z| z != &zone);
    ensure!(
        !h.cli(&["zone", "list"])?.contains(&zone),
        "zone metadata survived deletion"
    );
    ensure!(!cgroup(&zone).exists(), "cgroup survived deletion");
    ensure!(
        process_start(pid).ok().as_ref() != Some(&start),
        "force delete left workload alive"
    );
    Ok(())
}

fn logs(h: &mut Harness) -> Result<()> {
    let zone = h.audit_zone("logs")?;
    let id = h.run(
        &zone,
        &[
            "/bin/sh",
            "-c",
            "echo hello-from-logs; echo line2; echo line3",
        ],
    )?;
    wait_for(|| Ok(h.cli(&["logs", &id])?.contains("line3")))?;
    ensure!(
        h.cli(&["logs", &id])?.contains("hello-from-logs"),
        "one-shot logs missing first line"
    );
    let tail = h.cli(&["logs", &id, "--tail", "1"])?;
    ensure!(
        tail.contains("line3") && !tail.contains("hello-from-logs"),
        "tail did not select final line: {tail}"
    );
    h.stop_delete(&id)
}

fn sandbox(h: &mut Harness) -> Result<()> {
    ensure!(
        h.cli(&[
            "sandbox",
            "--audit",
            "--image",
            &h.image,
            "--",
            "/bin/echo",
            "hello-from-sandbox"
        ])?
        .contains("hello-from-sandbox"),
        "stdout missing"
    );
    h.cli(&["sandbox", "--audit", "--image", &h.image, "--", "/bin/true"])?;
    ensure!(
        h.output(&["sandbox", "--audit", "--image", &h.image, "--", "/bin/sh", "-c", "exit 3"])?
            .status
            .code()
            == Some(3),
        "task exit code not mirrored"
    );
    let result = h.json(&[
        "sandbox",
        "--audit",
        "--image",
        &h.image,
        "--",
        "/bin/echo",
        "hi",
    ])?;
    let raw = result.to_string();
    for expected in [
        "\"status\":\"succeeded\"",
        "\"exit_code\":0",
        "\"admission\":\"audit\"",
        "rauha.execution-receipt.v1",
        "\"digest_verified\":false",
    ] {
        ensure!(
            raw.contains(expected),
            "receipt contract missing {expected}: {raw}"
        );
    }
    let inspection = h.json(&["image", "inspect", &h.image])?;
    let digest = inspection["digest"]
        .as_str()
        .context("image digest missing")?;
    let name = h.image.split('@').next().unwrap_or(&h.image);
    let name = match name.rsplit_once(':') {
        Some((base, suffix)) if !suffix.contains('/') => base,
        _ => name,
    };
    let pinned = format!("{name}@{digest}");
    h.cli(&["image", "pull", &pinned])?;
    let receipt = h.json(&["sandbox", "--audit", "--image", &pinned, "--", "/bin/true"])?;
    let raw = receipt.to_string();
    ensure!(
        raw.contains("\"digest_verified\":true") && raw.contains(digest),
        "pinned image not attested: {raw}"
    );
    let dsse = &receipt["receipt_dsse"];
    ensure!(
        dsse["payloadType"] == "application/vnd.in-toto+json",
        "wrong DSSE type"
    );
    let statement: Value = serde_json::from_slice(
        &base64::engine::general_purpose::STANDARD
            .decode(dsse["payload"].as_str().context("missing DSSE payload")?)?,
    )?;
    ensure!(
        statement["predicateType"] == "https://rauha.dev/execution/v0",
        "wrong predicate"
    );
    ensure!(
        statement["subject"][0]["digest"]["sha256"] == digest.trim_start_matches("sha256:"),
        "DSSE manifest subject mismatch"
    );
    let key = PathBuf::from(std::env::var("RAUHA_ROOT")?).join("metadata/receipt.ed25519.pub");
    for (name, value) in [("receipt.json", &receipt), ("dsse.json", dsse)] {
        let file = h.temporary.path().join(name);
        fs::write(&file, serde_json::to_vec(value)?)?;
        h.cli(&[
            "receipt",
            file.to_str().unwrap(),
            "--public-key",
            key.to_str().unwrap(),
        ])?;
    }
    let zone = h.audit_zone("sandbox")?;
    ensure!(
        h.sandbox(&zone, &["/bin/echo", "named"])?.status.success(),
        "named task failed"
    );
    ensure!(
        h.cli(&["zone", "list"])?.contains(&zone),
        "task deleted its named zone"
    );
    Ok(())
}

fn broker(h: &mut Harness) -> Result<()> {
    let zone = h.zone("broker", &policy("broker"))?;
    for args in [
        vec!["/bin/cat", "/etc/hostname"],
        vec!["/bin/sh", "-c", "cd /etc && cat hostname"],
        vec!["/bin/ls", "/usr"],
    ] {
        let output = h.sandbox(&zone, &args)?;
        ensure!(
            output.status.success() && !output.stdout.is_empty(),
            "broker failed read or directory open"
        );
    }
    h.shell(&zone, "echo brokered > /tmp/broker-write-test", false)?;
    let result = h.json(&[
        "sandbox",
        "--name",
        &zone,
        "--image",
        &h.image,
        "--",
        "/bin/cat",
        "/etc/hostname",
    ])?;
    let raw = result.to_string();
    ensure!(
        raw.contains("seccomp_notify") && raw.contains("zone.syscall.brokered.granted"),
        "broker decisions missing from result"
    );
    for run_container in [false, true] {
        let path = h.temporary.path().join("events.jsonl");
        let mut command = h.command(&["events", "--json"]);
        command
            .stdout(fs::File::create(&path)?)
            .stderr(Stdio::null());
        let _events = Process(command.spawn()?);
        thread::sleep(Duration::from_secs(1));
        if run_container {
            h.run(&zone, &["/bin/cat", "/etc/hostname"])?;
        } else {
            ensure!(
                h.sandbox(&zone, &["/bin/cat", "/etc/hostname"])?
                    .status
                    .success(),
                "broker workload failed"
            );
        }
        wait_for(|| Ok(fs::read_to_string(&path)?.contains("zone.syscall.brokered")))?;
    }
    Ok(())
}

fn exec(h: &mut Harness) -> Result<()> {
    let zone = h.audit_zone("exec")?;
    let id = h.run(&zone, &["/bin/sleep", "60"])?;
    let original = pid(&zone)?;
    ensure!(
        h.cli(&["exec", "-it", &id, "/bin/echo", "exec-test"])?
            .contains("exec-test"),
        "exec stdout missing"
    );
    let exited = h.output(&[
        "exec",
        "-it",
        &id,
        "/bin/sh",
        "-c",
        "printf exec-exit-seven; exit 7",
    ])?;
    ensure!(
        exited.status.code() == Some(7)
            && String::from_utf8_lossy(&exited.stdout).contains("exec-exit-seven"),
        "exec did not preserve output and exit 7: status={} stdout={} stderr={}",
        exited.status,
        String::from_utf8_lossy(&exited.stdout),
        String::from_utf8_lossy(&exited.stderr)
    );
    let before = pids(&zone)?;
    let _client = Process(
        h.command(&["exec", "-it", &id, "/bin/sleep", "10"])
            .stdout(Stdio::null())
            .spawn()?,
    );
    let mut exec_pid = None;
    wait_for(|| {
        exec_pid = pids(&zone)?.into_iter().find(|pid| !before.contains(pid));
        Ok(exec_pid.is_some())
    })?;
    for ns in ["net", "uts", "ipc", "mnt", "pid"] {
        ensure!(
            namespace(format!("/proc/{original}/ns/{ns}"))?
                == namespace(format!("/proc/{}/ns/{ns}", exec_pid.unwrap()))?,
            "exec did not join {ns} namespace"
        );
    }
    h.stop_delete(&id)
}

fn isolation(h: &mut Harness) -> Result<()> {
    let zone = h.audit_zone("isolation")?;
    let output = h.output(&["--json", "zone", "verify", &zone])?;
    let value: Value = serde_json::from_slice(&output.stdout)?;
    for check in value["checks"].as_array().context("checks missing")? {
        ensure!(
            check["passed"] == true
                || (check["name"].as_str().unwrap_or("").starts_with("ebpf:")
                    && check["detail"]
                        .as_str()
                        .unwrap_or("")
                        .contains("kernel does not expose this required BPF-LSM hook")),
            "unexpected verification failure: {check}"
        );
    }
    ensure!(cgroup(&zone).is_dir(), "cgroup missing");
    ensure!(
        Path::new(&format!("/var/run/netns/rauha-{zone}")).exists(),
        "netns missing"
    );
    let container = h.run(&zone, &["/bin/sleep", "120"])?;
    pid(&zone)?;
    let other = h.audit_zone("file-owner")?;
    let other_container = h.run(&other, &["/bin/sleep", "120"])?;
    let root = PathBuf::from(std::env::var("RAUHA_ROOT")?);
    let image_file = |zone: &str, container: &str| {
        root.join("zones")
            .join(zone)
            .join("containers")
            .join(container)
            .join("merged/etc/os-release")
    };
    let own = image_file(&zone, &container);
    let foreign = image_file(&other, &other_container);
    ensure!(
        own.is_file() && foreign.is_file(),
        "image must supply /etc/os-release for inode enforcement probe"
    );
    checked(
        Command::new(std::env::current_exe()?)
            .arg("file-open-helper")
            .arg(workload_cgroup(&zone)?)
            .arg(&own)
            .arg(&foreign),
    )?;
    h.delete_zone(&zone)?;
    h.zones.retain(|z| z != &zone);
    ensure!(!cgroup(&zone).exists(), "cgroup survived deletion");
    Ok(())
}

pub fn file_open_helper(cgroup: &Path, own: &Path, foreign: &Path) -> Result<()> {
    // Keep host mount visibility so only the enrolled BPF file boundary can deny this read.
    fs::write(cgroup.join("cgroup.procs"), std::process::id().to_string())?;
    fs::read(own).context("same-zone tracked file must remain readable")?;
    let error = fs::read(foreign).expect_err("cross-zone tracked file was readable");
    ensure!(
        error.raw_os_error() == Some(libc::EPERM),
        "cross-zone read failed for the wrong reason: {error}"
    );
    println!("PASS: actual registered overlay file allowed locally and denied across zones");
    Ok(())
}

fn cgroup_lock(h: &mut Harness) -> Result<()> {
    let a = format!("test-cglock-a-{}", std::process::id());
    h.zones.push(a.clone());
    let admission = h.output(&["zone", "create", "--name", &a])?;
    if !admission.status.success() {
        ensure!(
            String::from_utf8_lossy(&admission.stderr).contains("lsm.cgroup_attach_task"),
            "strict admission failed unexpectedly: {}",
            String::from_utf8_lossy(&admission.stderr)
        );
        h.zones.clear();
        println!("PASS: unavailable cgroup_attach_task hook rejected strict admission");
        return Ok(());
    }
    let b = format!("test-cglock-b-{}", std::process::id());
    h.zones.push(b.clone());
    h.cli(&["zone", "create", "--name", &b])?;
    h.run(&a, &["/bin/sleep", "30"])?;
    let source_cgroup = workload_cgroup(&a)?;
    let mut helper = Process(
        Command::new(std::env::current_exe()?)
            .arg("cgroup-helper")
            .arg(cgroup(&b).join("cgroup.procs"))
            .stdin(Stdio::piped())
            .spawn()?,
    );
    fs::write(
        source_cgroup.join("cgroup.procs"),
        helper.0.id().to_string(),
    )?;
    helper
        .0
        .stdin
        .take()
        .context("helper stdin")?
        .write_all(b"go")?;
    ensure!(
        helper.0.wait()?.success(),
        "cross-zone cgroup move was not denied"
    );
    Ok(())
}
pub fn cgroup_helper(target: &Path) -> Result<()> {
    let mut signal = [0; 2];
    std::io::stdin().read_exact(&mut signal)?;
    let result = fs::write(target, std::process::id().to_string());
    ensure!(
        matches!(
            result.as_ref().err().and_then(std::io::Error::raw_os_error),
            Some(libc::EPERM | libc::EACCES)
        ),
        "cross-zone write must fail with permission denial: {result:?}"
    );
    ensure!(
        !fs::read_to_string(target)?
            .lines()
            .any(|s| s == std::process::id().to_string()),
        "helper entered target cgroup"
    );
    Ok(())
}

fn boundaries(h: &mut Harness) -> Result<()> {
    let full = format!("test-full-strict-{}", std::process::id());
    h.zones.push(full.clone());
    let output = h.output(&[
        "zone",
        "create",
        "--name",
        &full,
        "--policy",
        policy("strict").to_str().unwrap(),
    ])?;
    ensure!(
        !output.status.success()
            && String::from_utf8_lossy(&output.stderr)
                .contains("strict policy requests unsupported or unavailable Linux controls"),
        "unsupported strict controls must reject admission"
    );
    h.zones.retain(|z| z != &full);
    let baseline = "[zone]\nname = \"host-boundaries\"\ntype = \"non-global\"\n[admission]\nmode = \"strict\"\n[capabilities]\nallowed = []\n[resources]\ncpu_shares = 512\nmemory_limit = \"1Gi\"\nio_weight = 50\npids_max = 128\n[network]\nmode = \"isolated\"\nallowed_zones = []\nallowed_egress = []\nallowed_ingress = []\n";
    let file = h.temporary.path().join("baseline.toml");
    fs::write(&file, baseline)?;
    let zone = match h.zone("boundaries", &file) {
        Ok(zone) => zone,
        Err(error) if error.to_string().contains("lsm.") => {
            fs::write(
                &file,
                baseline.replace("mode = \"strict\"", "mode = \"audit\""),
            )?;
            h.zones.pop();
            h.zone("boundaries", &file)?
        }
        Err(error) => return Err(error),
    };
    let hostname = fs::read_to_string("/proc/sys/kernel/hostname")?;
    let baseline_container = h.run(&zone, &["/bin/sleep", "120"])?;
    let pid = pid(&zone)?;
    ensure!(
        fs::read_to_string("/proc/sys/kernel/hostname")? == hostname,
        "workload changed host hostname"
    );
    for ns in ["net", "uts", "pid"] {
        ensure!(
            namespace(format!("/proc/{pid}/ns/{ns}"))? != namespace(format!("/proc/self/ns/{ns}"))?,
            "workload shares host {ns} namespace"
        );
    }
    ensure!(
        namespace(format!("/proc/{pid}/ns/net"))?
            == namespace(format!("/var/run/netns/rauha-{zone}"))?,
        "workload not in zone network namespace"
    );
    let status = fs::read_to_string(format!("/proc/{pid}/status"))?;
    ensure!(
        status
            .lines()
            .any(|s| s.split_whitespace().collect::<Vec<_>>() == ["CapEff:", "0000000000000000"]),
        "effective capabilities not empty"
    );
    ensure!(
        status
            .lines()
            .any(|s| s.split_whitespace().collect::<Vec<_>>() == ["NoNewPrivs:", "1"]),
        "NoNewPrivs missing"
    );
    h.shell(&zone, "touch /rauha-write-probe", false)?;
    for script in [
        "test ! -e /run/rauha-zone.procs",
        "test ! -e /sys/fs/cgroup/rauha.slice && ! grep -q ' cgroup2 ' /proc/self/mounts",
        "test \"$$\" -eq 1 && test \"$(cat /proc/1/comm)\" = sh",
        "i=0; while [ \"$i\" -lt 20 ]; do /bin/sh -c 'sleep 0.01 &' ; i=$((i + 1)); done; sleep 1; ! grep -l '^State:.*Z' /proc/[0-9]*/status >/dev/null 2>&1",
    ] { h.shell(&zone, script, true)?; }
    ensure!(
        h.cli(&[
            "exec",
            "-it",
            &baseline_container,
            "/bin/sh",
            "-c",
            "kill -0 $$ && printf baseline-kill-allowed"
        ])?
        .contains("baseline-kill-allowed"),
        "baseline native exec could not probe its own PID"
    );
    let hardened = h.temporary.path().join("hardened.toml");
    let hardened_policy = fs::read_to_string(policy("strict"))?;
    ensure!(
        hardened_policy.contains("deny = ["),
        "strict syscall deny list missing"
    );
    fs::write(
        &hardened,
        hardened_policy
            .replace("mode = \"strict\"", "mode = \"audit\"")
            .replacen("deny = [", "deny = [\"kill\", ", 1),
    )?;
    let hard = h.zone("hardened", &hardened)?;
    h.shell(&hard, "touch /tmp/allowed && ! touch /etc/denied && test -c /dev/null && test -c /dev/zero && test -c /dev/urandom && test ! -e /dev/kmsg && grep -Eq '^Seccomp:[[:space:]]+2$' /proc/self/status", true)?;
    let id = h.run(&hard, &["/bin/sleep", "30"])?;
    let exec_output = h.output(&["exec", "-it", &id, "/bin/sh", "-c",
        "grep -E '^(Seccomp|CapEff|NoNewPrivs):' /proc/self/status; kill -0 $$; kill_status=$?; printf 'kill_status=%s\\n' \"$kill_status\"; grep -Eq '^Seccomp:[[:space:]]+2$' /proc/self/status && grep -Eq '^CapEff:[[:space:]]+0000000000000000$' /proc/self/status && grep -Eq '^NoNewPrivs:[[:space:]]+1$' /proc/self/status && test \"$kill_status\" -ne 0 && printf hardened-exec-filtered"])?;
    let exec_boundary = String::from_utf8_lossy(&exec_output.stdout);
    ensure!(
        exec_boundary.contains("hardened-exec-filtered"),
        "native exec lost seccomp, capabilities, NoNewPrivs, or the custom kill denial: {exec_boundary}; stderr={}", String::from_utf8_lossy(&exec_output.stderr)
    );
    h.stop_delete(&id)?;
    let mut sentinel = Process(Command::new("sleep").arg("120").spawn()?);
    h.run(&zone, &["/bin/kill", "-TERM", &sentinel.0.id().to_string()])?;
    thread::sleep(Duration::from_secs(1));
    ensure!(
        sentinel.0.try_wait()?.is_none(),
        "workload killed host sentinel"
    );
    Ok(())
}

fn networking(h: &mut Harness) -> Result<()> {
    let a = format!("test-net-a-{}", std::process::id());
    let b = format!("test-net-b-{}", std::process::id());
    let prefix = "[zone]\nname = \"placeholder\"\ntype = \"non-global\"\n[admission]\nmode = \"audit\"\n[capabilities]\nallowed = [\"CAP_NET_RAW\"]\n[network]\nmode = \"bridged\"\n";
    let allowed = h.temporary.path().join("network.toml");
    fs::write(
        &allowed,
        format!("{prefix}allowed_zones = [{a:?}, {b:?}]\nallowed_egress = [\"0.0.0.0/0\"]\n"),
    )?;
    let denied = h.temporary.path().join("deny.toml");
    fs::write(
        &denied,
        format!("{prefix}allowed_zones = []\nallowed_egress = []\nallowed_ingress = []\n"),
    )?;
    let a = h.zone("net-a", &allowed)?;
    let b = h.zone("net-b", &allowed)?;
    let c = h.zone("net-c", &denied)?;
    ensure!(
        checked(Command::new("ip").args(["addr", "show", "rauha0"]))?.contains("10.89.0.1"),
        "gateway missing"
    );
    ensure!(
        fs::read_to_string("/proc/sys/net/ipv4/ip_forward")?.trim() == "1",
        "forwarding disabled"
    );
    ensure!(
        checked(Command::new("nft").args(["list", "table", "inet", "rauha"]))?
            .contains("masquerade"),
        "NAT missing"
    );
    ensure!(
        checked(Command::new("nft").args(["list", "table", "bridge", "rauha"]))?
            .contains("policy drop"),
        "bridge default drop missing"
    );
    let ip = |zone: &str| -> Result<String> {
        let value: Value = serde_json::from_str(&checked(Command::new("ip").args([
            "-j",
            "-n",
            &format!("rauha-{zone}"),
            "-4",
            "addr",
            "show",
            "eth0",
        ]))?)?;
        value[0]["addr_info"]
            .as_array()
            .and_then(|a| a.iter().find(|v| v["family"] == "inet"))
            .and_then(|v| v["local"].as_str())
            .map(str::to_owned)
            .context("zone IP missing")
    };
    for (destination, success) in [
        ("8.8.8.8".to_owned(), true),
        (ip(&b)?, true),
        (ip(&c)?, false),
    ] {
        ensure!(
            h.sandbox(&a, &["/bin/ping", "-c1", "-W5", &destination])?
                .status
                .success()
                == success,
            "unexpected IPv4 reachability to {destination}"
        );
    }
    let listener = std::net::TcpListener::bind("10.89.0.1:0")?;
    listener.set_nonblocking(true)?;
    let port = listener.local_addr()?.port();
    let done = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
    let stop = done.clone();
    let server = thread::spawn(move || {
        while !stop.load(std::sync::atomic::Ordering::Relaxed) {
            if let Ok((mut stream, _)) = listener.accept() {
                let _ = stream.write_all(b"HTTP/1.0 200 OK\r\nContent-Length: 2\r\n\r\nok");
            }
            thread::sleep(Duration::from_millis(10));
        }
    });
    let denied = h.sandbox(
        &a,
        &[
            "/bin/wget",
            "-q",
            "-T",
            "2",
            "-O-",
            &format!("http://10.89.0.1:{port}"),
        ],
    );
    done.store(true, std::sync::atomic::Ordering::Relaxed);
    server
        .join()
        .map_err(|_| anyhow::anyhow!("HTTP fixture panicked"))?;
    ensure!(
        !denied?.status.success(),
        "zone reached undeclared host HTTP service"
    );
    checked(Command::new("ip").args(["-6", "addr", "add", "fd89::1/64", "dev", "rauha0"]))?;
    let ipv6 = (|| -> Result<()> {
        for (zone, address) in [(&a, "fd89::a/64"), (&c, "fd89::c/64")] {
            checked(Command::new("ip").args([
                "-n",
                &format!("rauha-{zone}"),
                "-6",
                "addr",
                "add",
                address,
                "dev",
                "eth0",
            ]))?;
        }
        for address in ["fd89::1", "fd89::c"] {
            ensure!(
                !h.sandbox(&a, &["/bin/ping", "-6", "-c1", "-W2", address])?
                    .status
                    .success(),
                "zone reached undeclared IPv6 {address}"
            );
        }
        Ok(())
    })();
    let cleanup =
        checked(Command::new("ip").args(["-6", "addr", "del", "fd89::1/64", "dev", "rauha0"]));
    ipv6?;
    cleanup?;
    let dns = h.sandbox(&a, &["/bin/cat", "/etc/resolv.conf"])?;
    ensure!(
        dns.status.success() && String::from_utf8_lossy(&dns.stdout).contains("nameserver"),
        "DNS configuration missing"
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn command_failures_are_not_silenced() {
        assert!(checked(&mut Command::new("false")).is_err());
    }
    #[test]
    fn scenarios_are_unique_and_complete() {
        let mut names = SCENARIOS.to_vec();
        names.sort();
        names.dedup();
        assert_eq!(names.len(), 10);
    }
}
