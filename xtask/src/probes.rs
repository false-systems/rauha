use std::fs;
use std::path::Path;
use std::process::{Command, Stdio};
use std::time::Instant;

use anyhow::{bail, ensure, Context, Result};
use serde_json::json;

use crate::checks::{checked, pid, policy, process_start, wait_for, workload_cgroup, Harness};

fn inode_check(h: &Harness, zone: &str) -> Result<()> {
    // Audit admission can report unavailable hooks; require the specific recovered controls.
    let output = h.output(&["--json", "zone", "verify", zone])?;
    let value: serde_json::Value = serde_json::from_slice(&output.stdout)?;
    let checks = value["checks"]
        .as_array()
        .context("verification checks missing")?;
    let inode = checks
        .iter()
        .find(|v| v["name"] == "filesystem:inode_ownership")
        .context("inode ownership check missing")?;
    ensure!(
        inode["passed"] == true
            && inode["detail"]
                .as_str()
                .and_then(|s| s.split_whitespace().next())
                .and_then(|s| s.parse::<usize>().ok())
                .is_some_and(|n| n > 0),
        "inode ownership incomplete: {inode}"
    );
    ensure!(
        checks
            .iter()
            .any(|v| v["name"] == "bpf_membership" && v["passed"] == true),
        "BPF membership incomplete"
    );
    Ok(())
}

pub fn recovery(phase: &str, state: &Path) -> Result<()> {
    let mut h = Harness::new()?;
    match phase {
        "prepare" => {
            h.pull()?;
            let zone = h.zone("recovery", &policy("audit"))?;
            let container = h.run(&zone, &["/bin/sleep", "300"])?;
            let pid = pid(&zone)?;
            inode_check(&h, &zone)?;
            let start = process_start(pid)?;
            // Keep this established format for runtime_output's cleanup regression.
            fs::write(
                state,
                format!("zone={zone}\ncontainer={container}\npid={pid}\nstart={start}\n"),
            )?;
            h.zones.clear();
        }
        "verify" => {
            let text = fs::read_to_string(state)?;
            let fields: std::collections::HashMap<_, _> = text
                .lines()
                .filter_map(|line| line.split_once('='))
                .collect();
            let zone = *fields.get("zone").context("recovery zone missing")?;
            let pid: u32 = fields.get("pid").context("recovery PID missing")?.parse()?;
            let start = *fields.get("start").context("recovery start missing")?;
            h.zones.push(zone.to_owned());
            ensure!(
                h.cli(&["zone", "list"])?.contains(zone),
                "zone metadata not recovered"
            );
            ensure!(
                process_start(pid)? == start,
                "original workload lost across restart"
            );
            inode_check(&h, zone)?;
            let container = fields
                .get("container")
                .context("recovery container missing")?;
            ensure!(
                h.cli(&["exec", "-it", container, "/bin/echo", "recovered-exec"])?
                    .contains("recovered-exec"),
                "recovered shim could not create an exec using refreshed membership authority"
            );
        }
        _ => bail!("phase must be prepare or verify"),
    }
    println!("PASS: recovery {phase}");
    Ok(())
}

struct RuntimeBundle {
    directory: tempfile::TempDir,
    ids: Vec<String>,
    mounted: bool,
}
impl RuntimeBundle {
    fn command(&self) -> Command {
        let mut command = Command::new("crun");
        command
            .arg("--root")
            .arg(self.directory.path().join("runtime"))
            .arg("--cgroup-manager=disabled");
        command
    }
}
impl Drop for RuntimeBundle {
    fn drop(&mut self) {
        for id in &self.ids {
            if let Err(error) = checked(self.command().args(["delete", "--force", id])) {
                eprintln!("crun cleanup {id}: {error:#}");
            }
        }
        if self.mounted {
            if let Err(error) =
                checked(Command::new("umount").arg(self.directory.path().join("rootfs")))
            {
                // Never recursively delete a still-mounted rootfs.
                eprintln!(
                    "rootfs cleanup failed; retaining {}: {error:#}",
                    self.directory.path().display()
                );
                self.directory.disable_cleanup(true);
            }
        }
    }
}

pub fn oci() -> Result<()> {
    let mut h = Harness::new()?;
    h.pull()?;
    let zone = h.audit_zone("oci-executor")?;
    let id = h.run(&zone, &["/bin/sleep", "120"])?;
    inode_check(&h, &zone).context("native container rootfs ownership before raw OCI probe")?;
    let enrollment = workload_cgroup(&zone)?.join("cgroup.procs");
    let root = std::path::PathBuf::from(std::env::var("RAUHA_ROOT")?);
    let container = root.join("zones").join(&zone).join("containers").join(id);
    let rootfs = [container.join("merged"), container.join("rootfs")]
        .into_iter()
        .find(|p| p.is_dir())
        .context("prepared rootfs missing")?;
    let mut bundle = RuntimeBundle {
        directory: tempfile::Builder::new()
            .prefix("oci-executor.")
            .tempdir_in(&root)?,
        ids: Vec::new(),
        mounted: false,
    };
    fs::create_dir(bundle.directory.path().join("runtime"))?;
    fs::create_dir(bundle.directory.path().join("rootfs"))?;
    checked(
        Command::new("mount")
            .arg("--bind")
            .arg(rootfs)
            .arg(bundle.directory.path().join("rootfs")),
    )?;
    bundle.mounted = true;
    let spec = json!({
        "ociVersion": "1.0.2",
        "process": {"terminal": false, "user": {"uid": 0, "gid": 0},
            "args": ["/bin/sh", "-c", "hostname; grep -E '^(CapEff|NoNewPrivs):' /proc/self/status; readlink /proc/self/ns/net; cat /proc/self/cgroup"],
            "env": ["PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"], "cwd": "/",
            "capabilities": {"bounding": [], "effective": [], "inheritable": [], "permitted": [], "ambient": []}, "noNewPrivileges": true},
        "root": {"path": "rootfs", "readonly": true}, "hostname": format!("crun-{zone}"),
        "mounts": [
            {"destination": "/proc", "type": "proc", "source": "proc", "options": ["nosuid", "noexec", "nodev"]},
            {"destination": "/dev", "type": "tmpfs", "source": "tmpfs", "options": ["nosuid", "noexec", "mode=755", "size=65536k"]}
        ],
        "linux": {"namespaces": [{"type": "pid"}, {"type": "mount"}, {"type": "uts"}, {"type": "ipc"}, {"type": "network", "path": format!("/var/run/netns/rauha-{zone}")}]}
    });
    fs::write(
        bundle.directory.path().join("config.json"),
        serde_json::to_vec(&spec)?,
    )?;
    let host_net = fs::read_link("/proc/self/ns/net")?;
    let mut warm = Instant::now();
    for iteration in 0..6 {
        if iteration == 1 {
            warm = Instant::now();
        }
        let id = format!("probe-{zone}-{iteration}");
        bundle.ids.push(id.clone());
        let output = bundle.directory.path().join(format!("output-{iteration}"));
        let pidfile = bundle.directory.path().join(format!("pid-{iteration}"));
        let status = bundle
            .command()
            .arg("create")
            .arg("--bundle")
            .arg(bundle.directory.path())
            .arg("--pid-file")
            .arg(&pidfile)
            .arg(&id)
            .stdout(fs::File::create(&output)?)
            .status()?;
        ensure!(status.success(), "crun create failed");
        ensure!(
            fs::metadata(&output)?.len() == 0,
            "workload ran before enrollment"
        );
        let pid = fs::read_to_string(pidfile)?;
        fs::write(&enrollment, pid.trim())?;
        ensure!(
            fs::read_to_string(format!("/proc/{}/cgroup", pid.trim()))?
                .contains(&format!("/rauha.slice/zone-{zone}")),
            "init enrollment failed"
        );
        checked(bundle.command().args(["start", &id]))?;
        wait_for(|| {
            let state: serde_json::Value =
                serde_json::from_str(&checked(bundle.command().args(["state", &id]))?)?;
            Ok(state["status"] == "stopped")
        })?;
        checked(bundle.command().args(["delete", &id]))?;
        bundle.ids.retain(|s| s != &id);
        let output = fs::read_to_string(output)?;
        ensure!(
            output.lines().any(|s| s == format!("crun-{zone}")),
            "UTS isolation missing"
        );
        ensure!(
            output.lines().any(
                |s| s.split_whitespace().collect::<Vec<_>>() == ["CapEff:", "0000000000000000"]
            ),
            "capability restriction missing"
        );
        ensure!(
            output
                .lines()
                .any(|s| s.split_whitespace().collect::<Vec<_>>() == ["NoNewPrivs:", "1"]),
            "NoNewPrivs missing"
        );
        let net = output
            .lines()
            .find(|s| s.starts_with("net:["))
            .context("netns output missing")?;
        ensure!(
            Path::new(net) != host_net,
            "workload shares host network namespace"
        );
        ensure!(
            output.contains(&format!("/rauha.slice/zone-{zone}")),
            "workload escaped cgroup"
        );
    }
    inode_check(&h, &zone)?;
    println!(
        "PASS: crun create/enroll/start; warm launch average {}us (n=5)",
        warm.elapsed().as_micros() / 5
    );
    Ok(())
}

const WASM: &[u8] = &[
    0, 97, 115, 109, 1, 0, 0, 0, 1, 4, 1, 96, 0, 0, 3, 2, 1, 0, 7, 10, 1, 6, 95, 115, 116, 97, 114,
    116, 0, 0, 10, 4, 1, 2, 0, 11,
];
pub fn wasm() -> Result<()> {
    let iterations: u32 = std::env::var("ITERATIONS")
        .unwrap_or_else(|_| "10".into())
        .parse()?;
    ensure!(iterations > 0, "ITERATIONS must be positive");
    let mut bundle = RuntimeBundle {
        directory: tempfile::Builder::new()
            .prefix("rauha-wasm-tier.")
            .tempdir()?,
        ids: Vec::new(),
        mounted: false,
    };
    fs::create_dir(bundle.directory.path().join("rootfs"))?;
    fs::create_dir(bundle.directory.path().join("runtime"))?;
    fs::write(bundle.directory.path().join("rootfs/probe.wasm"), WASM)?;
    fs::write(
        bundle.directory.path().join("config.json"),
        serde_json::to_vec(
            &json!({"ociVersion":"1.0.2","annotations":{"run.oci.handler":"wasm"},"process":{"terminal":false,"user":{"uid":0,"gid":0},"args":["/probe.wasm"],"env":[],"cwd":"/","noNewPrivileges":true},"root":{"path":"rootfs","readonly":true},"mounts":[],"linux":{"namespaces":[{"type":"pid"},{"type":"mount"}]}}),
        )?,
    )?;
    let version = checked(Command::new("crun").arg("--version"))?;
    let start = Instant::now();
    for iteration in 1..=iterations {
        let id = format!("rauha-wasm-{}-{iteration}", std::process::id());
        bundle.ids.push(id.clone());
        let output = bundle
            .command()
            .arg("run")
            .arg("--bundle")
            .arg(bundle.directory.path())
            .arg(&id)
            .stdin(Stdio::null())
            .output()?;
        if !output.status.success() {
            ensure!(
                iteration == 1,
                "Wasm handler failed after initial success: {}",
                String::from_utf8_lossy(&output.stderr)
            );
            println!(
                "crun={}\navailable=false\nprobe_us={}\nerror={}",
                version.lines().next().unwrap_or(&version),
                start.elapsed().as_micros(),
                String::from_utf8_lossy(&output.stderr)
            );
            return Ok(());
        }
        bundle.ids.retain(|s| s != &id);
    }
    println!(
        "crun={}\navailable=true\niterations={iterations}\naverage_us={}",
        version.lines().next().unwrap_or(&version),
        start.elapsed().as_micros() / iterations as u128
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn wasm_fixture_keeps_the_original_start_export() {
        assert_eq!(&WASM[..8], b"\0asm\x01\0\0\0");
        assert!(WASM.windows(6).any(|bytes| bytes == b"_start"));
    }
}
