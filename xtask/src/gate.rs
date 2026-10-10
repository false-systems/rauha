use std::fs;
use std::io;
use std::io::Write;
use std::net::{Shutdown, TcpListener, TcpStream};
use std::os::unix::fs::PermissionsExt;
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::thread;
use std::time::Duration;

use anyhow::{ensure, Context, Result};

use crate::checks::{checked, wait_for, Harness, Process, SCENARIOS};

pub fn dispatch() -> Result<()> {
    if cfg!(target_os = "linux") {
        return run();
    }
    let instance = match std::env::var("RAUHA_LIMA_INSTANCE") {
        Ok(instance) => instance,
        Err(_) => {
            let list = checked(Command::new("limactl").args([
                "list",
                "--format",
                "{{.Name}} {{.Status}}",
            ]))?;
            let running: Vec<_> = list
                .lines()
                .filter_map(|line| line.strip_suffix(" Running"))
                .collect();
            ensure!(
                running.len() == 1,
                "expected one running Lima instance; set RAUHA_LIMA_INSTANCE"
            );
            running[0].to_owned()
        }
    };
    ensure!(
        checked(Command::new("limactl").args(["list", "--format", "{{.Status}}", &instance]))?
            == "Running",
        "Lima instance is not running"
    );
    let mut command = Command::new("limactl");
    command.args(["shell", &instance, "--", "env"]);
    for key in [
        "TEST_IMAGE",
        "TEST_SECONDARY_IMAGE",
        "CARGO_TARGET_DIR",
        "RAUHA_TEST_TIMEOUT_SECONDS",
    ] {
        if let Some(value) = std::env::var_os(key) {
            command.arg(format!("{key}={}", value.to_string_lossy()));
        }
    }
    command
        .arg("cargo")
        .arg("run")
        .arg("--manifest-path")
        .arg(super::project_root().join("xtask/Cargo.toml"))
        .args(["--", "linux-gate"]);
    status(&mut command)
}

fn status(command: &mut Command) -> Result<()> {
    ensure!(
        command
            .status()
            .with_context(|| format!("launch {command:?}"))?
            .success(),
        "command failed: {command:?}"
    );
    Ok(())
}

fn artifact(manifest: Option<&Path>, package: Option<&str>, target: &str) -> Result<PathBuf> {
    let mut command = Command::new("cargo");
    command.current_dir(super::project_root()).args([
        "test",
        "--locked",
        "--no-run",
        "--message-format=json",
    ]);
    if let Some(manifest) = manifest {
        command.arg("--manifest-path").arg(manifest);
    }
    if let Some(package) = package {
        command.args(["-p", package]);
        if target == "rauha_oci" {
            command.arg("--lib");
        } else {
            command.args(["--test", target]);
        }
    }
    let output = checked(&mut command)?;
    output
        .lines()
        .filter_map(|line| serde_json::from_str::<serde_json::Value>(line).ok())
        .filter(|v| v["reason"] == "compiler-artifact" && v["target"]["name"] == target)
        .find_map(|v| v["executable"].as_str().map(PathBuf::from))
        .context("test executable missing from Cargo output")
}

pub fn run() -> Result<()> {
    // `cargo build --workspace` replaces this executable while we are running.
    let executable = std::env::current_exe()?;
    ensure!(cfg!(target_os = "linux"), "Linux required");
    ensure!(
        Path::new("/sys/kernel/btf/vmlinux").is_file(),
        "kernel BTF required"
    );
    ensure!(
        fs::read_to_string("/sys/kernel/security/lsm")?
            .split(',')
            .any(|s| s.trim() == "bpf"),
        "BPF LSM required"
    );
    let root = super::project_root();
    for args in [
        vec!["fmt", "--all", "--", "--check"],
        vec![
            "clippy",
            "--workspace",
            "--all-targets",
            "--locked",
            "--",
            "-D",
            "warnings",
        ],
        vec!["test", "--workspace", "--locked"],
        vec!["build", "--workspace", "--locked"],
    ] {
        status(Command::new("cargo").current_dir(&root).args(args))?;
    }
    super::build_ebpf(true)?;
    let output_test = artifact(None, Some("rauhad"), "runtime_output")?;
    let oci_test = artifact(None, Some("rauha-oci"), "rauha_oci")?;
    let containerd_test = artifact(None, Some("containerd-shim-rauha-v2"), "lifecycle")?;
    let oracle_test = artifact(
        Some(&root.join("eval/oracle/Cargo.toml")),
        None,
        "rauha-oracle",
    )?;
    let mut command = if unsafe { libc::geteuid() } == 0 {
        Command::new(&executable)
    } else {
        let mut command = Command::new("sudo");
        command.args(["--preserve-env=CARGO_TARGET_DIR,TEST_IMAGE,TEST_SECONDARY_IMAGE,RAUHA_TEST_TIMEOUT_SECONDS", "--"]).arg(&executable);
        command
    };
    command
        .arg("gate-runtime")
        .arg(output_test)
        .arg(oracle_test)
        .arg(oci_test)
        .arg(containerd_test);
    status(&mut command)
}

struct Daemon {
    process: Option<Process>,
    root: tempfile::TempDir,
    endpoint: PathBuf,
    executable: PathBuf,
    log: PathBuf,
    hostname: String,
    bpf: PathBuf,
    retain_artifacts: bool,
}
impl Daemon {
    fn new(profile: &str) -> Result<Self> {
        ensure!(
            unsafe { libc::geteuid() } == 0,
            "privileged runtime gate must run as root"
        );
        let root = tempfile::Builder::new()
            .prefix("rauha-security.")
            .tempdir()?;
        fs::set_permissions(root.path(), fs::Permissions::from_mode(0o700))?;
        // The daemon owns a global cgroup subtree and bridge. Never recover somebody else's zones.
        let slice = Path::new("/sys/fs/cgroup/rauha.slice");
        if slice.exists() {
            ensure!(
                !fs::read_dir(slice)?
                    .filter_map(Result::ok)
                    .any(|e| e.file_name().to_string_lossy().starts_with("zone-")),
                "existing Rauha zones found; use a dedicated test host"
            );
        }
        ensure!(
            UnixStream::connect("/run/rauha/rauhad.sock").is_err(),
            "an existing daemon is active; use a dedicated test host"
        );
        let endpoint = root.path().join("api/rauhad.sock");
        let bpf = PathBuf::from(format!("/sys/fs/bpf/rauha-gate-{}", std::process::id()));
        ensure!(!bpf.exists(), "gate pin directory already exists");
        fs::write(
            root.path().join("rauha.toml"),
            format!(
                // The private containerd fixture explicitly administers a /run
                // tmpfs. Keep kernel interface roots reserved; production
                // defaults continue reserving /run as well.
                "[server]\naddr = {:?}\n[paths]\nbpf_pin_dir = {:?}\n[policy]\nsafe_writable_roots = [\"/proc\", \"/sys\", \"/dev\"]\n",
                endpoint, bpf
            ),
        )?;
        let project = super::project_root();
        let target = super::configured_target_dir(&project, project.join("target"));
        let ebpf_target = super::configured_target_dir(&project, project.join("rauha-ebpf/target"));
        let ebpf = ebpf_target.join("bpfel-unknown-none/release/rauha-ebpf");
        fs::copy(&ebpf, root.path().join("rauha-ebpf"))?;
        fs::copy(
            rauha_ebpf_common::offsets::offsets_sidecar_path(&ebpf),
            rauha_ebpf_common::offsets::offsets_sidecar_path(&root.path().join("rauha-ebpf")),
        )?;
        fs::create_dir_all(project.join(".gate"))?;
        let log = project.join(".gate/rauhad.log");
        fs::write(&log, "")?;
        std::env::set_var("RAUHA_ROOT", root.path());
        std::env::set_var("RAUHA_ADDR", &endpoint);
        std::env::set_var("RAUHA_BIN", target.join(profile).join("rauha"));
        std::env::set_var("RAUHA_TEST_ENDPOINT", &endpoint);
        std::env::set_var("RAUHA_TEST_RUN_DIR", "/run/rauha");
        Ok(Self {
            process: None,
            root,
            endpoint,
            executable: target.join(profile).join("rauhad"),
            log,
            hostname: fs::read_to_string("/proc/sys/kernel/hostname")?,
            bpf,
            retain_artifacts: true,
        })
    }
    fn start(&mut self) -> Result<()> {
        println!(
            "Gate daemon root={} socket={} log={}",
            self.root.path().display(),
            self.endpoint.display(),
            self.log.display()
        );
        let log = fs::OpenOptions::new().append(true).open(&self.log)?;
        self.process = Some(Process(
            Command::new(&self.executable)
                .env("RAUHA_ROOT", self.root.path())
                .stdout(log.try_clone()?)
                .stderr(log)
                .spawn()?,
        ));
        let h = Harness::new()?;
        let result = wait_for(|| {
            ensure!(
                self.process.as_mut().unwrap().0.try_wait()?.is_none(),
                "rauhad exited before ready"
            );
            Ok(self.endpoint.exists() && h.output(&["zone", "list"])?.status.success())
        });
        if result.is_err() {
            eprintln!("{}", fs::read_to_string(&self.log)?);
        }
        result
    }
    fn crash(&mut self) -> Result<()> {
        let mut process = self.process.take().context("daemon not running")?;
        process.0.kill()?;
        process.0.wait()?;
        Ok(())
    }
}
impl Drop for Daemon {
    fn drop(&mut self) {
        if self.process.is_some() {
            if let Ok(harness) = Harness::new() {
                let listing = Command::new("timeout")
                    .arg("15")
                    .arg(&harness.binary)
                    .args(["--json", "zone", "list"])
                    .output();
                if let Ok(output) = listing {
                    if let Ok(value) = serde_json::from_slice::<serde_json::Value>(&output.stdout) {
                        if let Some(zones) = value["zones"].as_array() {
                            for name in zones.iter().filter_map(|zone| zone["name"].as_str()) {
                                if let Err(error) = checked(
                                    Command::new("timeout")
                                        .arg("30")
                                        .arg(&harness.binary)
                                        .args(["zone", "delete", name, "--force"]),
                                ) {
                                    eprintln!("gate zone cleanup {name}: {error:#}");
                                }
                            }
                        }
                    }
                }
            }
        }
        if let Some(mut process) = self.process.take() {
            unsafe {
                libc::kill(process.0.id() as i32, libc::SIGTERM);
            }
            for _ in 0..50 {
                if process.0.try_wait().ok().flatten().is_some() {
                    break;
                }
                thread::sleep(Duration::from_millis(100));
            }
        }
        // Only kill shims whose exact --rootfs-root argument belongs to this run.
        if let Ok(entries) = fs::read_dir("/proc") {
            for entry in entries.flatten() {
                let Ok(pid) = entry.file_name().to_string_lossy().parse::<i32>() else {
                    continue;
                };
                let Ok(cmdline) = fs::read(entry.path().join("cmdline")) else {
                    continue;
                };
                let args: Vec<_> = cmdline.split(|b| *b == 0).collect();
                if args.windows(2).any(|w| {
                    w[0] == b"--rootfs-root"
                        && Path::new(std::ffi::OsStr::from_bytes(w[1]))
                            .starts_with(self.root.path())
                }) {
                    unsafe {
                        libc::kill(pid, libc::SIGTERM);
                    }
                }
            }
        }
        let cleanup = cleanup_mounts(self.root.path());
        if let Err(error) = cleanup {
            eprintln!(
                "mount cleanup failed; retaining {}: {error:#}",
                self.root.path().display()
            );
            self.root.disable_cleanup(true);
        }
        if let Ok(now) = fs::read_to_string("/proc/sys/kernel/hostname") {
            if now != self.hostname {
                let _ = fs::write("/proc/sys/kernel/hostname", &self.hostname);
            }
        }
        if let Err(error) = fs::remove_dir_all(&self.bpf) {
            if error.kind() != io::ErrorKind::NotFound {
                eprintln!("BPF cleanup: {error}");
            }
        }
        if self.retain_artifacts {
            if let Err(error) = fs::copy(&self.log, self.root.path().join("rauhad.log")) {
                eprintln!("preserving failed daemon log: {error}");
            }
            eprintln!(
                "Retaining failed gate artifacts at {}",
                self.root.path().display()
            );
            self.root.disable_cleanup(true);
        }
    }
}
use std::os::unix::ffi::OsStrExt;

fn cleanup_mounts(root: &Path) -> Result<()> {
    let output = checked(Command::new("findmnt").args(["--json", "--list", "--output", "TARGET"]))?;
    let value: serde_json::Value = serde_json::from_str(&output)?;
    let mut mounts: Vec<_> = value["filesystems"]
        .as_array()
        .context("findmnt filesystems missing")?
        .iter()
        .filter_map(|v| v["target"].as_str())
        .map(PathBuf::from)
        .filter(|p| p.starts_with(root))
        .collect();
    mounts.sort_by_key(|p| std::cmp::Reverse(p.components().count()));
    for mount in mounts {
        checked(Command::new("umount").arg(mount))?;
    }
    Ok(())
}

fn bounded(command: &mut Command) -> Result<()> {
    let timeout = std::env::var("RAUHA_TEST_TIMEOUT_SECONDS").unwrap_or_else(|_| "120".into());
    let seconds: u64 = timeout.parse()?;
    ensure!(seconds > 0, "test timeout must be positive");
    let mut wrapped = Command::new("timeout");
    wrapped
        .args(["--kill-after=5s", &timeout])
        .arg(command.get_program())
        .args(command.get_args());
    for (name, value) in command.get_envs() {
        if let Some(value) = value {
            wrapped.env(name, value);
        } else {
            wrapped.env_remove(name);
        }
    }
    if let Some(dir) = command.get_current_dir() {
        wrapped.current_dir(dir);
    }
    status(&mut wrapped)
}

pub fn runtime(
    output_test: &Path,
    oracle_test: &Path,
    oci_test: &Path,
    containerd_test: &Path,
    containerd_only: bool,
) -> Result<()> {
    ensure!(
        fs::read_link("/proc/self/ns/net")?
            != fs::read_link(format!("/proc/{}/ns/net", unsafe { libc::getppid() }))?,
        "runtime gate must run in its isolated network namespace"
    );
    let parent = unsafe { libc::getppid() };
    ensure!(
        fs::read_link("/proc/self/ns/mnt")? != fs::read_link(format!("/proc/{parent}/ns/mnt"))?,
        "runtime gate requires a private mount namespace"
    );
    // ip netns exec remounts sysfs, hiding its host submounts. Restore only
    // the kernel interfaces needed by this gate in our private mount namespace.
    for (kind, target) in [
        ("cgroup2", "/sys/fs/cgroup"),
        ("bpf", "/sys/fs/bpf"),
        ("securityfs", "/sys/kernel/security"),
    ] {
        checked(Command::new("mount").args(["-t", kind, "none", target]))?;
    }
    bounded(Command::new(oci_test).args([
        "live_overlay_preserves_whiteouts_and_container_cleanup",
        "--ignored",
        "--nocapture",
    ]))?;
    let mut daemon = Daemon::new("debug")?;
    daemon.start()?;
    if containerd_only {
        containerd_lifecycle(
            daemon.root.path(),
            containerd_test,
            std::env::var_os("RAUHA_TEST_ROOTFS").map(PathBuf::from),
        )?;
        daemon.retain_artifacts = false;
        return Ok(());
    }
    let mut failures = Vec::new();
    if let Err(error) = containerd_lifecycle(daemon.root.path(), containerd_test, None) {
        eprintln!("FAILED containerd: {error:#}");
        failures.push("containerd");
    }
    for scenario in SCENARIOS {
        println!("RUN: {scenario}");
        if let Err(error) =
            bounded(Command::new(std::env::current_exe()?).args(["integration", scenario]))
        {
            eprintln!("FAILED {scenario}: {error:#}");
            failures.push(*scenario);
        }
    }
    for name in ["hostile_output", "transport_disconnect"] {
        bounded(Command::new(output_test).args([
            name,
            "--ignored",
            "--nocapture",
            "--test-threads=1",
        ]))?;
    }
    let task_state = daemon.root.path().join("task-recovery.json");
    std::env::set_var("RAUHA_TEST_TASK_RECOVERY_STATE", &task_state);
    bounded(Command::new(output_test).args([
        "durable_recovery_prepare",
        "--ignored",
        "--nocapture",
    ]))?;
    daemon.crash()?;
    daemon.start()?;
    bounded(Command::new(output_test).args([
        "durable_recovery_verify",
        "--ignored",
        "--nocapture",
    ]))?;
    let recovery_state = daemon.root.path().join("recovery-probe.state");
    crate::probes::recovery("prepare", &recovery_state)?;
    daemon.crash()?;
    daemon.start()?;
    crate::probes::recovery("verify", &recovery_state)?;
    bounded(
        Command::new(output_test)
            .env("RAUHA_TEST_RECOVERY_STATE", &recovery_state)
            .args(["recovered_shim_cleanup", "--ignored", "--nocapture"]),
    )?;
    crate::probes::oci()?;
    // Only the oracle and proxy enter this nested network namespace. The daemon
    // retains its isolated uplink for registry downloads.
    if let Err(error) = bounded(
        Command::new("unshare")
            .arg("--net")
            .arg(std::env::current_exe()?)
            .arg("oracle-proxy")
            .arg(oracle_test),
    ) {
        eprintln!("FAILED oracle: {error:#}");
        failures.push("oracle");
    }
    ensure!(failures.is_empty(), "failed gates: {failures:?}");
    daemon.retain_artifacts = false;
    Ok(())
}

fn containerd_lifecycle(root: &Path, executable: &Path, cached: Option<PathBuf>) -> Result<()> {
    // Snapshots are owned by their zone and disappear with it. Keep an ordinary
    // fixture container alive while the adapter copies its published snapshot.
    let mut fixture = Harness::new()?;
    let rootfs = if let Some(path) = cached {
        ensure!(
            path.is_absolute() && path.join("bin/sh").is_file(),
            "invalid cached containerd rootfs"
        );
        path
    } else {
        fixture.pull()?;
        let zone = fixture.audit_zone("containerd-fixture")?;
        fixture.run(&zone, &["/bin/sleep", "300"])?;
        let snapshots = root.join("zones").join(zone).join("snapshots-v2");
        fs::read_dir(&snapshots)
            .with_context(|| format!("containerd fixture snapshots at {}", snapshots.display()))?
            .filter_map(std::result::Result::ok)
            .map(|entry| entry.path())
            .find(|path| path.is_dir() && path.join("bin/sh").symlink_metadata().is_ok())
            .context("containerd test requires a prepared image with /bin/sh")?
    };
    let mut containerd = Command::new(executable);
    containerd.env("RAUHA_TEST_ROOTFS", rootfs).args([
        "isolated_containerd_lifecycle",
        "--ignored",
        "--nocapture",
    ]);
    for (variable, binary) in [("CONTAINERD_BINARY", "containerd"), ("CTR_BINARY", "ctr")] {
        let bundled = Path::new("/var/lib/rancher/k3s/data/current/bin").join(binary);
        if std::env::var_os(variable).is_none() && bundled.is_file() {
            containerd.env(variable, bundled);
        }
    }
    bounded(&mut containerd)
}

/// Only the scoped uplink exists in the host namespace; Rauha's drop policies do not.
pub fn isolated_runtime(
    output_test: &Path,
    oracle_test: &Path,
    oci_test: &Path,
    containerd_test: &Path,
    containerd_only: bool,
) -> Result<()> {
    ensure!(
        unsafe { libc::geteuid() } == 0,
        "runtime gate requires root"
    );
    ensure!(
        fs::read_to_string("/proc/sys/net/ipv4/ip_forward")?.trim() == "1",
        "host IPv4 forwarding must already be enabled; the gate never changes host sysctls"
    );
    let routes: serde_json::Value = serde_json::from_str(&checked(
        Command::new("ip").args(["-j", "-4", "route", "show", "table", "all"]),
    )?)?;
    for route in routes.as_array().context("invalid route listing")? {
        if let Some(destination) = route["dst"].as_str() {
            ensure!(
                !route_overlaps_uplink(destination)?,
                "gate uplink overlaps existing host route {destination}"
            );
        }
    }
    let suffix = std::process::id();
    let mut network = GateNetwork {
        namespace: format!("xtask-gate-{suffix}"),
        host_link: format!("rgh{suffix}"),
        guest_link: format!("rgn{suffix}"),
        table: format!("rauha_gate_{suffix}"),
        namespace_created: false,
        link_created: false,
        table_created: false,
        dns_created: false,
    };
    checked(Command::new("ip").args(["netns", "add", &network.namespace]))?;
    network.namespace_created = true;
    checked(Command::new("ip").args([
        "link",
        "add",
        &network.host_link,
        "type",
        "veth",
        "peer",
        "name",
        &network.guest_link,
    ]))?;
    network.link_created = true;
    checked(Command::new("ip").args([
        "link",
        "set",
        &network.guest_link,
        "netns",
        &network.namespace,
    ]))?;
    checked(Command::new("ip").args([
        "addr",
        "add",
        "198.19.255.1/30",
        "dev",
        &network.host_link,
    ]))?;
    checked(Command::new("ip").args(["link", "set", &network.host_link, "up"]))?;
    checked(Command::new("ip").args([
        "-n",
        &network.namespace,
        "addr",
        "add",
        "198.19.255.2/30",
        "dev",
        &network.guest_link,
    ]))?;
    for interface in ["lo", network.guest_link.as_str()] {
        checked(Command::new("ip").args([
            "-n",
            &network.namespace,
            "link",
            "set",
            interface,
            "up",
        ]))?;
    }
    checked(Command::new("ip").args([
        "-n",
        &network.namespace,
        "route",
        "add",
        "default",
        "via",
        "198.19.255.1",
    ]))?;
    let rules = format!("create table ip {table}\nadd chain ip {table} uplink {{ type nat hook postrouting priority srcnat; policy accept; }}\nadd rule ip {table} uplink ip saddr 198.19.255.2 oifname != \"{link}\" masquerade\n", table=network.table, link=network.host_link);
    let mut nft = Process(
        Command::new("nft")
            .args(["-f", "-"])
            .stdin(std::process::Stdio::piped())
            .spawn()?,
    );
    nft.0
        .stdin
        .take()
        .context("nft stdin missing")?
        .write_all(rules.as_bytes())?;
    ensure!(
        nft.0.wait()?.success(),
        "could not install scoped gate uplink NAT"
    );
    network.table_created = true;
    fs::create_dir_all("/etc/netns")?;
    let dns_dir = Path::new("/etc/netns").join(&network.namespace);
    fs::create_dir(&dns_dir)?;
    network.dns_created = true;
    let resolv = fs::read_to_string("/etc/resolv.conf")?;
    let nameservers: Vec<_> = resolv
        .lines()
        .filter_map(|line| {
            let mut parts = line.split_whitespace();
            if parts.next()? != "nameserver" {
                return None;
            }
            let address = parts.next()?.parse::<std::net::IpAddr>().ok()?;
            (!address.is_loopback()).then_some(format!("nameserver {address}\n"))
        })
        .collect();
    fs::write(
        dns_dir.join("resolv.conf"),
        if nameservers.is_empty() {
            "nameserver 1.1.1.1\n".to_owned()
        } else {
            nameservers.concat()
        },
    )?;
    println!(
        "Isolated gate network={} uplink={} (198.19.255.0/30)",
        network.namespace, network.host_link
    );
    let mut command = Command::new("ip");
    command
        .args(["netns", "exec", &network.namespace])
        .arg(std::env::current_exe()?)
        .arg("gate-runtime-inner")
        .args([output_test, oracle_test, oci_test, containerd_test]);
    if containerd_only {
        command.arg("--containerd-only");
    }
    status(&mut command)
}

fn route_overlaps_uplink(route: &str) -> Result<bool> {
    if route == "default" {
        return Ok(false);
    }
    let (address, prefix) = route.split_once('/').unwrap_or((route, "32"));
    let address = u32::from(address.parse::<std::net::Ipv4Addr>()?);
    let prefix: u32 = prefix.parse()?;
    ensure!(prefix <= 32, "invalid route prefix {route}");
    let common = prefix.min(30);
    let mask = if common == 0 {
        0
    } else {
        u32::MAX << (32 - common)
    };
    Ok(address & mask == u32::from(std::net::Ipv4Addr::new(198, 19, 255, 0)) & mask)
}

struct GateNetwork {
    namespace: String,
    host_link: String,
    guest_link: String,
    table: String,
    namespace_created: bool,
    link_created: bool,
    table_created: bool,
    dns_created: bool,
}
impl Drop for GateNetwork {
    fn drop(&mut self) {
        if self.table_created {
            if let Err(error) =
                checked(Command::new("nft").args(["delete", "table", "ip", &self.table]))
            {
                eprintln!("gate NAT cleanup: {error:#}");
            }
        }
        if self.link_created {
            if let Err(error) =
                checked(Command::new("ip").args(["link", "delete", &self.host_link]))
            {
                eprintln!("gate uplink cleanup: {error:#}");
            }
        }
        if self.namespace_created {
            if let Err(error) =
                checked(Command::new("ip").args(["netns", "delete", &self.namespace]))
            {
                eprintln!("gate netns cleanup: {error:#}");
            }
        }
        if self.dns_created {
            if let Err(error) = fs::remove_dir_all(Path::new("/etc/netns").join(&self.namespace)) {
                eprintln!("gate DNS cleanup: {error}");
            }
        }
    }
}

pub fn oracle_proxy(executable: &Path) -> Result<()> {
    ensure!(
        cfg!(target_os = "linux"),
        "oracle proxy requires Linux network namespaces"
    );
    // Refuse accidental direct use in the host's network namespace.
    let parent_net = format!("/proc/{}/ns/net", unsafe { libc::getppid() });
    ensure!(
        fs::read_link("/proc/self/ns/net")? != fs::read_link(parent_net)?,
        "oracle proxy must run under unshare --net"
    );
    checked(Command::new("ip").args(["link", "set", "lo", "up"]))?;
    let socket = PathBuf::from(std::env::var("RAUHA_ADDR")?);
    ensure!(
        socket.is_absolute(),
        "oracle proxy needs an absolute Unix socket"
    );
    let listener = TcpListener::bind("[::1]:0")?;
    let endpoint = format!("http://{}", listener.local_addr()?);
    listener.set_nonblocking(true)?;
    let mut test = Process(
        Command::new(executable)
            .env("RAUHA_GRPC_ENDPOINT", endpoint)
            .arg("--nocapture")
            .spawn()?,
    );
    loop {
        match listener.accept() {
            Ok((mut tcp, _)) => {
                let unix = UnixStream::connect(&socket)?;
                thread::spawn(move || {
                    if let Err(error) = forward(&mut tcp, unix) {
                        eprintln!("oracle proxy connection: {error}");
                    }
                });
            }
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => {}
            Err(error) => return Err(error.into()),
        }
        if let Some(status) = test.0.try_wait()? {
            ensure!(status.success(), "oracle failed: {status}");
            return Ok(());
        }
        thread::sleep(Duration::from_millis(5));
    }
}

fn forward(tcp: &mut TcpStream, mut unix: UnixStream) -> io::Result<()> {
    let mut read_tcp = tcp.try_clone()?;
    let mut write_unix = unix.try_clone()?;
    let upload = thread::spawn(move || {
        io::copy(&mut read_tcp, &mut write_unix)?;
        write_unix.shutdown(Shutdown::Write)
    });
    let download = io::copy(&mut unix, tcp);
    let _ = tcp.shutdown(Shutdown::Write);
    let upload = upload
        .join()
        .map_err(|_| io::Error::other("proxy thread panicked"))?;
    download?;
    upload
}

pub fn demo() -> Result<()> {
    ensure!(cfg!(target_os = "linux"), "demo requires Linux");
    status(
        Command::new("cargo")
            .current_dir(super::project_root())
            .args([
                "build",
                "--release",
                "--bin",
                "rauha",
                "--bin",
                "rauhad",
                "--bin",
                "rauha-shim",
            ]),
    )?;
    super::build_ebpf(true)?;
    let mut daemon = Daemon::new("release")?;
    daemon.start()?;
    let mut h = Harness::new()?;
    h.pull()?;
    for label in ["agent-sandbox", "database"] {
        let zone = h.zone(label, &crate::checks::policy("standard"))?;
        println!("{}", h.cli(&["zone", "verify", &zone])?);
        h.run(&zone, &["/bin/sleep", "300"])?;
    }
    println!("{}", h.cli(&["zone", "list"])?);
    println!("{}", h.cli(&["ps"])?);
    println!("Demo verified. Press Enter to stop and remove the demonstration zones.");
    let mut line = String::new();
    io::stdin().read_line(&mut line)?;
    daemon.retain_artifacts = false;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn gate_uplink_rejects_overlapping_host_routes() {
        for route in [
            "198.19.255.0/30",
            "198.19.255.2/32",
            "198.19.0.0/16",
            "0.0.0.0/0",
        ] {
            assert!(route_overlaps_uplink(route).unwrap(), "{route}");
        }
        for route in [
            "default",
            "198.19.255.4/30",
            "10.42.0.0/16",
            "192.168.0.0/16",
        ] {
            assert!(!route_overlaps_uplink(route).unwrap(), "{route}");
        }
        assert!(route_overlaps_uplink("198.19.255.0/33").is_err());
    }
    #[cfg(target_os = "linux")]
    use std::io::{Read, Write};
    #[cfg(target_os = "linux")]
    #[test]
    fn proxy_preserves_bytes_and_half_close_in_both_directions() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let mut client = TcpStream::connect(listener.local_addr().unwrap()).unwrap();
        let (mut tcp, _) = listener.accept().unwrap();
        let (unix, mut server) = UnixStream::pair().unwrap();
        let proxy = thread::spawn(move || forward(&mut tcp, unix).unwrap());
        client.write_all(b"request\0body").unwrap();
        client.shutdown(Shutdown::Write).unwrap();
        let mut request = Vec::new();
        server.read_to_end(&mut request).unwrap();
        assert_eq!(request, b"request\0body");
        server.write_all(b"response\0body").unwrap();
        server.shutdown(Shutdown::Write).unwrap();
        let mut response = Vec::new();
        client.read_to_end(&mut response).unwrap();
        assert_eq!(response, b"response\0body");
        proxy.join().unwrap();
    }
    #[test]
    fn mount_cleanup_uses_path_boundaries_not_text_prefixes() {
        assert!(!Path::new("/tmp/rauha-run-other/merged").starts_with("/tmp/rauha-run"));
        assert!(Path::new("/tmp/rauha-run/merged").starts_with("/tmp/rauha-run"));
    }
}
