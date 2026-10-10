#![cfg(target_os = "linux")]

use std::{
    collections::HashSet,
    fs::{self, File},
    io::Read,
    path::{Path, PathBuf},
    process::{Child, Command, Output, Stdio},
    time::{Duration, Instant},
};

#[path = "../src/rauha_client.rs"]
mod rauha_client;

struct Instance {
    directory: Option<tempfile::TempDir>,
    daemon: Child,
    ctr: PathBuf,
    socket: PathBuf,
    namespace: String,
    rootfs: PathBuf,
    shim: PathBuf,
    tasks: Vec<String>,
}

impl Instance {
    fn start(endpoint: &str) -> Self {
        let directory = tempfile::tempdir().unwrap();
        let root = directory.path();
        let rootfs = root.join("rootfs");
        rauha_oci::snapshotter::copy_dir_recursive(
            Path::new(
                &std::env::var("RAUHA_TEST_ROOTFS")
                    .expect("set RAUHA_TEST_ROOTFS to an unpacked Alpine rootfs"),
            ),
            &rootfs,
        )
        .unwrap();
        let socket = root.join("containerd.sock");
        let config = root.join("config.toml");
        fs::write(&config, "version = 2\ndisabled_plugins = [\"io.containerd.grpc.v1.cri\", \"io.containerd.cri.v1.images\", \"io.containerd.cri.v1.runtime\"]\n").unwrap();
        // The test VM lacks one LSM hook; exercise lifecycle in explicit audit mode.
        let policy = root.join("rauha-policy.toml");
        fs::write(
            &policy,
            "[admission]\nmode = 'audit'\n[filesystem]\nwritable_paths = ['/run']\n",
        )
        .unwrap();
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&policy, fs::Permissions::from_mode(0o600)).unwrap();
        let log = File::create(root.join("containerd.log")).unwrap();
        let shim = std::env::var_os("RAUHA_SHIM_BINARY")
            .map(PathBuf::from)
            .unwrap_or_else(|| env!("CARGO_BIN_EXE_containerd-shim-rauha-v2").into());
        let mut paths = vec![shim.parent().unwrap().to_path_buf()];
        paths.extend(std::env::split_paths(
            &std::env::var_os("PATH").unwrap_or_default(),
        ));
        let daemon = Command::new(
            std::env::var_os("CONTAINERD_BINARY").unwrap_or_else(|| "containerd".into()),
        )
        .args(["--config"])
        .arg(config)
        .arg("--root")
        .arg(root.join("data"))
        .arg("--state")
        .arg(root.join("state"))
        .arg("--address")
        .arg(&socket)
        .env("RAUHA_ADDR", endpoint)
        .env("RAUHA_CONTAINERD_POLICY", &policy)
        .env("PATH", std::env::join_paths(paths).unwrap())
        .stdin(Stdio::null())
        .stdout(log.try_clone().unwrap())
        .stderr(log)
        .spawn()
        .expect("start isolated containerd");
        let namespace = format!(
            "rauha-test-{}",
            directory
                .path()
                .file_name()
                .unwrap()
                .to_string_lossy()
                .chars()
                .filter(char::is_ascii_alphanumeric)
                .collect::<String>()
        );
        let mut instance = Self {
            directory: Some(directory),
            daemon,
            ctr: std::env::var_os("CTR_BINARY")
                .unwrap_or_else(|| "ctr".into())
                .into(),
            socket,
            namespace,
            rootfs,
            shim,
            tasks: Vec::new(),
        };
        let deadline = Instant::now() + Duration::from_secs(15);
        while !instance.run(&["version"]).status.success() {
            assert!(
                Instant::now() < deadline,
                "isolated containerd did not become ready"
            );
            assert!(
                instance.daemon.try_wait().unwrap().is_none(),
                "isolated containerd exited"
            );
            std::thread::sleep(Duration::from_millis(50));
        }
        instance
    }

    fn command(&self, args: &[&str]) -> Command {
        let mut command = Command::new("timeout");
        command
            .arg("30s")
            .arg(&self.ctr)
            .arg("--address")
            .arg(&self.socket)
            .arg("--namespace")
            .arg(&self.namespace)
            .args(args);
        command
    }

    fn run(&self, args: &[&str]) -> Output {
        self.command(args).output().unwrap()
    }

    fn success(&self, args: &[&str]) -> String {
        if args != ["tasks", "list"] {
            eprintln!("containerd lifecycle: ctr {args:?}");
        }
        let output = self.run(args);
        assert!(
            output.status.success(),
            "ctr {args:?}: {}\n{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
        String::from_utf8(output.stdout).unwrap()
    }

    fn start_task(&mut self, id: &str, command: &[&str], detach: bool) -> Output {
        self.start_task_with(id, command, detach, &[])
    }

    fn start_task_with(
        &mut self,
        id: &str,
        command: &[&str],
        detach: bool,
        options: &[&str],
    ) -> Output {
        eprintln!("containerd lifecycle: start {id}");
        self.tasks.push(id.into());
        // This VM's crun advertises OCI 1.0; construct a 1.0-only fixture rather
        // than downgrade a caller's newer production specification.
        let mut spec = serde_json::to_value(oci_spec::runtime::Spec::default()).unwrap();
        spec["ociVersion"] = "1.0.2".into();
        spec["root"]["path"] = self.rootfs.to_str().unwrap().into();
        spec["process"]["args"] = serde_json::json!(command);
        spec["process"]["terminal"] = false.into();
        spec["mounts"]
            .as_array_mut()
            .unwrap()
            .push(serde_json::json!({
                "destination":"/run","type":"tmpfs","source":"tmpfs",
                "options":["nosuid","strictatime","mode=755","size=65536k"]
            }));
        let (option_pairs, remainder) = options.as_chunks::<2>();
        assert!(
            remainder.is_empty(),
            "fixture options must be flag/value pairs"
        );
        for option in option_pairs {
            match option[0] {
                "--annotation" => {
                    let (key, value) = option[1].split_once('=').unwrap();
                    spec["annotations"][key] = value.into();
                }
                "--with-ns" => {
                    let (kind, path) = option[1].split_once(':').unwrap();
                    spec["linux"]["namespaces"]
                        .as_array_mut()
                        .unwrap()
                        .iter_mut()
                        .find(|namespace| namespace["type"] == kind)
                        .unwrap()["path"] = path.into();
                }
                other => panic!("unsupported fixture option {other}"),
            }
        }
        let config = self
            .directory
            .as_ref()
            .unwrap()
            .path()
            .join(format!("{id}.json"));
        fs::write(&config, serde_json::to_vec(&spec).unwrap()).unwrap();
        let mut args = vec![
            "run",
            "--config",
            config.to_str().unwrap(),
            "--runtime",
            self.shim.to_str().unwrap(),
        ];
        args.push(if detach { "--detach" } else { "--rm" });
        args.extend_from_slice(options);
        args.push(id);
        self.run(&args)
    }

    fn tty_exec(&self, id: &str) -> String {
        eprintln!("containerd lifecycle: terminal exec {id}");
        use std::os::unix::process::CommandExt;
        let pty = nix::pty::openpty(None, None).unwrap();
        let slave = File::from(pty.slave);
        let mut command = self.command(&[
            "tasks",
            "exec",
            "--tty",
            "--exec-id",
            "terminal",
            id,
            "/bin/sh",
            "-c",
            "test -t 0 && printf terminal-ok",
        ]);
        command
            .stdin(slave.try_clone().unwrap())
            .stdout(slave.try_clone().unwrap())
            .stderr(slave);
        unsafe {
            command.pre_exec(|| {
                nix::unistd::setsid().map_err(std::io::Error::from)?;
                if nix::libc::ioctl(0, nix::libc::TIOCSCTTY, 0) != 0 {
                    return Err(std::io::Error::last_os_error());
                }
                Ok(())
            });
        }
        let mut child = command.spawn().unwrap();
        drop(command);
        let reader = std::thread::spawn(move || {
            let mut master = File::from(pty.master);
            let mut output = Vec::new();
            let mut buffer = [0; 4096];
            loop {
                match master.read(&mut buffer) {
                    Ok(0) => break,
                    Ok(n) => output.extend_from_slice(&buffer[..n]),
                    Err(error) if error.raw_os_error() == Some(nix::libc::EIO) => break,
                    Err(error) => panic!("reading terminal: {error}"),
                }
            }
            String::from_utf8(output).unwrap()
        });
        let status = child.wait().unwrap();
        let output = reader.join().unwrap();
        assert!(status.success(), "terminal exec: {output}");
        output
    }
}

impl Drop for Instance {
    fn drop(&mut self) {
        for task in &self.tasks {
            let _ = self.run(&["tasks", "kill", "--signal", "SIGKILL", "--all", task]);
            let _ = self.run(&["tasks", "delete", "--force", task]);
            let _ = self.run(&["containers", "delete", task]);
        }
        let _ = self.daemon.kill();
        let _ = self.daemon.wait();
        if let Err(error) = terminate_owned_shims(&self.shim, &self.namespace, &self.socket) {
            let path = self.directory.take().unwrap().keep();
            if !std::thread::panicking() {
                panic!(
                    "test-owned shim cleanup failed: {error}; diagnostics: {}",
                    path.display()
                );
            }
            eprintln!(
                "test-owned shim cleanup failed: {error}; diagnostics: {}",
                path.display()
            );
        }
        if std::thread::panicking() && self.directory.is_some() {
            eprintln!(
                "containerd test diagnostics: {}",
                self.directory.take().unwrap().keep().display()
            );
        }
    }
}

fn owned_shim_command(command: &[u8], shim: &Path, namespace: &str, socket: &Path) -> bool {
    use std::os::unix::ffi::OsStrExt;
    let args: Vec<_> = command
        .split(|byte| *byte == 0)
        .filter(|arg| !arg.is_empty())
        .collect();
    let matches = |flag: &[u8], value: &[u8]| {
        let mut found = args.windows(2).filter(|pair| pair[0] == flag);
        found.next().is_some_and(|pair| pair[1] == value) && found.next().is_none()
    };
    args.first()
        .is_some_and(|arg| *arg == shim.as_os_str().as_bytes())
        && matches(b"-namespace", namespace.as_bytes())
        && matches(b"-address", socket.as_os_str().as_bytes())
}

fn terminate_owned_shims(shim: &Path, namespace: &str, socket: &Path) -> std::io::Result<()> {
    use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
    for entry in fs::read_dir("/proc")? {
        let entry = entry?;
        let Some(pid) = entry
            .file_name()
            .to_str()
            .and_then(|name| name.parse::<u32>().ok())
        else {
            continue;
        };
        // Pin identity before reading command metadata: a recycled PID cannot
        // redirect the signal to the new process.
        let fd = unsafe { libc::syscall(libc::SYS_pidfd_open, pid, 0) };
        if fd < 0 {
            let error = std::io::Error::last_os_error();
            if error.raw_os_error() == Some(libc::ESRCH) {
                continue;
            }
            return Err(error);
        }
        let fd = unsafe { OwnedFd::from_raw_fd(fd as i32) };
        let command = match fs::read(entry.path().join("cmdline")) {
            Ok(command) => command,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => continue,
            Err(error) => return Err(error),
        };
        if !owned_shim_command(&command, shim, namespace, socket) {
            continue;
        }
        let mut poll = libc::pollfd {
            fd: fd.as_raw_fd(),
            events: libc::POLLIN,
            revents: 0,
        };
        for signal in [libc::SIGTERM, libc::SIGKILL] {
            let result = unsafe {
                libc::syscall(
                    libc::SYS_pidfd_send_signal,
                    fd.as_raw_fd(),
                    signal,
                    std::ptr::null::<libc::siginfo_t>(),
                    0,
                )
            };
            if result < 0 {
                let error = std::io::Error::last_os_error();
                if error.raw_os_error() != Some(libc::ESRCH) {
                    return Err(error);
                }
            }
            let ready = unsafe { libc::poll(&mut poll, 1, 1000) };
            if ready < 0 {
                return Err(std::io::Error::last_os_error());
            }
            if ready > 0 {
                break;
            }
        }
        if poll.revents & libc::POLLIN == 0 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::TimedOut,
                "test-owned adapter did not exit",
            ));
        }
    }
    Ok(())
}

#[test]
fn orphan_cleanup_matches_only_the_exact_test_owner() {
    let owned = b"/tmp/test-shim\0-namespace\0test-one\0-address\0/tmp/test-one.sock\0-id\0task\0";
    let matches = |args: &[u8]| {
        owned_shim_command(
            args,
            Path::new("/tmp/test-shim"),
            "test-one",
            Path::new("/tmp/test-one.sock"),
        )
    };
    assert!(matches(owned));
    for other in [
        b"/tmp/test-shim\0-namespace\0test-two\0-address\0/tmp/test-one.sock\0".as_slice(),
        b"/tmp/test-shim\0-namespace\0test-one\0-address\0/run/k3s/containerd.sock\0",
        b"/usr/bin/containerd-shim-runc-v2\0-namespace\0test-one\0-address\0/tmp/test-one.sock\0",
        b"/tmp/test-shim\0-namespace\0test-one\0-namespace\0test-two\0-address\0/tmp/test-one.sock\0",
    ] { assert!(!matches(other)); }
}

struct NamespaceHolder(Child);

impl NamespaceHolder {
    fn start() -> Self {
        use std::os::unix::fs::MetadataExt;
        let mut holder = Self(
            Command::new("unshare")
                .args(["--net", "sleep", "300"])
                .stdin(Stdio::null())
                .stdout(Stdio::null())
                .spawn()
                .unwrap(),
        );
        let parent = fs::metadata("/proc/self/ns/net").unwrap();
        let deadline = Instant::now() + Duration::from_secs(5);
        loop {
            let child = fs::metadata(holder.path("net")).unwrap();
            if (child.dev(), child.ino()) != (parent.dev(), parent.ino()) {
                break;
            }
            assert!(
                holder.0.try_wait().unwrap().is_none(),
                "namespace holder exited"
            );
            assert!(
                Instant::now() < deadline,
                "namespace holder did not unshare"
            );
            std::thread::sleep(Duration::from_millis(10));
        }
        holder
    }

    fn path(&self, kind: &str) -> String {
        format!("/proc/{}/ns/{kind}", self.0.id())
    }
}

impl Drop for NamespaceHolder {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

fn pod_lifecycle(
    instance: &mut Instance,
    runtime: &tokio::runtime::Runtime,
    client: &mut rauha_client::RauhaClient,
) {
    use std::os::unix::fs::MetadataExt;
    let holder = NamespaceHolder::start();
    let network = format!("network:{}", holder.path("net"));
    let output = instance.start_task_with(
        "pod-sandbox",
        &["/bin/sleep", "300"],
        true,
        &[
            "--annotation",
            "io.kubernetes.cri.container-type=sandbox",
            "--with-ns",
            &network,
        ],
    );
    assert!(
        output.status.success(),
        "sandbox: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let list = runtime
        .block_on(client.containers.list_containers(
            rauha_client::pb::container::ListContainersRequest {
                zone_name: String::new(),
            },
        ))
        .unwrap()
        .into_inner()
        .containers;
    let sandbox = list
        .iter()
        .find(|container| container.name == "pod-sandbox")
        .unwrap();
    let ipc = format!("ipc:/proc/{}/ns/ipc", sandbox.pid);
    let uts = format!("uts:/proc/{}/ns/uts", sandbox.pid);
    let pid = format!("pid:/proc/{}/ns/pid", sandbox.pid);
    let output = instance.start_task_with(
        "pod-worker",
        &["/bin/sleep", "300"],
        true,
        &[
            "--annotation",
            "io.kubernetes.cri.container-type=container",
            "--annotation",
            "io.kubernetes.cri.sandbox-id=pod-sandbox",
            "--with-ns",
            &network,
            "--with-ns",
            &ipc,
            "--with-ns",
            &uts,
            "--with-ns",
            &pid,
        ],
    );
    assert!(
        output.status.success(),
        "pod worker: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let list = runtime
        .block_on(client.containers.list_containers(
            rauha_client::pb::container::ListContainersRequest {
                zone_name: String::new(),
            },
        ))
        .unwrap()
        .into_inner()
        .containers;
    let worker = list
        .iter()
        .find(|container| container.name == "pod-worker")
        .unwrap();
    assert_eq!(sandbox.zone_id, worker.zone_id);
    for kind in ["net", "ipc", "uts", "pid"] {
        let a = fs::metadata(format!("/proc/{}/ns/{kind}", sandbox.pid)).unwrap();
        let b = fs::metadata(format!("/proc/{}/ns/{kind}", worker.pid)).unwrap();
        assert_eq!(
            (a.dev(), a.ino()),
            (b.dev(), b.ino()),
            "pod {kind} namespace must be shared"
        );
    }
    let output =
        instance.start_task_with("other-pod", &["/bin/true"], false, &["--with-ns", &network]);
    assert!(
        !output.status.success(),
        "another zone acquired the pod network namespace"
    );
    assert_ne!(output.status.code(), Some(124), "cross-pod rejection hung");
    instance.success(&[
        "tasks",
        "exec",
        "--detach",
        "--exec-id",
        "survivor",
        "pod-worker",
        "/bin/sleep",
        "300",
    ]);
    instance.success(&["tasks", "kill", "--signal", "SIGKILL", "pod-worker"]);
    let deadline = Instant::now() + Duration::from_secs(5);
    while !instance.success(&["tasks", "list"]).contains("STOPPED") {
        assert!(Instant::now() < deadline, "worker init did not exit");
        std::thread::sleep(Duration::from_millis(10));
    }
    let survivors = runtime
        .block_on(client.containers.container_stats(
            rauha_client::pb::container::GetContainerRequest {
                container_id: worker.id.clone(),
            },
        ))
        .unwrap()
        .into_inner()
        .process_ids;
    assert!(
        !survivors.is_empty(),
        "shared-PID fixture needs a surviving exec process"
    );
    for id in ["pod-worker", "pod-sandbox"] {
        if id == "pod-sandbox" {
            instance.success(&["tasks", "kill", "--signal", "SIGKILL", "--all", id]);
        }
        instance.success(&["tasks", "delete", "--force", id]);
        instance.success(&["containers", "delete", id]);
    }
    for pid in survivors {
        assert!(
            !Path::new(&format!("/proc/{pid}")).exists(),
            "force deletion left an exec process alive"
        );
    }
}

#[test]
#[ignore = "requires a privileged Linux daemon and unpacked Alpine fixture"]
fn isolated_containerd_lifecycle() {
    assert_eq!(
        unsafe { libc::geteuid() },
        0,
        "containerd lifecycle test requires root"
    );
    let runtime = tokio::runtime::Runtime::new().unwrap();
    let endpoint = rauha_client::RauhaClient::endpoint();
    let mut client = runtime
        .block_on(rauha_client::RauhaClient::connect(&endpoint))
        .unwrap();
    let before: HashSet<_> = runtime
        .block_on(
            client
                .zones
                .list_zones(rauha_client::pb::zone::ListZonesRequest {}),
        )
        .unwrap()
        .into_inner()
        .zones
        .into_iter()
        .map(|zone| zone.id)
        .collect();
    let mut instance = Instance::start(&endpoint);
    for code in [0, 7] {
        let id = format!("arbitrary-task-not-an-image-{code}");
        let output = instance.start_task(
            &id,
            &[
                "/bin/sh",
                "-c",
                &format!("printf actual-output; exit {code}"),
            ],
            false,
        );
        assert_eq!(
            output.status.code(),
            Some(code),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        assert!(String::from_utf8_lossy(&output.stdout).contains("actual-output"));
    }
    let output = instance.start_task(
        "long-running",
        &[
            "/bin/sh",
            "-c",
            "trap 'exit 42' TERM; : > /run/signal-ready; while :; do sleep 300; done",
        ],
        true,
    );
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let containers = runtime
        .block_on(client.containers.list_containers(
            rauha_client::pb::container::ListContainersRequest {
                zone_name: String::new(),
            },
        ))
        .unwrap()
        .into_inner()
        .containers;
    let container = containers
        .iter()
        .find(|container| container.name == "long-running")
        .unwrap();
    assert!(container.pid > 1);
    assert!(fs::read_to_string(format!("/proc/{}/comm", container.pid))
        .unwrap()
        .contains("sh"));
    let ready = format!("/proc/{}/root/run/signal-ready", container.pid);
    let deadline = Instant::now() + Duration::from_secs(5);
    while !Path::new(&ready).exists() {
        assert!(
            Instant::now() < deadline,
            "init did not install its TERM handler"
        );
        std::thread::sleep(Duration::from_millis(10));
    }
    assert!(instance
        .success(&["tasks", "ps", "long-running"])
        .contains(&container.pid.to_string()));
    instance.success(&["tasks", "metrics", "long-running"]);
    runtime
        .block_on(client.containers.update_container_resources(
            rauha_client::pb::container::UpdateContainerResourcesRequest {
                container_id: container.id.clone(),
                resources_json: r#"{"memory":{"limit":67108864}}"#.into(),
            },
        ))
        .unwrap();
    let stats = runtime
        .block_on(client.containers.container_stats(
            rauha_client::pb::container::GetContainerRequest {
                container_id: container.id.clone(),
            },
        ))
        .unwrap()
        .into_inner();
    assert_eq!(stats.memory_limit_bytes, 67_108_864);
    instance.success(&["tasks", "pause", "long-running"]);
    assert!(instance.success(&["tasks", "list"]).contains("PAUSED"));
    instance.success(&["tasks", "resume", "long-running"]);
    let process_status = instance.success(&[
        "tasks",
        "exec",
        "--exec-id",
        "capabilities",
        "long-running",
        "/bin/cat",
        "/proc/self/status",
    ]);
    for field in ["CapEff:", "CapPrm:", "CapBnd:"] {
        let value = process_status
            .lines()
            .find_map(|line| line.strip_prefix(field))
            .unwrap_or_else(|| panic!("exec omitted {field}: {process_status}"));
        assert_eq!(
            value.trim(),
            "0000000000000000",
            "runtime setup leaked {field}"
        );
    }
    assert!(instance
        .success(&[
            "tasks",
            "exec",
            "--exec-id",
            "output",
            "long-running",
            "/bin/echo",
            "exec-output"
        ])
        .contains("exec-output"));
    let failed = instance.run(&[
        "tasks",
        "exec",
        "--exec-id",
        "exit-seven",
        "long-running",
        "/bin/sh",
        "-c",
        "exit 7",
    ]);
    assert_eq!(
        failed.status.code(),
        Some(7),
        "{}",
        String::from_utf8_lossy(&failed.stderr)
    );
    assert!(instance.tty_exec("long-running").contains("terminal-ok"));
    instance.success(&[
        "tasks",
        "kill",
        "--signal",
        "SIGTERM",
        "--all",
        "long-running",
    ]);
    let deadline = Instant::now() + Duration::from_secs(10);
    while !instance.success(&["tasks", "list"]).contains("STOPPED") {
        assert!(Instant::now() < deadline, "task did not stop after SIGTERM");
        std::thread::sleep(Duration::from_millis(50));
    }
    let stopped = runtime
        .block_on(client.containers.get_container(
            rauha_client::pb::container::GetContainerRequest {
                container_id: container.id.clone(),
            },
        ))
        .unwrap()
        .into_inner()
        .container
        .unwrap();
    assert_eq!(
        stopped.exit_code,
        Some(42),
        "TERM handler did not determine the exit status"
    );
    instance.success(&["tasks", "delete", "long-running"]);
    instance.success(&["containers", "delete", "long-running"]);
    pod_lifecycle(&mut instance, &runtime, &mut client);
    drop(instance);
    let after: HashSet<_> = runtime
        .block_on(
            client
                .zones
                .list_zones(rauha_client::pb::zone::ListZonesRequest {}),
        )
        .unwrap()
        .into_inner()
        .zones
        .into_iter()
        .map(|zone| zone.id)
        .collect();
    assert_eq!(before, after, "task deletion leaked zones");
    let mut unavailable = Instance::start("/run/rauha/nonexistent-integration-test.sock");
    let output = unavailable.start_task("daemon-unavailable", &["/bin/true"], false);
    assert!(
        !output.status.success(),
        "a disconnected adapter reported successful creation"
    );
    assert_ne!(
        output.status.code(),
        Some(124),
        "adapter hung while the daemon was unavailable"
    );
}
