//! rauha-guest-agent — runs inside lightweight VMs on macOS.
//!
//! Listens on virtio-vsock port 5123 for ShimRequest messages from the
//! host rauhad daemon. This is the macOS equivalent of rauha-shim.

mod attach;
mod container;

use std::collections::HashMap;
use std::os::unix::net::UnixListener;
use std::path::PathBuf;

use rauha_common::shim::{self, ShimRequest, ShimResponse};

/// Port the guest agent listens on for vsock connections.
const VSOCK_PORT: u16 = 5123;

/// Guest-side state tracking all containers in this VM.
struct AgentState {
    rootfs_root: PathBuf,
    containers: HashMap<String, ContainerProcess>,
    shutdown: bool,
}

struct ContainerProcess {
    pid: u32,
    status: ContainerStatus,
    exit_code: Option<i32>,
    spec_json: String,
}

#[derive(Debug, Clone, Copy, PartialEq)]
enum ContainerStatus {
    Created,
    Running,
    Stopped,
}

impl AgentState {
    fn new(rootfs_root: PathBuf) -> Self {
        Self {
            rootfs_root,
            containers: HashMap::new(),
            shutdown: false,
        }
    }

    fn create_container(&mut self, id: &str, spec_json: &str) -> Result<u32, String> {
        if self.containers.contains_key(id) {
            return Err(format!("container {id} already exists"));
        }
        self.containers.insert(
            id.to_string(),
            ContainerProcess {
                pid: 0,
                status: ContainerStatus::Created,
                exit_code: None,
                spec_json: spec_json.to_string(),
            },
        );
        Ok(0)
    }

    fn start_container(&mut self, id: &str) -> Result<u32, String> {
        let proc = self
            .containers
            .get(id)
            .ok_or_else(|| format!("container {id} not found"))?;
        if proc.status != ContainerStatus::Created {
            return Err(format!("container {id} not in created state"));
        }
        let spec_json = proc.spec_json.clone();

        let pid = container::fork_and_exec(id, &spec_json, &self.rootfs_root)
            .map_err(|e| e.to_string())?;

        let proc = self
            .containers
            .get_mut(id)
            .ok_or_else(|| format!("container {id} not found after fork"))?;
        proc.pid = pid;
        proc.status = ContainerStatus::Running;
        Ok(pid)
    }

    fn stop_container(&mut self, id: &str, signal: i32) -> Result<(), String> {
        let proc = self
            .containers
            .get(id)
            .ok_or_else(|| format!("container {id} not found"))?;
        if proc.status != ContainerStatus::Running || proc.pid == 0 {
            return Err(format!("container {id} is not running"));
        }
        container::send_signal(proc.pid, signal).map_err(|e| e.to_string())
    }

    fn get_state(&self, id: &str) -> Option<(u32, String, Option<i32>)> {
        self.containers.get(id).map(|p| {
            let status = match p.status {
                ContainerStatus::Created => "created",
                ContainerStatus::Running => "running",
                ContainerStatus::Stopped => "stopped",
            };
            (p.pid, status.to_string(), p.exit_code)
        })
    }

    fn reap_children(&mut self) {
        for proc in self.containers.values_mut() {
            if proc.status != ContainerStatus::Running || proc.pid == 0 {
                continue;
            }
            if let Some(exit_code) = container::try_wait(proc.pid) {
                proc.status = ContainerStatus::Stopped;
                proc.exit_code = Some(exit_code);
            }
        }
    }
}

fn handle_request(state: &mut AgentState, request: ShimRequest) -> ShimResponse {
    match request {
        ShimRequest::CreateContainer { id, spec_json } => {
            match state.create_container(&id, &spec_json) {
                Ok(pid) => ShimResponse::Created { pid },
                Err(e) => ShimResponse::Error { message: e },
            }
        }
        ShimRequest::StartContainer { id } => match state.start_container(&id) {
            Ok(pid) => ShimResponse::Created { pid },
            Err(e) => ShimResponse::Error { message: e },
        },
        ShimRequest::StopContainer { id, signal } => match state.stop_container(&id, signal) {
            Ok(()) => ShimResponse::Ok,
            Err(e) => ShimResponse::Error { message: e },
        },
        ShimRequest::Signal { id, signal } => match state.stop_container(&id, signal) {
            Ok(()) => ShimResponse::Ok,
            Err(e) => ShimResponse::Error { message: e },
        },
        ShimRequest::GetState { id } => match state.get_state(&id) {
            Some((pid, status, exit_code)) => ShimResponse::State {
                pid,
                status,
                exit_code,
            },
            None => ShimResponse::Error {
                message: format!("container {id} not found"),
            },
        },
        ShimRequest::Shutdown => {
            state.shutdown = true;
            ShimResponse::Ok
        }
        ShimRequest::GetStats => {
            let (cpu_usage_ns, memory_bytes, pids) = container::collect_stats();
            ShimResponse::Stats {
                cpu_usage_ns,
                memory_bytes,
                pids,
            }
        }
        ShimRequest::Attach { .. } => ShimResponse::Error {
            message: "attach not yet supported in guest agent".into(),
        },
        ShimRequest::Exec {
            id,
            command,
            env,
            pty,
        } => {
            tracing::info!(container = %id, ?command, pty, "exec in container");

            if !pty {
                return ShimResponse::Error {
                    message: "non-PTY exec not yet supported".into(),
                };
            }

            // Verify container exists and is running.
            match state.get_state(&id) {
                Some((_pid, status, _exit_code)) if status == "running" => {}
                Some((_, status, _)) => {
                    return ShimResponse::Error {
                        message: format!("container {id} is in {status} state, not running"),
                    };
                }
                None => {
                    return ShimResponse::Error {
                        message: format!("container {id} not found"),
                    };
                }
            }

            let vsock_port = attach::allocate_session_port();

            match attach::fork_and_exec_pty(&state.rootfs_root, &id, &command, &env) {
                Ok((master_fd, _pid)) => match attach::serve_vsock_session(master_fd, vsock_port) {
                    Ok(()) => ShimResponse::ExecReady {
                        socket_path: None,
                        vsock_port: Some(vsock_port),
                    },
                    Err(e) => ShimResponse::Error {
                        message: format!("failed to create vsock session: {e}"),
                    },
                },
                Err(e) => ShimResponse::Error {
                    message: format!("exec failed: {e}"),
                },
            }
        }
    }
}

fn main() -> anyhow::Result<()> {
    // When running as PID 1 inside a VM, mount essential filesystems first.
    #[cfg(target_os = "linux")]
    if std::process::id() == 1 {
        init_filesystems();
    }

    tracing_subscriber::fmt()
        .with_env_filter("rauha_guest_agent=info")
        .init();

    tracing::info!("rauha-guest-agent starting");

    // The rootfs is shared from the host via virtio-fs, mounted at /mnt/rauha.
    let rootfs_root = PathBuf::from("/mnt/rauha");
    let mut state = AgentState::new(rootfs_root);

    // Listen on vsock for connections from the host rauhad daemon.
    #[cfg(target_os = "linux")]
    {
        tracing::info!(port = VSOCK_PORT, "listening on vsock");
        listen_vsock(VSOCK_PORT, &mut state)?;
    }

    #[cfg(not(target_os = "linux"))]
    {
        let socket_path = "/run/rauha-guest-agent.sock";
        tracing::info!(path = socket_path, "listening on unix socket (not Linux)");
        listen_unix(socket_path, &mut state)?;
    }

    tracing::info!("guest agent exited");
    Ok(())
}

/// Mount essential filesystems when running as PID 1 (init) inside a VM.
#[cfg(target_os = "linux")]
fn init_filesystems() {
    use nix::mount::{mount, MsFlags};

    eprintln!("rauha-guest-agent: running as PID 1, mounting filesystems");

    let mounts = [
        ("proc", "/proc", "proc", MsFlags::empty()),
        ("sysfs", "/sys", "sysfs", MsFlags::empty()),
        ("devtmpfs", "/dev", "devtmpfs", MsFlags::empty()),
    ];

    for (src, target, fstype, flags) in &mounts {
        let _ = std::fs::create_dir_all(target);
        if let Err(e) = mount(Some(*src), *target, Some(*fstype), *flags, None::<&str>) {
            eprintln!("  mount {target}: {e}");
        }
    }

    // devpts for PTY support.
    let _ = std::fs::create_dir_all("/dev/pts");
    let _ = mount(
        Some("devpts"),
        "/dev/pts",
        Some("devpts"),
        MsFlags::empty(),
        None::<&str>,
    );

    // Mount virtio-fs share from host.
    let _ = std::fs::create_dir_all("/mnt/rauha");
    if let Err(e) = mount(
        Some("rauha"),
        "/mnt/rauha",
        Some("virtiofs"),
        MsFlags::empty(),
        None::<&str>,
    ) {
        eprintln!("  mount /mnt/rauha (virtiofs): {e}");
    }

    // /run for socket files.
    let _ = std::fs::create_dir_all("/run");
}

/// Listen on virtio-vsock for connections from the host.
#[cfg(target_os = "linux")]
fn listen_vsock(port: u16, state: &mut AgentState) -> anyhow::Result<()> {
    const AF_VSOCK: i32 = 40;
    const VMADDR_CID_ANY: u32 = 0xFFFFFFFF;

    #[repr(C)]
    struct SockaddrVm {
        svm_family: u16,
        svm_reserved1: u16,
        svm_port: u32,
        svm_cid: u32,
        svm_zero: [u8; 4],
    }

    let fd = unsafe { libc::socket(AF_VSOCK, libc::SOCK_STREAM, 0) };
    if fd < 0 {
        anyhow::bail!(
            "failed to create vsock socket: {}",
            std::io::Error::last_os_error()
        );
    }

    let addr = SockaddrVm {
        svm_family: AF_VSOCK as u16,
        svm_reserved1: 0,
        svm_port: port as u32,
        svm_cid: VMADDR_CID_ANY,
        svm_zero: [0; 4],
    };

    let ret = unsafe {
        libc::bind(
            fd,
            &addr as *const _ as *const libc::sockaddr,
            std::mem::size_of::<SockaddrVm>() as u32,
        )
    };
    if ret < 0 {
        unsafe {
            libc::close(fd);
        }
        anyhow::bail!("failed to bind vsock: {}", std::io::Error::last_os_error());
    }

    let ret = unsafe { libc::listen(fd, 5) };
    if ret < 0 {
        unsafe {
            libc::close(fd);
        }
        anyhow::bail!(
            "failed to listen on vsock: {}",
            std::io::Error::last_os_error()
        );
    }

    tracing::info!(port, "vsock listening");

    loop {
        let client_fd = unsafe { libc::accept(fd, std::ptr::null_mut(), std::ptr::null_mut()) };
        if client_fd < 0 {
            tracing::error!("vsock accept failed: {}", std::io::Error::last_os_error());
            continue;
        }

        // Wrap the fd in a File for Read + Write.
        let mut stream =
            unsafe { <std::fs::File as std::os::fd::FromRawFd>::from_raw_fd(client_fd) };

        match shim::decode_from::<ShimRequest>(&mut stream) {
            Ok(request) => {
                let response = handle_request(state, request);
                if let Err(e) = shim::encode_to(&mut stream, &response) {
                    tracing::error!(%e, "failed to send response");
                }
                if state.shutdown {
                    tracing::info!("shutting down");
                    break;
                }
            }
            Err(e) => {
                tracing::error!(%e, "failed to decode request");
            }
        }

        state.reap_children();
    }

    unsafe {
        libc::close(fd);
    }
    Ok(())
}

fn listen_unix(path: &str, state: &mut AgentState) -> anyhow::Result<()> {
    if std::path::Path::new(path).exists() {
        std::fs::remove_file(path)?;
    }

    let listener = UnixListener::bind(path)?;

    for stream in listener.incoming() {
        match stream {
            Ok(mut stream) => match shim::decode_from::<ShimRequest>(&mut stream) {
                Ok(request) => {
                    let response = handle_request(state, request);
                    if let Err(e) = shim::encode_to(&mut stream, &response) {
                        tracing::error!(%e, "failed to send response");
                    }
                    if state.shutdown {
                        tracing::info!("shutting down");
                        break;
                    }
                }
                Err(e) => {
                    tracing::error!(%e, "failed to decode request");
                }
            },
            Err(e) => {
                tracing::error!(%e, "accept error");
            }
        }

        state.reap_children();
    }

    let _ = std::fs::remove_file(path);
    Ok(())
}
