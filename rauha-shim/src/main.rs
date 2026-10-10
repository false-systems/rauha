mod attach;
mod broker;
mod container;
#[cfg(target_os = "linux")]
mod exec_cgroup;
#[cfg(target_os = "linux")]
mod output;
#[cfg(target_os = "linux")]
mod process_io;
#[cfg(target_os = "linux")]
mod resources;
mod state;

use std::os::unix::net::UnixListener;
use std::path::PathBuf;

use clap::Parser;
use rauha_common::shim::{self, ShimRequest, ShimResponse};
use tracing_subscriber::EnvFilter;

use crate::state::ShimState;

#[derive(Parser)]
#[command(
    name = "rauha-shim",
    about = "Zone shim — one per zone, runs container processes"
)]
struct Args {
    /// Zone name.
    #[arg(long)]
    zone_name: String,

    /// Path to the shim Unix socket.
    #[arg(long)]
    socket: PathBuf,

    /// Root path for zone data (rootfs dirs, etc.).
    #[arg(long)]
    rootfs_root: PathBuf,

    /// Inherited zone-membership map descriptor, supplied only by rauhad.
    #[cfg(target_os = "linux")]
    #[arg(long)]
    membership_fd: i32,
}

fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::from_default_env().add_directive("rauha_shim=info".parse()?))
        .init();

    let args = Args::parse();
    #[cfg(target_os = "linux")]
    crate::exec_cgroup::install_membership_map(take_membership_fd(args.membership_fd)?)?;

    tracing::info!(
        zone = %args.zone_name,
        socket = %args.socket.display(),
        "rauha-shim starting"
    );

    // Remove stale socket if it exists.
    if args.socket.exists() {
        std::fs::remove_file(&args.socket)?;
    }

    // Ensure parent directory exists.
    if let Some(parent) = args.socket.parent() {
        std::fs::create_dir_all(parent)?;
    }

    let listener = UnixListener::bind(&args.socket)?;
    listener.set_nonblocking(true)?;
    tracing::info!(socket = %args.socket.display(), "listening");

    let mut shim_state = ShimState::new(args.zone_name.clone(), args.rootfs_root.clone());

    // Main loop: accept connections, handle one request per connection.
    // rauhad opens a new connection for each request.
    loop {
        match listener.accept() {
            Ok((mut stream, _)) => {
                match shim::decode_from::<ShimRequest>(&mut stream) {
                    Ok(request) => {
                        let response = if matches!(request, ShimRequest::RefreshMembership) {
                            refresh_membership(&mut stream)
                        } else {
                            handle_request(&mut shim_state, request)
                        };
                        if let Err(e) = shim::encode_to(&mut stream, &response) {
                            tracing::error!(%e, "failed to send response");
                        }
                        // Check for shutdown.
                        if matches!(response, ShimResponse::Ok) && shim_state.should_shutdown() {
                            tracing::info!("shutting down");
                            break;
                        }
                    }
                    Err(e) => {
                        tracing::error!(%e, "failed to decode request");
                    }
                }
            }
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                // Reap detached execs even when no daemon RPC is arriving.
                std::thread::sleep(std::time::Duration::from_millis(50));
            }
            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => {}
            Err(e) => {
                tracing::error!(%e, "accept error");
                return Err(e.into());
            }
        }

        // Reap finished child processes.
        shim_state.reap_children();
    }

    // Clean up socket.
    let _ = std::fs::remove_file(&args.socket);
    tracing::info!("shim exited");
    Ok(())
}

#[cfg(target_os = "linux")]
fn take_membership_fd(fd: i32) -> anyhow::Result<std::os::fd::OwnedFd> {
    use std::os::fd::FromRawFd;
    anyhow::ensure!(
        fd >= 64,
        "membership descriptor must be a dedicated inherited fd"
    );
    let flags = unsafe { libc::fcntl(fd, libc::F_GETFD) };
    if flags < 0 {
        return Err(std::io::Error::last_os_error().into());
    }
    // This descriptor is transferred to us at exec and must never leak to crun
    // or a workload. Take ownership before any subsequent fallible operation.
    let owned = unsafe { std::os::fd::OwnedFd::from_raw_fd(fd) };
    if unsafe { libc::fcntl(fd, libc::F_SETFD, flags | libc::FD_CLOEXEC) } < 0 {
        return Err(std::io::Error::last_os_error().into());
    }
    Ok(owned)
}

fn refresh_membership(stream: &mut std::os::unix::net::UnixStream) -> ShimResponse {
    #[cfg(target_os = "linux")]
    let result = (|| -> anyhow::Result<()> {
        stream.set_read_timeout(Some(std::time::Duration::from_secs(5)))?;
        let fd = shim::descriptor::receive(stream)?;
        crate::exec_cgroup::install_membership_map(fd)
    })();
    #[cfg(not(target_os = "linux"))]
    let result: anyhow::Result<()> = {
        let _ = stream;
        Err(anyhow::anyhow!("membership descriptors require Linux"))
    };
    match result {
        Ok(()) => ShimResponse::Ok,
        Err(error) => ShimResponse::Error {
            message: format!("membership refresh failed: {error:#}"),
        },
    }
}

#[cfg(all(test, target_os = "linux"))]
#[test]
fn inherited_membership_fd_is_owned_and_close_on_exec() {
    use std::os::fd::AsRawFd;
    let file = std::fs::File::open("/dev/null").unwrap();
    let fd = unsafe { libc::fcntl(file.as_raw_fd(), libc::F_DUPFD, 64) };
    assert!(fd >= 64);
    assert_eq!(
        unsafe { libc::fcntl(fd, libc::F_GETFD) } & libc::FD_CLOEXEC,
        0
    );
    let owned = take_membership_fd(fd).unwrap();
    assert_ne!(
        unsafe { libc::fcntl(owned.as_raw_fd(), libc::F_GETFD) } & libc::FD_CLOEXEC,
        0
    );
    drop(owned);
    assert!(take_membership_fd(0).is_err());
}

fn handle_request(state: &mut ShimState, request: ShimRequest) -> ShimResponse {
    state.reap_children();
    match request {
        ShimRequest::RefreshMembership => ShimResponse::Error {
            message: "membership refresh requires its authenticated descriptor stream".into(),
        },
        ShimRequest::Process {
            id,
            exec_id,
            operation,
        } => match state.process_operation(&id, &exec_id, operation) {
            Ok(response) => response,
            Err(error) => ShimResponse::Error {
                message: error.to_string(),
            },
        },
        ShimRequest::CreateContainer { id, spec_json } => {
            tracing::info!(container = %id, "creating container");
            match state.create_container(&id, &spec_json) {
                Ok(pid) => ShimResponse::Created { pid },
                Err(e) => ShimResponse::Error {
                    message: e.to_string(),
                },
            }
        }
        ShimRequest::StartContainer { id } => {
            tracing::info!(container = %id, "starting container");
            match state.start_container(&id) {
                Ok(pid) => ShimResponse::Created { pid },
                Err(e) => ShimResponse::Error {
                    message: e.to_string(),
                },
            }
        }
        ShimRequest::StopContainer { id, signal } => {
            tracing::info!(container = %id, signal, "stopping container");
            match state.stop_container(&id, signal) {
                Ok(()) => ShimResponse::Ok,
                Err(e) => ShimResponse::Error {
                    message: e.to_string(),
                },
            }
        }
        ShimRequest::Signal { id, signal } => match state.signal_container(&id, signal) {
            Ok(()) => ShimResponse::Ok,
            Err(e) => ShimResponse::Error {
                message: e.to_string(),
            },
        },
        ShimRequest::GetState { id } => match state.get_state(&id) {
            Ok(Some((pid, status, exit_code))) => ShimResponse::State {
                pid,
                status,
                exit_code,
            },
            Ok(None) => ShimResponse::Error {
                message: format!("container {id} not found"),
            },
            Err(error) => ShimResponse::Error {
                message: error.to_string(),
            },
        },
        ShimRequest::Shutdown => match state.request_shutdown() {
            Ok(()) => ShimResponse::Ok,
            Err(e) => ShimResponse::Error {
                message: e.to_string(),
            },
        },
        ShimRequest::DeleteContainer { id } => match state.delete_container(&id) {
            Ok(()) => ShimResponse::Ok,
            Err(e) => ShimResponse::Error {
                message: e.to_string(),
            },
        },
        ShimRequest::GetStats => {
            let (pids, container_count) = state.container_summary();
            ShimResponse::Stats {
                cpu_usage_ns: 0, // TODO: read from cgroup
                memory_bytes: 0, // TODO: read from cgroup
                pids,
                container_count,
                network_rx_bytes: 0,
                network_tx_bytes: 0,
            }
        }
        ShimRequest::ResizePty {
            id,
            session_id,
            rows,
            cols,
        } => {
            let Some(session_id) = session_id else {
                return ShimResponse::Error {
                    message: format!("missing PTY session id for container {id}"),
                };
            };
            match attach::resize_pty(&session_id, rows, cols) {
                Ok(()) => ShimResponse::Ok,
                Err(e) => ShimResponse::Error {
                    message: e.to_string(),
                },
            }
        }
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
            let session_id = uuid::Uuid::new_v4().to_string();
            match state.interactive_exec(&id, &session_id, &command, &env) {
                Ok(socket_path) => ShimResponse::ExecReady {
                    session_id: Some(session_id),
                    socket_path,
                },
                Err(e) => ShimResponse::Error {
                    message: format!("exec failed: {e}"),
                },
            }
        }
        ShimRequest::Attach { id, pty } => {
            tracing::info!(container = %id, pty, "attach to container");
            // Attach to an existing container's PTY requires the container
            // to have been started with a PTY. For now, return not supported
            // since Phase 3 containers use log-file stdio.
            ShimResponse::Error {
                message: "attach to non-PTY container not supported — use `exec -it` instead"
                    .into(),
            }
        }
    }
}
