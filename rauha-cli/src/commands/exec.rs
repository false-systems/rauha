use clap::Args;

pub mod pb {
    pub mod container {
        tonic::include_proto!("rauha.container.v1");
    }
}

use pb::container::container_service_client::ContainerServiceClient;

#[derive(Args)]
pub struct ExecArgs {
    /// Container ID
    pub container_id: String,
    /// Allocate a pseudo-TTY
    #[arg(short = 'i', long = "interactive")]
    pub interactive: bool,
    /// Allocate a TTY
    #[arg(short = 't', long = "tty")]
    pub tty: bool,
    /// Command to run
    #[arg(trailing_var_arg = true, required = true)]
    pub command: Vec<String>,
}

#[derive(Args)]
pub struct AttachArgs {
    /// Container ID
    pub container_id: String,
}

pub async fn handle_exec(args: ExecArgs) -> anyhow::Result<()> {
    let channel = super::connect().await?;
    let mut client = ContainerServiceClient::new(channel);

    let use_tty = args.tty || args.interactive;

    // Build the initial start message.
    let start_msg = pb::container::ExecStreamRequest {
        message: Some(pb::container::exec_stream_request::Message::Start(
            pb::container::ExecStreamStart {
                container_id: args.container_id,
                command: args.command,
                env: Default::default(),
                tty: use_tty,
            },
        )),
    };

    // Create a channel for sending messages to the server.
    let (tx, rx) = tokio::sync::mpsc::channel(64);
    tx.send(start_msg).await?;

    let in_stream = tokio_stream::wrappers::ReceiverStream::new(rx);

    let response = client.exec_stream(in_stream).await?;
    let mut out_stream = response.into_inner();

    // If TTY mode, set terminal to raw mode.
    #[cfg(unix)]
    let _raw_guard = if use_tty { set_raw_mode() } else { None };

    // Spawn task to read stdin and send to server.
    let tx_clone = tx.clone();
    tokio::spawn(async move {
        use tokio::io::AsyncReadExt;
        let mut stdin = tokio::io::stdin();
        let mut buf = [0u8; 1024];
        loop {
            match stdin.read(&mut buf).await {
                Ok(0) => break,
                Ok(n) => {
                    let msg = pb::container::ExecStreamRequest {
                        message: Some(pb::container::exec_stream_request::Message::StdinData(
                            buf[..n].to_vec(),
                        )),
                    };
                    if tx_clone.send(msg).await.is_err() {
                        break;
                    }
                }
                Err(_) => break,
            }
        }
    });

    // Read from server and write to stdout.
    let mut exit_code = None;
    use tokio_stream::StreamExt;
    while let Some(result) = out_stream.next().await {
        match result {
            Ok(resp) => match resp.message {
                Some(pb::container::exec_stream_response::Message::StdoutData(data)) => {
                    use std::io::Write;
                    let _ = std::io::stdout().write_all(&data);
                    let _ = std::io::stdout().flush();
                }
                Some(pb::container::exec_stream_response::Message::StderrData(data)) => {
                    use std::io::Write;
                    let _ = std::io::stderr().write_all(&data);
                    let _ = std::io::stderr().flush();
                }
                Some(pb::container::exec_stream_response::Message::ExitCode(code)) => {
                    exit_code = Some(code);
                    break;
                }
                None => {}
            },
            Err(e) => {
                return Err(e.into());
            }
        }
    }

    // Drop _raw_guard before exiting so terminal state is restored.
    drop(_raw_guard);

    let code =
        exit_code.ok_or_else(|| anyhow::anyhow!("exec stream ended without an exit status"))?;
    std::process::exit(code);
}

pub async fn handle_attach(args: AttachArgs) -> anyhow::Result<()> {
    let channel = super::connect().await?;
    let mut client = ContainerServiceClient::new(channel);

    let start_msg = pb::container::AttachRequest {
        message: Some(pb::container::attach_request::Message::Start(
            pb::container::AttachStart {
                container_id: args.container_id,
            },
        )),
    };

    let (tx, rx) = tokio::sync::mpsc::channel(64);
    tx.send(start_msg).await?;

    let in_stream = tokio_stream::wrappers::ReceiverStream::new(rx);
    let response = client.attach(in_stream).await?;
    let mut out_stream = response.into_inner();

    #[cfg(unix)]
    let _raw_guard = set_raw_mode();

    // Stdin -> server.
    let tx_clone = tx.clone();
    tokio::spawn(async move {
        use tokio::io::AsyncReadExt;
        let mut stdin = tokio::io::stdin();
        let mut buf = [0u8; 1024];
        loop {
            match stdin.read(&mut buf).await {
                Ok(0) => break,
                Ok(n) => {
                    let msg = pb::container::AttachRequest {
                        message: Some(pb::container::attach_request::Message::StdinData(
                            buf[..n].to_vec(),
                        )),
                    };
                    if tx_clone.send(msg).await.is_err() {
                        break;
                    }
                }
                Err(_) => break,
            }
        }
    });

    // Server -> stdout.
    let mut exit_code = None;
    use tokio_stream::StreamExt;
    while let Some(result) = out_stream.next().await {
        match result {
            Ok(resp) => match resp.message {
                Some(pb::container::attach_response::Message::StdoutData(data)) => {
                    use std::io::Write;
                    let _ = std::io::stdout().write_all(&data);
                    let _ = std::io::stdout().flush();
                }
                Some(pb::container::attach_response::Message::ExitCode(code)) => {
                    exit_code = Some(code);
                    break;
                }
                None => {}
            },
            Err(e) => {
                eprintln!("Error: {e}");
                break;
            }
        }
    }

    // Drop _raw_guard before exiting so terminal state is restored.
    drop(_raw_guard);

    if let Some(code) = exit_code {
        std::process::exit(code);
    }

    Ok(())
}

/// Set terminal to raw mode and return a guard that restores it on drop.
#[cfg(unix)]
fn set_raw_mode() -> Option<RawModeGuard> {
    use std::os::unix::io::AsRawFd;
    let fd = std::io::stdin().as_raw_fd();
    let original = unsafe {
        let mut termios = std::mem::zeroed();
        if libc::tcgetattr(fd, &mut termios) != 0 {
            return None;
        }
        termios
    };

    let mut raw = original;
    unsafe {
        libc::cfmakeraw(&mut raw);
        libc::tcsetattr(fd, libc::TCSANOW, &raw);
    }

    Some(RawModeGuard { fd, original })
}

#[cfg(unix)]
struct RawModeGuard {
    fd: i32,
    original: libc::termios,
}

#[cfg(unix)]
impl Drop for RawModeGuard {
    fn drop(&mut self) {
        unsafe {
            libc::tcsetattr(self.fd, libc::TCSANOW, &self.original);
        }
    }
}
