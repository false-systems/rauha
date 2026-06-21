//! IPC protocol between rauhad and rauha-shim.
//!
//! Wire format: `[u32 LE length][postcard-encoded message]`
//! Why postcard over protobuf? The shim is sync (no tonic/async runtime).
//! postcard is tiny, sync, and already a workspace dep. This IPC is internal —
//! no compatibility contract with external tools.

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ShimRequest {
    CreateContainer {
        id: String,
        /// OCI runtime spec as JSON.
        spec_json: String,
    },
    StartContainer {
        id: String,
    },
    StopContainer {
        id: String,
        signal: i32,
    },
    Signal {
        id: String,
        signal: i32,
    },
    GetState {
        id: String,
    },
    Shutdown,
    /// Request resource usage stats from all containers in this zone.
    GetStats,
    /// Attach to a running container's PTY.
    /// The shim creates a Unix socket for the attach session and returns its path.
    Attach {
        id: String,
        /// Whether to allocate a PTY for the session.
        pty: bool,
    },
    /// Execute a command in a running container's namespace.
    /// The shim creates a Unix socket for the exec session and returns its path.
    Exec {
        id: String,
        command: Vec<String>,
        env: Vec<String>,
        /// Whether to allocate a PTY for the exec process.
        pty: bool,
    },
    /// Resize an active PTY session.
    ResizePty {
        id: String,
        session_id: Option<String>,
        rows: u32,
        cols: u32,
    },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ShimResponse {
    Ok,
    Created {
        pid: u32,
    },
    State {
        pid: u32,
        status: String,
        exit_code: Option<i32>,
    },
    Error {
        message: String,
    },
    /// Zone-level resource usage statistics.
    Stats {
        cpu_usage_ns: u64,
        memory_bytes: u64,
        pids: u32,
        container_count: u32,
        network_rx_bytes: u64,
        network_tx_bytes: u64,
    },
    /// An attach/exec session is ready. Connect to the socket at `socket_path`
    /// for bidirectional I/O with the container process.
    AttachReady {
        socket_path: String,
        session_id: Option<String>,
    },
    /// An exec session is ready. Connect via the appropriate transport for
    /// bidirectional I/O with the exec process.
    ///
    /// Linux shim sets `socket_path`; macOS guest agent sets `vsock_port`.
    ExecReady {
        /// Internal session identifier used for follow-up control messages.
        session_id: Option<String>,
        /// Unix socket path (Linux shim).
        socket_path: Option<String>,
        /// Vsock port number (macOS guest agent).
        vsock_port: Option<u32>,
    },
}

/// Encode a message to the wire format: [u32 LE length][postcard bytes].
pub fn encode<T: Serialize>(msg: &T) -> Result<Vec<u8>, postcard::Error> {
    let payload = postcard::to_allocvec(msg)?;
    let len = (payload.len() as u32).to_le_bytes();
    let mut buf = Vec::with_capacity(4 + payload.len());
    buf.extend_from_slice(&len);
    buf.extend_from_slice(&payload);
    Ok(buf)
}

/// Read a length-prefixed message from a reader.
pub fn decode_from<T: for<'de> Deserialize<'de>>(
    reader: &mut impl std::io::Read,
) -> Result<T, ShimIoError> {
    let mut len_buf = [0u8; 4];
    reader.read_exact(&mut len_buf).map_err(ShimIoError::Io)?;
    let len = u32::from_le_bytes(len_buf) as usize;

    if len > 1024 * 1024 {
        return Err(ShimIoError::MessageTooLarge(len));
    }

    let mut payload = vec![0u8; len];
    reader.read_exact(&mut payload).map_err(ShimIoError::Io)?;
    postcard::from_bytes(&payload).map_err(ShimIoError::Decode)
}

/// Write a length-prefixed message to a writer.
pub fn encode_to<T: Serialize>(
    writer: &mut impl std::io::Write,
    msg: &T,
) -> Result<(), ShimIoError> {
    let buf = encode(msg).map_err(ShimIoError::Encode)?;
    writer.write_all(&buf).map_err(ShimIoError::Io)?;
    writer.flush().map_err(ShimIoError::Io)?;
    Ok(())
}

#[derive(Debug)]
pub enum ShimIoError {
    Io(std::io::Error),
    Encode(postcard::Error),
    Decode(postcard::Error),
    MessageTooLarge(usize),
}

impl std::fmt::Display for ShimIoError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Io(e) => write!(f, "shim I/O error: {e}"),
            Self::Encode(e) => write!(f, "shim encode error: {e}"),
            Self::Decode(e) => write!(f, "shim decode error: {e}"),
            Self::MessageTooLarge(n) => write!(f, "shim message too large: {n} bytes"),
        }
    }
}

impl std::error::Error for ShimIoError {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip_request() {
        let req = ShimRequest::CreateContainer {
            id: "test-123".into(),
            spec_json: r#"{"root":{"path":"/rootfs"}}"#.into(),
        };
        let encoded = encode(&req).unwrap();
        let decoded: ShimRequest = decode_from(&mut &encoded[..]).unwrap();
        match decoded {
            ShimRequest::CreateContainer { id, spec_json } => {
                assert_eq!(id, "test-123");
                assert!(spec_json.contains("rootfs"));
            }
            _ => panic!("wrong variant"),
        }
    }

    #[test]
    fn roundtrip_response() {
        let resp = ShimResponse::Created { pid: 42 };
        let encoded = encode(&resp).unwrap();
        let decoded: ShimResponse = decode_from(&mut &encoded[..]).unwrap();
        match decoded {
            ShimResponse::Created { pid } => assert_eq!(pid, 42),
            _ => panic!("wrong variant"),
        }
    }

    #[test]
    fn roundtrip_all_request_variants() {
        let cases: Vec<ShimRequest> = vec![
            ShimRequest::CreateContainer {
                id: "c1".into(),
                spec_json: "{}".into(),
            },
            ShimRequest::StartContainer { id: "c1".into() },
            ShimRequest::StopContainer {
                id: "c1".into(),
                signal: 15,
            },
            ShimRequest::Signal {
                id: "c1".into(),
                signal: 9,
            },
            ShimRequest::GetState { id: "c1".into() },
            ShimRequest::Shutdown,
            ShimRequest::GetStats,
            ShimRequest::Attach {
                id: "c1".into(),
                pty: true,
            },
            ShimRequest::Exec {
                id: "c1".into(),
                command: vec!["/bin/sh".into()],
                env: vec!["TERM=xterm".into()],
                pty: true,
            },
            ShimRequest::ResizePty {
                id: "c1".into(),
                session_id: Some("session-1".into()),
                rows: 40,
                cols: 120,
            },
        ];

        for req in cases {
            let encoded = encode(&req).unwrap();
            let _decoded: ShimRequest = decode_from(&mut &encoded[..]).unwrap();
        }
    }

    #[test]
    fn roundtrip_all_response_variants() {
        let cases: Vec<ShimResponse> = vec![
            ShimResponse::Ok,
            ShimResponse::Created { pid: 12345 },
            ShimResponse::State {
                pid: 999,
                status: "running".into(),
                exit_code: None,
            },
            ShimResponse::State {
                pid: 999,
                status: "stopped".into(),
                exit_code: Some(42),
            },
            ShimResponse::Error {
                message: "something failed".into(),
            },
            ShimResponse::Stats {
                cpu_usage_ns: 1_000_000,
                memory_bytes: 64 * 1024 * 1024,
                pids: 5,
                container_count: 2,
                network_rx_bytes: 1024,
                network_tx_bytes: 2048,
            },
            ShimResponse::AttachReady {
                socket_path: "/run/rauha/containers/abc/attach-123.sock".into(),
                session_id: Some("attach-123".into()),
            },
            ShimResponse::ExecReady {
                session_id: Some("exec-456".into()),
                socket_path: Some("/run/rauha/containers/abc/exec-456.sock".into()),
                vsock_port: None,
            },
            ShimResponse::ExecReady {
                session_id: Some("exec-vsock".into()),
                socket_path: None,
                vsock_port: Some(6001),
            },
        ];

        for resp in cases {
            let encoded = encode(&resp).unwrap();
            let _decoded: ShimResponse = decode_from(&mut &encoded[..]).unwrap();
        }
    }

    #[test]
    fn encode_to_decode_from_stream() {
        let req = ShimRequest::StopContainer {
            id: "test".into(),
            signal: 15,
        };

        let mut buf = Vec::new();
        encode_to(&mut buf, &req).unwrap();

        let decoded: ShimRequest = decode_from(&mut &buf[..]).unwrap();
        match decoded {
            ShimRequest::StopContainer { id, signal } => {
                assert_eq!(id, "test");
                assert_eq!(signal, 15);
            }
            _ => panic!("wrong variant"),
        }
    }

    #[test]
    fn multiple_messages_on_stream() {
        let mut buf = Vec::new();

        let req1 = ShimRequest::StartContainer { id: "a".into() };
        let req2 = ShimRequest::GetState { id: "b".into() };

        encode_to(&mut buf, &req1).unwrap();
        encode_to(&mut buf, &req2).unwrap();

        let mut cursor = &buf[..];
        let d1: ShimRequest = decode_from(&mut cursor).unwrap();
        let d2: ShimRequest = decode_from(&mut cursor).unwrap();

        match d1 {
            ShimRequest::StartContainer { id } => assert_eq!(id, "a"),
            _ => panic!("wrong variant"),
        }
        match d2 {
            ShimRequest::GetState { id } => assert_eq!(id, "b"),
            _ => panic!("wrong variant"),
        }
    }

    #[test]
    fn truncated_message_returns_error() {
        let req = ShimRequest::Shutdown;
        let encoded = encode(&req).unwrap();

        // Only give it part of the message.
        let truncated = &encoded[..encoded.len() - 1];
        let result = decode_from::<ShimRequest>(&mut &truncated[..]);
        assert!(result.is_err());
    }
}
