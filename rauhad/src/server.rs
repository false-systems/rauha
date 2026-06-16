use std::sync::Arc;
use tokio::sync::mpsc;
use tokio_stream::wrappers::ReceiverStream;
use tonic::{Request, Response, Status, Streaming};

use rauha_common::error::RauhaError;
#[cfg(target_os = "linux")]
use rauha_evidence::{
    event_name, FalseEventBuilder, FieldValue, ResourceAttrs, Severity, BACKEND_LINUX_EBPF,
};

use crate::zone::registry::ZoneRegistry;

/// Convert RauhaError to the appropriate gRPC status code.
/// The error type system already distinguishes not-found, already-exists,
/// invalid-argument, etc. — this function preserves that at the gRPC boundary.
fn to_status(e: RauhaError) -> Status {
    match &e {
        RauhaError::ZoneNotFound(_)
        | RauhaError::ContainerNotFound(_)
        | RauhaError::ImageNotFound(_) => Status::not_found(e.to_string()),

        RauhaError::ZoneAlreadyExists(_) | RauhaError::ContainerAlreadyExists { .. } => {
            Status::already_exists(e.to_string())
        }

        RauhaError::InvalidInput(_) | RauhaError::InvalidPolicy(_) => {
            Status::invalid_argument(e.to_string())
        }

        RauhaError::PermissionDenied(_) | RauhaError::CrossZoneAccessDenied { .. } => {
            Status::permission_denied(e.to_string())
        }

        RauhaError::ZoneNotEmpty { .. } => Status::failed_precondition(e.to_string()),

        _ => Status::internal(e.to_string()),
    }
}

pub mod pb {
    pub mod zone {
        tonic::include_proto!("rauha.zone.v1");
    }
    pub mod container {
        tonic::include_proto!("rauha.container.v1");
    }
    pub mod image {
        tonic::include_proto!("rauha.image.v1");
    }
    pub mod sandbox {
        tonic::include_proto!("rauha.sandbox.v1");
    }
}

use pb::zone::zone_service_server::ZoneService;
use pb::container::container_service_server::ContainerService;
use pb::image::image_service_server::ImageService;
use pb::sandbox::sandbox_service_server::SandboxService;

// --- Zone Service ---

pub struct ZoneServiceImpl {
    registry: Arc<ZoneRegistry>,
    root: String,
    /// Enforcement event broadcast sender (Linux only, None on macOS).
    #[cfg(target_os = "linux")]
    event_tx: Option<tokio::sync::broadcast::Sender<rauha_evidence::FalseEvent>>,
}

impl ZoneServiceImpl {
    pub fn new(
        registry: Arc<ZoneRegistry>,
        root: String,
        #[cfg(target_os = "linux")]
        event_tx: Option<tokio::sync::broadcast::Sender<rauha_evidence::FalseEvent>>,
    ) -> Self {
        Self {
            registry,
            root,
            #[cfg(target_os = "linux")]
            event_tx,
        }
    }
}

#[tonic::async_trait]
impl ZoneService for ZoneServiceImpl {
    async fn create_zone(
        &self,
        request: Request<pb::zone::CreateZoneRequest>,
    ) -> Result<Response<pb::zone::CreateZoneResponse>, Status> {
        let req = request.into_inner();

        // Zone type from gRPC request field.
        let zone_type = match req.zone_type.as_str() {
            "privileged" => rauha_common::zone::ZoneType::Privileged,
            "global" => rauha_common::zone::ZoneType::Global,
            _ => rauha_common::zone::ZoneType::NonGlobal,
        };

        // Reject oversized policy TOML to prevent memory exhaustion during parsing.
        const MAX_POLICY_SIZE: usize = 64 * 1024;
        if req.policy_toml.len() > MAX_POLICY_SIZE {
            return Err(Status::invalid_argument(format!(
                "policy_toml exceeds maximum size of {MAX_POLICY_SIZE} bytes"
            )));
        }

        let policy = if req.policy_toml.is_empty() {
            rauha_common::zone::ZonePolicy::default()
        } else {
            let (_toml_zone_type, parsed_policy) =
                crate::zone::policy::parse_policy(&req.policy_toml, &self.root)
                    .map_err(|e| Status::invalid_argument(e.to_string()))?;

            // The gRPC request's zone_type takes precedence over the TOML's
            // [zone].type field. This allows reusing a policy file across
            // different zone types.
            parsed_policy
        };

        let zone = self
            .registry
            .create_zone(&req.name, zone_type, policy)
            .await
            .map_err(to_status)?;

        Ok(Response::new(pb::zone::CreateZoneResponse {
            zone_id: zone.id.to_string(),
            name: zone.name,
            state: format!("{:?}", zone.state),
        }))
    }

    async fn delete_zone(
        &self,
        request: Request<pb::zone::DeleteZoneRequest>,
    ) -> Result<Response<pb::zone::DeleteZoneResponse>, Status> {
        let req = request.into_inner();
        self.registry
            .delete_zone(&req.name, req.force)
            .await
            .map_err(to_status)?;
        Ok(Response::new(pb::zone::DeleteZoneResponse {}))
    }

    async fn get_zone(
        &self,
        request: Request<pb::zone::GetZoneRequest>,
    ) -> Result<Response<pb::zone::GetZoneResponse>, Status> {
        let req = request.into_inner();
        let zone = self
            .registry
            .get_zone(&req.name)
            .await
            .map_err(to_status)?;

        let containers = self
            .registry
            .list_containers(Some(&req.name))
            .map_err(to_status)?;

        Ok(Response::new(pb::zone::GetZoneResponse {
            zone: Some(pb::zone::ZoneInfo {
                id: zone.id.to_string(),
                name: zone.name,
                zone_type: format!("{:?}", zone.zone_type),
                state: format!("{:?}", zone.state),
                container_count: containers.len() as u32,
                created_at: zone.created_at.to_rfc3339(),
            }),
        }))
    }

    async fn list_zones(
        &self,
        _request: Request<pb::zone::ListZonesRequest>,
    ) -> Result<Response<pb::zone::ListZonesResponse>, Status> {
        let zones = self
            .registry
            .list_zones()
            .map_err(to_status)?;

        let zone_infos = zones
            .into_iter()
            .map(|z| {
                let container_count = self
                    .registry
                    .list_containers(Some(&z.name))
                    .map(|c| c.len() as u32)
                    .unwrap_or(0);
                pb::zone::ZoneInfo {
                    id: z.id.to_string(),
                    name: z.name,
                    zone_type: format!("{:?}", z.zone_type),
                    state: format!("{:?}", z.state),
                    container_count,
                    created_at: z.created_at.to_rfc3339(),
                }
            })
            .collect();

        Ok(Response::new(pb::zone::ListZonesResponse {
            zones: zone_infos,
        }))
    }

    async fn apply_policy(
        &self,
        request: Request<pb::zone::ApplyPolicyRequest>,
    ) -> Result<Response<pb::zone::ApplyPolicyResponse>, Status> {
        let req = request.into_inner();

        const MAX_POLICY_SIZE: usize = 64 * 1024;
        if req.policy_toml.len() > MAX_POLICY_SIZE {
            return Err(Status::invalid_argument(format!(
                "policy_toml exceeds maximum size of {MAX_POLICY_SIZE} bytes"
            )));
        }

        let (_zone_type, policy) =
            crate::zone::policy::parse_policy(&req.policy_toml, &self.root)
                .map_err(|e| Status::invalid_argument(e.to_string()))?;

        self.registry
            .apply_policy(&req.zone_name, policy)
            .await
            .map_err(to_status)?;

        Ok(Response::new(pb::zone::ApplyPolicyResponse {}))
    }

    async fn get_policy(
        &self,
        request: Request<pb::zone::GetPolicyRequest>,
    ) -> Result<Response<pb::zone::GetPolicyResponse>, Status> {
        let req = request.into_inner();
        let zone = self
            .registry
            .get_zone(&req.zone_name)
            .await
            .map_err(to_status)?;

        let toml =
            crate::zone::policy::policy_to_toml(&zone.name, zone.zone_type, &zone.policy);

        Ok(Response::new(pb::zone::GetPolicyResponse {
            policy_toml: toml,
        }))
    }

    async fn zone_stats(
        &self,
        request: Request<pb::zone::ZoneStatsRequest>,
    ) -> Result<Response<pb::zone::ZoneStatsResponse>, Status> {
        let req = request.into_inner();
        let stats = self
            .registry
            .zone_stats(&req.zone_name)
            .await
            .map_err(to_status)?;

        Ok(Response::new(pb::zone::ZoneStatsResponse {
            zone_id: stats.zone_id.to_string(),
            container_count: stats.container_count,
            cpu_usage_percent: stats.cpu_usage_percent,
            memory_usage_bytes: stats.memory_usage_bytes,
            memory_limit_bytes: stats.memory_limit_bytes,
            network_rx_bytes: stats.network_rx_bytes,
            network_tx_bytes: stats.network_tx_bytes,
            pids_current: stats.pids_current,
        }))
    }

    async fn verify_isolation(
        &self,
        request: Request<pb::zone::VerifyIsolationRequest>,
    ) -> Result<Response<pb::zone::VerifyIsolationResponse>, Status> {
        let req = request.into_inner();
        let report = self
            .registry
            .verify_isolation(&req.zone_name)
            .await
            .map_err(to_status)?;

        Ok(Response::new(pb::zone::VerifyIsolationResponse {
            is_isolated: report.is_isolated,
            checks: report
                .checks
                .into_iter()
                .map(|c| pb::zone::IsolationCheck {
                    name: c.name,
                    passed: c.passed,
                    detail: c.detail,
                })
                .collect(),
        }))
    }

    type WatchEventsStream = ReceiverStream<Result<pb::zone::ZoneEvent, Status>>;

    async fn watch_events(
        &self,
        request: Request<pb::zone::WatchEventsRequest>,
    ) -> Result<Response<Self::WatchEventsStream>, Status> {
        #[cfg(target_os = "linux")]
        let zone_filter = request.into_inner().zone_name;
        #[cfg(not(target_os = "linux"))]
        let _ = request.into_inner();

        #[cfg(target_os = "linux")]
        let (tx, rx) = mpsc::channel(128);
        #[cfg(not(target_os = "linux"))]
        let (_tx, rx) = mpsc::channel(128);

        #[cfg(target_os = "linux")]
        if let Some(event_tx) = &self.event_tx {
            let mut event_rx = event_tx.subscribe();
            tokio::spawn(async move {
                loop {
                    match event_rx.recv().await {
                        Ok(event) => {
                            // Filter by zone if requested.
                            if !zone_filter.is_empty() {
                                let matches_zone = event.zone.name.as_deref()
                                    == Some(zone_filter.as_str())
                                    || event.zone.id == zone_filter;
                                if !matches_zone {
                                    continue;
                                }
                            }

                            let grpc_event = pb::zone::ZoneEvent {
                                zone_name: event
                                    .zone
                                    .name
                                    .clone()
                                    .unwrap_or_else(|| event.zone.id.clone()),
                                event_type: event.event.clone(),
                                message: event.machine_json().unwrap_or_else(|e| {
                                    format!(
                                        r#"{{"event":"{}","serialization_error":"{}"}}"#,
                                        event.event, e
                                    )
                                }),
                                timestamp: event.ts.clone(),
                            };

                            if tx.send(Ok(grpc_event)).await.is_err() {
                                // Client disconnected.
                                break;
                            }
                        }
                        Err(tokio::sync::broadcast::error::RecvError::Lagged(n)) => {
                            let shed = FalseEventBuilder::new(event_name::PIPELINE_SHED)
                                .level(Severity::Warn)
                                .zone(
                                    if zone_filter.is_empty() {
                                        "zone-unknown".to_string()
                                    } else {
                                        zone_filter.clone()
                                    },
                                    None,
                                )
                                .resource_attributes(ResourceAttrs::new(BACKEND_LINUX_EBPF))
                                .field("shed_events", FieldValue::U64(n))
                                .field(
                                    "reason",
                                    FieldValue::String("watch_subscriber_lagged".into()),
                                )
                                .build();
                            if let Ok(shed) = shed {
                                shed.emit_tracing();
                                let grpc_event = pb::zone::ZoneEvent {
                                    zone_name: shed.zone.id.clone(),
                                    event_type: shed.event.clone(),
                                    message: shed.machine_json().unwrap_or_else(|e| {
                                        format!(
                                            r#"{{"event":"{}","serialization_error":"{}"}}"#,
                                            shed.event, e
                                        )
                                    }),
                                    timestamp: shed.ts.clone(),
                                };
                                if tx.send(Ok(grpc_event)).await.is_err() {
                                    break;
                                }
                            }
                        }
                        Err(tokio::sync::broadcast::error::RecvError::Closed) => break,
                    }
                }
            });
        }

        Ok(Response::new(ReceiverStream::new(rx)))
    }
}

// --- Container Service ---

pub struct ContainerServiceImpl {
    registry: Arc<ZoneRegistry>,
}

impl ContainerServiceImpl {
    pub fn new(registry: Arc<ZoneRegistry>) -> Self {
        Self { registry }
    }
}

#[tonic::async_trait]
impl ContainerService for ContainerServiceImpl {
    async fn create_container(
        &self,
        request: Request<pb::container::CreateContainerRequest>,
    ) -> Result<Response<pb::container::CreateContainerResponse>, Status> {
        let req = request.into_inner();
        let spec = rauha_common::container::ContainerSpec {
            name: req.name,
            image: req.image,
            command: req.command,
            env: req.env.into_iter().collect(),
            working_dir: if req.working_dir.is_empty() {
                None
            } else {
                Some(req.working_dir)
            },
            rootfs_path: None,
            overlay_layers: None,
        };

        let container = self
            .registry
            .create_container(&req.zone_name, spec)
            .await
            .map_err(to_status)?;

        Ok(Response::new(pb::container::CreateContainerResponse {
            container_id: container.id.to_string(),
            name: container.name,
            state: format!("{:?}", container.state),
        }))
    }

    async fn start_container(
        &self,
        request: Request<pb::container::StartContainerRequest>,
    ) -> Result<Response<pb::container::StartContainerResponse>, Status> {
        let req = request.into_inner();
        let container_id = req
            .container_id
            .parse::<uuid::Uuid>()
            .map_err(|e| Status::invalid_argument(format!("invalid container ID: {e}")))?;

        self.registry
            .start_container(&container_id)
            .await
            .map_err(to_status)?;

        Ok(Response::new(pb::container::StartContainerResponse {}))
    }

    async fn stop_container(
        &self,
        request: Request<pb::container::StopContainerRequest>,
    ) -> Result<Response<pb::container::StopContainerResponse>, Status> {
        let req = request.into_inner();
        let container_id = req
            .container_id
            .parse::<uuid::Uuid>()
            .map_err(|e| Status::invalid_argument(format!("invalid container ID: {e}")))?;

        self.registry
            .stop_container(&container_id, req.timeout_seconds)
            .await
            .map_err(to_status)?;

        Ok(Response::new(pb::container::StopContainerResponse {}))
    }

    async fn delete_container(
        &self,
        request: Request<pb::container::DeleteContainerRequest>,
    ) -> Result<Response<pb::container::DeleteContainerResponse>, Status> {
        let req = request.into_inner();
        let container_id = req
            .container_id
            .parse::<uuid::Uuid>()
            .map_err(|e| Status::invalid_argument(format!("invalid container ID: {e}")))?;

        self.registry
            .delete_container(&container_id, req.force)
            .await
            .map_err(to_status)?;

        Ok(Response::new(pb::container::DeleteContainerResponse {}))
    }

    async fn get_container(
        &self,
        request: Request<pb::container::GetContainerRequest>,
    ) -> Result<Response<pb::container::GetContainerResponse>, Status> {
        let req = request.into_inner();
        let container_id = req
            .container_id
            .parse::<uuid::Uuid>()
            .map_err(|e| Status::invalid_argument(format!("invalid container ID: {e}")))?;

        let container = self
            .registry
            .get_container(&container_id)
            .map_err(to_status)?;
        let zone_name = self
            .registry
            .zone_name_for_container(&container.zone_id)
            .await
            .ok_or_else(|| Status::internal("zone not found for container"))?;

        Ok(Response::new(pb::container::GetContainerResponse {
            container: Some(pb::container::ContainerInfo {
                id: container.id.to_string(),
                name: container.name,
                zone_id: container.zone_id.to_string(),
                zone_name,
                image: container.image,
                state: format!("{:?}", container.state),
                pid: container.pid.unwrap_or(0),
                created_at: container.created_at.to_rfc3339(),
                started_at: container
                    .started_at
                    .map(|t| t.to_rfc3339())
                    .unwrap_or_default(),
            }),
        }))
    }

    async fn list_containers(
        &self,
        request: Request<pb::container::ListContainersRequest>,
    ) -> Result<Response<pb::container::ListContainersResponse>, Status> {
        let req = request.into_inner();
        let zone_filter = if req.zone_name.is_empty() {
            None
        } else {
            Some(req.zone_name.as_str())
        };

        let containers = self
            .registry
            .list_containers(zone_filter)
            .map_err(to_status)?;

        let mut infos = Vec::with_capacity(containers.len());
        for c in containers {
            let zone_name = self
                .registry
                .zone_name_for_container(&c.zone_id)
                .await
                .ok_or_else(|| Status::internal("zone not found for container"))?;
            infos.push(pb::container::ContainerInfo {
                id: c.id.to_string(),
                name: c.name,
                zone_id: c.zone_id.to_string(),
                zone_name,
                image: c.image,
                state: format!("{:?}", c.state),
                pid: c.pid.unwrap_or(0),
                created_at: c.created_at.to_rfc3339(),
                started_at: c.started_at.map(|t| t.to_rfc3339()).unwrap_or_default(),
            });
        }

        Ok(Response::new(pb::container::ListContainersResponse {
            containers: infos,
        }))
    }

    type ContainerLogsStream = ReceiverStream<Result<pb::container::ContainerLogEntry, Status>>;

    async fn container_logs(
        &self,
        request: Request<pb::container::ContainerLogsRequest>,
    ) -> Result<Response<Self::ContainerLogsStream>, Status> {
        let req = request.into_inner();
        let container_id = req
            .container_id
            .parse::<uuid::Uuid>()
            .map_err(|e| Status::invalid_argument(format!("invalid container ID: {e}")))?;

        // Verify container exists.
        self.registry
            .get_container(&container_id)
            .map_err(to_status)?;

        let (tx, rx) = mpsc::channel(256);
        let follow = req.follow;
        let tail = req.tail;
        let id_str = container_id.to_string();

        // Cancellation flag: set when the tx channel is dropped (client disconnects).
        let cancelled = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
        let cancelled_clone = cancelled.clone();

        // Monitor the receiver: when the client drops, signal cancellation.
        let tx_clone = tx.clone();
        tokio::spawn(async move {
            tx_clone.closed().await;
            cancelled_clone.store(true, std::sync::atomic::Ordering::Relaxed);
        });

        tokio::task::spawn_blocking(move || {
            crate::logs::tail_logs(&id_str, follow, tail, &cancelled, |log_line| {
                tx.blocking_send(Ok(pb::container::ContainerLogEntry {
                    source: log_line.source,
                    line: log_line.line,
                    timestamp: log_line.timestamp,
                }))
                .is_ok()
            });
        });

        Ok(Response::new(ReceiverStream::new(rx)))
    }

    async fn exec_in_container(
        &self,
        _request: Request<pb::container::ExecInContainerRequest>,
    ) -> Result<Response<pb::container::ExecInContainerResponse>, Status> {
        Err(Status::unimplemented(
            "exec_in_container: use ExecStream for interactive exec",
        ))
    }

    type ExecStreamStream = ReceiverStream<Result<pb::container::ExecStreamResponse, Status>>;

    async fn exec_stream(
        &self,
        request: Request<Streaming<pb::container::ExecStreamRequest>>,
    ) -> Result<Response<Self::ExecStreamStream>, Status> {
        use tokio_stream::StreamExt;

        let mut in_stream = request.into_inner();

        // First message must be ExecStreamStart.
        let start = match in_stream.next().await {
            Some(Ok(msg)) => match msg.message {
                Some(pb::container::exec_stream_request::Message::Start(s)) => s,
                _ => return Err(Status::invalid_argument("first message must be ExecStreamStart")),
            },
            _ => return Err(Status::invalid_argument("empty stream")),
        };

        let container_id = start
            .container_id
            .parse::<uuid::Uuid>()
            .map_err(|e| Status::invalid_argument(format!("invalid container ID: {e}")))?;

        // Verify container exists and get its zone.
        let container = self
            .registry
            .get_container(&container_id)
            .map_err(to_status)?;

        // Look up zone name.
        let zone_name = self
            .registry
            .zone_name_for_container(&container.zone_id)
            .await
            .ok_or_else(|| Status::internal("zone not found for container"))?;

        // Send Exec request to shim.
        let exec_req = rauha_common::shim::ShimRequest::Exec {
            id: container_id.to_string(),
            command: start.command,
            env: start.env.into_iter().map(|(k, v)| format!("{k}={v}")).collect(),
            pty: start.tty,
        };

        let response = self
            .registry
            .shim_request(&zone_name, &exec_req)
            .await
            .map_err(|e| Status::internal(format!("shim exec failed: {e}")))?;

        let (tx, rx) = mpsc::channel(256);

        // Connect to the exec session and spawn relay tasks.
        // The transport differs by platform but the relay logic is identical.
        match response {
            rauha_common::shim::ShimResponse::ExecReady {
                session_id,
                socket_path: Some(path),
                ..
            } => {
                let stream = tokio::net::UnixStream::connect(&path).await.map_err(|e| {
                    Status::internal(format!("failed to connect to exec socket: {e}"))
                })?;
                let (r, w) = stream.into_split();
                spawn_exec_relay(
                    r,
                    w,
                    tx,
                    in_stream,
                    Some(PtyResizeTarget {
                        registry: self.registry.clone(),
                        zone_name: zone_name.clone(),
                        container_id: container_id.to_string(),
                        session_id,
                    }),
                );
            }
            rauha_common::shim::ShimResponse::ExecReady {
                session_id,
                vsock_port: Some(port),
                ..
            } => {
                let stream = self
                    .registry
                    .connect_exec_vsock(&zone_name, port)
                    .await
                    .map_err(|e| {
                        Status::internal(format!("failed to connect exec vsock: {e}"))
                    })?;
                let (r, w) = tokio::io::split(stream);
                spawn_exec_relay(
                    r,
                    w,
                    tx,
                    in_stream,
                    Some(PtyResizeTarget {
                        registry: self.registry.clone(),
                        zone_name: zone_name.clone(),
                        container_id: container_id.to_string(),
                        session_id,
                    }),
                );
            }
            // Legacy: accept AttachReady for backward compat with older shims.
            rauha_common::shim::ShimResponse::AttachReady {
                socket_path,
                session_id,
            } => {
                let stream = tokio::net::UnixStream::connect(&socket_path)
                    .await
                    .map_err(|e| {
                        Status::internal(format!("failed to connect to attach socket: {e}"))
                    })?;
                let (r, w) = stream.into_split();
                spawn_exec_relay(
                    r,
                    w,
                    tx,
                    in_stream,
                    Some(PtyResizeTarget {
                        registry: self.registry.clone(),
                        zone_name: zone_name.clone(),
                        container_id: container_id.to_string(),
                        session_id,
                    }),
                );
            }
            rauha_common::shim::ShimResponse::Error { message } => {
                return Err(Status::internal(format!("exec failed: {message}")));
            }
            _ => return Err(Status::internal("unexpected shim response")),
        };

        Ok(Response::new(ReceiverStream::new(rx)))
    }

    type AttachStream = ReceiverStream<Result<pb::container::AttachResponse, Status>>;

    async fn attach(
        &self,
        request: Request<Streaming<pb::container::AttachRequest>>,
    ) -> Result<Response<Self::AttachStream>, Status> {
        use tokio_stream::StreamExt;

        let mut in_stream = request.into_inner();

        // First message must be AttachStart.
        let start = match in_stream.next().await {
            Some(Ok(msg)) => match msg.message {
                Some(pb::container::attach_request::Message::Start(s)) => s,
                _ => return Err(Status::invalid_argument("first message must be AttachStart")),
            },
            _ => return Err(Status::invalid_argument("empty stream")),
        };

        let container_id = start
            .container_id
            .parse::<uuid::Uuid>()
            .map_err(|e| Status::invalid_argument(format!("invalid container ID: {e}")))?;

        let container = self
            .registry
            .get_container(&container_id)
            .map_err(to_status)?;

        let zone_name = self
            .registry
            .zone_name_for_container(&container.zone_id)
            .await
            .ok_or_else(|| Status::internal("zone not found for container"))?;

        let attach_req = rauha_common::shim::ShimRequest::Attach {
            id: container_id.to_string(),
            pty: true,
        };

        let response = self
            .registry
            .shim_request(&zone_name, &attach_req)
            .await
            .map_err(|e| Status::internal(format!("shim attach failed: {e}")))?;

        match response {
            rauha_common::shim::ShimResponse::AttachReady {
                socket_path,
                session_id,
            } => {
                let stream = tokio::net::UnixStream::connect(&socket_path)
                    .await
                    .map_err(|e| {
                        Status::internal(format!("failed to connect to attach socket: {e}"))
                    })?;

                let (read_half, write_half) = stream.into_split();
                let (tx, rx) = mpsc::channel(256);
                let resize_target = PtyResizeTarget {
                    registry: self.registry.clone(),
                    zone_name,
                    container_id: container_id.to_string(),
                    session_id,
                };

                tokio::spawn(async move {
                    use tokio::io::AsyncReadExt;
                    let mut reader = read_half;
                    let mut buf = [0u8; 4096];
                    loop {
                        match reader.read(&mut buf).await {
                            Ok(0) => break,
                            Ok(n) => {
                                let resp = pb::container::AttachResponse {
                                    message: Some(
                                        pb::container::attach_response::Message::StdoutData(
                                            buf[..n].to_vec(),
                                        ),
                                    ),
                                };
                                if tx.send(Ok(resp)).await.is_err() {
                                    break;
                                }
                            }
                            Err(_) => break,
                        }
                    }
                });

                tokio::spawn(async move {
                    use tokio::io::AsyncWriteExt;
                    let mut writer = write_half;
                    while let Some(Ok(msg)) = in_stream.next().await {
                        match msg.message {
                            Some(pb::container::attach_request::Message::StdinData(data)) => {
                                if writer.write_all(&data).await.is_err() {
                                    break;
                                }
                            }
                            Some(pb::container::attach_request::Message::Resize(resize)) => {
                                resize_target.resize(resize.rows, resize.cols).await;
                            }
                            _ => {}
                        }
                    }
                });

                Ok(Response::new(ReceiverStream::new(rx)))
            }
            rauha_common::shim::ShimResponse::Error { message } => {
                Err(Status::internal(format!("attach failed: {message}")))
            }
            _ => Err(Status::internal("unexpected shim response")),
        }
    }
}

/// Spawn read and write relay tasks between an exec I/O stream and gRPC.
///
/// Generic over the stream type so it works with both Unix sockets (Linux)
/// and vsock streams (macOS).
fn spawn_exec_relay<R, W>(
    reader: R,
    writer: W,
    tx: mpsc::Sender<Result<pb::container::ExecStreamResponse, Status>>,
    in_stream: Streaming<pb::container::ExecStreamRequest>,
    resize_target: Option<PtyResizeTarget>,
) where
    R: tokio::io::AsyncRead + Unpin + Send + 'static,
    W: tokio::io::AsyncWrite + Unpin + Send + 'static,
{
    use tokio_stream::StreamExt;

    // Read from exec stream → send to gRPC client.
    tokio::spawn(async move {
        use tokio::io::AsyncReadExt;
        let mut reader = reader;
        let mut buf = [0u8; 4096];
        loop {
            match reader.read(&mut buf).await {
                Ok(0) => break,
                Ok(n) => {
                    let resp = pb::container::ExecStreamResponse {
                        message: Some(
                            pb::container::exec_stream_response::Message::StdoutData(
                                buf[..n].to_vec(),
                            ),
                        ),
                    };
                    if tx.send(Ok(resp)).await.is_err() {
                        break;
                    }
                }
                Err(_) => break,
            }
        }
    });

    // Read from gRPC client → write to exec stream.
    tokio::spawn(async move {
        use tokio::io::AsyncWriteExt;
        let mut writer = writer;
        let mut in_stream = in_stream;
        while let Some(Ok(msg)) = in_stream.next().await {
            match msg.message {
                Some(pb::container::exec_stream_request::Message::StdinData(data)) => {
                    if writer.write_all(&data).await.is_err() {
                        break;
                    }
                }
                Some(pb::container::exec_stream_request::Message::Resize(resize)) => {
                    if let Some(target) = &resize_target {
                        target.resize(resize.rows, resize.cols).await;
                    }
                }
                _ => {}
            }
        }
    });
}

#[derive(Clone)]
struct PtyResizeTarget {
    registry: Arc<ZoneRegistry>,
    zone_name: String,
    container_id: String,
    session_id: Option<String>,
}

impl PtyResizeTarget {
    async fn resize(&self, rows: u32, cols: u32) {
        let request = rauha_common::shim::ShimRequest::ResizePty {
            id: self.container_id.clone(),
            session_id: self.session_id.clone(),
            rows,
            cols,
        };

        match self.registry.shim_request(&self.zone_name, &request).await {
            Ok(rauha_common::shim::ShimResponse::Ok) => {}
            Ok(rauha_common::shim::ShimResponse::Error { message }) => {
                tracing::warn!(
                    zone = %self.zone_name,
                    container = %self.container_id,
                    error = %message,
                    "PTY resize failed"
                );
            }
            Ok(other) => {
                tracing::warn!(
                    zone = %self.zone_name,
                    container = %self.container_id,
                    response = ?other,
                    "unexpected PTY resize response"
                );
            }
            Err(e) => {
                tracing::warn!(
                    zone = %self.zone_name,
                    container = %self.container_id,
                    error = %e,
                    "PTY resize request failed"
                );
            }
        }
    }
}

// --- Image Service ---

pub struct ImageServiceImpl {
    image_service: Arc<rauha_oci::image::ImageService>,
}

impl ImageServiceImpl {
    pub fn new(image_service: Arc<rauha_oci::image::ImageService>) -> Self {
        Self { image_service }
    }
}

#[tonic::async_trait]
impl ImageService for ImageServiceImpl {
    type PullStream = ReceiverStream<Result<pb::image::PullProgress, Status>>;

    async fn pull(
        &self,
        request: Request<pb::image::PullRequest>,
    ) -> Result<Response<Self::PullStream>, Status> {
        let req = request.into_inner();
        let (tx, rx) = mpsc::channel(64);
        let svc = self.image_service.clone();

        tokio::spawn(async move {
            let reference = req.reference;
            let tx_clone = tx.clone();

            let result = svc
                .pull(&reference, |progress| {
                    let _ = tx_clone.try_send(Ok(pb::image::PullProgress {
                        status: progress.status,
                        layer: progress.layer,
                        current: progress.current,
                        total: progress.total,
                        done: progress.done,
                    }));
                })
                .await;

            if let Err(e) = result {
                let _ = tx.send(Err(Status::internal(e.to_string()))).await;
            }
        });

        Ok(Response::new(ReceiverStream::new(rx)))
    }

    async fn list(
        &self,
        _request: Request<pb::image::ListImagesRequest>,
    ) -> Result<Response<pb::image::ListImagesResponse>, Status> {
        let images = self
            .image_service
            .list_images()
            .map_err(to_status)?;

        let infos = images
            .into_iter()
            .map(|img| pb::image::ImageInfo {
                digest: img.digest,
                tags: vec![img.reference],
                size: img.size,
                created_at: String::new(),
            })
            .collect();

        Ok(Response::new(pb::image::ListImagesResponse {
            images: infos,
        }))
    }

    async fn remove(
        &self,
        request: Request<pb::image::RemoveImageRequest>,
    ) -> Result<Response<pb::image::RemoveImageResponse>, Status> {
        let req = request.into_inner();
        self.image_service
            .remove_image(&req.reference)
            .map_err(to_status)?;
        Ok(Response::new(pb::image::RemoveImageResponse {}))
    }

    async fn inspect(
        &self,
        request: Request<pb::image::InspectImageRequest>,
    ) -> Result<Response<pb::image::InspectImageResponse>, Status> {
        let req = request.into_inner();
        let inspection = self
            .image_service
            .inspect_full(&req.reference)
            .map_err(to_status)?;

        Ok(Response::new(pb::image::InspectImageResponse {
            digest: inspection.digest,
            tags: vec![req.reference],
            size: inspection.size,
            config_json: inspection.config_json,
            layers: inspection.layers,
        }))
    }
}

// --- Sandbox Service ---
//
// Task-level sandbox execution. The runtime path (allocate zone, start
// container, wait, capture stdout/stderr/exit, collect events, clean up)
// is not implemented yet — this impl exists to land the public contract.
// The next PR replaces the Unimplemented body with a real implementation
// built on top of existing zone/container primitives.

pub struct SandboxServiceImpl;

impl SandboxServiceImpl {
    pub fn new() -> Self {
        Self
    }
}

impl Default for SandboxServiceImpl {
    fn default() -> Self {
        Self::new()
    }
}

#[tonic::async_trait]
impl SandboxService for SandboxServiceImpl {
    async fn run_sandbox(
        &self,
        _request: Request<pb::sandbox::RunSandboxRequest>,
    ) -> Result<Response<pb::sandbox::SandboxResult>, Status> {
        Err(Status::unimplemented(
            "sandbox execution is not implemented yet; use zone/run/exec commands or see docs/sandbox-runtime.md",
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tonic::Code;

    #[tokio::test]
    async fn sandbox_service_returns_unimplemented_contract() {
        let service = SandboxServiceImpl::new();
        let request = Request::new(pb::sandbox::RunSandboxRequest::default());

        let status = service
            .run_sandbox(request)
            .await
            .expect_err("sandbox runtime should not be implemented in this PR");

        assert_eq!(status.code(), Code::Unimplemented);
        assert_eq!(
            status.message(),
            "sandbox execution is not implemented yet; use zone/run/exec commands or see docs/sandbox-runtime.md"
        );
    }
}
