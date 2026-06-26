use std::sync::Arc;
use tokio::sync::mpsc;
use tokio_stream::wrappers::ReceiverStream;
use tonic::{Request, Response, Status, Streaming};
use tracing::Instrument;

use rauha_common::error::RauhaError;
use rauha_evidence::{
    event_name, EnforcementMode, EventKind, EventOutcome, FalseEvent, FieldValue,
    RuntimeEventBuilder, Severity, TrustLevel,
};
#[cfg(target_os = "linux")]
use rauha_evidence::{FalseEventBuilder, ResourceAttrs, BACKEND_LINUX_EBPF};

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

use pb::container::container_service_server::ContainerService;
use pb::image::image_service_server::ImageService;
use pb::sandbox::sandbox_service_server::SandboxService;
use pb::zone::zone_service_server::ZoneService;

fn rpc_span<T>(
    request: &Request<T>,
    rpc_service: &'static str,
    rpc_method: &'static str,
) -> tracing::Span {
    let request_id = metadata_value(request, "x-request-id").unwrap_or_else(new_request_id);
    let correlation_id =
        metadata_value(request, "x-correlation-id").unwrap_or_else(|| request_id.clone());
    let trace_id = request_id.replace('-', "");
    let span_id = trace_id
        .get(..16)
        .map(str::to_string)
        .unwrap_or_else(|| trace_id.clone());

    tracing::info_span!(
        "grpc.request",
        rpc.service = rpc_service,
        rpc.method = rpc_method,
        request_id = %request_id,
        correlation_id = %correlation_id,
        trace.id = %trace_id,
        span.id = %span_id,
    )
}

fn metadata_value<T>(request: &Request<T>, key: &str) -> Option<String> {
    request
        .metadata()
        .get(key)
        .and_then(|value| value.to_str().ok())
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(ToOwned::to_owned)
}

fn new_request_id() -> String {
    uuid::Uuid::new_v4().to_string()
}

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
        #[cfg(target_os = "linux")] event_tx: Option<
            tokio::sync::broadcast::Sender<rauha_evidence::FalseEvent>,
        >,
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
        let span = rpc_span(&request, "rauha.zone.v1.ZoneService", "CreateZone");
        async move {
            tracing::info!(event.name = "grpc.request.started", "grpc request started");
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
        .instrument(span)
        .await
    }

    async fn delete_zone(
        &self,
        request: Request<pb::zone::DeleteZoneRequest>,
    ) -> Result<Response<pb::zone::DeleteZoneResponse>, Status> {
        let span = rpc_span(&request, "rauha.zone.v1.ZoneService", "DeleteZone");
        async move {
            tracing::info!(event.name = "grpc.request.started", "grpc request started");
            let req = request.into_inner();
            self.registry
                .delete_zone(&req.name, req.force)
                .await
                .map_err(to_status)?;
            Ok(Response::new(pb::zone::DeleteZoneResponse {}))
        }
        .instrument(span)
        .await
    }

    async fn get_zone(
        &self,
        request: Request<pb::zone::GetZoneRequest>,
    ) -> Result<Response<pb::zone::GetZoneResponse>, Status> {
        let span = rpc_span(&request, "rauha.zone.v1.ZoneService", "GetZone");
        async move {
            tracing::info!(event.name = "grpc.request.started", "grpc request started");
            let req = request.into_inner();
            let zone = self.registry.get_zone(&req.name).await.map_err(to_status)?;

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
        .instrument(span)
        .await
    }

    async fn list_zones(
        &self,
        request: Request<pb::zone::ListZonesRequest>,
    ) -> Result<Response<pb::zone::ListZonesResponse>, Status> {
        let span = rpc_span(&request, "rauha.zone.v1.ZoneService", "ListZones");
        async move {
            tracing::info!(event.name = "grpc.request.started", "grpc request started");
            let zones = self.registry.list_zones().map_err(to_status)?;

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
        .instrument(span)
        .await
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

        let (_zone_type, policy) = crate::zone::policy::parse_policy(&req.policy_toml, &self.root)
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

        let toml = crate::zone::policy::policy_to_toml(&zone.name, zone.zone_type, &zone.policy);

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
                _ => {
                    return Err(Status::invalid_argument(
                        "first message must be ExecStreamStart",
                    ))
                }
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
            env: start
                .env
                .into_iter()
                .map(|(k, v)| format!("{k}={v}"))
                .collect(),
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
                    .map_err(|e| Status::internal(format!("failed to connect exec vsock: {e}")))?;
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
                _ => {
                    return Err(Status::invalid_argument(
                        "first message must be AttachStart",
                    ))
                }
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
                        message: Some(pb::container::exec_stream_response::Message::StdoutData(
                            buf[..n].to_vec(),
                        )),
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
        let images = self.image_service.list_images().map_err(to_status)?;

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
// Task-level sandbox execution. This implementation builds on the existing
// zone/container primitives: allocate or resolve a zone, start one container,
// wait, capture output/events, and clean up according to request policy.

use rauha_common::sandbox::{
    EnforcementEventSummary, SandboxEventSummary, SandboxExecResult, SandboxStatus,
};

const SANDBOX_LOG_MAX_BYTES_PER_STREAM: usize = 1024 * 1024;

fn command_hash(command: &[String]) -> String {
    use sha2::{Digest, Sha256};

    let mut hasher = Sha256::new();
    for arg in command {
        hasher.update(arg.as_bytes());
        hasher.update([0]);
    }
    format!("sha256:{}", hex::encode(hasher.finalize()))
}

// NOTE: a `safe_command_argv` keyword-denylist redactor was removed here. It
// matched secret keywords against each argv element, which leaks the common
// `--password <value>` / `-p <value>` / `--token <value>` patterns (the secret
// is the *next* element, with no keyword). `command_hash` is the safe default:
// it correlates commands without exposing argv. Any future human-readable argv
// surface must be opt-in, value-after-flag aware, and labeled not secret-safe.
fn sandbox_event_builder(
    registry: &ZoneRegistry,
    name: &'static str,
    outcome: EventOutcome,
    task_id: &str,
    zone_name: &str,
    zone_id: &str,
) -> RuntimeEventBuilder {
    RuntimeEventBuilder::new(name, EventKind::Execution, outcome)
        .task_id(task_id)
        .zone_name(zone_name)
        .zone_id(zone_id)
        .backend(
            registry.backend_name(),
            registry.backend_platform(),
            registry.enforcement_mode(),
        )
}

pub struct SandboxServiceImpl {
    registry: Arc<ZoneRegistry>,
    /// Broadcast of normalized kernel enforcement events, shared with the
    /// `WatchEvents` stream. `None` on backends without kernel enforcement
    /// (macOS VMs, or Linux with eBPF not loaded), in which case sandbox
    /// results carry no enforcement events.
    event_tx: Option<tokio::sync::broadcast::Sender<FalseEvent>>,
}

struct ContainerCleanupGuard {
    registry: Arc<ZoneRegistry>,
    container_id: uuid::Uuid,
    armed: bool,
}

impl ContainerCleanupGuard {
    fn new(registry: Arc<ZoneRegistry>, container_id: uuid::Uuid) -> Self {
        Self {
            registry,
            container_id,
            armed: true,
        }
    }

    fn disarm(&mut self) {
        self.armed = false;
    }
}

impl Drop for ContainerCleanupGuard {
    fn drop(&mut self) {
        if !self.armed {
            return;
        }

        let registry = self.registry.clone();
        let container_id = self.container_id;
        tokio::spawn(async move {
            if let Err(e) = registry.delete_container(&container_id, true).await {
                tracing::warn!(
                    container = %container_id,
                    %e,
                    "failed to delete sandbox container during cancellation cleanup"
                );
            }
        });
    }
}

struct ZoneCleanupGuard {
    registry: Arc<ZoneRegistry>,
    zone_name: String,
    armed: bool,
}

impl ZoneCleanupGuard {
    fn new(registry: Arc<ZoneRegistry>, zone_name: String) -> Self {
        Self {
            registry,
            zone_name,
            armed: true,
        }
    }

    fn disarm(&mut self) {
        self.armed = false;
    }
}

impl Drop for ZoneCleanupGuard {
    fn drop(&mut self) {
        if !self.armed {
            return;
        }

        let registry = self.registry.clone();
        let zone_name = self.zone_name.clone();
        tokio::spawn(async move {
            if let Err(e) = registry.delete_zone(&zone_name, true).await {
                tracing::warn!(
                    zone = zone_name,
                    %e,
                    "failed to delete temporary sandbox zone during cancellation cleanup"
                );
            }
        });
    }
}

impl SandboxServiceImpl {
    pub fn new(
        registry: Arc<ZoneRegistry>,
        event_tx: Option<tokio::sync::broadcast::Sender<rauha_evidence::FalseEvent>>,
    ) -> Self {
        Self { registry, event_tx }
    }

    /// Run one task to completion inside an already-resolved zone.
    ///
    /// Returns `Err(message)` for any failure that prevents producing a normal
    /// result (e.g. the image isn't pulled or the container won't start); the
    /// caller turns that into a `RuntimeError` result. The container is always
    /// deleted before returning, success or failure.
    async fn execute_task(
        &self,
        task_id: &str,
        zone_name: &str,
        zone_id: &str,
        req: &pb::sandbox::RunSandboxRequest,
    ) -> std::result::Result<SandboxExecResult, String> {
        sandbox_event_builder(
            &self.registry,
            event_name::FS_ROOTFS_PREPARE_STARTED,
            EventOutcome::Started,
            task_id,
            zone_name,
            zone_id,
        )
        .image_ref(&req.image)
        .command_hash(command_hash(&req.command))
        .trust_level(TrustLevel::Complete)
        .emit();

        let spec = rauha_common::container::ContainerSpec {
            name: format!("{task_id}-task"),
            image: req.image.clone(),
            command: req.command.clone(),
            env: req.env.clone().into_iter().collect(),
            working_dir: (!req.workdir.is_empty()).then(|| req.workdir.clone()),
            rootfs_path: None,
            overlay_layers: None,
        };

        let container = self
            .registry
            .create_container(zone_name, spec)
            .await
            .map_err(|e| {
                sandbox_event_builder(
                    &self.registry,
                    event_name::FS_ROOTFS_PREPARE_FAILED,
                    EventOutcome::Failed,
                    task_id,
                    zone_name,
                    zone_id,
                )
                .level(Severity::Error)
                .image_ref(&req.image)
                .error("container_create_failed", "runtime", e.to_string())
                .emit();
                format!(
                    "failed to create container (is the image pulled? `rauha image pull {}`): {e}",
                    req.image
                )
            })?;
        let mut cleanup = ContainerCleanupGuard::new(self.registry.clone(), container.id);

        sandbox_event_builder(
            &self.registry,
            event_name::FS_ROOTFS_PREPARE_SUCCEEDED,
            EventOutcome::Succeeded,
            task_id,
            zone_name,
            zone_id,
        )
        .container_id(container.id.to_string())
        .image_ref(&req.image)
        .trust_level(TrustLevel::Complete)
        .emit();

        // Everything past container creation must still clean up the container,
        // so capture the outcome and delete unconditionally afterwards. The
        // guard covers client cancellation while this future is still running.
        let outcome = self
            .run_started_container(task_id, zone_name, zone_id, &container.id, req)
            .await;

        if let Err(e) = self.registry.delete_container(&container.id, true).await {
            tracing::warn!(container = %container.id, %e, "failed to delete sandbox container");
            sandbox_event_builder(
                &self.registry,
                event_name::SANDBOX_CLEANUP_PARTIAL,
                EventOutcome::Degraded,
                task_id,
                zone_name,
                zone_id,
            )
            .level(Severity::Warn)
            .container_id(container.id.to_string())
            .error("container_cleanup_failed", "cleanup", e.to_string())
            .trust_level(TrustLevel::Partial)
            .degraded_reason("container_delete_failed")
            .emit();
        } else {
            sandbox_event_builder(
                &self.registry,
                event_name::SANDBOX_CLEANUP_SUCCEEDED,
                EventOutcome::Succeeded,
                task_id,
                zone_name,
                zone_id,
            )
            .container_id(container.id.to_string())
            .trust_level(TrustLevel::Complete)
            .emit();
        }
        cleanup.disarm();

        outcome
    }

    async fn run_started_container(
        &self,
        task_id: &str,
        zone_name: &str,
        zone_id: &str,
        container_id: &uuid::Uuid,
        req: &pb::sandbox::RunSandboxRequest,
    ) -> std::result::Result<SandboxExecResult, String> {
        let mut events = vec![event("container.created", "sandbox container created")];

        // Begin capturing kernel enforcement events for this task's zone before
        // the workload starts, so nothing between start and exit is missed.
        let capture = self.begin_enforcement_capture(zone_name).await;
        emit_enforcement_capture_state(
            &self.registry,
            task_id,
            zone_name,
            zone_id,
            capture.as_ref(),
        );

        let started_at = chrono::Utc::now();
        self.registry
            .start_container(container_id)
            .await
            .map_err(|e| format!("failed to start container: {e}"))?;
        events.push(event("container.started", "sandbox container started"));
        sandbox_event_builder(
            &self.registry,
            event_name::SANDBOX_CONTAINER_STARTED,
            EventOutcome::Started,
            task_id,
            zone_name,
            zone_id,
        )
        .container_id(container_id.to_string())
        .command_hash(command_hash(&req.command))
        .image_ref(&req.image)
        .trust_level(TrustLevel::Complete)
        .emit();
        sandbox_event_builder(
            &self.registry,
            event_name::SANDBOX_COMMAND_STARTED,
            EventOutcome::Started,
            task_id,
            zone_name,
            zone_id,
        )
        .container_id(container_id.to_string())
        .command_hash(command_hash(&req.command))
        .image_ref(&req.image)
        .trust_level(TrustLevel::Complete)
        .emit();

        let timeout = (req.timeout_seconds > 0)
            .then(|| std::time::Duration::from_secs(req.timeout_seconds as u64));
        let (exit_code, timed_out) = self.wait_for_exit(container_id, timeout).await;

        if timed_out {
            let _ = self.registry.stop_container(container_id, 5).await;
            events.push(event(
                "container.timed_out",
                "sandbox task exceeded timeout",
            ));
        } else {
            events.push(event("container.exited", "sandbox container exited"));
        }

        let finished_at = chrono::Utc::now();
        let duration_ms = (finished_at - started_at).num_milliseconds().max(0) as u64;
        sandbox_event_builder(
            &self.registry,
            if timed_out {
                event_name::SANDBOX_COMMAND_TIMED_OUT
            } else {
                event_name::SANDBOX_COMMAND_EXITED
            },
            if timed_out {
                EventOutcome::TimedOut
            } else {
                EventOutcome::Succeeded
            },
            task_id,
            zone_name,
            zone_id,
        )
        .level(if timed_out {
            Severity::Warn
        } else {
            Severity::Info
        })
        .container_id(container_id.to_string())
        .duration_ms(duration_ms)
        .field(
            "exit_code",
            exit_code
                .map(|code| FieldValue::I64(code as i64))
                .unwrap_or_else(|| FieldValue::String("none".into())),
        )
        .trust_level(if timed_out {
            TrustLevel::Partial
        } else {
            TrustLevel::Complete
        })
        .emit();

        // Capture stdout/stderr from the shim-written log files (blocking I/O),
        // bounded so a chatty task cannot exceed tonic's default message size.
        let cid = container_id.to_string();
        let (stdout, stderr) = tokio::task::spawn_blocking(move || {
            crate::logs::read_all_capped(&cid, SANDBOX_LOG_MAX_BYTES_PER_STREAM)
        })
        .await
        .unwrap_or_default();
        sandbox_event_builder(
            &self.registry,
            event_name::SANDBOX_STDOUT_CAPTURED,
            EventOutcome::Succeeded,
            task_id,
            zone_name,
            zone_id,
        )
        .container_id(container_id.to_string())
        .field("bytes", FieldValue::U64(stdout.len() as u64))
        .trust_level(TrustLevel::Complete)
        .emit();
        sandbox_event_builder(
            &self.registry,
            event_name::SANDBOX_STDERR_CAPTURED,
            EventOutcome::Succeeded,
            task_id,
            zone_name,
            zone_id,
        )
        .container_id(container_id.to_string())
        .field("bytes", FieldValue::U64(stderr.len() as u64))
        .trust_level(TrustLevel::Complete)
        .emit();

        let status = if timed_out {
            SandboxStatus::TimedOut
        } else if exit_code == Some(0) {
            SandboxStatus::Succeeded
        } else {
            SandboxStatus::Failed
        };

        let enforcement_events = drain_enforcement_capture(capture);
        sandbox_event_builder(
            &self.registry,
            event_name::SANDBOX_RESULT_BUILT,
            EventOutcome::Succeeded,
            task_id,
            zone_name,
            zone_id,
        )
        .container_id(container_id.to_string())
        .duration_ms(duration_ms)
        .field(
            "enforcement_event_count",
            FieldValue::U64(enforcement_events.len() as u64),
        )
        .field("stdout_bytes", FieldValue::U64(stdout.len() as u64))
        .field("stderr_bytes", FieldValue::U64(stderr.len() as u64))
        .trust_level(TrustLevel::BestEffort)
        .degraded_reason("enforcement_capture_is_best_effort")
        .emit();

        Ok(SandboxExecResult {
            task_id: task_id.to_string(),
            zone_id: zone_id.to_string(),
            command: req.command.clone(),
            status,
            exit_code,
            stdout,
            stderr,
            duration_ms,
            started_at: Some(started_at),
            finished_at: Some(finished_at),
            events,
            // Drain the events that landed on this task's zone while it ran.
            enforcement_events,
        })
    }

    /// Poll the container until it exits, returning `(exit_code, timed_out)`.
    ///
    /// This is the task-completion policy — poll interval, the no-timeout case,
    /// and how a deadline maps to `timed_out`. Transient state-read errors are
    /// tolerated (the shim may be mid-exit); only the deadline ends the wait.
    async fn wait_for_exit(
        &self,
        container_id: &uuid::Uuid,
        timeout: Option<std::time::Duration>,
    ) -> (Option<i32>, bool) {
        const POLL: std::time::Duration = std::time::Duration::from_millis(200);
        let deadline = timeout.map(|t| std::time::Instant::now() + t);

        loop {
            match self.registry.get_container_state(container_id).await {
                Ok((status, exit_code)) if status == "stopped" => return (exit_code, false),
                Ok(_) => {}
                Err(e) => {
                    tracing::debug!(container = %container_id, %e, "transient state read while waiting");
                }
            }

            if let Some(deadline) = deadline {
                if std::time::Instant::now() >= deadline {
                    return (None, true);
                }
            }

            tokio::time::sleep(POLL).await;
        }
    }

    /// Subscribe to kernel enforcement events for `zone_name`, resolving the
    /// compact zone id needed to scope a daemon-wide broadcast down to this
    /// task. Called before the workload starts so no early event is missed.
    /// Yields `None` when there is no enforcement backend to capture from
    /// (macOS VMs, or Linux with eBPF not loaded) — the result then carries
    /// no enforcement events.
    async fn begin_enforcement_capture(&self, zone_name: &str) -> Option<EnforcementCapture> {
        let tx = self.event_tx.as_ref()?;
        Some(EnforcementCapture {
            rx: tx.subscribe(),
            kernel_zone_id: self.registry.kernel_zone_id(zone_name).await,
        })
    }
}

fn emit_enforcement_capture_state(
    registry: &ZoneRegistry,
    task_id: &str,
    zone_name: &str,
    zone_id: &str,
    capture: Option<&EnforcementCapture>,
) {
    match capture {
        Some(capture) if capture.kernel_zone_id.is_some() => {
            RuntimeEventBuilder::new(
                event_name::ENFORCEMENT_CAPTURE_BEST_EFFORT,
                EventKind::Enforcement,
                EventOutcome::Degraded,
            )
            .level(Severity::Warn)
            .task_id(task_id)
            .zone_name(zone_name)
            .zone_id(zone_id)
            .backend(
                registry.backend_name(),
                registry.backend_platform(),
                registry.enforcement_mode(),
            )
            .trust_level(TrustLevel::BestEffort)
            .degraded_reason("daemon_wide_broadcast_scoped_by_kernel_zone_id")
            .emit();
        }
        Some(_) => {
            RuntimeEventBuilder::new(
                event_name::ENFORCEMENT_CAPTURE_INCOMPLETE,
                EventKind::Enforcement,
                EventOutcome::Degraded,
            )
            .level(Severity::Warn)
            .task_id(task_id)
            .zone_name(zone_name)
            .zone_id(zone_id)
            .backend(
                registry.backend_name(),
                registry.backend_platform(),
                registry.enforcement_mode(),
            )
            .trust_level(TrustLevel::Partial)
            .degraded_reason("kernel_zone_id_unavailable")
            .emit();
        }
        None => {
            RuntimeEventBuilder::new(
                event_name::ENFORCER_UNAVAILABLE,
                EventKind::Enforcement,
                EventOutcome::Skipped,
            )
            .level(Severity::Warn)
            .task_id(task_id)
            .zone_name(zone_name)
            .zone_id(zone_id)
            .backend(
                registry.backend_name(),
                registry.backend_platform(),
                EnforcementMode::Unavailable,
            )
            .trust_level(TrustLevel::Unavailable)
            .degraded_reason("enforcement_event_broadcast_unavailable")
            .emit();
        }
    }
}

/// A user-facing lifecycle event stamped with the current time.
fn event(kind: &str, message: &str) -> SandboxEventSummary {
    SandboxEventSummary {
        timestamp: Some(chrono::Utc::now()),
        kind: kind.to_string(),
        message: message.to_string(),
    }
}

/// A live subscription to the enforcement-event broadcast, scoped to one zone.
///
/// The broadcast is daemon-wide (every zone's activity flows through it), so
/// `kernel_zone_id` is what lets us keep only this task's events when draining.
struct EnforcementCapture {
    rx: tokio::sync::broadcast::Receiver<FalseEvent>,
    kernel_zone_id: Option<u32>,
}

/// Drain everything buffered on the subscription since the task started and
/// project the events belonging to this task's zone into result summaries.
///
/// Non-blocking: it takes what is already queued, not future events. A `Lagged`
/// error means the broadcast outran our buffer; we keep draining what remains
/// rather than aborting (some events are better than none, and the drop is
/// already surfaced as a `pipeline.shed` event on the `WatchEvents` stream).
fn drain_enforcement_capture(capture: Option<EnforcementCapture>) -> Vec<EnforcementEventSummary> {
    use tokio::sync::broadcast::error::TryRecvError;

    let Some(mut capture) = capture else {
        return Vec::new();
    };

    let mut out = Vec::new();
    loop {
        match capture.rx.try_recv() {
            Ok(event) if enforcement_event_matches(&event, capture.kernel_zone_id) => {
                out.push(project_enforcement_event(&event));
            }
            Ok(_) => {}
            Err(TryRecvError::Lagged(_)) => continue,
            Err(TryRecvError::Empty | TryRecvError::Closed) => break,
        }
    }
    out
}

/// Decide whether a broadcast enforcement event belongs to this task.
///
/// This is the correlation policy. Events ride a single daemon-wide broadcast,
/// so we scope by the compact zone id the eBPF backend stamps on each event as
/// `caller_zone`. Without a resolved kernel id we attribute nothing — reporting
/// no events is safer than mis-attributing another zone's enforcement activity
/// to this task's result.
fn enforcement_event_matches(event: &FalseEvent, kernel_zone_id: Option<u32>) -> bool {
    let Some(zid) = kernel_zone_id else {
        return false;
    };
    matches!(
        event.fields.get("caller_zone"),
        Some(FieldValue::U64(z)) if *z == zid as u64
    )
}

/// Project a normalized evidence event into the sandbox result summary shape.
///
/// This is the user-facing boundary: raw BPF map/ring-buffer structures never
/// reach the caller — only the stable, named fields the evidence schema already
/// normalized are surfaced.
fn project_enforcement_event(event: &FalseEvent) -> EnforcementEventSummary {
    let string_field = |key: &str| match event.fields.get(key) {
        Some(FieldValue::String(s)) => Some(s.clone()),
        _ => None,
    };
    let u64_field = |key: &str| match event.fields.get(key) {
        Some(FieldValue::U64(v)) => Some(*v),
        _ => None,
    };

    EnforcementEventSummary {
        timestamp: chrono::DateTime::parse_from_rfc3339(&event.ts)
            .ok()
            .map(|t| t.with_timezone(&chrono::Utc)),
        hook: string_field("hook").unwrap_or_default(),
        // The evidence event name (e.g. `zone.file.denied`) is the action taken.
        action: event.event.clone(),
        decision: string_field("decision").unwrap_or_default(),
        message: if event.what_failed.is_empty() {
            event.event.clone()
        } else {
            event.what_failed.clone()
        },
        pid: u64_field("pid").map(|p| p as u32),
        source_zone: Some(event.zone.id.clone()),
        target_zone: u64_field("target_zone")
            .filter(|z| *z != 0)
            .map(|z| format!("zone-{z}")),
        object: event.resource.clone(),
    }
}

/// Validate the request before touching any zone/container state.
fn validate_sandbox_request(req: &pb::sandbox::RunSandboxRequest) -> Result<(), Status> {
    if req.image.trim().is_empty() {
        return Err(Status::invalid_argument("image is required"));
    }
    if req.command.is_empty() {
        return Err(Status::invalid_argument("command must not be empty"));
    }
    Ok(())
}

fn sandbox_status_str(status: SandboxStatus) -> String {
    match status {
        SandboxStatus::Succeeded => "succeeded",
        SandboxStatus::Failed => "failed",
        SandboxStatus::TimedOut => "timed_out",
        SandboxStatus::RuntimeError => "runtime_error",
    }
    .to_string()
}

fn to_proto_result(exec: SandboxExecResult) -> pb::sandbox::SandboxResult {
    pb::sandbox::SandboxResult {
        task_id: exec.task_id,
        zone_id: exec.zone_id,
        command: exec.command,
        status: sandbox_status_str(exec.status),
        exit_code: exec.exit_code,
        stdout: exec.stdout,
        stderr: exec.stderr,
        duration_ms: exec.duration_ms,
        started_at: exec.started_at.map(|t| t.to_rfc3339()).unwrap_or_default(),
        finished_at: exec.finished_at.map(|t| t.to_rfc3339()).unwrap_or_default(),
        events: exec
            .events
            .into_iter()
            .map(|e| pb::sandbox::SandboxEventSummary {
                timestamp: e.timestamp.map(|t| t.to_rfc3339()).unwrap_or_default(),
                kind: e.kind,
                message: e.message,
            })
            .collect(),
        enforcement_events: exec
            .enforcement_events
            .into_iter()
            .map(|e| pb::sandbox::EnforcementEventSummary {
                timestamp: e.timestamp.map(|t| t.to_rfc3339()).unwrap_or_default(),
                hook: e.hook,
                action: e.action,
                decision: e.decision,
                message: e.message,
                pid: e.pid,
                source_zone: e.source_zone.unwrap_or_default(),
                target_zone: e.target_zone.unwrap_or_default(),
                object: e.object.unwrap_or_default(),
            })
            .collect(),
    }
}

#[tonic::async_trait]
impl SandboxService for SandboxServiceImpl {
    async fn run_sandbox(
        &self,
        request: Request<pb::sandbox::RunSandboxRequest>,
    ) -> Result<Response<pb::sandbox::SandboxResult>, Status> {
        // Correlate the primary sandbox path with its gRPC request like the
        // zone handlers: open a request span so this handler's logs and all the
        // sandbox evidence events (emitted inline below) share one trace.id /
        // span.id / correlation_id. task_id stays a distinct field.
        let span = rpc_span(&request, "rauha.sandbox.v1.SandboxService", "RunSandbox");
        async move {
            tracing::info!(event.name = "grpc.request.started", "grpc request started");
            let req = request.into_inner();
            let task_id = format!("task-{}", uuid::Uuid::new_v4());
            RuntimeEventBuilder::new(
                event_name::SANDBOX_RUN_STARTED,
                EventKind::Execution,
                EventOutcome::Started,
            )
            .task_id(&task_id)
            .image_ref(&req.image)
            .command_hash(command_hash(&req.command))
            .repo_path_safe(&req.repo_path)
            .backend(
                self.registry.backend_name(),
                self.registry.backend_platform(),
                self.registry.enforcement_mode(),
            )
            .trust_level(TrustLevel::BestEffort)
            .degraded_reason("enforcement_capture_status_reported_separately")
            .emit();

            if let Err(status) = validate_sandbox_request(&req) {
                RuntimeEventBuilder::new(
                    event_name::SANDBOX_RUN_FAILED,
                    EventKind::Execution,
                    EventOutcome::Failed,
                )
                .level(Severity::Warn)
                .task_id(&task_id)
                .image_ref(&req.image)
                .command_hash(command_hash(&req.command))
                .backend(
                    self.registry.backend_name(),
                    self.registry.backend_platform(),
                    self.registry.enforcement_mode(),
                )
                .error(
                    "sandbox_request_invalid",
                    format!("{:?}", status.code()),
                    status.message().to_string(),
                )
                .trust_level(TrustLevel::Complete)
                .emit();
                return Err(status);
            }

            // Resolve the zone. An empty name allocates a temporary zone that we own
            // and (by default) delete afterwards; a named zone must already exist
            // and is left intact.
            let (zone_name, zone_id, temp_zone) = if req.name.trim().is_empty() {
                let name = format!(
                    "sandbox-{}",
                    &uuid::Uuid::new_v4().simple().to_string()[..12]
                );
                let zone = self
                    .registry
                    .create_zone(
                        &name,
                        rauha_common::zone::ZoneType::NonGlobal,
                        rauha_common::zone::ZonePolicy::default(),
                    )
                    .await
                    .map_err(to_status)?;
                sandbox_event_builder(
                    &self.registry,
                    event_name::SANDBOX_ZONE_ALLOCATED,
                    EventOutcome::Succeeded,
                    &task_id,
                    &zone.name,
                    &zone.id.to_string(),
                )
                .trust_level(TrustLevel::Complete)
                .emit();
                (zone.name, zone.id.to_string(), true)
            } else {
                let zone = self.registry.get_zone(&req.name).await.map_err(to_status)?;
                (zone.name, zone.id.to_string(), false)
            };
            let mut zone_cleanup = (temp_zone && !req.keep_zone)
                .then(|| ZoneCleanupGuard::new(self.registry.clone(), zone_name.clone()));

            let outcome = self
                .execute_task(&task_id, &zone_name, &zone_id, &req)
                .await;

            // Tear down the temporary zone unless the caller asked to keep it.
            if temp_zone && !req.keep_zone {
                if let Err(e) = self.registry.delete_zone(&zone_name, true).await {
                    tracing::warn!(zone = zone_name, %e, "failed to delete temporary sandbox zone");
                    sandbox_event_builder(
                        &self.registry,
                        event_name::SANDBOX_CLEANUP_PARTIAL,
                        EventOutcome::Degraded,
                        &task_id,
                        &zone_name,
                        &zone_id,
                    )
                    .level(Severity::Warn)
                    .error("zone_cleanup_failed", "cleanup", e.to_string())
                    .trust_level(TrustLevel::Partial)
                    .degraded_reason("temporary_zone_delete_failed")
                    .emit();
                }
                if let Some(cleanup) = &mut zone_cleanup {
                    cleanup.disarm();
                }
            }

            let exec = outcome.unwrap_or_else(|message| {
                SandboxExecResult::runtime_error(&task_id, &zone_id, req.command.clone(), message)
            });
            let run_event = match exec.status {
                SandboxStatus::Succeeded => (
                    event_name::SANDBOX_RUN_SUCCEEDED,
                    EventOutcome::Succeeded,
                    Severity::Info,
                ),
                SandboxStatus::Failed | SandboxStatus::RuntimeError => (
                    event_name::SANDBOX_RUN_FAILED,
                    EventOutcome::Failed,
                    Severity::Warn,
                ),
                SandboxStatus::TimedOut => (
                    event_name::SANDBOX_RUN_FAILED,
                    EventOutcome::TimedOut,
                    Severity::Warn,
                ),
            };
            sandbox_event_builder(
                &self.registry,
                run_event.0,
                run_event.1,
                &task_id,
                &zone_name,
                &zone_id,
            )
            .level(run_event.2)
            .duration_ms(exec.duration_ms)
            .field(
                "status",
                FieldValue::String(sandbox_status_str(exec.status).to_string()),
            )
            .field(
                "exit_code",
                exec.exit_code
                    .map(|code| FieldValue::I64(code as i64))
                    .unwrap_or_else(|| FieldValue::String("none".into())),
            )
            .trust_level(TrustLevel::BestEffort)
            .degraded_reason("enforcement_events_are_best_effort")
            .emit();

            Ok(Response::new(to_proto_result(exec)))
        }
        .instrument(span)
        .await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tonic::Code;

    fn req(image: &str, command: Vec<&str>) -> pb::sandbox::RunSandboxRequest {
        pb::sandbox::RunSandboxRequest {
            image: image.to_string(),
            command: command.into_iter().map(String::from).collect(),
            ..Default::default()
        }
    }

    #[test]
    fn empty_image_is_invalid() {
        let status = validate_sandbox_request(&req("", vec!["echo"])).unwrap_err();
        assert_eq!(status.code(), Code::InvalidArgument);
    }

    #[test]
    fn empty_command_is_invalid() {
        let status = validate_sandbox_request(&req("alpine", vec![])).unwrap_err();
        assert_eq!(status.code(), Code::InvalidArgument);
    }

    #[test]
    fn valid_request_passes_validation() {
        assert!(validate_sandbox_request(&req("alpine", vec!["echo", "hi"])).is_ok());
    }

    #[test]
    fn status_strings_match_contract() {
        assert_eq!(sandbox_status_str(SandboxStatus::Succeeded), "succeeded");
        assert_eq!(sandbox_status_str(SandboxStatus::TimedOut), "timed_out");
        assert_eq!(
            sandbox_status_str(SandboxStatus::RuntimeError),
            "runtime_error"
        );
    }

    #[test]
    fn runtime_error_maps_to_proto_result() {
        let exec =
            SandboxExecResult::runtime_error("task-1", "zone-1", vec!["pytest".into()], "boom");
        let proto = to_proto_result(exec);
        assert_eq!(proto.status, "runtime_error");
        assert_eq!(proto.stderr, "boom");
        assert_eq!(proto.exit_code, None);
        assert!(proto.started_at.is_empty());
    }

    // --- enforcement-event correlation & projection ---

    /// Build an enforcement-shaped evidence event for the given caller zone,
    /// mirroring what the eBPF backend's normalizer produces.
    fn enforcement_event(caller_zone: u32) -> FalseEvent {
        rauha_evidence::FalseEventBuilder::new("zone.file.denied")
            .zone(format!("zone-{caller_zone}"), None)
            .actor("pid:1234", Vec::new())
            .resource("inode:42")
            .field("pid", FieldValue::U64(1234))
            .field("hook", FieldValue::String("file_open".into()))
            .field("decision", FieldValue::String("deny".into()))
            .field("caller_zone", FieldValue::U64(caller_zone as u64))
            .field("target_zone", FieldValue::U64(0))
            .build()
            .expect("build enforcement event")
    }

    #[test]
    fn event_matches_only_its_own_zone() {
        let event = enforcement_event(7);
        assert!(enforcement_event_matches(&event, Some(7)));
        assert!(!enforcement_event_matches(&event, Some(8)));
    }

    #[test]
    fn unresolved_kernel_id_attributes_nothing() {
        // Without a kernel zone id we cannot safely attribute events — even a
        // real enforcement event must not leak into an unrelated task's result.
        let event = enforcement_event(7);
        assert!(!enforcement_event_matches(&event, None));
    }

    #[test]
    fn non_enforcement_event_without_caller_zone_does_not_match() {
        let lifecycle = rauha_evidence::FalseEventBuilder::new("zone.created")
            .zone("zone-7", None)
            .build()
            .expect("build lifecycle event");
        assert!(!enforcement_event_matches(&lifecycle, Some(7)));
    }

    #[test]
    fn projection_surfaces_stable_named_fields() {
        let summary = project_enforcement_event(&enforcement_event(7));
        assert_eq!(summary.hook, "file_open");
        assert_eq!(summary.decision, "deny");
        assert_eq!(summary.action, "zone.file.denied");
        assert_eq!(summary.pid, Some(1234));
        assert_eq!(summary.source_zone.as_deref(), Some("zone-7"));
        // target_zone of 0 means "no cross-zone target" and is dropped.
        assert_eq!(summary.target_zone, None);
        assert_eq!(summary.object.as_deref(), Some("inode:42"));
        assert!(summary.timestamp.is_some(), "ts should parse to a datetime");
    }

    #[test]
    fn drain_without_capture_yields_no_events() {
        assert!(drain_enforcement_capture(None).is_empty());
    }

    #[test]
    fn command_hash_does_not_expose_command_payload() {
        let command = vec!["echo".to_string(), "super-secret-token".to_string()];
        let hash = command_hash(&command);
        assert!(hash.starts_with("sha256:"));
        assert!(!hash.contains("super-secret-token"));
    }

    #[tokio::test]
    async fn drain_keeps_only_this_zones_events() {
        let (tx, rx) = tokio::sync::broadcast::channel(16);
        // One event for our zone (7), one for a neighbour (9).
        tx.send(enforcement_event(7)).unwrap();
        tx.send(enforcement_event(9)).unwrap();

        let capture = EnforcementCapture {
            rx,
            kernel_zone_id: Some(7),
        };
        let events = drain_enforcement_capture(Some(capture));

        assert_eq!(events.len(), 1, "only the task's own zone is captured");
        assert_eq!(events[0].source_zone.as_deref(), Some("zone-7"));
    }
}
