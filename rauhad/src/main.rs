mod backend;
mod logs;
mod metadata;
mod network;
mod server;
mod zone;

use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;

use rauha_common::observability::{LogFormat, ObservabilityConfig};
use rauha_evidence::{
    event_name, EnforcementMode, EventKind, EventOutcome, RuntimeEventBuilder, Severity, TrustLevel,
};
use tonic::transport::Server;
use tracing_subscriber::fmt::time::ChronoUtc;
use tracing_subscriber::EnvFilter;

use server::pb::container::container_service_server::ContainerServiceServer;
use server::pb::image::image_service_server::ImageServiceServer;
use server::pb::sandbox::sandbox_service_server::SandboxServiceServer;
use server::pb::zone::zone_service_server::ZoneServiceServer;

const DEFAULT_ROOT: &str = if cfg!(target_os = "macos") {
    "/tmp/rauha"
} else {
    "/var/lib/rauha"
};

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let observability = ObservabilityConfig::from_env_or_default()?;
    init_tracing(&observability)?;
    install_panic_hook();
    let _process_span = tracing::info_span!(
        "rauhad",
        service.name = "rauhad",
        service.version = env!("CARGO_PKG_VERSION"),
        environment = %observability.environment,
        host.id = %host_id(),
        host.name = %host_name(),
        pid = std::process::id(),
    )
    .entered();

    let root = std::env::var("RAUHA_ROOT").unwrap_or_else(|_| DEFAULT_ROOT.into());
    let root_path = PathBuf::from(&root);
    let platform = if cfg!(target_os = "linux") {
        "linux"
    } else if cfg!(target_os = "macos") {
        "macos"
    } else {
        std::env::consts::OS
    };
    RuntimeEventBuilder::new(
        event_name::DAEMON_START,
        EventKind::Lifecycle,
        EventOutcome::Started,
    )
    .backend("unselected", platform, EnforcementMode::Unavailable)
    .trust_level(TrustLevel::Partial)
    .degraded_reason("backend_not_selected_yet")
    .emit();

    // Ensure directories exist.
    std::fs::create_dir_all(root_path.join("metadata"))?;
    std::fs::create_dir_all(root_path.join("zones"))?;
    std::fs::create_dir_all(root_path.join("content"))?;

    tracing::info!(root = %root, "starting rauhad");

    // Open metadata store.
    let metadata = Arc::new(metadata::db::MetadataStore::open(
        &root_path.join("metadata").join("rauha.redb"),
    )?);

    // Create platform backend.
    #[cfg(target_os = "linux")]
    let (backend_box, event_tx) = backend::create_backend(&root)?;
    #[cfg(not(target_os = "linux"))]
    let backend_box = backend::create_backend(&root)?;
    let backend: Arc<dyn rauha_common::backend::IsolationBackend> = Arc::from(backend_box);

    tracing::info!(backend = backend.name(), "isolation backend initialized");
    let enforcement_mode = match backend.isolation_model() {
        rauha_common::zone::IsolationModel::SyscallPolicy
        | rauha_common::zone::IsolationModel::HardwareBoundary => EnforcementMode::Enforcing,
    };
    RuntimeEventBuilder::new(
        event_name::BACKEND_SELECTED,
        EventKind::Backend,
        EventOutcome::Succeeded,
    )
    .backend(backend.name(), platform, enforcement_mode)
    .trust_level(TrustLevel::Complete)
    .emit();

    // Create image service.
    let content_store = Arc::new(
        rauha_oci::content::ContentStore::new(&root_path.join("content"))
            .expect("failed to initialize content store"),
    );
    let image_service = Arc::new(rauha_oci::image::ImageService::new(
        content_store,
        root_path.clone(),
    ));

    // Create zone registry.
    let registry = Arc::new(zone::registry::ZoneRegistry::new(
        metadata.clone(),
        backend,
        image_service.clone(),
        root.clone(),
    ));

    // Reconcile persisted metadata with kernel state.
    registry.reconcile().await?;

    // Set up gRPC services.
    #[cfg(target_os = "linux")]
    let zone_svc = server::ZoneServiceImpl::new(registry.clone(), root.clone(), event_tx.clone());
    #[cfg(not(target_os = "linux"))]
    let zone_svc = server::ZoneServiceImpl::new(registry.clone(), root.clone());
    let container_svc = server::ContainerServiceImpl::new(registry.clone());
    let image_svc = server::ImageServiceImpl::new(image_service);
    #[cfg(target_os = "linux")]
    let sandbox_svc = server::SandboxServiceImpl::new(registry.clone(), event_tx.clone());
    #[cfg(not(target_os = "linux"))]
    let sandbox_svc = server::SandboxServiceImpl::new(registry.clone(), None);

    let addr: SocketAddr = "[::1]:9876".parse()?;
    tracing::info!(%addr, "listening on gRPC");
    RuntimeEventBuilder::new(
        event_name::DAEMON_READY,
        EventKind::Lifecycle,
        EventOutcome::Succeeded,
    )
    .backend(
        registry.backend_name(),
        registry.backend_platform(),
        registry.enforcement_mode(),
    )
    .field(
        "grpc_addr",
        rauha_evidence::FieldValue::String(addr.to_string()),
    )
    .trust_level(TrustLevel::Complete)
    .emit();

    // Graceful shutdown: clean up network state on SIGTERM/SIGINT.
    let mut sigterm = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
        .map_err(|e| anyhow::anyhow!("failed to register SIGTERM handler: {e}"))?;

    let shutdown = async move {
        tokio::select! {
            _ = tokio::signal::ctrl_c() => {
                tracing::info!("received SIGINT, shutting down");
            }
            _ = sigterm.recv() => {
                tracing::info!("received SIGTERM, shutting down");
            }
        }
    };

    let serve_result = Server::builder()
        .add_service(ZoneServiceServer::new(zone_svc))
        .add_service(ContainerServiceServer::new(container_svc))
        .add_service(ImageServiceServer::new(image_svc))
        .add_service(SandboxServiceServer::new(sandbox_svc))
        .serve_with_shutdown(addr, shutdown)
        .await;

    // Cleanup runs unconditionally — even if serve errored.
    cleanup_network();

    tracing::info!("rauhad stopped");
    RuntimeEventBuilder::new(
        event_name::DAEMON_SHUTDOWN,
        EventKind::Lifecycle,
        if serve_result.is_ok() {
            EventOutcome::Succeeded
        } else {
            EventOutcome::Failed
        },
    )
    .level(if serve_result.is_ok() {
        Severity::Info
    } else {
        Severity::Error
    })
    .backend(
        registry.backend_name(),
        registry.backend_platform(),
        registry.enforcement_mode(),
    )
    .trust_level(TrustLevel::Complete)
    .emit();
    serve_result?;
    Ok(())
}

fn cleanup_network() {
    tracing::info!("cleaning up network state");
    #[cfg(target_os = "linux")]
    backend::linux::cleanup_network();
}

fn init_tracing(config: &ObservabilityConfig) -> anyhow::Result<()> {
    let filter = EnvFilter::try_from_default_env()
        .or_else(|_| EnvFilter::try_new(format!("rauhad={}", config.level)))?;
    let format = match config.format {
        LogFormat::Json => LogFormat::Json,
        LogFormat::Text => LogFormat::Text,
        LogFormat::Auto if stdout_is_tty() => LogFormat::Text,
        LogFormat::Auto => LogFormat::Json,
    };

    match format {
        LogFormat::Json | LogFormat::Auto => tracing_subscriber::fmt()
            .json()
            .flatten_event(true)
            .with_current_span(true)
            .with_timer(ChronoUtc::rfc_3339())
            .with_env_filter(filter)
            .with_writer(std::io::stdout)
            .init(),
        LogFormat::Text => tracing_subscriber::fmt()
            .with_timer(ChronoUtc::rfc_3339())
            .with_env_filter(filter)
            .with_writer(std::io::stdout)
            .init(),
    }
    Ok(())
}

fn install_panic_hook() {
    std::panic::set_hook(Box::new(|info| {
        let location = info
            .location()
            .map(|loc| format!("{}:{}:{}", loc.file(), loc.line(), loc.column()))
            .unwrap_or_else(|| "unknown".into());
        let payload = info
            .payload()
            .downcast_ref::<&str>()
            .map(|s| (*s).to_string())
            .or_else(|| info.payload().downcast_ref::<String>().cloned())
            .unwrap_or_else(|| "panic payload is not a string".into());
        let backtrace = std::backtrace::Backtrace::force_capture().to_string();

        tracing::error!(
            event.name = "process.panic",
            error.kind = "panic",
            error.message = %payload,
            location = %location,
            backtrace = %backtrace,
            "process.panic"
        );
    }));
}

fn stdout_is_tty() -> bool {
    unsafe { libc::isatty(libc::STDOUT_FILENO) == 1 }
}

fn host_id() -> String {
    std::fs::read_to_string("/etc/machine-id")
        .or_else(|_| std::fs::read_to_string("/var/lib/dbus/machine-id"))
        .map(|s| s.trim().to_string())
        .ok()
        .filter(|s| !s.is_empty())
        .unwrap_or_else(host_name)
}

fn host_name() -> String {
    std::env::var("HOSTNAME")
        .ok()
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| "unknown".into())
}
