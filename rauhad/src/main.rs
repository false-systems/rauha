mod backend;
mod logs;
mod metadata;
mod network;
mod server;
mod zone;

use std::path::PathBuf;
use std::sync::Arc;

use tonic::transport::Server;
use tracing_subscriber::EnvFilter;

use server::pb::zone::zone_service_server::ZoneServiceServer;
use server::pb::container::container_service_server::ContainerServiceServer;
use server::pb::image::image_service_server::ImageServiceServer;
use server::pb::sandbox::sandbox_service_server::SandboxServiceServer;

const DEFAULT_ROOT: &str = if cfg!(target_os = "macos") {
    "/tmp/rauha"
} else {
    "/var/lib/rauha"
};

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::from_default_env().add_directive("rauhad=info".parse()?))
        .init();

    let root = std::env::var("RAUHA_ROOT").unwrap_or_else(|_| DEFAULT_ROOT.into());
    let root_path = PathBuf::from(&root);

    // Ensure directories exist.
    std::fs::create_dir_all(root_path.join("metadata"))?;
    std::fs::create_dir_all(root_path.join("zones"))?;
    std::fs::create_dir_all(root_path.join("content"))?;

    tracing::info!(root = %root, "starting rauhad");

    // Open metadata store.
    let metadata = Arc::new(
        metadata::db::MetadataStore::open(&root_path.join("metadata").join("rauha.redb"))?,
    );

    // Create platform backend.
    #[cfg(target_os = "linux")]
    let (backend_box, event_tx) = backend::create_backend(&root)?;
    #[cfg(not(target_os = "linux"))]
    let backend_box = backend::create_backend(&root)?;
    let backend: Arc<dyn rauha_common::backend::IsolationBackend> = Arc::from(backend_box);

    tracing::info!(backend = backend.name(), "isolation backend initialized");

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
    let zone_svc = server::ZoneServiceImpl::new(registry.clone(), root.clone(), event_tx);
    #[cfg(not(target_os = "linux"))]
    let zone_svc = server::ZoneServiceImpl::new(registry.clone(), root.clone());
    let container_svc = server::ContainerServiceImpl::new(registry.clone());
    let image_svc = server::ImageServiceImpl::new(image_service);
    #[cfg(target_os = "linux")]
    let sandbox_svc = server::SandboxServiceImpl::new(registry.clone(), event_tx.clone());
    #[cfg(not(target_os = "linux"))]
    let sandbox_svc = server::SandboxServiceImpl::new(registry.clone(), None);

    let addr = "[::1]:9876".parse()?;
    tracing::info!(%addr, "listening on gRPC");

    // Graceful shutdown: clean up network state on SIGTERM/SIGINT.
    let mut sigterm = tokio::signal::unix::signal(
        tokio::signal::unix::SignalKind::terminate(),
    ).map_err(|e| anyhow::anyhow!("failed to register SIGTERM handler: {e}"))?;

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
    serve_result?;
    Ok(())
}

fn cleanup_network() {
    tracing::info!("cleaning up network state");
    #[cfg(target_os = "linux")]
    backend::linux::cleanup_network();
}
