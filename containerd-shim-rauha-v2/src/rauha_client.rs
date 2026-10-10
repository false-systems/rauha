//! Rauha gRPC client wrapper.
//!
//! Thin wrapper around the generated gRPC clients for zone and container
//! services. Connects to rauhad at the configured endpoint.

use anyhow::{Context, Result};
use tonic::transport::Channel;

pub mod pb {
    pub mod zone {
        tonic::include_proto!("rauha.zone.v1");
    }
    pub mod container {
        tonic::include_proto!("rauha.container.v1");
    }
}

use pb::container::container_service_client::ContainerServiceClient;
use pb::zone::zone_service_client::ZoneServiceClient;

/// Client handle to rauhad's gRPC API.
#[derive(Clone)]
pub struct RauhaClient {
    pub zones: ZoneServiceClient<Channel>,
    pub containers: ContainerServiceClient<Channel>,
}

impl RauhaClient {
    pub async fn connect(endpoint: &str) -> Result<Self> {
        let channel = rauha_common::rpc::connect(endpoint)
            .await
            .context("failed to connect to rauhad")?;

        Ok(Self {
            zones: ZoneServiceClient::new(channel.clone()),
            containers: ContainerServiceClient::new(channel),
        })
    }

    /// Default endpoint from env or fallback.
    pub fn endpoint() -> String {
        std::env::var("RAUHA_ADDR")
            .unwrap_or_else(|_| rauha_common::rpc::DEFAULT_ADDRESS.to_string())
    }
}
