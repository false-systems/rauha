pub mod exec;
pub mod image;
pub mod logs;
pub mod output;
pub mod policy;
pub mod receipt;
pub mod run;
pub mod sandbox;
pub mod trace;
pub mod zone;

/// Connect to the rauhad gRPC server.
pub async fn connect() -> anyhow::Result<tonic::transport::Channel> {
    let addr =
        std::env::var("RAUHA_ADDR").unwrap_or_else(|_| rauha_common::rpc::DEFAULT_ADDRESS.into());
    rauha_common::rpc::connect(&addr).await
}
