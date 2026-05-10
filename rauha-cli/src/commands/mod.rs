pub mod exec;
pub mod image;
pub mod logs;
pub mod output;
pub mod policy;
pub mod run;
pub mod sandbox;
pub mod setup;
pub mod trace;
pub mod zone;

/// Connect to the rauhad gRPC server.
pub async fn connect(
) -> anyhow::Result<tonic::transport::Channel> {
    let addr = std::env::var("RAUHA_ADDR").unwrap_or_else(|_| "http://[::1]:9876".into());
    let channel = tonic::transport::Channel::from_shared(addr)?
        .connect()
        .await?;
    Ok(channel)
}
