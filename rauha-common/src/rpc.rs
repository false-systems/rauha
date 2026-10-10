//! Local administration uses filesystem permissions, not unauthenticated TCP.
pub const DEFAULT_ADDRESS: &str = "/run/rauha/rauhad.sock";

pub async fn connect(address: &str) -> anyhow::Result<tonic::transport::Channel> {
    let path = address.strip_prefix("unix://").unwrap_or(address);
    anyhow::ensure!(
        std::path::Path::new(path).is_absolute(),
        "expected an absolute Unix socket path; TCP administration is disabled"
    );
    let path = path.to_owned();
    Ok(tonic::transport::Endpoint::from_static("http://localhost")
        .connect_with_connector(tower::service_fn(move |_| {
            let path = path.clone();
            async move {
                tokio::net::UnixStream::connect(path)
                    .await
                    .map(hyper_util::rt::TokioIo::new)
            }
        }))
        .await?)
}

#[cfg(test)]
mod tests {
    #[tokio::test]
    async fn tcp_endpoints_are_refused() {
        assert!(super::connect("http://127.0.0.1:9876")
            .await
            .unwrap_err()
            .to_string()
            .contains("TCP administration is disabled"));
    }
}
