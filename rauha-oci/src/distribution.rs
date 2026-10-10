use sha2::{Digest as _, Sha256};
use std::collections::HashMap;
use std::io::Write;
use std::sync::Arc;

use crate::content::{ContentStore, Digest};
use crate::reference::ImageReference;
use rauha_common::error::RauhaError;

/// OCI manifest (simplified — we parse what we need).
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct OciManifest {
    pub schema_version: u32,
    #[serde(default)]
    pub media_type: String,
    pub config: OciDescriptor,
    pub layers: Vec<OciDescriptor>,
}

/// OCI Image Index (manifest list) — multi-arch wrapper pointing to
/// platform-specific manifests.
#[derive(Debug, Clone, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct OciIndex {
    #[allow(dead_code)]
    pub schema_version: u32,
    pub manifests: Vec<OciPlatformManifest>,
}

#[derive(Debug, Clone, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct OciPlatformManifest {
    pub media_type: String,
    pub digest: String,
    #[allow(dead_code)]
    pub size: u64,
    pub platform: Option<OciPlatform>,
}

#[derive(Debug, Clone, serde::Deserialize)]
pub struct OciPlatform {
    pub architecture: String,
    pub os: String,
}

#[derive(Debug, Clone, serde::Deserialize, serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub struct OciDescriptor {
    pub media_type: String,
    pub digest: String,
    pub size: u64,
}

/// OCI image config (the parts we need for container creation).
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct OciImageConfig {
    #[serde(default)]
    pub config: Option<OciImageConfigInner>,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct OciImageConfigInner {
    #[serde(default, rename = "Cmd")]
    pub cmd: Option<Vec<String>>,
    #[serde(default, rename = "Entrypoint")]
    pub entrypoint: Option<Vec<String>>,
    #[serde(default, rename = "Env")]
    pub env: Option<Vec<String>>,
    #[serde(default, rename = "WorkingDir")]
    pub working_dir: Option<String>,
    #[serde(default, rename = "User")]
    pub user: Option<String>,
}

/// OCI Distribution Spec client for pulling images from registries.
pub struct DistributionClient {
    content: Arc<ContentStore>,
    http: reqwest::Client,
    /// Token cache keyed by (registry, scope).
    tokens: tokio::sync::Mutex<HashMap<(String, String), String>>,
}

impl DistributionClient {
    pub fn new(content: Arc<ContentStore>) -> Self {
        Self {
            content,
            http: reqwest::Client::builder()
                .user_agent("rauha/0.1")
                .connect_timeout(std::time::Duration::from_secs(15))
                .timeout(std::time::Duration::from_secs(300))
                .build()
                .expect("failed to build HTTP client"),
            tokens: tokio::sync::Mutex::new(HashMap::new()),
        }
    }

    /// Pull and store a manifest, returning the parsed manifest.
    ///
    /// Handles OCI Image Index (manifest list) by selecting the platform
    /// manifest matching the current architecture, then fetching it by digest.
    pub async fn pull_manifest(
        &self,
        reference: &ImageReference,
    ) -> Result<OciManifest, RauhaError> {
        let selector = reference.digest.as_deref().unwrap_or(&reference.tag);
        let url = format!(
            "https://{}/v2/{}/manifests/{}",
            reference.registry, reference.repository, selector
        );

        let accept = &[
            "application/vnd.oci.image.manifest.v1+json",
            "application/vnd.docker.distribution.manifest.v2+json",
            "application/vnd.oci.image.index.v1+json",
            "application/vnd.docker.distribution.manifest.list.v2+json",
        ];

        let body = self
            .authenticated_get(&url, &reference.registry, &reference.repository, accept)
            .await?;

        let canonical = reference.to_string_canonical();
        verify_manifest_digest(reference.digest.as_deref(), &body, &canonical)?;

        // Try parsing as a single manifest first.
        if let Ok(manifest) = serde_json::from_slice::<OciManifest>(&body) {
            self.content
                .put_manifest(&canonical, &body)
                .map_err(|e| RauhaError::ContentError {
                    message: format!("failed to store manifest: {e}"),
                })?;
            return Ok(manifest);
        }

        // Try parsing as a manifest list / OCI index.
        let index: OciIndex =
            serde_json::from_slice(&body).map_err(|e| RauhaError::ImagePullError {
                reference: canonical.clone(),
                message: format!("invalid manifest JSON (not a manifest or index): {e}"),
            })?;

        // Pick the platform manifest matching current OS/arch.
        let (target_os, target_arch) = current_platform();
        let platform_entry = index
            .manifests
            .iter()
            .find(|m| {
                m.platform
                    .as_ref()
                    .map(|p| p.os == target_os && p.architecture == target_arch)
                    .unwrap_or(false)
            })
            .or_else(|| {
                // Fallback: linux/amd64 is the most common default.
                index.manifests.iter().find(|m| {
                    m.platform
                        .as_ref()
                        .map(|p| p.os == "linux" && p.architecture == "amd64")
                        .unwrap_or(false)
                })
            })
            .ok_or_else(|| RauhaError::ImagePullError {
                reference: canonical.clone(),
                message: format!("no manifest for platform {target_os}/{target_arch} in index"),
            })?;

        // Fetch the platform-specific manifest by digest.
        let manifest_url = format!(
            "https://{}/v2/{}/manifests/{}",
            reference.registry, reference.repository, platform_entry.digest
        );

        let manifest_body = self
            .authenticated_get(
                &manifest_url,
                &reference.registry,
                &reference.repository,
                &[
                    "application/vnd.oci.image.manifest.v1+json",
                    "application/vnd.docker.distribution.manifest.v2+json",
                ],
            )
            .await?;
        verify_manifest_digest(Some(&platform_entry.digest), &manifest_body, &canonical)?;

        self.content
            .put_manifest(&canonical, &manifest_body)
            .map_err(|e| RauhaError::ContentError {
                message: format!("failed to store manifest: {e}"),
            })?;

        serde_json::from_slice(&manifest_body).map_err(|e| RauhaError::ImagePullError {
            reference: canonical,
            message: format!("invalid platform manifest JSON: {e}"),
        })
    }

    /// Pull and store a blob (layer or config), with progress callback.
    pub async fn pull_blob<F>(
        &self,
        registry: &str,
        repository: &str,
        digest: &Digest,
        on_progress: F,
    ) -> Result<(), RauhaError>
    where
        F: FnMut(u64, u64),
    {
        // Skip if already present.
        if self.content.has_blob(digest) {
            return Ok(());
        }

        let url = format!(
            "https://{}/v2/{}/blobs/{}",
            registry,
            repository,
            digest.as_str()
        );

        let resp = self
            .authenticated_get_response(&url, registry, repository)
            .await?;

        self.store_blob_response(resp, digest, 4 * 1024 * 1024 * 1024, on_progress)
            .await
    }

    async fn store_blob_response<F>(
        &self,
        resp: reqwest::Response,
        digest: &Digest,
        limit: u64,
        mut on_progress: F,
    ) -> Result<(), RauhaError>
    where
        F: FnMut(u64, u64),
    {
        let total = resp.content_length().unwrap_or(0);
        check_body_size(total, limit)?;
        let mut downloaded: u64 = 0;

        let mut file = self.content.temporary_blob()?;
        let mut hash = Sha256::new();
        {
            use tokio_stream::StreamExt;
            let mut stream = resp.bytes_stream();
            while let Some(chunk) = stream.next().await {
                let chunk = chunk.map_err(|e| RauhaError::ImagePullError {
                    reference: digest.to_string(),
                    message: format!("download error: {e}"),
                })?;
                downloaded += chunk.len() as u64;
                check_body_size(downloaded, limit)?;
                hash.update(&chunk);
                file.write_all(&chunk)?;
                on_progress(downloaded, total);
            }
        }

        // Verify digest.
        if hex::encode(hash.finalize()) != digest.hex() {
            return Err(RauhaError::ContentError {
                message: format!("digest mismatch for {digest}"),
            });
        }

        self.content
            .publish_blob(file, digest)
            .map_err(|e| RauhaError::ContentError {
                message: format!("failed to store blob: {e}"),
            })?;

        Ok(())
    }

    /// GET with OCI auth challenge-response flow.
    async fn authenticated_get(
        &self,
        url: &str,
        registry: &str,
        repository: &str,
        accept: &[&str],
    ) -> Result<Vec<u8>, RauhaError> {
        let scope = format!("repository:{}:pull", repository);

        // Try with cached token first.
        if let Some(token) = self.get_cached_token(registry, &scope).await {
            let resp = self
                .send_with_rate_limit(
                    self.http
                        .get(url)
                        .header("Accept", accept.join(", "))
                        .bearer_auth(&token),
                    url,
                )
                .await?;

            if resp.status().is_success() {
                return bounded_body(resp).await;
            }
        }

        // Initial request (may get 401).
        let resp = self
            .send_with_rate_limit(self.http.get(url).header("Accept", accept.join(", ")), url)
            .await?;

        if resp.status() == reqwest::StatusCode::UNAUTHORIZED {
            let www_auth = resp
                .headers()
                .get("www-authenticate")
                .and_then(|v| v.to_str().ok())
                .unwrap_or("")
                .to_string();

            let token = self.fetch_token(&www_auth, &scope).await?;
            self.cache_token(registry, &scope, &token).await;

            // Retry with token.
            let resp = self
                .send_with_rate_limit(
                    self.http
                        .get(url)
                        .header("Accept", accept.join(", "))
                        .bearer_auth(&token),
                    url,
                )
                .await?;

            if !resp.status().is_success() {
                return Err(RauhaError::ImagePullError {
                    reference: url.to_string(),
                    message: format!("HTTP {}", resp.status()),
                });
            }

            bounded_body(resp).await
        } else if resp.status().is_success() {
            bounded_body(resp).await
        } else {
            Err(RauhaError::ImagePullError {
                reference: url.to_string(),
                message: format!("HTTP {}", resp.status()),
            })
        }
    }

    /// GET a streaming response with auth.
    async fn authenticated_get_response(
        &self,
        url: &str,
        registry: &str,
        repository: &str,
    ) -> Result<reqwest::Response, RauhaError> {
        let scope = format!("repository:{}:pull", repository);

        // Try with cached token.
        if let Some(token) = self.get_cached_token(registry, &scope).await {
            let resp = self
                .send_with_rate_limit(self.http.get(url).bearer_auth(&token), url)
                .await?;

            if resp.status().is_success() {
                return Ok(resp);
            }
        }

        // Initial request.
        let resp = self.send_with_rate_limit(self.http.get(url), url).await?;

        if resp.status() == reqwest::StatusCode::UNAUTHORIZED {
            let www_auth = resp
                .headers()
                .get("www-authenticate")
                .and_then(|v| v.to_str().ok())
                .unwrap_or("")
                .to_string();

            let token = self.fetch_token(&www_auth, &scope).await?;
            self.cache_token(registry, &scope, &token).await;

            let resp = self
                .send_with_rate_limit(self.http.get(url).bearer_auth(&token), url)
                .await?;

            if !resp.status().is_success() {
                return Err(RauhaError::ImagePullError {
                    reference: url.to_string(),
                    message: format!("HTTP {}", resp.status()),
                });
            }

            Ok(resp)
        } else if resp.status().is_success() {
            Ok(resp)
        } else {
            Err(RauhaError::ImagePullError {
                reference: url.to_string(),
                message: format!("HTTP {}", resp.status()),
            })
        }
    }

    /// Parse `Www-Authenticate: Bearer realm="...",service="...",scope="..."` and fetch a token.
    async fn fetch_token(&self, www_authenticate: &str, scope: &str) -> Result<String, RauhaError> {
        let realm = extract_param(www_authenticate, "realm").unwrap_or_default();
        let service = extract_param(www_authenticate, "service").unwrap_or_default();

        if realm.is_empty() {
            return Err(RauhaError::ImagePullError {
                reference: String::new(),
                message: "no realm in Www-Authenticate header".into(),
            });
        }

        let url = format!("{realm}?service={service}&scope={scope}");

        let response = self.send_with_rate_limit(self.http.get(&url), &url).await?;
        let resp: serde_json::Value = serde_json::from_slice(&bounded_body(response).await?)
            .map_err(|e| RauhaError::ImagePullError {
                reference: url,
                message: format!("invalid token response: {e}"),
            })?;

        // Docker Hub returns "token", some registries return "access_token".
        resp.get("token")
            .or_else(|| resp.get("access_token"))
            .and_then(|v| v.as_str())
            .map(|s| s.to_string())
            .ok_or_else(|| RauhaError::ImagePullError {
                reference: String::new(),
                message: "no token in auth response".into(),
            })
    }

    async fn get_cached_token(&self, registry: &str, scope: &str) -> Option<String> {
        self.tokens
            .lock()
            .await
            .get(&(registry.to_string(), scope.to_string()))
            .cloned()
    }

    async fn cache_token(&self, registry: &str, scope: &str, token: &str) {
        self.tokens
            .lock()
            .await
            .insert((registry.to_string(), scope.to_string()), token.to_string());
    }

    async fn send_with_rate_limit(
        &self,
        request: reqwest::RequestBuilder,
        reference: &str,
    ) -> Result<reqwest::Response, RauhaError> {
        for attempt in 0..4 {
            let response = request
                .try_clone()
                .expect("OCI GET requests are cloneable")
                .send()
                .await
                .map_err(|error| RauhaError::ImagePullError {
                    reference: reference.into(),
                    message: format!("request failed: {error}"),
                })?;
            if response.status() != reqwest::StatusCode::TOO_MANY_REQUESTS || attempt == 3 {
                return Ok(response);
            }
            tokio::time::sleep(std::time::Duration::from_secs(1 << attempt)).await;
        }
        unreachable!()
    }
}

fn check_body_size(bytes: u64, limit: u64) -> Result<(), RauhaError> {
    if bytes > limit {
        return Err(RauhaError::ContentError {
            message: format!("registry response exceeds {limit} byte limit"),
        });
    }
    Ok(())
}

async fn bounded_body(response: reqwest::Response) -> Result<Vec<u8>, RauhaError> {
    use tokio_stream::StreamExt;
    check_body_size(response.content_length().unwrap_or(0), 4 * 1024 * 1024)?;
    let mut stream = response.bytes_stream();
    let mut body = Vec::new();
    while let Some(chunk) = stream.next().await {
        let chunk = chunk.map_err(|e| RauhaError::ContentError {
            message: e.to_string(),
        })?;
        check_body_size(
            (body.len() as u64).saturating_add(chunk.len() as u64),
            4 * 1024 * 1024,
        )?;
        body.extend_from_slice(&chunk);
    }
    Ok(body)
}

fn verify_manifest_digest(
    expected: Option<&str>,
    body: &[u8],
    reference: &str,
) -> Result<(), RauhaError> {
    let Some(expected) = expected else {
        return Ok(());
    };
    let digest = Digest::parse(expected).ok_or_else(|| RauhaError::ImagePullError {
        reference: reference.into(),
        message: format!("invalid manifest digest: {expected}"),
    })?;
    if digest.validate(body) {
        Ok(())
    } else {
        Err(RauhaError::ImagePullError {
            reference: reference.into(),
            message: format!("manifest digest mismatch for {digest}"),
        })
    }
}

/// Returns (os, architecture) matching OCI platform conventions.
fn current_platform() -> (&'static str, &'static str) {
    let os = if cfg!(target_os = "linux") {
        "linux"
    } else if cfg!(target_os = "macos") {
        // OCI images are Linux; when pulling on macOS we want linux images.
        "linux"
    } else {
        "linux"
    };

    let arch = if cfg!(target_arch = "x86_64") {
        "amd64"
    } else if cfg!(target_arch = "aarch64") {
        "arm64"
    } else {
        "amd64"
    };

    (os, arch)
}

/// Extract a parameter from a Bearer challenge header.
/// e.g., `Bearer realm="https://...",service="registry.docker.io"`
fn extract_param<'a>(header: &'a str, key: &str) -> Option<&'a str> {
    let needle = format!("{key}=\"");
    let start = header.find(&needle)? + needle.len();
    let end = header[start..].find('"')? + start;
    Some(&header[start..end])
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(target_os = "linux")]
    async fn registry_response(response: Vec<u8>) -> reqwest::Response {
        use std::io::{Read, Write};
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        std::thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            let mut request = [0; 4096];
            assert!(stream.read(&mut request).unwrap() > 0);
            let _ = stream.write_all(&response);
        });
        reqwest::get(format!("http://{address}/v2/test/blobs/sha256:test"))
            .await
            .unwrap()
    }

    #[cfg(target_os = "linux")]
    #[tokio::test]
    async fn streamed_blobs_verify_digest_and_remove_incomplete_downloads() {
        let dir = tempfile::tempdir().unwrap();
        let store = Arc::new(ContentStore::new(dir.path()).unwrap());
        let client = DistributionClient::new(store.clone());
        let digest = Digest::from_data(b"hello world");
        for response in [
            b"HTTP/1.1 200 OK\r\nContent-Length: 11\r\n\r\nwrong bytes".to_vec(),
            b"HTTP/1.1 200 OK\r\nContent-Length: 11\r\n\r\nshort".to_vec(),
            b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n8\r\n12345678\r\n8\r\n12345678\r\n0\r\n\r\n".to_vec(),
            b"HTTP/1.1 200 OK\r\nContent-Length: 5000000000\r\n\r\n".to_vec(),
        ] {
            assert!(client.store_blob_response(registry_response(response).await, &digest, 11, |_, _| {}).await.is_err());
            assert!(!store.has_blob(&digest));
            assert_eq!(std::fs::read_dir(dir.path().join("blobs/sha256")).unwrap().count(), 0);
        }
        let response = registry_response(b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n6\r\nhello \r\n5\r\nworld\r\n0\r\n\r\n".to_vec()).await;
        let mut final_progress = 0;
        client
            .store_blob_response(response, &digest, 11, |downloaded, _| {
                final_progress = downloaded
            })
            .await
            .unwrap();
        assert_eq!(final_progress, 11);
        assert_eq!(store.get_blob(&digest).unwrap(), b"hello world");
    }

    #[cfg(target_os = "linux")]
    #[tokio::test]
    async fn manifests_reject_oversized_headers_and_chunked_bodies() {
        let response =
            registry_response(b"HTTP/1.1 200 OK\r\nContent-Length: 4194305\r\n\r\n".to_vec()).await;
        assert!(bounded_body(response).await.is_err());
        let mut response =
            b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n400001\r\n".to_vec();
        response.resize(response.len() + 4 * 1024 * 1024 + 1, b'x');
        response.extend_from_slice(b"\r\n0\r\n\r\n");
        assert!(bounded_body(registry_response(response).await)
            .await
            .is_err());
    }

    #[test]
    fn response_bounds_are_inclusive() {
        assert!(check_body_size(4, 4).is_ok());
        assert!(check_body_size(5, 4).is_err());
    }

    #[test]
    fn extract_param_realm() {
        let header = r#"Bearer realm="https://auth.docker.io/token",service="registry.docker.io",scope="repository:library/nginx:pull""#;
        assert_eq!(
            extract_param(header, "realm"),
            Some("https://auth.docker.io/token")
        );
        assert_eq!(extract_param(header, "service"), Some("registry.docker.io"));
        assert_eq!(
            extract_param(header, "scope"),
            Some("repository:library/nginx:pull")
        );
    }

    #[test]
    fn extract_param_missing_key() {
        let header = r#"Bearer realm="https://auth.example.com/token""#;
        assert_eq!(extract_param(header, "service"), None);
    }

    #[test]
    fn extract_param_empty_header() {
        assert_eq!(extract_param("", "realm"), None);
        assert_eq!(extract_param("Basic", "realm"), None);
    }

    #[test]
    fn extract_param_ghcr() {
        let header = r#"Bearer realm="https://ghcr.io/token",service="ghcr.io",scope="repository:owner/repo:pull""#;
        assert_eq!(
            extract_param(header, "realm"),
            Some("https://ghcr.io/token")
        );
        assert_eq!(extract_param(header, "service"), Some("ghcr.io"));
    }

    #[test]
    fn manifest_digest_mismatch_is_rejected() {
        let body = b"manifest";
        let digest = Digest::from_data(body);
        verify_manifest_digest(Some(digest.as_str()), body, "image").unwrap();
        assert!(verify_manifest_digest(
            Some("sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"),
            body,
            "image",
        )
        .is_err());
    }

    #[test]
    fn manifest_deserialization() {
        let json = r#"{
            "schemaVersion": 2,
            "mediaType": "application/vnd.docker.distribution.manifest.v2+json",
            "config": {
                "mediaType": "application/vnd.docker.container.image.v1+json",
                "digest": "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                "size": 1234
            },
            "layers": [
                {
                    "mediaType": "application/vnd.docker.image.rootfs.diff.tar.gzip",
                    "digest": "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
                    "size": 5678
                },
                {
                    "mediaType": "application/vnd.docker.image.rootfs.diff.tar.gzip",
                    "digest": "sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc",
                    "size": 9012
                }
            ]
        }"#;

        let manifest: OciManifest = serde_json::from_str(json).unwrap();
        assert_eq!(manifest.schema_version, 2);
        assert_eq!(manifest.layers.len(), 2);
        assert_eq!(manifest.config.size, 1234);
        assert_eq!(manifest.layers[0].size, 5678);
        assert!(manifest.layers[1].digest.starts_with("sha256:"));
    }

    #[test]
    fn image_config_deserialization() {
        let json = r#"{
            "config": {
                "Cmd": ["/bin/sh"],
                "Entrypoint": ["/docker-entrypoint.sh"],
                "Env": ["PATH=/usr/local/bin:/usr/bin", "NGINX_VERSION=1.25"],
                "WorkingDir": "/app",
                "User": "nobody"
            }
        }"#;

        let config: OciImageConfig = serde_json::from_str(json).unwrap();
        let inner = config.config.unwrap();
        assert_eq!(inner.cmd.unwrap(), vec!["/bin/sh"]);
        assert_eq!(inner.entrypoint.unwrap(), vec!["/docker-entrypoint.sh"]);
        assert_eq!(inner.env.as_ref().unwrap().len(), 2);
        assert_eq!(inner.working_dir.unwrap(), "/app");
        assert_eq!(inner.user.unwrap(), "nobody");
    }

    #[test]
    fn image_config_empty() {
        // Config with no inner config (minimal image).
        let json = r#"{}"#;
        let config: OciImageConfig = serde_json::from_str(json).unwrap();
        assert!(config.config.is_none());
    }

    #[test]
    fn image_config_partial() {
        // Config with only some fields set.
        let json = r#"{"config": {"Cmd": ["echo", "hello"]}}"#;
        let config: OciImageConfig = serde_json::from_str(json).unwrap();
        let inner = config.config.unwrap();
        assert_eq!(inner.cmd.unwrap(), vec!["echo", "hello"]);
        assert!(inner.entrypoint.is_none());
        assert!(inner.env.is_none());
        assert!(inner.working_dir.is_none());
    }
}
