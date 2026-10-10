use std::path::{Component, Path, PathBuf};
use std::sync::Arc;

use rauha_common::error::RauhaError;

use crate::content::{ContentStore, Digest};
use crate::distribution::{DistributionClient, OciImageConfig, OciManifest};
use crate::reference::ImageReference;

/// Progress event during an image pull.
#[derive(Debug, Clone)]
pub struct PullProgress {
    pub status: String,
    pub layer: String,
    pub current: u64,
    pub total: u64,
    pub done: bool,
}

/// Information about a locally stored image.
#[derive(Debug, Clone)]
pub struct ImageInfo {
    pub reference: String,
    pub digest: String,
    pub layers: usize,
    pub size: u64,
}

/// Full inspection result including manifest metadata and config.
#[derive(Debug, Clone)]
pub struct ImageInspection {
    pub digest: String,
    pub config: OciImageConfig,
    pub config_json: String,
    pub layers: Vec<String>,
    pub size: u64,
}

/// Orchestrates image pull, storage, and rootfs preparation.
pub struct ImageService {
    content: Arc<ContentStore>,
    client: DistributionClient,
    root: PathBuf,
}

impl ImageService {
    pub fn new(content: Arc<ContentStore>, root: PathBuf) -> Self {
        let client = DistributionClient::new(content.clone());
        Self {
            content,
            client,
            root,
        }
    }

    fn manifest_blobs_present(&self, manifest: &OciManifest) -> bool {
        std::iter::once(&manifest.config)
            .chain(manifest.layers.iter())
            .all(|entry| {
                Digest::parse(&entry.digest).is_some_and(|digest| self.content.has_blob(&digest))
            })
    }

    /// Pull an image from a registry, storing blobs in the content store.
    /// Returns progress events via the callback.
    pub async fn pull<F>(
        &self,
        reference_str: &str,
        mut on_progress: F,
    ) -> Result<OciManifest, RauhaError>
    where
        F: FnMut(PullProgress),
    {
        let reference =
            ImageReference::parse(reference_str).map_err(|e| RauhaError::ImagePullError {
                reference: reference_str.into(),
                message: e,
            })?;
        let canonical = reference.to_string_canonical();
        let cached = self
            .content
            .get_manifest(&canonical)
            .map_err(|error| RauhaError::ContentError {
                message: format!("failed to read cached manifest: {error}"),
            })?
            .and_then(|bytes| serde_json::from_slice::<OciManifest>(&bytes).ok())
            .filter(|manifest| self.manifest_blobs_present(manifest));

        // A digest reference is immutable, so a complete cache is final. A tag
        // can move, so it is re-resolved against the registry; the cache only
        // stands in when the registry cannot be reached.
        if reference.digest.is_some() {
            if let Some(manifest) = cached {
                on_progress(PullProgress {
                    status: "pull complete (cached)".into(),
                    layer: String::new(),
                    current: 0,
                    total: 0,
                    done: true,
                });
                return Ok(manifest);
            }
        }

        on_progress(PullProgress {
            status: "pulling manifest".into(),
            layer: String::new(),
            current: 0,
            total: 0,
            done: false,
        });

        let manifest = match self.client.pull_manifest(&reference).await {
            Ok(manifest) => manifest,
            Err(error) => {
                let Some(manifest) = cached else {
                    return Err(error);
                };
                tracing::warn!(reference = %canonical, %error, "registry unreachable; using cached tag");
                on_progress(PullProgress {
                    status: "pull complete (cached; registry unreachable)".into(),
                    layer: String::new(),
                    current: 0,
                    total: 0,
                    done: true,
                });
                return Ok(manifest);
            }
        };

        // Pull config blob.
        let config_digest =
            Digest::parse(&manifest.config.digest).ok_or_else(|| RauhaError::ImagePullError {
                reference: reference_str.into(),
                message: format!("invalid config digest: {}", manifest.config.digest),
            })?;

        on_progress(PullProgress {
            status: "pulling config".into(),
            layer: config_digest.to_string(),
            current: 0,
            total: manifest.config.size,
            done: false,
        });

        self.client
            .pull_blob(
                &reference.registry,
                &reference.repository,
                &config_digest,
                |_, _| {},
            )
            .await?;

        // Pull layer blobs.
        for (i, layer) in manifest.layers.iter().enumerate() {
            let layer_digest =
                Digest::parse(&layer.digest).ok_or_else(|| RauhaError::ImagePullError {
                    reference: reference_str.into(),
                    message: format!("invalid layer digest: {}", layer.digest),
                })?;

            let layer_num = format!("{}/{}", i + 1, manifest.layers.len());
            on_progress(PullProgress {
                status: format!("pulling layer {layer_num}"),
                layer: layer_digest.to_string(),
                current: 0,
                total: layer.size,
                done: false,
            });

            let status_prefix = format!("pulling layer {layer_num}");
            let manifest_size = layer.size;
            let mut last_reported_pct: i64 = -1;
            self.client
                .pull_blob(
                    &reference.registry,
                    &reference.repository,
                    &layer_digest,
                    |current, total| {
                        // Use manifest-declared size when CDN strips Content-Length.
                        let effective_total = if total > 0 { total } else { manifest_size };
                        if effective_total == 0 {
                            return;
                        }
                        let pct = (current * 100 / effective_total) as i64;
                        // Throttle: report every 5% or at 100%.
                        if pct >= last_reported_pct + 5 || (pct == 100 && last_reported_pct != 100)
                        {
                            last_reported_pct = pct;
                            on_progress(PullProgress {
                                status: status_prefix.clone(),
                                layer: layer_digest.to_string(),
                                current,
                                total: effective_total,
                                done: false,
                            });
                        }
                    },
                )
                .await?;
        }

        on_progress(PullProgress {
            status: "pull complete".into(),
            layer: String::new(),
            current: 0,
            total: 0,
            done: true,
        });

        Ok(manifest)
    }

    /// Prepare a rootfs directory by unpacking all image layers sequentially.
    ///
    /// Phase 3 simplification: no overlayfs — all layers extracted into a single directory.
    pub fn prepare_rootfs(&self, reference_str: &str, target: &Path) -> Result<(), RauhaError> {
        let canonical = {
            let reference =
                ImageReference::parse(reference_str).map_err(|e| RauhaError::ImagePullError {
                    reference: reference_str.into(),
                    message: e,
                })?;
            reference.to_string_canonical()
        };

        // Load manifest from content store.
        let manifest_bytes = self
            .content
            .get_manifest(&canonical)
            .map_err(|e| RauhaError::ContentError {
                message: format!("failed to read manifest: {e}"),
            })?
            .ok_or_else(|| RauhaError::ImagePullError {
                reference: reference_str.into(),
                message: "image not pulled — run `rauha image pull` first".into(),
            })?;

        let manifest: OciManifest =
            serde_json::from_slice(&manifest_bytes).map_err(|e| RauhaError::ContentError {
                message: format!("corrupt manifest: {e}"),
            })?;

        std::fs::create_dir_all(target).map_err(|e| RauhaError::RootfsError {
            message: format!("failed to create rootfs dir: {e}"),
        })?;

        // Unpack layers in order.
        for layer in &manifest.layers {
            let digest = Digest::parse(&layer.digest).ok_or_else(|| RauhaError::RootfsError {
                message: format!("invalid layer digest: {}", layer.digest),
            })?;

            let blob_path = self.content.blob_file_path(&digest);
            tracing::info!(layer = %digest, "unpacking layer");

            let file = std::fs::File::open(&blob_path).map_err(|e| RauhaError::RootfsError {
                message: format!("failed to open layer blob {digest}: {e}"),
            })?;

            let decoder = flate2::read::GzDecoder::new(file);
            let archive = tar::Archive::new(decoder);

            // Unpack with whiteout handling for OCI layer semantics.
            unpack_layer(archive, target)?;
        }

        tracing::info!(rootfs = %target.display(), layers = manifest.layers.len(), "rootfs prepared");
        Ok(())
    }

    /// Prepare the same immutable layer-chain snapshot used by overlay mounts.
    pub fn prepare_base_rootfs(&self, reference_str: &str) -> Result<PathBuf, RauhaError> {
        let (_, digests, content_root) = self.layer_digests(reference_str)?;
        crate::snapshotter::OverlayfsSnapshotter::new(&self.root)
            .prepare_layers("", &digests, &content_root)?
            .into_iter()
            .next()
            .ok_or_else(|| RauhaError::RootfsError {
                message: "snapshot preparation returned no rootfs".into(),
            })
    }

    /// Return layer digests and content root for an image.
    ///
    /// Pins the attested manifest and its ordered layer chain in one read.
    pub fn layer_digests(
        &self,
        reference_str: &str,
    ) -> Result<(String, Vec<String>, PathBuf), RauhaError> {
        let canonical = {
            let reference =
                ImageReference::parse(reference_str).map_err(|e| RauhaError::ImagePullError {
                    reference: reference_str.into(),
                    message: e,
                })?;
            reference.to_string_canonical()
        };

        let manifest_bytes = self
            .content
            .get_manifest(&canonical)
            .map_err(|e| RauhaError::ContentError {
                message: format!("failed to read manifest: {e}"),
            })?
            .ok_or_else(|| RauhaError::ImagePullError {
                reference: reference_str.into(),
                message: "image not pulled — run `rauha image pull` first".into(),
            })?;

        let manifest: OciManifest =
            serde_json::from_slice(&manifest_bytes).map_err(|e| RauhaError::ContentError {
                message: format!("corrupt manifest: {e}"),
            })?;

        let digests = manifest.layers.iter().map(|l| l.digest.clone()).collect();

        let content_root = self.root.join("content");
        Ok((
            Digest::from_data(&manifest_bytes).to_string(),
            digests,
            content_root,
        ))
    }

    /// Get the image config (CMD, ENV, WORKDIR, etc.) from a pulled image.
    pub fn inspect(&self, reference_str: &str) -> Result<OciImageConfig, RauhaError> {
        let canonical = {
            let reference =
                ImageReference::parse(reference_str).map_err(|e| RauhaError::ImagePullError {
                    reference: reference_str.into(),
                    message: e,
                })?;
            reference.to_string_canonical()
        };

        let manifest_bytes = self
            .content
            .get_manifest(&canonical)
            .map_err(|e| RauhaError::ContentError {
                message: format!("failed to read manifest: {e}"),
            })?
            .ok_or_else(|| RauhaError::ImageNotFound(reference_str.into()))?;

        let manifest: OciManifest =
            serde_json::from_slice(&manifest_bytes).map_err(|e| RauhaError::ContentError {
                message: format!("corrupt manifest: {e}"),
            })?;

        let config_digest =
            Digest::parse(&manifest.config.digest).ok_or_else(|| RauhaError::ContentError {
                message: format!("invalid config digest: {}", manifest.config.digest),
            })?;

        let config_bytes =
            self.content
                .get_blob(&config_digest)
                .map_err(|e| RauhaError::ContentError {
                    message: format!("failed to read config blob: {e}"),
                })?;

        serde_json::from_slice(&config_bytes).map_err(|e| RauhaError::ContentError {
            message: format!("corrupt image config: {e}"),
        })
    }

    /// Get full image inspection: config, digest, layers, size.
    pub fn inspect_full(&self, reference_str: &str) -> Result<ImageInspection, RauhaError> {
        let canonical = {
            let reference =
                ImageReference::parse(reference_str).map_err(|e| RauhaError::ImagePullError {
                    reference: reference_str.into(),
                    message: e,
                })?;
            reference.to_string_canonical()
        };

        let manifest_bytes = self
            .content
            .get_manifest(&canonical)
            .map_err(|e| RauhaError::ContentError {
                message: format!("failed to read manifest: {e}"),
            })?
            .ok_or_else(|| RauhaError::ImageNotFound(reference_str.into()))?;

        let manifest: OciManifest =
            serde_json::from_slice(&manifest_bytes).map_err(|e| RauhaError::ContentError {
                message: format!("corrupt manifest: {e}"),
            })?;

        let config_digest =
            Digest::parse(&manifest.config.digest).ok_or_else(|| RauhaError::ContentError {
                message: format!("invalid config digest: {}", manifest.config.digest),
            })?;

        let config_bytes =
            self.content
                .get_blob(&config_digest)
                .map_err(|e| RauhaError::ContentError {
                    message: format!("failed to read config blob: {e}"),
                })?;

        let config: OciImageConfig =
            serde_json::from_slice(&config_bytes).map_err(|e| RauhaError::ContentError {
                message: format!("corrupt image config: {e}"),
            })?;

        let config_json = String::from_utf8_lossy(&config_bytes).into_owned();

        let layers: Vec<String> = manifest.layers.iter().map(|l| l.digest.clone()).collect();
        let size: u64 = manifest.layers.iter().map(|l| l.size).sum();

        // Compute the manifest digest (not config digest) — this is what
        // callers expect as the image identifier.
        let manifest_digest = Digest::from_data(&manifest_bytes);

        Ok(ImageInspection {
            digest: manifest_digest.as_str().to_string(),
            config,
            config_json,
            layers,
            size,
        })
    }

    /// List locally stored images (by scanning manifest references).
    pub fn list_images(&self) -> Result<Vec<ImageInfo>, RauhaError> {
        let manifests_dir = self.root.join("content").join("references-v2");
        if !manifests_dir.exists() {
            return Ok(Vec::new());
        }

        let mut images = Vec::new();
        let entries = std::fs::read_dir(&manifests_dir).map_err(|e| RauhaError::ContentError {
            message: format!("failed to read manifests dir: {e}"),
        })?;

        for entry in entries.flatten() {
            let path = entry.path();
            if path.extension().and_then(|e| e.to_str()) != Some("json") {
                continue;
            }

            let bytes = std::fs::read(&path)?;
            let (reference, digest_str): (String, String) = serde_json::from_slice(&bytes)
                .map_err(|e| RauhaError::ContentError {
                    message: format!("corrupt image reference: {e}"),
                })?;

            // Try to load manifest for layer count / size.
            let (layers, size) = if let Some(digest) = Digest::parse(&digest_str) {
                if let Ok(data) = self.content.get_blob(&digest) {
                    if let Ok(m) = serde_json::from_slice::<OciManifest>(&data) {
                        (m.layers.len(), m.layers.iter().map(|l| l.size).sum())
                    } else {
                        (0, 0)
                    }
                } else {
                    (0, 0)
                }
            } else {
                (0, 0)
            };

            images.push(ImageInfo {
                reference,
                digest: digest_str,
                layers,
                size,
            });
        }

        Ok(images)
    }

    /// Remove an image's manifest reference (blobs are kept for potential sharing).
    pub fn remove_image(&self, reference_str: &str) -> Result<(), RauhaError> {
        let canonical = {
            let reference =
                ImageReference::parse(reference_str).map_err(|e| RauhaError::ImagePullError {
                    reference: reference_str.into(),
                    message: e,
                })?;
            reference.to_string_canonical()
        };

        let ref_path = self.content.manifest_ref_path(&canonical);

        if ref_path.exists() {
            std::fs::remove_file(&ref_path).map_err(|e| RauhaError::ContentError {
                message: format!("failed to remove manifest ref: {e}"),
            })?;
        }

        Ok(())
    }
}

fn invalid_layer_path(path: &Path, reason: &str) -> RauhaError {
    RauhaError::RootfsError {
        message: format!("unsafe layer path {}: {reason}", path.display()),
    }
}

fn clean_layer_path(path: &Path) -> Result<PathBuf, RauhaError> {
    let mut clean = PathBuf::new();
    for component in path.components() {
        match component {
            Component::Normal(part) => clean.push(part),
            Component::CurDir => {}
            Component::ParentDir | Component::RootDir | Component::Prefix(_) => {
                return Err(invalid_layer_path(path, "path escapes the rootfs"));
            }
        }
    }
    if clean.as_os_str().is_empty() {
        return Err(invalid_layer_path(path, "path is empty"));
    }
    Ok(clean)
}

/// Resolve an existing whiteout parent without following image-controlled symlinks.
///
/// Layer extraction happens in a private staging directory, so rejecting every
/// symlink component closes the whiteout escape without another path library.
fn whiteout_parent(target: &Path, relative: &Path) -> Result<Option<PathBuf>, RauhaError> {
    let mut current = target.canonicalize().map_err(|e| RauhaError::RootfsError {
        message: format!("failed to resolve rootfs {}: {e}", target.display()),
    })?;

    for component in relative.components() {
        let Component::Normal(part) = component else {
            return Err(invalid_layer_path(relative, "invalid whiteout parent"));
        };
        current.push(part);
        match std::fs::symlink_metadata(&current) {
            Ok(metadata) if metadata.file_type().is_symlink() => {
                return Err(invalid_layer_path(relative, "whiteout parent is a symlink"));
            }
            Ok(metadata) if !metadata.is_dir() => {
                return Err(invalid_layer_path(
                    relative,
                    "whiteout parent is not a directory",
                ));
            }
            Ok(_) => {}
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(error) => {
                return Err(RauhaError::RootfsError {
                    message: format!(
                        "failed to inspect whiteout parent {}: {error}",
                        current.display()
                    ),
                });
            }
        }
    }

    Ok(Some(current))
}

fn remove_path(path: &Path) -> Result<(), RauhaError> {
    let metadata = match std::fs::symlink_metadata(path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(error) => {
            return Err(RauhaError::RootfsError {
                message: format!(
                    "failed to inspect whiteout target {}: {error}",
                    path.display()
                ),
            });
        }
    };

    let result = if metadata.is_dir() && !metadata.file_type().is_symlink() {
        std::fs::remove_dir_all(path)
    } else {
        std::fs::remove_file(path)
    };
    result.map_err(|e| RauhaError::RootfsError {
        message: format!("failed to apply whiteout to {}: {e}", path.display()),
    })
}

fn clear_directory(path: &Path) -> Result<(), RauhaError> {
    for entry in std::fs::read_dir(path).map_err(|e| RauhaError::RootfsError {
        message: format!(
            "failed to read opaque whiteout directory {}: {e}",
            path.display()
        ),
    })? {
        remove_path(
            &entry
                .map_err(|e| RauhaError::RootfsError {
                    message: format!("failed to read opaque whiteout entry: {e}"),
                })?
                .path(),
        )?;
    }
    Ok(())
}

/// Unpack a tar layer into a target directory, handling OCI whiteout files.
pub fn unpack_layer(
    archive: tar::Archive<flate2::read::GzDecoder<std::fs::File>>,
    target: &Path,
) -> Result<(), RauhaError> {
    use std::io::{Seek, SeekFrom};
    let mut file = archive.into_inner().into_inner();
    // Whiteouts only remove lower-layer content, regardless of tar entry order.
    for whiteouts in [true, false] {
        file.seek(SeekFrom::Start(0))?;
        let mut pass = tar::Archive::new(flate2::read::GzDecoder::new(file.try_clone()?));
        unpack_layer_pass(&mut pass, target, whiteouts)?;
    }
    Ok(())
}

pub(crate) fn unpack_layer_file(blob: &Path, target: &Path) -> Result<(), RauhaError> {
    let archive = tar::Archive::new(flate2::read::GzDecoder::new(std::fs::File::open(blob)?));
    unpack_layer(archive, target)
}

fn unpack_layer_pass(
    archive: &mut tar::Archive<flate2::read::GzDecoder<std::fs::File>>,
    target: &Path,
    whiteouts: bool,
) -> Result<(), RauhaError> {
    let mut expanded = 0u64;
    for entry in archive.entries().map_err(|e| RauhaError::RootfsError {
        message: format!("failed to read tar entries: {e}"),
    })? {
        let mut entry = entry.map_err(|e| RauhaError::RootfsError {
            message: format!("corrupt tar entry: {e}"),
        })?;

        let path = entry.path().map_err(|e| RauhaError::RootfsError {
            message: format!("invalid tar entry path: {e}"),
        })?;
        let path = clean_layer_path(&path)?;
        expanded = expanded.saturating_add(entry.size());
        if expanded > 16 * 1024 * 1024 * 1024 {
            return Err(invalid_layer_path(
                &path,
                "layer exceeds 16 GiB extracted size limit",
            ));
        }
        let is_whiteout = path
            .file_name()
            .and_then(|v| v.to_str())
            .is_some_and(|v| v.starts_with(".wh."));
        if is_whiteout != whiteouts {
            continue;
        }

        // Check for OCI whiteout markers.
        if let Some(name) = path.file_name().and_then(|n| n.to_str()) {
            if name == ".wh..wh..opq" {
                // Opaque whiteout: remove all existing contents of the parent directory.
                if let Some(parent) = path.parent() {
                    if let Some(full_parent) = whiteout_parent(target, parent)? {
                        clear_directory(&full_parent)?;
                    }
                }
                continue;
            }
            if let Some(original) = name.strip_prefix(".wh.") {
                // The derived target must be exactly one plain name: `.wh...`
                // would otherwise resolve to `..` and delete the staging
                // directory's parent on the host.
                if original.is_empty()
                    || original == "."
                    || original == ".."
                    || original.contains('/')
                {
                    return Err(invalid_layer_path(&path, "invalid whiteout target"));
                }
                // File whiteout: delete the corresponding file.
                if let Some(parent) = path.parent() {
                    if let Some(full_parent) = whiteout_parent(target, parent)? {
                        remove_path(&full_parent.join(original))?;
                    }
                }
                continue;
            }
        }

        entry
            .unpack_in(target)
            .map_err(|e| RauhaError::RootfsError {
                message: format!("failed to unpack {}: {e}", path.display()),
            })?;
    }

    Ok(())
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use crate::content::ContentStore;
    use crate::distribution::{OciDescriptor, OciManifest};

    /// Create a gzipped tar archive from a list of (path, content) pairs.
    pub fn make_tar_gz(files: &[(&str, &[u8])]) -> Vec<u8> {
        let mut tar_data = Vec::new();
        {
            let enc = flate2::write::GzEncoder::new(&mut tar_data, flate2::Compression::fast());
            let mut builder = tar::Builder::new(enc);

            for (path, content) in files {
                let mut header = tar::Header::new_gnu();
                header.set_path(path).unwrap();
                header.set_size(content.len() as u64);
                header.set_mode(0o644);
                header.set_cksum();
                builder.append(&header, *content).unwrap();
            }

            builder.finish().unwrap();
            let enc = builder.into_inner().unwrap();
            enc.finish().unwrap();
        }
        tar_data
    }

    /// Set up a content store with a fake manifest and layers.
    fn setup_content_store_with_image(dir: &std::path::Path) -> (Arc<ContentStore>, String) {
        let content_dir = dir.join("content");
        let store = Arc::new(ContentStore::new(&content_dir).unwrap());

        // Create a layer.
        let layer_data = make_tar_gz(&[
            ("hello.txt", b"hello world"),
            ("bin/test", b"#!/bin/sh\necho hi"),
        ]);
        let layer_digest = store.put_blob(&layer_data).unwrap();

        // Create image config.
        let config_json = br#"{"config":{"Cmd":["/bin/sh"],"Env":["PATH=/usr/bin"]}}"#;
        let config_digest = store.put_blob(config_json).unwrap();

        // Create manifest.
        let manifest = OciManifest {
            schema_version: 2,
            media_type: "application/vnd.oci.image.manifest.v1+json".into(),
            config: OciDescriptor {
                media_type: "application/vnd.oci.image.config.v1+json".into(),
                digest: config_digest.as_str().to_string(),
                size: config_json.len() as u64,
            },
            layers: vec![OciDescriptor {
                media_type: "application/vnd.oci.image.rootfs.diff.tar.gzip".into(),
                digest: layer_digest.as_str().to_string(),
                size: layer_data.len() as u64,
            }],
        };
        let manifest_bytes = serde_json::to_vec(&manifest).unwrap();

        // Store manifest under canonical reference.
        let reference = "registry-1.docker.io/library/testimage:latest";
        store.put_manifest(reference, &manifest_bytes).unwrap();

        (store, reference.to_string())
    }

    #[test]
    fn inspect_returns_image_config() {
        let dir = tempfile::tempdir().unwrap();
        let (store, _reference) = setup_content_store_with_image(dir.path());

        let svc = ImageService::new(store, dir.path().to_path_buf());
        let config = svc.inspect("testimage:latest").unwrap();

        let inner = config.config.unwrap();
        assert_eq!(inner.cmd.unwrap(), vec!["/bin/sh"]);
        assert_eq!(inner.env.unwrap(), vec!["PATH=/usr/bin"]);
    }

    /// Re-key the fixture manifest under a reference whose registry is a
    /// closed local port, so a pull that consults the registry fails fast
    /// instead of reaching the network.
    fn store_manifest_under(store: &ContentStore, reference: &str) -> String {
        let bytes = store
            .get_manifest("registry-1.docker.io/library/testimage:latest")
            .unwrap()
            .unwrap();
        let canonical = ImageReference::parse(reference)
            .unwrap()
            .to_string_canonical();
        store.put_manifest(&canonical, &bytes).unwrap();
        reference.to_string()
    }

    #[tokio::test]
    async fn pull_by_digest_is_served_from_a_complete_cache() {
        let dir = tempfile::tempdir().unwrap();
        let (store, _) = setup_content_store_with_image(dir.path());
        let manifest_bytes = store
            .get_manifest("registry-1.docker.io/library/testimage:latest")
            .unwrap()
            .unwrap();
        let digest = store.put_blob(&manifest_bytes).unwrap();
        let reference = store_manifest_under(
            &store,
            &format!("127.0.0.1:1/testimage@{}", digest.as_str()),
        );
        let svc = ImageService::new(store, dir.path().to_path_buf());
        let mut statuses = Vec::new();

        let manifest = svc
            .pull(&reference, |progress| statuses.push(progress.status))
            .await
            .unwrap();

        assert_eq!(manifest.layers.len(), 1);
        assert_eq!(statuses, ["pull complete (cached)"]);
    }

    #[tokio::test]
    async fn pull_by_tag_consults_the_registry_and_falls_back_to_cache() {
        let dir = tempfile::tempdir().unwrap();
        let (store, _) = setup_content_store_with_image(dir.path());
        let reference = store_manifest_under(&store, "127.0.0.1:1/testimage:latest");
        let svc = ImageService::new(store, dir.path().to_path_buf());
        let mut statuses = Vec::new();

        let manifest = svc
            .pull(&reference, |progress| statuses.push(progress.status))
            .await
            .unwrap();

        assert_eq!(manifest.layers.len(), 1);
        assert_eq!(
            statuses,
            [
                "pulling manifest",
                "pull complete (cached; registry unreachable)"
            ]
        );
    }

    #[test]
    fn inspect_missing_image_returns_error() {
        let dir = tempfile::tempdir().unwrap();
        let content_dir = dir.path().join("content");
        let store = Arc::new(ContentStore::new(&content_dir).unwrap());

        let svc = ImageService::new(store, dir.path().to_path_buf());
        let result = svc.inspect("nonexistent:latest");
        assert!(result.is_err());
    }

    #[test]
    fn prepare_rootfs_unpacks_layer() {
        let dir = tempfile::tempdir().unwrap();
        let (store, _reference) = setup_content_store_with_image(dir.path());

        let svc = ImageService::new(store, dir.path().to_path_buf());
        let rootfs = dir.path().join("test-rootfs");
        svc.prepare_rootfs("testimage:latest", &rootfs).unwrap();

        // Verify files were unpacked.
        assert!(rootfs.join("hello.txt").exists());
        assert_eq!(
            std::fs::read_to_string(rootfs.join("hello.txt")).unwrap(),
            "hello world"
        );
        assert!(rootfs.join("bin/test").exists());
    }

    #[test]
    fn prepare_rootfs_missing_image_errors() {
        let dir = tempfile::tempdir().unwrap();
        let content_dir = dir.path().join("content");
        let store = Arc::new(ContentStore::new(&content_dir).unwrap());

        let svc = ImageService::new(store, dir.path().to_path_buf());
        let rootfs = dir.path().join("test-rootfs");
        let result = svc.prepare_rootfs("nonexistent:latest", &rootfs);
        assert!(result.is_err());
    }

    #[test]
    fn prepare_base_rootfs_extracts_and_returns_path() {
        let dir = tempfile::tempdir().unwrap();
        let (store, _reference) = setup_content_store_with_image(dir.path());

        let svc = ImageService::new(store, dir.path().to_path_buf());
        let rootfs = svc.prepare_base_rootfs("testimage:latest").unwrap();

        // Verify path structure.
        assert_eq!(rootfs.parent().unwrap(), dir.path().join("snapshots-v2"));
        assert!(rootfs.join("hello.txt").exists());
        assert_eq!(
            std::fs::read_to_string(rootfs.join("hello.txt")).unwrap(),
            "hello world"
        );
        // Only fully extracted trees receive their final digest name.
        assert_eq!(rootfs.file_name().unwrap().len(), 64);
    }

    #[test]
    fn prepare_base_rootfs_idempotent_skips_reextraction() {
        let dir = tempfile::tempdir().unwrap();
        let (store, _reference) = setup_content_store_with_image(dir.path());

        let svc = ImageService::new(store, dir.path().to_path_buf());

        // First call extracts.
        let path1 = svc.prepare_base_rootfs("testimage:latest").unwrap();
        // Second call returns immediately (idempotent).
        let path2 = svc.prepare_base_rootfs("testimage:latest").unwrap();

        assert_eq!(path1, path2);
        assert!(path1.join("hello.txt").exists());
    }

    #[test]
    fn prepare_base_rootfs_recovers_from_partial_extraction() {
        let dir = tempfile::tempdir().unwrap();
        let (store, _reference) = setup_content_store_with_image(dir.path());

        let svc = ImageService::new(store, dir.path().to_path_buf());

        // Simulate a crashed extraction: create rootfs dir with content but no marker.
        let safe_name = "registry-1.docker.io_library_testimage_latest";
        let image_dir = dir.path().join("images").join(safe_name);
        let rootfs_dir = image_dir.join("rootfs");
        std::fs::create_dir_all(&rootfs_dir).unwrap();
        std::fs::write(rootfs_dir.join("stale-file"), b"leftover").unwrap();
        // No .complete marker — simulates crash mid-extraction.

        // Should re-extract despite non-empty dir.
        let path = svc.prepare_base_rootfs("testimage:latest").unwrap();
        assert!(path.join("hello.txt").exists());
        // Stale file should be gone (replaced by fresh extraction).
        assert!(!path.join("stale-file").exists());
    }

    #[test]
    fn list_images_empty() {
        let dir = tempfile::tempdir().unwrap();
        let content_dir = dir.path().join("content");
        let store = Arc::new(ContentStore::new(&content_dir).unwrap());

        let svc = ImageService::new(store, dir.path().to_path_buf());
        let images = svc.list_images().unwrap();
        assert!(images.is_empty());
    }

    #[test]
    fn list_images_returns_stored_image() {
        let dir = tempfile::tempdir().unwrap();
        let (store, _reference) = setup_content_store_with_image(dir.path());

        let svc = ImageService::new(store, dir.path().to_path_buf());
        let images = svc.list_images().unwrap();
        assert_eq!(images.len(), 1);
        assert_eq!(images[0].layers, 1);
        assert!(images[0].size > 0);
    }

    #[test]
    fn remove_image_deletes_reference() {
        let dir = tempfile::tempdir().unwrap();
        let (store, _reference) = setup_content_store_with_image(dir.path());

        let svc = ImageService::new(store, dir.path().to_path_buf());

        // Verify image exists.
        assert!(svc.inspect("testimage:latest").is_ok());

        // Remove it.
        svc.remove_image("testimage:latest").unwrap();

        // Should no longer be inspectable.
        assert!(svc.inspect("testimage:latest").is_err());
    }

    #[test]
    fn whiteout_file_deletion() {
        let dir = tempfile::tempdir().unwrap();
        let content_dir = dir.path().join("content");
        let store = Arc::new(ContentStore::new(&content_dir).unwrap());

        // Layer 1: create a file.
        let layer1 = make_tar_gz(&[("etc/config.txt", b"original")]);
        let layer1_digest = store.put_blob(&layer1).unwrap();

        // Layer 2: whiteout that file.
        let layer2 = make_tar_gz(&[("etc/.wh.config.txt", b"")]);
        let layer2_digest = store.put_blob(&layer2).unwrap();

        let config_json = br#"{"config":{"Cmd":["/bin/sh"]}}"#;
        let config_digest = store.put_blob(config_json).unwrap();

        let manifest = OciManifest {
            schema_version: 2,
            media_type: String::new(),
            config: OciDescriptor {
                media_type: String::new(),
                digest: config_digest.as_str().to_string(),
                size: config_json.len() as u64,
            },
            layers: vec![
                OciDescriptor {
                    media_type: String::new(),
                    digest: layer1_digest.as_str().to_string(),
                    size: layer1.len() as u64,
                },
                OciDescriptor {
                    media_type: String::new(),
                    digest: layer2_digest.as_str().to_string(),
                    size: layer2.len() as u64,
                },
            ],
        };
        let manifest_bytes = serde_json::to_vec(&manifest).unwrap();
        let reference = "registry-1.docker.io/library/whiteout-test:latest";
        store.put_manifest(reference, &manifest_bytes).unwrap();

        let svc = ImageService::new(store, dir.path().to_path_buf());
        let rootfs = dir.path().join("rootfs");
        svc.prepare_rootfs("whiteout-test:latest", &rootfs).unwrap();

        // The file should have been deleted by the whiteout.
        assert!(!rootfs.join("etc/config.txt").exists());
    }

    #[test]
    fn whiteout_target_cannot_name_the_parent_directory() {
        let dir = tempfile::tempdir().unwrap();
        let target = dir.path().join("rootfs");
        std::fs::create_dir_all(&target).unwrap();
        std::fs::write(dir.path().join("sibling"), b"host data").unwrap();

        for name in [".wh...", ".wh.."] {
            let layer = make_tar_gz(&[(name, b"")]);
            let layer_path = dir.path().join("layer.tar.gz");
            std::fs::write(&layer_path, layer).unwrap();
            let decoder = flate2::read::GzDecoder::new(std::fs::File::open(&layer_path).unwrap());
            let archive = tar::Archive::new(decoder);

            let error = unpack_layer(archive, &target).unwrap_err();
            assert!(
                error.to_string().contains("invalid whiteout target"),
                "{name}"
            );
        }
        assert!(target.is_dir());
        assert_eq!(
            std::fs::read(dir.path().join("sibling")).unwrap(),
            b"host data"
        );
    }

    #[test]
    fn whiteout_rejects_parent_traversal() {
        let error = clean_layer_path(Path::new("../outside/.wh.victim")).unwrap_err();
        assert!(error.to_string().contains("path escapes the rootfs"));
    }

    #[cfg(unix)]
    #[test]
    fn whiteout_does_not_follow_a_symlinked_parent() {
        use std::os::unix::fs::symlink;

        let dir = tempfile::tempdir().unwrap();
        let target = dir.path().join("rootfs");
        let outside = dir.path().join("outside");
        std::fs::create_dir_all(&target).unwrap();
        std::fs::create_dir_all(&outside).unwrap();
        std::fs::write(outside.join("victim"), b"host data").unwrap();
        symlink(&outside, target.join("escape")).unwrap();

        let layer = make_tar_gz(&[("escape/.wh.victim", b"")]);
        let layer_path = dir.path().join("layer.tar.gz");
        std::fs::write(&layer_path, layer).unwrap();
        let decoder = flate2::read::GzDecoder::new(std::fs::File::open(layer_path).unwrap());
        let archive = tar::Archive::new(decoder);

        let error = unpack_layer(archive, &target).unwrap_err();
        assert!(error.to_string().contains("whiteout parent is a symlink"));
        assert_eq!(std::fs::read(outside.join("victim")).unwrap(), b"host data");
    }

    #[test]
    fn multiple_layers_applied_in_order() {
        let dir = tempfile::tempdir().unwrap();
        let content_dir = dir.path().join("content");
        let store = Arc::new(ContentStore::new(&content_dir).unwrap());

        // Layer 1: create a file.
        let layer1 = make_tar_gz(&[("data.txt", b"layer1")]);
        let layer1_digest = store.put_blob(&layer1).unwrap();

        // Layer 2: overwrite the file.
        let layer2 = make_tar_gz(&[("data.txt", b"layer2")]);
        let layer2_digest = store.put_blob(&layer2).unwrap();

        let config_json = br#"{"config":{"Cmd":["/bin/sh"]}}"#;
        let config_digest = store.put_blob(config_json).unwrap();

        let manifest = OciManifest {
            schema_version: 2,
            media_type: String::new(),
            config: OciDescriptor {
                media_type: String::new(),
                digest: config_digest.as_str().to_string(),
                size: config_json.len() as u64,
            },
            layers: vec![
                OciDescriptor {
                    media_type: String::new(),
                    digest: layer1_digest.as_str().to_string(),
                    size: layer1.len() as u64,
                },
                OciDescriptor {
                    media_type: String::new(),
                    digest: layer2_digest.as_str().to_string(),
                    size: layer2.len() as u64,
                },
            ],
        };
        let manifest_bytes = serde_json::to_vec(&manifest).unwrap();
        let reference = "registry-1.docker.io/library/layered:latest";
        store.put_manifest(reference, &manifest_bytes).unwrap();

        let svc = ImageService::new(store, dir.path().to_path_buf());
        let rootfs = dir.path().join("rootfs");
        svc.prepare_rootfs("layered:latest", &rootfs).unwrap();

        // Layer 2 should have overwritten layer 1.
        assert_eq!(
            std::fs::read_to_string(rootfs.join("data.txt")).unwrap(),
            "layer2"
        );
    }
}
