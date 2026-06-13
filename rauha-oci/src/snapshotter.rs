//! Overlayfs snapshotter for container rootfs.
//!
//! Instead of copying the entire image rootfs per container (O(image_size)),
//! overlayfs layers the shared read-only image layers under a per-container
//! writable upper directory. Container creation becomes O(1).
//!
//! Directory layout:
//! ```text
//! images/{safe_name}/layers/{0,1,...}/   — shared read-only, extracted once
//! containers/{id}/upper/                 — per-container writable layer
//! containers/{id}/work/                  — overlayfs work directory
//! containers/{id}/merged/                — union mount point (the rootfs)
//! ```
//!
//! Linux-only: falls back to full copy on other platforms.

use std::path::{Path, PathBuf};

use rauha_common::error::{RauhaError, Result};

/// Manages overlayfs mounts for container rootfs.
pub struct OverlayfsSnapshotter {
    root: PathBuf,
}

impl OverlayfsSnapshotter {
    pub fn new(root: &Path) -> Self {
        Self {
            root: root.to_path_buf(),
        }
    }

    /// Prepare per-layer directories for an image.
    ///
    /// Each OCI layer is extracted into its own numbered directory under
    /// `images/{safe_name}/layers/`. Returns the list of layer paths in order
    /// (bottom to top). Idempotent: skips layers that already have a
    /// `.complete` marker.
    pub fn prepare_layers(
        &self,
        image_safe_name: &str,
        layer_digests: &[String],
        content_root: &Path,
    ) -> Result<Vec<PathBuf>> {
        let layers_dir = self.root.join("images").join(image_safe_name).join("layers");
        std::fs::create_dir_all(&layers_dir).map_err(|e| RauhaError::RootfsError {
            message: format!("failed to create layers dir: {e}"),
        })?;

        let mut layer_paths = Vec::with_capacity(layer_digests.len());

        for (i, digest_str) in layer_digests.iter().enumerate() {
            // Key by digest (truncated to 12 chars for readability) instead of
            // index, so reordering layers in a manifest doesn't re-extract.
            let digest_key = if let Some(hex) = digest_str.strip_prefix("sha256:") {
                &hex[..hex.len().min(12)]
            } else {
                &digest_str[..digest_str.len().min(12)]
            };
            let layer_dir = layers_dir.join(digest_key);
            let marker = layers_dir.join(format!("{digest_key}.complete"));

            if marker.exists() {
                tracing::debug!(layer = i, digest = %digest_key, "layer already extracted");
                layer_paths.push(layer_dir);
                continue;
            }

            // Extract layer from content store blob.
            let digest = crate::content::Digest::parse(digest_str).ok_or_else(|| {
                RauhaError::RootfsError {
                    message: format!("invalid layer digest: {digest_str}"),
                }
            })?;

            let blob_path = content_root.join("blobs").join("sha256").join(digest.hex());

            // Clean up partial extraction.
            if layer_dir.exists() {
                let _ = std::fs::remove_dir_all(&layer_dir);
            }
            std::fs::create_dir_all(&layer_dir).map_err(|e| RauhaError::RootfsError {
                message: format!("failed to create layer dir {digest_key}: {e}"),
            })?;

            tracing::info!(layer = i, digest = %digest, "extracting layer");

            let file =
                std::fs::File::open(&blob_path).map_err(|e| RauhaError::RootfsError {
                    message: format!("failed to open layer blob {digest}: {e}"),
                })?;

            let decoder = flate2::read::GzDecoder::new(file);
            let mut archive = tar::Archive::new(decoder);
            crate::image::unpack_layer(&mut archive, &layer_dir)?;

            // Write completion marker.
            std::fs::write(&marker, b"").map_err(|e| RauhaError::RootfsError {
                message: format!("failed to write layer marker: {e}"),
            })?;

            layer_paths.push(layer_dir);
        }

        Ok(layer_paths)
    }

    /// Mount an overlayfs for a container, returning the merged rootfs path.
    ///
    /// Creates `upper/`, `work/`, and `merged/` under the container directory,
    /// then calls `mount(2)` with type "overlay".
    ///
    /// On non-Linux platforms, falls back to copying from the lowest layer.
    pub fn mount_overlay(
        &self,
        container_id: &str,
        layer_paths: &[PathBuf],
        container_root: &Path,
    ) -> Result<PathBuf> {
        let upper = container_root.join("upper");
        let work = container_root.join("work");
        let merged = container_root.join("merged");

        std::fs::create_dir_all(&upper).map_err(|e| RauhaError::RootfsError {
            message: format!("failed to create upper dir: {e}"),
        })?;
        std::fs::create_dir_all(&work).map_err(|e| RauhaError::RootfsError {
            message: format!("failed to create work dir: {e}"),
        })?;
        std::fs::create_dir_all(&merged).map_err(|e| RauhaError::RootfsError {
            message: format!("failed to create merged dir: {e}"),
        })?;

        #[cfg(target_os = "linux")]
        {
            self.do_overlay_mount(container_id, layer_paths, &upper, &work, &merged)?;
        }

        #[cfg(not(target_os = "linux"))]
        {
            let _ = container_id;
            // Fallback: copy lowest layer into merged, then apply upper layers on top.
            // This preserves the directory structure for non-Linux development.
            self.fallback_copy(layer_paths, &merged)?;
        }

        Ok(merged)
    }

    /// Unmount an overlayfs for a container.
    pub fn unmount_overlay(&self, container_root: &Path) -> Result<()> {
        let merged = container_root.join("merged");

        #[cfg(target_os = "linux")]
        {
            use nix::mount::{umount2, MntFlags};
            if merged.exists() {
                umount2(&merged, MntFlags::MNT_DETACH).map_err(|e| RauhaError::RootfsError {
                    message: format!("failed to unmount overlay: {e}"),
                })?;
            }
        }

        #[cfg(not(target_os = "linux"))]
        {
            // Nothing to unmount on non-Linux — merged was a plain copy.
            let _ = &merged;
        }

        Ok(())
    }

    /// Perform the actual overlayfs mount on Linux.
    #[cfg(target_os = "linux")]
    fn do_overlay_mount(
        &self,
        container_id: &str,
        layer_paths: &[PathBuf],
        upper: &Path,
        work: &Path,
        merged: &Path,
    ) -> Result<()> {
        use nix::mount::{mount, MsFlags};

        if layer_paths.is_empty() {
            return Err(RauhaError::RootfsError {
                message: "no layers to mount".into(),
            });
        }

        // overlayfs lowerdir is colon-separated, top layer first.
        let lowerdir = layer_paths
            .iter()
            .rev()
            .map(|p| p.to_string_lossy().to_string())
            .collect::<Vec<_>>()
            .join(":");

        let mount_data = format!(
            "lowerdir={},upperdir={},workdir={}",
            lowerdir,
            upper.display(),
            work.display()
        );

        tracing::info!(
            container = container_id,
            mount_data = %mount_data,
            "mounting overlayfs"
        );

        mount(
            Some("overlay"),
            merged,
            Some("overlay"),
            MsFlags::empty(),
            Some(mount_data.as_str()),
        )
        .map_err(|e| RauhaError::RootfsError {
            message: format!(
                "overlayfs mount failed: {e} — try: modprobe overlay; or check that /proc/filesystems contains overlay"
            ),
        })?;

        Ok(())
    }

    /// Non-Linux fallback: merge all layers into the merged directory by copying.
    #[cfg(not(target_os = "linux"))]
    fn fallback_copy(&self, layer_paths: &[PathBuf], merged: &Path) -> Result<()> {
        for layer_path in layer_paths {
            if layer_path.exists() {
                copy_dir_recursive(layer_path, merged)?;
            }
        }
        Ok(())
    }
}

/// Recursively copy a directory tree, merging into the destination.
#[cfg(not(target_os = "linux"))]
fn copy_dir_recursive(src: &Path, dst: &Path) -> Result<()> {
    std::fs::create_dir_all(dst).map_err(|e| RauhaError::RootfsError {
        message: format!("failed to create dir {}: {e}", dst.display()),
    })?;

    for entry in std::fs::read_dir(src).map_err(|e| RauhaError::RootfsError {
        message: format!("failed to read dir {}: {e}", src.display()),
    })? {
        let entry = entry.map_err(|e| RauhaError::RootfsError {
            message: format!("failed to read entry: {e}"),
        })?;
        let src_path = entry.path();
        let dst_path = dst.join(entry.file_name());

        let meta =
            std::fs::symlink_metadata(&src_path).map_err(|e| RauhaError::RootfsError {
                message: format!("failed to stat {}: {e}", src_path.display()),
            })?;

        if meta.is_symlink() {
            let link_target =
                std::fs::read_link(&src_path).map_err(|e| RauhaError::RootfsError {
                    message: format!("failed to read symlink {}: {e}", src_path.display()),
                })?;
            // Remove existing target if it exists (we're merging layers).
            let _ = std::fs::remove_file(&dst_path);
            std::os::unix::fs::symlink(&link_target, &dst_path).map_err(|e| {
                RauhaError::RootfsError {
                    message: format!(
                        "failed to create symlink {} -> {}: {e}",
                        dst_path.display(),
                        link_target.display()
                    ),
                }
            })?;
        } else if meta.is_dir() {
            copy_dir_recursive(&src_path, &dst_path)?;
        } else {
            std::fs::copy(&src_path, &dst_path).map_err(|e| RauhaError::RootfsError {
                message: format!(
                    "failed to copy {} -> {}: {e}",
                    src_path.display(),
                    dst_path.display()
                ),
            })?;
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use rauha_common::error::RauhaError;

    fn is_unprivileged_mount_error(err: &RauhaError) -> bool {
        matches!(
            err,
            RauhaError::RootfsError { message }
                if message.contains("EPERM") || message.contains("Operation not permitted")
        )
    }

    #[test]
    fn prepare_layers_creates_layer_dirs() {
        let dir = tempfile::tempdir().unwrap();

        // Set up a fake content store with one layer blob.
        let content_dir = dir.path().join("content");
        let store = crate::content::ContentStore::new(&content_dir).unwrap();

        let layer_data = crate::image::tests::make_tar_gz(&[
            ("hello.txt", b"hello world"),
            ("bin/test", b"#!/bin/sh\necho hi"),
        ]);
        let digest = store.put_blob(&layer_data).unwrap();

        let snap = OverlayfsSnapshotter::new(dir.path());
        let paths = snap
            .prepare_layers("test_image", &[digest.as_str().to_string()], &content_dir)
            .unwrap();

        assert_eq!(paths.len(), 1);
        assert!(paths[0].join("hello.txt").exists());
        assert!(paths[0].join("bin/test").exists());

        // Verify idempotency — calling again should skip extraction.
        let paths2 = snap
            .prepare_layers("test_image", &[digest.as_str().to_string()], &content_dir)
            .unwrap();
        assert_eq!(paths, paths2);
    }

    #[test]
    fn prepare_layers_multiple_layers() {
        let dir = tempfile::tempdir().unwrap();
        let content_dir = dir.path().join("content");
        let store = crate::content::ContentStore::new(&content_dir).unwrap();

        let layer1 = crate::image::tests::make_tar_gz(&[("a.txt", b"layer1")]);
        let layer2 = crate::image::tests::make_tar_gz(&[("b.txt", b"layer2")]);
        let d1 = store.put_blob(&layer1).unwrap();
        let d2 = store.put_blob(&layer2).unwrap();

        let snap = OverlayfsSnapshotter::new(dir.path());
        let paths = snap
            .prepare_layers(
                "multi",
                &[d1.as_str().to_string(), d2.as_str().to_string()],
                &content_dir,
            )
            .unwrap();

        assert_eq!(paths.len(), 2);
        assert!(paths[0].join("a.txt").exists());
        assert!(paths[1].join("b.txt").exists());
    }

    #[test]
    fn mount_overlay_creates_directories() {
        let dir = tempfile::tempdir().unwrap();
        let content_dir = dir.path().join("content");
        let store = crate::content::ContentStore::new(&content_dir).unwrap();

        let layer_data =
            crate::image::tests::make_tar_gz(&[("file.txt", b"content")]);
        let digest = store.put_blob(&layer_data).unwrap();

        let snap = OverlayfsSnapshotter::new(dir.path());
        let layer_paths = snap
            .prepare_layers("test", &[digest.as_str().to_string()], &content_dir)
            .unwrap();

        let container_root = dir.path().join("containers").join("test-container");
        let merged = match snap.mount_overlay("test-container", &layer_paths, &container_root) {
            Ok(merged) => merged,
            Err(err) if cfg!(target_os = "linux") && is_unprivileged_mount_error(&err) => {
                assert!(container_root.join("upper").exists());
                assert!(container_root.join("work").exists());
                assert!(container_root.join("merged").exists());
                return;
            }
            Err(err) => panic!("mount_overlay failed: {err}"),
        };

        assert!(container_root.join("upper").exists());
        assert!(container_root.join("work").exists());
        assert!(merged.exists());

        // On non-Linux (test environment), the fallback copy should have files.
        #[cfg(not(target_os = "linux"))]
        assert!(merged.join("file.txt").exists());
    }

    #[test]
    fn unmount_overlay_succeeds_when_not_mounted() {
        let dir = tempfile::tempdir().unwrap();
        let container_root = dir.path().join("containers").join("fake");
        std::fs::create_dir_all(container_root.join("merged")).unwrap();

        let snap = OverlayfsSnapshotter::new(dir.path());
        // Should not error even if not actually mounted (non-Linux is always a no-op).
        match snap.unmount_overlay(&container_root) {
            Ok(()) => {}
            Err(err) if cfg!(target_os = "linux") && is_unprivileged_mount_error(&err) => {}
            Err(err) => panic!("unmount_overlay failed: {err}"),
        }
    }
}
