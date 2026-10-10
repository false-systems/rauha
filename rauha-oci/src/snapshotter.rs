//! Overlayfs snapshotter for container rootfs.
//!
//! Instead of copying the entire image rootfs per container (O(image_size)),
//! overlayfs layers the shared read-only image layers under a per-container
//! writable upper directory. Container creation becomes O(1).
//!
//! Directory layout:
//! ```text
//! snapshots-v2/{layer-chain-digest}/    — shared flattened tree, extracted once
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

    /// Prepare one immutable snapshot for an ordered image layer chain.
    ///
    /// Flatten the ordered layers once, then use the immutable tree as one
    /// overlay lowerdir. Whiteouts operate on the preceding layers, not on
    /// empty independent directories. Publication is serialized across processes.
    pub fn prepare_layers(
        &self,
        _image_safe_name: &str,
        layer_digests: &[String],
        content_root: &Path,
    ) -> Result<Vec<PathBuf>> {
        let digests = layer_digests
            .iter()
            .map(|value| {
                crate::content::Digest::parse(value).ok_or_else(|| RauhaError::RootfsError {
                    message: format!("invalid layer digest: {value}"),
                })
            })
            .collect::<Result<Vec<_>>>()?;
        let key = crate::content::Digest::from_data(layer_digests.join("\n").as_bytes());
        let directory = self.root.join("snapshots-v2");
        std::fs::create_dir_all(&directory)?;
        let lock = std::fs::OpenOptions::new()
            .create(true)
            .truncate(false)
            .read(true)
            .write(true)
            .open(directory.join(format!("{}.lock", key.hex())))?;
        lock.lock()?;
        let published = directory.join(key.hex());
        if published.is_dir() {
            return Ok(vec![published]);
        }
        let staging = tempfile::tempdir_in(&directory)?;
        for digest in digests {
            let blob = content_root.join("blobs/sha256").join(digest.hex());
            crate::image::unpack_layer_file(&blob, staging.path())?;
        }
        sync_tree(staging.path())?;
        std::fs::rename(staging.path(), &published)?;
        std::fs::File::open(&directory)?.sync_all()?;
        Ok(vec![published])
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
                match umount2(&merged, MntFlags::MNT_DETACH) {
                    Ok(()) | Err(nix::errno::Errno::EINVAL | nix::errno::Errno::ENOENT) => {}
                    Err(e) => {
                        return Err(RauhaError::RootfsError {
                            message: format!("failed to unmount overlay: {e}"),
                        })
                    }
                }
            }
        }

        #[cfg(not(target_os = "linux"))]
        {
            // Nothing to unmount on non-Linux — merged was a plain copy.
            let _ = &merged;
        }

        Ok(())
    }

    /// Only called after the executor is stopped; failures retain metadata for retry.
    pub fn remove_container(&self, container_root: &Path) -> Result<()> {
        #[cfg(target_os = "linux")]
        match std::fs::read_dir(container_root.join("namespaces")) {
            Ok(entries) => {
                for entry in entries {
                    let entry = entry?;
                    if !matches!(entry.file_name().to_str(), Some("ipc" | "uts" | "pid"))
                        || entry.file_type()?.is_symlink()
                    {
                        return Err(RauhaError::RootfsError {
                            message: "unexpected namespace mount entry".into(),
                        });
                    }
                    match nix::mount::umount2(&entry.path(), nix::mount::MntFlags::empty()) {
                        Ok(()) | Err(nix::errno::Errno::EINVAL | nix::errno::Errno::ENOENT) => {}
                        Err(error) => {
                            return Err(RauhaError::RootfsError {
                                message: format!("cannot unmount namespace pin: {error}"),
                            })
                        }
                    }
                }
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => return Err(error.into()),
        }
        self.unmount_overlay(container_root)?;
        match std::fs::remove_dir_all(container_root) {
            Ok(()) => Ok(()),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(e) => Err(e.into()),
        }
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
        use nix::mount::{mount, umount2, MntFlags, MsFlags};

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
        if let Err(error) = mount(
            None::<&str>,
            merged,
            None::<&str>,
            MsFlags::MS_PRIVATE,
            None::<&str>,
        ) {
            let _ = umount2(merged, MntFlags::MNT_DETACH);
            return Err(RauhaError::RootfsError {
                message: format!("failed to make overlay rootfs private: {error}"),
            });
        }

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

/// Persist file contents before publishing the directory that marks completion.
fn sync_tree(path: &Path) -> std::io::Result<()> {
    use std::os::unix::fs::OpenOptionsExt;
    for entry in std::fs::read_dir(path)? {
        let entry = entry?;
        let kind = entry.file_type()?;
        if kind.is_dir() {
            sync_tree(&entry.path())?;
        } else if kind.is_file() {
            std::fs::OpenOptions::new()
                .read(true)
                .custom_flags(libc::O_NOFOLLOW)
                .open(entry.path())?
                .sync_all()?;
        }
    }
    std::fs::File::open(path)?.sync_all()
}

/// Recursively copy a directory tree, merging into the destination.
/// Cross-platform: used by the snapshotter on non-Linux and by the
/// daemon's writable-path copy-up on Linux.
pub fn copy_dir_recursive(src: &Path, dst: &Path) -> Result<()> {
    if !std::fs::symlink_metadata(src)?.is_dir() {
        return Err(RauhaError::RootfsError {
            message: format!("copy source is not a real directory: {}", src.display()),
        });
    }
    match std::fs::symlink_metadata(dst) {
        Ok(metadata) if !metadata.is_dir() => std::fs::remove_file(dst)?,
        Ok(_) => {}
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => return Err(error.into()),
    }
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

        let meta = std::fs::symlink_metadata(&src_path).map_err(|e| RauhaError::RootfsError {
            message: format!("failed to stat {}: {e}", src_path.display()),
        })?;

        if meta.is_symlink() {
            let link_target =
                std::fs::read_link(&src_path).map_err(|e| RauhaError::RootfsError {
                    message: format!("failed to read symlink {}: {e}", src_path.display()),
                })?;
            // Remove existing target if it exists (we're merging layers).
            remove_destination(&dst_path)?;
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
        } else if meta.is_file() {
            let mut source = std::fs::File::open(&src_path)?;
            let mut temporary = tempfile::NamedTempFile::new_in(dst)?;
            std::io::copy(&mut source, &mut temporary)?;
            temporary.as_file().set_permissions(meta.permissions())?;
            remove_destination(&dst_path)?;
            temporary.persist(&dst_path).map_err(|error| error.error)?;
        } else {
            return Err(RauhaError::RootfsError {
                message: format!("refusing to copy special file {}", src_path.display()),
            });
        }
    }

    Ok(())
}

fn remove_destination(path: &Path) -> std::io::Result<()> {
    match std::fs::symlink_metadata(path) {
        Ok(metadata) if metadata.is_dir() => std::fs::remove_dir_all(path),
        Ok(_) => std::fs::remove_file(path),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rauha_common::error::RauhaError;

    #[test]
    fn copy_replaces_destination_links_without_modifying_their_targets() {
        use std::{fs, os::unix::fs::symlink};
        let dir = tempfile::tempdir().unwrap();
        let src = dir.path().join("src");
        let dst = dir.path().join("dst");
        let outside = dir.path().join("outside");
        fs::create_dir_all(src.join("nested")).unwrap();
        fs::create_dir(&dst).unwrap();
        fs::create_dir(&outside).unwrap();
        fs::write(outside.join("sentinel"), b"unchanged").unwrap();
        fs::write(src.join("nested/sentinel"), b"new").unwrap();
        fs::write(src.join("leaf"), b"new").unwrap();
        fs::write(src.join("hardlink"), b"new").unwrap();
        symlink(&outside, dst.join("nested")).unwrap();
        symlink(outside.join("sentinel"), dst.join("leaf")).unwrap();
        fs::hard_link(outside.join("sentinel"), dst.join("hardlink")).unwrap();
        copy_dir_recursive(&src, &dst).unwrap();
        assert_eq!(fs::read(outside.join("sentinel")).unwrap(), b"unchanged");
        assert_eq!(fs::read(dst.join("nested/sentinel")).unwrap(), b"new");
        assert_eq!(fs::read(dst.join("leaf")).unwrap(), b"new");
        assert_eq!(fs::read(dst.join("hardlink")).unwrap(), b"new");
    }

    #[test]
    fn whiteouts_and_concurrent_publication_preserve_the_final_image() {
        let dir = tempfile::tempdir().unwrap();
        let content = dir.path().join("content");
        let store = crate::content::ContentStore::new(&content).unwrap();
        let lower = store
            .put_blob(&crate::image::tests::make_tar_gz(&[
                ("removed", b"old"),
                ("opaque/old", b"old"),
                ("replaced", b"old"),
            ]))
            .unwrap();
        let upper = store
            .put_blob(&crate::image::tests::make_tar_gz(&[
                ("replaced", b"new"),
                ("opaque/new", b"new"),
                (".wh.removed", b""),
                ("opaque/.wh..wh..opq", b""),
                (".wh.replaced", b""),
            ]))
            .unwrap();
        let digests = vec![lower.to_string(), upper.to_string()];
        std::thread::scope(|scope| {
            let barrier = std::sync::Arc::new(std::sync::Barrier::new(4));
            let mut workers = Vec::new();
            for _ in 0..4 {
                let barrier = barrier.clone();
                let content = &content;
                let digests = &digests;
                let root = dir.path();
                workers.push(scope.spawn(move || {
                    barrier.wait();
                    OverlayfsSnapshotter::new(root)
                        .prepare_layers("test", digests, content)
                        .unwrap()
                }));
            }
            let paths: Vec<_> = workers.into_iter().map(|w| w.join().unwrap()).collect();
            assert!(paths.windows(2).all(|pair| pair[0] == pair[1]));
            let root = &paths[0][0];
            assert!(!root.join("removed").exists());
            assert!(!root.join("opaque/old").exists());
            assert_eq!(std::fs::read(root.join("opaque/new")).unwrap(), b"new");
            assert_eq!(std::fs::read(root.join("replaced")).unwrap(), b"new");
        });
    }

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

        assert_eq!(paths.len(), 1);
        assert!(paths[0].join("a.txt").exists());
        assert!(paths[0].join("b.txt").exists());
    }

    #[test]
    fn mount_overlay_creates_directories() {
        let dir = tempfile::tempdir().unwrap();
        let content_dir = dir.path().join("content");
        let store = crate::content::ContentStore::new(&content_dir).unwrap();

        let layer_data = crate::image::tests::make_tar_gz(&[("file.txt", b"content")]);
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

        assert!(merged.join("file.txt").exists());
        snap.remove_container(&container_root).unwrap();
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

    #[cfg(target_os = "linux")]
    #[test]
    #[ignore = "requires root and overlayfs; invoked by the privileged Linux gate"]
    fn live_overlay_preserves_whiteouts_and_container_cleanup() {
        let dir = tempfile::tempdir().unwrap();
        let content = dir.path().join("content");
        let store = crate::content::ContentStore::new(&content).unwrap();
        let lower = store
            .put_blob(&crate::image::tests::make_tar_gz(&[
                ("removed", b"old"),
                ("opaque/old", b"old"),
                ("replaced", b"old"),
            ]))
            .unwrap();
        let upper = store
            .put_blob(&crate::image::tests::make_tar_gz(&[
                ("replaced", b"new"),
                ("opaque/new", b"new"),
                (".wh.removed", b""),
                ("opaque/.wh..wh..opq", b""),
                (".wh.replaced", b""),
            ]))
            .unwrap();
        let snap = OverlayfsSnapshotter::new(dir.path());
        let layers = snap
            .prepare_layers("", &[lower.to_string(), upper.to_string()], &content)
            .unwrap();
        let container = dir.path().join("container");
        let merged = snap.mount_overlay("probe", &layers, &container).unwrap();
        let namespaces = container.join("namespaces");
        std::fs::create_dir(&namespaces).unwrap();
        let ipc = namespaces.join("ipc");
        std::fs::File::create(&ipc).unwrap();
        if let Err(error) = nix::mount::mount(
            Some("/proc/self/ns/ipc"),
            &ipc,
            None::<&str>,
            nix::mount::MsFlags::MS_BIND,
            None::<&str>,
        ) {
            snap.remove_container(&container).unwrap();
            panic!("could not bind namespace pin: {error}");
        }
        let removed = merged.join("removed").exists();
        let opaque_old = merged.join("opaque/old").exists();
        let opaque_new = std::fs::read(merged.join("opaque/new"));
        let replaced = std::fs::read(merged.join("replaced"));
        snap.remove_container(&container).unwrap();
        assert!(!removed && !opaque_old);
        assert_eq!(opaque_new.unwrap(), b"new");
        assert_eq!(replaced.unwrap(), b"new");
        assert!(!container.exists());
        assert!(layers[0].is_dir());
    }
}
