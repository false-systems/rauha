use std::fs::{File, OpenOptions};
use std::os::unix::fs::{DirBuilderExt, FileTypeExt, MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};

pub struct SocketGuard {
    path: PathBuf,
    _lock: File,
}

impl Drop for SocketGuard {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.path);
    }
}

pub fn bind(path: &Path) -> anyhow::Result<(tokio::net::UnixListener, SocketGuard)> {
    anyhow::ensure!(path.is_absolute(), "daemon socket path must be absolute");
    let parent = path
        .parent()
        .ok_or_else(|| anyhow::anyhow!("missing socket directory"))?;
    match std::fs::DirBuilder::new()
        .mode(0o700)
        .recursive(true)
        .create(parent)
    {
        Ok(()) => {}
        Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {}
        Err(e) => return Err(e.into()),
    }
    let metadata = std::fs::symlink_metadata(parent)?;
    anyhow::ensure!(
        metadata.is_dir()
            && metadata.uid() == unsafe { libc::geteuid() }
            && metadata.mode() & 0o077 == 0,
        "socket directory must be owned by the daemon user and mode 0700"
    );
    let lock = OpenOptions::new()
        .create(true)
        .truncate(false)
        .read(true)
        .write(true)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW)
        .open(path.with_extension("lock"))?;
    lock.try_lock()
        .map_err(|e| anyhow::anyhow!("daemon socket is already owned: {e}"))?;
    match std::fs::symlink_metadata(path) {
        Ok(metadata) => {
            anyhow::ensure!(
                metadata.file_type().is_socket(),
                "refusing to replace a non-socket"
            );
            anyhow::ensure!(
                std::os::unix::net::UnixStream::connect(path).is_err(),
                "daemon socket is already listening"
            );
            std::fs::remove_file(path)?;
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
        Err(e) => return Err(e.into()),
    }
    let listener = tokio::net::UnixListener::bind(path)?;
    let guard = SocketGuard {
        path: path.to_owned(),
        _lock: lock,
    };
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))?;
    Ok((listener, guard))
}

#[cfg(test)]
mod tests {
    use super::*;
    #[tokio::test]
    async fn listener_is_private_and_cannot_be_replaced() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("private/daemon.sock");
        let (listener, guard) = bind(&path).unwrap();
        assert_eq!(std::fs::metadata(&path).unwrap().mode() & 0o777, 0o600);
        assert!(bind(&path).is_err());
        drop(listener);
        drop(guard);
        assert!(!path.exists());
        std::fs::write(&path, b"preserve").unwrap();
        assert!(bind(&path).is_err());
        assert_eq!(std::fs::read(path).unwrap(), b"preserve");
    }
}
