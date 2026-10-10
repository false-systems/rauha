//! Host-side writes must never follow image-controlled paths outside the rootfs.
use std::fs::{File, OpenOptions};
use std::io::{self, Write};
use std::os::fd::{AsRawFd, FromRawFd};
use std::os::unix::fs::OpenOptionsExt;
use std::path::Path;
use std::sync::atomic::{AtomicU64, Ordering};

static NEXT_TEMP: AtomicU64 = AtomicU64::new(0);

pub fn write_resolv_conf(root: &Path, contents: &[u8]) -> io::Result<()> {
    let root = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW)
        .open(root)?;
    let created = unsafe { libc::mkdirat(root.as_raw_fd(), c"etc".as_ptr(), 0o755) };
    if created != 0 && io::Error::last_os_error().raw_os_error() != Some(libc::EEXIST) {
        return Err(io::Error::last_os_error());
    }
    let etc = open_at(&root, c"etc", libc::O_RDONLY | libc::O_DIRECTORY)?;
    let mut metadata = std::mem::MaybeUninit::<libc::stat>::uninit();
    let result = unsafe {
        libc::fstatat(
            etc.as_raw_fd(),
            c"resolv.conf".as_ptr(),
            metadata.as_mut_ptr(),
            libc::AT_SYMLINK_NOFOLLOW,
        )
    };
    if result == 0 {
        let metadata = unsafe { metadata.assume_init() };
        if metadata.st_mode & libc::S_IFMT != libc::S_IFREG || metadata.st_nlink != 1 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "DNS destination must be an unshared regular file",
            ));
        }
    } else if io::Error::last_os_error().raw_os_error() != Some(libc::ENOENT) {
        return Err(io::Error::last_os_error());
    }
    // Never open the image's leaf: even opening a device can have host side effects.
    for _ in 0..128 {
        let name = std::ffi::CString::new(format!(
            ".rauha-dns-{}-{}",
            std::process::id(),
            NEXT_TEMP.fetch_add(1, Ordering::Relaxed)
        ))
        .unwrap();
        let mut file = match open_at(&etc, &name, libc::O_WRONLY | libc::O_CREAT | libc::O_EXCL) {
            Ok(file) => file,
            Err(error) if error.kind() == io::ErrorKind::AlreadyExists => continue,
            Err(error) => return Err(error),
        };
        let result = (|| {
            file.write_all(contents)?;
            file.sync_all()?;
            if unsafe {
                libc::renameat(
                    etc.as_raw_fd(),
                    name.as_ptr(),
                    etc.as_raw_fd(),
                    c"resolv.conf".as_ptr(),
                )
            } != 0
            {
                return Err(io::Error::last_os_error());
            }
            etc.sync_all()
        })();
        unsafe {
            libc::unlinkat(etc.as_raw_fd(), name.as_ptr(), 0);
        }
        return result;
    }
    Err(io::Error::new(
        io::ErrorKind::AlreadyExists,
        "DNS staging filenames exhausted",
    ))
}

fn open_at(directory: &File, name: &std::ffi::CStr, flags: i32) -> io::Result<File> {
    let fd = unsafe {
        libc::openat(
            directory.as_raw_fd(),
            name.as_ptr(),
            flags | libc::O_CLOEXEC | libc::O_NOFOLLOW,
            0o644,
        )
    };
    if fd < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(unsafe { File::from_raw_fd(fd) })
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn dns_writes_refuse_image_symlinks_and_hardlinks() {
        use std::{fs, os::unix::fs::symlink};
        for attack in ["parent", "leaf", "hardlink"] {
            let dir = tempfile::tempdir().unwrap();
            let root = dir.path().join("root");
            let outside = dir.path().join("outside");
            fs::create_dir(&root).unwrap();
            fs::create_dir(&outside).unwrap();
            fs::write(outside.join("resolv.conf"), b"unchanged").unwrap();
            if attack == "parent" {
                symlink(&outside, root.join("etc")).unwrap();
            } else {
                fs::create_dir(root.join("etc")).unwrap();
                if attack == "leaf" {
                    symlink(outside.join("resolv.conf"), root.join("etc/resolv.conf")).unwrap();
                } else {
                    fs::hard_link(outside.join("resolv.conf"), root.join("etc/resolv.conf"))
                        .unwrap();
                }
            }
            assert!(write_resolv_conf(&root, b"nameserver 1.1.1.1\n").is_err());
            assert_eq!(fs::read(outside.join("resolv.conf")).unwrap(), b"unchanged");
        }
        let root = tempfile::tempdir().unwrap();
        write_resolv_conf(root.path(), b"nameserver 1.1.1.1\n").unwrap();
        assert_eq!(
            std::fs::read(root.path().join("etc/resolv.conf")).unwrap(),
            b"nameserver 1.1.1.1\n"
        );
    }

    #[test]
    fn dns_write_rejects_fifo_without_opening_it_and_replaces_regular_file() {
        let root = tempfile::tempdir().unwrap();
        std::fs::create_dir(root.path().join("etc")).unwrap();
        let leaf = root.path().join("etc/resolv.conf");
        use std::os::unix::ffi::OsStrExt;
        let name = std::ffi::CString::new(leaf.as_os_str().as_bytes()).unwrap();
        assert_eq!(unsafe { libc::mkfifo(name.as_ptr(), 0o600) }, 0);
        assert!(write_resolv_conf(root.path(), b"dns").is_err());
        std::fs::remove_file(&leaf).unwrap();
        std::fs::write(&leaf, b"old longer contents").unwrap();
        write_resolv_conf(root.path(), b"dns").unwrap();
        assert_eq!(std::fs::read(&leaf).unwrap(), b"dns");
        assert_eq!(
            std::fs::read_dir(root.path().join("etc")).unwrap().count(),
            1
        );
    }
}
