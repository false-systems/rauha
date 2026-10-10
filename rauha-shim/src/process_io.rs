//! containerd FIFOs and the OCI console socket, with bounded backpressure.
use rauha_common::shim::ProcessIo;
use std::{
    fs::{File, OpenOptions},
    io::{Read, Write},
    os::{
        fd::{AsRawFd, FromRawFd, OwnedFd},
        unix::{
            fs::{FileTypeExt, OpenOptionsExt, PermissionsExt},
            net::{UnixListener, UnixStream},
        },
    },
    path::{Path, PathBuf},
    process::Stdio,
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    },
    thread::JoinHandle,
    time::{Duration, Instant},
};

fn fifo(path: &str, input: bool) -> anyhow::Result<Option<File>> {
    if path.is_empty() {
        return Ok(None);
    }
    anyhow::ensure!(Path::new(path).is_absolute(), "FIFO path must be absolute");
    let file = OpenOptions::new()
        .read(input)
        .write(!input)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open(path)?;
    anyhow::ensure!(
        file.metadata()?.file_type().is_fifo(),
        "I/O path is not a FIFO"
    );
    Ok(Some(file))
}

fn blocking(file: File) -> anyhow::Result<File> {
    let flags = unsafe { libc::fcntl(file.as_raw_fd(), libc::F_GETFL) };
    if flags < 0
        || unsafe { libc::fcntl(file.as_raw_fd(), libc::F_SETFL, flags & !libc::O_NONBLOCK) } < 0
    {
        return Err(std::io::Error::last_os_error().into());
    }
    Ok(file)
}

pub struct IoSession {
    stop: Arc<AtomicBool>,
    close_input: Arc<AtomicBool>,
    threads: Vec<JoinHandle<std::io::Result<()>>>,
    master: Option<File>,
    failure: Option<String>,
}

impl IoSession {
    /// Keep output relays alive on timeout so deletion can retry without loss.
    pub fn finish(&mut self) -> anyhow::Result<()> {
        self.close_stdin();
        let deadline = Instant::now() + Duration::from_secs(1);
        while self.threads.iter().any(|thread| !thread.is_finished()) {
            anyhow::ensure!(
                Instant::now() < deadline,
                "container output drain timed out; retry cleanup after draining its FIFO"
            );
            std::thread::sleep(Duration::from_millis(10));
        }
        for thread in self.threads.drain(..) {
            match thread.join() {
                Ok(Ok(())) => {}
                Ok(Err(error)) => self.failure = Some(error.to_string()),
                Err(_) => self.failure = Some("container I/O relay panicked".into()),
            }
        }
        if let Some(error) = &self.failure {
            anyhow::bail!("container output was not delivered: {error}");
        }
        Ok(())
    }

    pub fn close_stdin(&self) {
        self.close_input.store(true, Ordering::Release);
    }
    pub fn resize(&self, rows: u16, cols: u16) -> anyhow::Result<()> {
        let master = self
            .master
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("process has no terminal"))?;
        let size = libc::winsize {
            ws_row: rows,
            ws_col: cols,
            ws_xpixel: 0,
            ws_ypixel: 0,
        };
        if unsafe { libc::ioctl(master.as_raw_fd(), libc::TIOCSWINSZ, &size) } < 0 {
            return Err(std::io::Error::last_os_error().into());
        }
        Ok(())
    }
}

impl Drop for IoSession {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Release);
        for thread in self.threads.drain(..) {
            let _ = thread.join();
        }
    }
}

pub struct PreparedIo {
    pub stdin: Stdio,
    pub stdout: Stdio,
    pub stderr: Stdio,
    pub session: IoSession,
    console: Option<(UnixListener, PathBuf, Option<File>, Option<File>)>,
    console_directory: Option<tempfile::TempDir>,
}

impl PreparedIo {
    pub fn take_session(&mut self) -> IoSession {
        std::mem::replace(
            &mut self.session,
            IoSession {
                stop: Arc::new(AtomicBool::new(false)),
                close_input: Arc::new(AtomicBool::new(false)),
                threads: Vec::new(),
                master: None,
                failure: None,
            },
        )
    }
    pub fn new(io: &ProcessIo, _directory: &Path) -> anyhow::Result<Self> {
        let input = fifo(&io.stdin, true)?;
        let output = fifo(&io.stdout, false)?;
        let error = if io.terminal {
            None
        } else {
            fifo(&io.stderr, false)?
        };
        let session = IoSession {
            stop: Arc::new(AtomicBool::new(false)),
            close_input: Arc::new(AtomicBool::new(false)),
            threads: Vec::new(),
            master: None,
            failure: None,
        };
        let mut prepared = Self {
            stdin: Stdio::null(),
            stdout: Stdio::null(),
            stderr: Stdio::null(),
            session,
            console: None,
            console_directory: None,
        };
        if io.terminal {
            // sockaddr_un is much shorter than an arbitrary bundle path. Keep
            // the handshake in a private, short directory independent of TMPDIR.
            let directory = tempfile::Builder::new()
                .prefix("rauha-console-")
                .permissions(std::fs::Permissions::from_mode(0o700))
                .tempdir_in("/tmp")?;
            let path = directory.path().join("console.sock");
            let listener = UnixListener::bind(&path)?;
            listener.set_nonblocking(true)?;
            prepared.console = Some((listener, path, input, output));
            prepared.console_directory = Some(directory);
        } else {
            if let Some(input) = input {
                let (reader, writer) = UnixStream::pair()?;
                writer.set_nonblocking(true)?;
                prepared.stdin = Stdio::from(OwnedFd::from(reader));
                prepared.session.threads.push(relay(
                    input,
                    File::from(OwnedFd::from(writer)),
                    prepared.session.stop.clone(),
                    prepared.session.close_input.clone(),
                    true,
                )?);
            }
            prepared.stdout = output
                .map(blocking)
                .transpose()?
                .map(Stdio::from)
                .unwrap_or_else(Stdio::null);
            prepared.stderr = error
                .map(blocking)
                .transpose()?
                .map(Stdio::from)
                .unwrap_or_else(Stdio::null);
        }
        Ok(prepared)
    }

    pub fn console_path(&self) -> Option<&Path> {
        self.console.as_ref().map(|(_, path, _, _)| path.as_path())
    }

    pub fn receive_console(&mut self) -> anyhow::Result<()> {
        self.receive_console_mode(false).map(|_| ())
    }

    pub fn receive_direct_console(&mut self) -> anyhow::Result<File> {
        self.receive_console_mode(true)?
            .ok_or_else(|| anyhow::anyhow!("interactive exec requires a console"))
    }

    fn receive_console_mode(&mut self, direct: bool) -> anyhow::Result<Option<File>> {
        let Some((listener, path, input, output)) = self.console.take() else {
            return Ok(None);
        };
        let result = (|| -> anyhow::Result<Option<File>> {
            let deadline = Instant::now() + Duration::from_secs(5);
            let stream = loop {
                match listener.accept() {
                    Ok((stream, _)) => break stream,
                    Err(e)
                        if e.kind() == std::io::ErrorKind::WouldBlock
                            && Instant::now() < deadline =>
                    {
                        std::thread::sleep(Duration::from_millis(10))
                    }
                    Err(e) => return Err(e.into()),
                }
            };
            stream.set_read_timeout(Some(Duration::from_secs(5)))?;
            let mut bytes = [0u8; 1];
            let mut iov = [std::io::IoSliceMut::new(&mut bytes)];
            let mut ancillary = nix::cmsg_space!([std::os::fd::RawFd; 1]);
            let message = nix::sys::socket::recvmsg::<()>(
                stream.as_raw_fd(),
                &mut iov,
                Some(&mut ancillary),
                nix::sys::socket::MsgFlags::MSG_CMSG_CLOEXEC,
            )?;
            let mut received = Vec::new();
            for control in message.cmsgs()? {
                if let nix::sys::socket::ControlMessageOwned::ScmRights(fds) = control {
                    for fd in fds {
                        received.push(unsafe { File::from_raw_fd(fd) });
                    }
                }
            }
            anyhow::ensure!(
                received.len() == 1
                    && !message
                        .flags
                        .contains(nix::sys::socket::MsgFlags::MSG_CTRUNC),
                "runtime returned an invalid console descriptor"
            );
            let master = received.pop().unwrap();
            let flags = unsafe { libc::fcntl(master.as_raw_fd(), libc::F_GETFL) };
            if flags < 0
                || unsafe {
                    libc::fcntl(master.as_raw_fd(), libc::F_SETFL, flags | libc::O_NONBLOCK)
                } < 0
            {
                return Err(std::io::Error::last_os_error().into());
            }
            if direct {
                anyhow::ensure!(
                    input.is_none() && output.is_none(),
                    "direct console cannot use FIFOs"
                );
                return Ok(Some(master));
            }
            let output = match output {
                Some(output) => output,
                None => OpenOptions::new().write(true).open("/dev/null")?,
            };
            self.session.threads.push(relay(
                master.try_clone()?,
                output,
                self.session.stop.clone(),
                Arc::new(AtomicBool::new(false)),
                false,
            )?);
            if let Some(input) = input {
                self.session.threads.push(relay(
                    input,
                    master.try_clone()?,
                    self.session.stop.clone(),
                    self.session.close_input.clone(),
                    true,
                )?);
            }
            self.session.master = Some(master);
            Ok(None)
        })();
        let remove = std::fs::remove_file(path);
        drop(self.console_directory.take());
        let master = result?;
        remove?;
        Ok(master)
    }
}

impl Drop for PreparedIo {
    fn drop(&mut self) {
        if let Some((_, path, _, _)) = &self.console {
            let _ = std::fs::remove_file(path);
        }
    }
}

fn relay(
    mut reader: File,
    mut writer: File,
    stop: Arc<AtomicBool>,
    close: Arc<AtomicBool>,
    input: bool,
) -> std::io::Result<JoinHandle<std::io::Result<()>>> {
    std::thread::Builder::new()
        .name("containerd-io".into())
        .spawn(move || {
            let mut bytes = [0u8; 8192];
            let mut seen_input = false;
            while !stop.load(Ordering::Acquire) && !close.load(Ordering::Acquire) {
                let size = match reader.read(&mut bytes) {
                    Ok(0) if input && !seen_input => {
                        let mut descriptor = libc::pollfd {
                            fd: reader.as_raw_fd(),
                            events: libc::POLLIN,
                            revents: 0,
                        };
                        let result = unsafe { libc::poll(&mut descriptor, 1, 0) };
                        if result < 0 {
                            return Err(std::io::Error::last_os_error());
                        }
                        if descriptor.revents & libc::POLLHUP != 0 {
                            break;
                        }
                        std::thread::sleep(Duration::from_millis(10));
                        continue;
                    }
                    Ok(0) => break,
                    Ok(n) => {
                        seen_input = true;
                        n
                    }
                    Err(e)
                        if matches!(
                            e.kind(),
                            std::io::ErrorKind::WouldBlock | std::io::ErrorKind::Interrupted
                        ) =>
                    {
                        std::thread::sleep(Duration::from_millis(10));
                        continue;
                    }
                    Err(error) if error.raw_os_error() == Some(libc::EIO) && !input => break,
                    Err(error) => return if input { Ok(()) } else { Err(error) },
                };
                let mut written = 0;
                while written < size
                    && !stop.load(Ordering::Acquire)
                    && !close.load(Ordering::Acquire)
                {
                    match writer.write(&bytes[written..size]) {
                        Ok(0) => {
                            return if input {
                                Ok(())
                            } else {
                                Err(std::io::Error::from(std::io::ErrorKind::WriteZero))
                            }
                        }
                        Ok(n) => written += n,
                        Err(e)
                            if matches!(
                                e.kind(),
                                std::io::ErrorKind::WouldBlock | std::io::ErrorKind::Interrupted
                            ) =>
                        {
                            std::thread::sleep(Duration::from_millis(10))
                        }
                        Err(error) => return if input { Ok(()) } else { Err(error) },
                    }
                }
            }
            if input && unsafe { libc::isatty(writer.as_raw_fd()) } == 1 {
                let _ = writer.write_all(&[4]);
            }
            Ok(())
        })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn session(reader: File, writer: File, input: bool) -> IoSession {
        let stop = Arc::new(AtomicBool::new(false));
        let close_input = Arc::new(AtomicBool::new(false));
        let close = if input {
            close_input.clone()
        } else {
            Arc::new(AtomicBool::new(false))
        };
        let worker = relay(reader, writer, stop.clone(), close, input).unwrap();
        IoSession {
            stop,
            close_input,
            threads: vec![worker],
            master: None,
            failure: None,
        }
    }

    #[test]
    fn empty_fifo_writer_closure_delivers_stdin_eof() {
        let path = std::env::temp_dir().join(format!("rauha-empty-stdin-{}", uuid::Uuid::new_v4()));
        let name = std::ffi::CString::new(path.as_os_str().as_encoded_bytes()).unwrap();
        assert_eq!(unsafe { libc::mkfifo(name.as_ptr(), 0o600) }, 0);
        let input = fifo(path.to_str().unwrap(), true).unwrap().unwrap();
        let writer = OpenOptions::new().write(true).open(&path).unwrap();
        drop(writer);
        std::fs::remove_file(path).unwrap();
        let (mut consumer, writer) = UnixStream::pair().unwrap();
        writer.set_nonblocking(true).unwrap();
        consumer
            .set_read_timeout(Some(Duration::from_secs(1)))
            .unwrap();
        let mut session = session(input, File::from(OwnedFd::from(writer)), true);
        let mut bytes = Vec::new();
        let read = consumer.read_to_end(&mut bytes);
        session.finish().unwrap();
        assert_eq!(read.unwrap(), 0);
    }

    #[test]
    fn output_drain_timeout_preserves_pending_bytes_for_retry() {
        let (reader, mut producer) = UnixStream::pair().unwrap();
        reader.set_nonblocking(true).unwrap();
        let (mut consumer, mut writer) = UnixStream::pair().unwrap();
        writer.set_nonblocking(true).unwrap();
        let filler = [b'x'; 4096];
        let mut filled = 0;
        loop {
            match writer.write(&filler) {
                Ok(count) => filled += count,
                Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => break,
                Err(error) => panic!("fill output buffer: {error}"),
            }
        }
        let tail = b"the final terminal output";
        producer.write_all(tail).unwrap();
        drop(producer);
        let mut session = session(
            File::from(OwnedFd::from(reader)),
            File::from(OwnedFd::from(writer)),
            false,
        );
        assert!(session
            .finish()
            .unwrap_err()
            .to_string()
            .contains("timed out"));
        consumer
            .set_read_timeout(Some(Duration::from_secs(2)))
            .unwrap();
        let draining = std::thread::spawn(move || {
            let mut output = vec![0; filled + tail.len()];
            consumer.read_exact(&mut output).unwrap();
            output
        });
        session.finish().unwrap();
        let output = draining.join().unwrap();
        assert_eq!(&output[filled..], tail);
    }

    #[test]
    fn output_delivery_errors_remain_visible_on_cleanup_retry() {
        let (reader, mut producer) = UnixStream::pair().unwrap();
        reader.set_nonblocking(true).unwrap();
        let (consumer, writer) = UnixStream::pair().unwrap();
        writer.set_nonblocking(true).unwrap();
        drop(consumer);
        producer.write_all(b"undeliverable").unwrap();
        drop(producer);
        let mut session = session(
            File::from(OwnedFd::from(reader)),
            File::from(OwnedFd::from(writer)),
            false,
        );
        assert!(session.finish().is_err());
        assert!(session.finish().is_err());
    }

    #[test]
    fn console_socket_ignores_long_bundle_paths_and_remains_private() {
        use std::os::unix::fs::PermissionsExt;
        let bundle = PathBuf::from("/tmp")
            .join("a".repeat(200))
            .join("b".repeat(200));
        let io = ProcessIo {
            stdin: String::new(),
            stdout: String::new(),
            stderr: String::new(),
            terminal: true,
        };
        let prepared = PreparedIo::new(&io, &bundle).unwrap();
        let socket = prepared.console_path().unwrap().to_path_buf();
        let directory = socket.parent().unwrap().to_path_buf();
        assert!(socket.as_os_str().len() < 108);
        assert_eq!(
            std::fs::metadata(&directory).unwrap().permissions().mode() & 0o777,
            0o700
        );
        drop(prepared);
        assert!(!socket.exists());
        assert!(!directory.exists());
    }

    #[test]
    fn direct_console_preserves_output_without_starting_fifo_relays() {
        let directory = std::env::temp_dir().join(format!("r-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir(&directory).unwrap();
        let io = ProcessIo {
            stdin: String::new(),
            stdout: String::new(),
            stderr: String::new(),
            terminal: true,
        };
        let mut prepared = PreparedIo::new(&io, &directory).unwrap();
        let terminal = nix::pty::openpty(None, None).unwrap();
        let stream = UnixStream::connect(prepared.console_path().unwrap()).unwrap();
        nix::sys::socket::sendmsg::<()>(
            stream.as_raw_fd(),
            &[std::io::IoSlice::new(b"p")],
            &[nix::sys::socket::ControlMessage::ScmRights(&[terminal
                .master
                .as_raw_fd()])],
            nix::sys::socket::MsgFlags::empty(),
            None,
        )
        .unwrap();
        let mut master = prepared.receive_direct_console().unwrap();
        assert!(prepared.session.threads.is_empty());
        File::from(terminal.slave).write_all(b"tail").unwrap();
        let mut output = [0; 4];
        master.read_exact(&mut output).unwrap();
        assert_eq!(&output, b"tail");
        prepared.session.finish().unwrap();
        std::fs::remove_dir(directory).unwrap();
    }

    #[test]
    fn terminal_without_output_fifo_still_drains_and_closes() {
        let directory = std::env::temp_dir().join(format!("r-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir(&directory).unwrap();
        let io = ProcessIo {
            stdin: String::new(),
            stdout: String::new(),
            stderr: String::new(),
            terminal: true,
        };
        let mut prepared = PreparedIo::new(&io, &directory).unwrap();
        let terminal = nix::pty::openpty(None, None).unwrap();
        let stream = UnixStream::connect(prepared.console_path().unwrap()).unwrap();
        let descriptors = [terminal.master.as_raw_fd()];
        nix::sys::socket::sendmsg::<()>(
            stream.as_raw_fd(),
            &[std::io::IoSlice::new(b"p")],
            &[nix::sys::socket::ControlMessage::ScmRights(&descriptors)],
            nix::sys::socket::MsgFlags::empty(),
            None,
        )
        .unwrap();
        drop(stream);
        drop(terminal.master);
        prepared.receive_console().unwrap();
        let (done, result) = std::sync::mpsc::channel();
        let writing = std::thread::spawn(move || {
            let mut slave = File::from(terminal.slave);
            let result = slave.write_all(&[b'a'; 128 * 1024]);
            drop(slave);
            done.send(result).unwrap();
        });
        let completed = result.recv_timeout(Duration::from_secs(2));
        let drained = prepared.session.finish();
        drop(prepared);
        writing.join().unwrap();
        std::fs::remove_dir(directory).unwrap();
        completed.unwrap().unwrap();
        drained.unwrap();
    }
}
