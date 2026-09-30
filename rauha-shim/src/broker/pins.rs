//! Task pinning for the judgment path: pidfd + `/proc/<tid>/{mem,root}`
//! held across a task's notifications, and the bounded cache that keeps
//! them.
//!
//! Holding a pidfd pins the task's `struct pid`, which means **the tid
//! cannot be reused** while the pin lives — the kernel cannot assign that
//! number to a new thread. That is what makes the cached path
//! race-equivalent to the cold path: a notification arriving with a cached
//! tid was made by the same task the cache pinned, or by nobody (the task
//! is dead and `alive()` evicts it — hygiene, not correctness: a dead task
//! suspends no syscalls, and its `mem` reads fail closed).

use std::collections::{HashMap, VecDeque};
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::os::unix::fs::OpenOptionsExt;

/// pidfd + /proc fds pinned for one task, cached across its notifications.
pub(crate) struct TaskPins {
    pub pidfd: OwnedFd,
    pub mem: std::fs::File,
    pub root: OwnedFd,
}

impl TaskPins {
    /// Cold path: pin the task and its /proc objects. Fails with the errno
    /// of the first failing step (ESRCH when the task is already gone).
    /// Everything is close-on-exec: the shim forks and execs helpers, and
    /// a leaked /proc/<tid>/mem in a child is an evidence-grade mistake.
    pub(crate) fn open(tid: u32) -> Result<Self, i32> {
        let pidfd = unsafe { libc::syscall(libc::SYS_pidfd_open, tid, 0) };
        if pidfd < 0 {
            return Err(std::io::Error::last_os_error()
                .raw_os_error()
                .unwrap_or(libc::ESRCH));
        }
        let pidfd = unsafe { OwnedFd::from_raw_fd(pidfd as libc::c_int) };
        let mem = std::fs::OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_CLOEXEC)
            .open(format!("/proc/{tid}/mem"))
            .map_err(|e| e.raw_os_error().unwrap_or(libc::ESRCH))?;
        let root_path =
            std::ffi::CString::new(format!("/proc/{tid}/root")).map_err(|_| libc::EINVAL)?;
        let root = unsafe { libc::open(root_path.as_ptr(), libc::O_PATH | libc::O_CLOEXEC) };
        if root < 0 {
            return Err(std::io::Error::last_os_error()
                .raw_os_error()
                .unwrap_or(libc::ESRCH));
        }
        Ok(Self {
            pidfd,
            mem,
            root: unsafe { OwnedFd::from_raw_fd(root) },
        })
    }

    /// False once the pinned task has exited (pidfd reports POLLIN on
    /// exit). A poll error also counts as dead — evicting is always safe.
    pub(crate) fn alive(&self) -> bool {
        let mut pollfd = libc::pollfd {
            fd: self.pidfd.as_raw_fd(),
            events: libc::POLLIN,
            revents: 0,
        };
        (unsafe { libc::poll(&mut pollfd, 1, 0) }) <= 0
    }
}

/// Pins for one judgment: usually a cached borrow, or a cold, un-cached
/// lease when the cache is disabled or full (dropped after the judgment).
pub(crate) enum PinHandle<'a> {
    Cached(&'a TaskPins),
    Cold(TaskPins),
}

impl std::ops::Deref for PinHandle<'_> {
    type Target = TaskPins;
    fn deref(&self) -> &TaskPins {
        match self {
            PinHandle::Cached(pins) => pins,
            PinHandle::Cold(pins) => pins,
        }
    }
}

/// Cache of [`TaskPins`] by task id. Bounded, FIFO-evicting: a zone cannot
/// grow the broker's memory by spawning threads that make brokered calls,
/// and under churn the cache stays useful (the oldest pin goes, not the
/// newest task's). Capacity 0 disables caching entirely.
pub(crate) struct PinCache {
    pins: HashMap<u32, TaskPins>,
    order: VecDeque<u32>,
    max_tasks: usize,
}

impl PinCache {
    pub(crate) fn new(max_tasks: usize) -> Self {
        Self {
            pins: HashMap::new(),
            order: VecDeque::new(),
            max_tasks,
        }
    }

    /// Pins for the task, cached when possible. Dead (evicted) entries are
    /// refilled from the cold path, which preserves the race protocol: the
    /// /proc fds are opened *before* the caller's `id_valid` check.
    pub(crate) fn for_task(&mut self, tid: u32) -> Result<PinHandle<'_>, i32> {
        // Two-step lookup: the cached borrow must not outlive the
        // possible remove below.
        let alive = self.pins.get(&tid).is_some_and(TaskPins::alive);
        if alive {
            return Ok(PinHandle::Cached(
                self.pins.get(&tid).expect("alive implies present"),
            ));
        }
        self.pins.remove(&tid);
        if self.max_tasks == 0 {
            return TaskPins::open(tid).map(PinHandle::Cold);
        }
        while self.pins.len() >= self.max_tasks {
            // Evict oldest-inserted; stale `order` entries (already removed
            // as dead) pop harmlessly.
            let Some(evict) = self.order.pop_front() else {
                break;
            };
            self.pins.remove(&evict);
        }
        let pins = TaskPins::open(tid)?;
        self.pins.insert(tid, pins);
        self.order.push_back(tid);
        Ok(PinHandle::Cached(
            self.pins.get(&tid).expect("just inserted"),
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pin_cache_reuses_live_tasks_and_caches_nothing_when_disabled() {
        // Our own process is a task that is certainly alive.
        let mut cache = PinCache::new(8);
        let pid = std::process::id();
        cache.for_task(pid).expect("pins for a live task");
        cache.for_task(pid).expect("pins reused");
        assert_eq!(cache.pins.len(), 1, "second lookup must reuse the entry");

        // Capacity 0: every judgment is a cold lease, nothing is cached.
        let mut disabled = PinCache::new(0);
        match disabled.for_task(pid).expect("cold path still works") {
            PinHandle::Cold(_) => {}
            PinHandle::Cached(_) => panic!("capacity 0 must not cache"),
        }
        assert!(disabled.pins.is_empty());
    }

    #[test]
    fn pin_cache_cold_path_reports_missing_tasks() {
        // A pid that has been reaped cannot be pinned: ESRCH.
        let mut cache = PinCache::new(8);
        let mut child = std::process::Command::new("true").spawn().unwrap();
        let pid = child.id();
        child.wait().unwrap(); // reaped: the pid is gone
        for _ in 0..50 {
            if let Err(errno) = cache.for_task(pid) {
                assert_eq!(errno, libc::ESRCH);
                return;
            }
            std::thread::sleep(std::time::Duration::from_millis(10));
        }
        panic!("reaped pid {pid} was still pinnable");
    }

    #[test]
    fn full_cache_evicts_oldest_instead_of_going_cold_forever() {
        let mut cache = PinCache::new(1);
        let first = std::process::id();
        let mut second = std::process::Command::new("sleep")
            .arg("5")
            .spawn()
            .expect("spawn a second live task");
        cache.for_task(first).expect("first task cached");
        // Second task overflows capacity 1: the oldest pin is evicted and
        // the newcomer is cached — the cache stays useful under churn.
        cache
            .for_task(second.id())
            .expect("live task must be servable");
        assert_eq!(cache.pins.len(), 1, "capacity is respected");
        assert!(
            cache.pins.contains_key(&second.id()),
            "the newcomer should hold the slot, not be dropped"
        );
        let _ = second.kill();
        let _ = second.wait_with_output();
    }

    #[test]
    fn task_pins_for_our_own_process_read_memory() {
        // The mem fd of a live task can read that task's own memory: prove
        // the pins are usable end to end on this kernel. The NUL makes the
        // read deterministic — read_path_into stops at it.
        let pins = TaskPins::open(std::process::id()).expect("pins for self");
        let canary = *b"rauha-broker\0";
        let ptr = canary.as_ptr() as u64;
        let mut buf = Vec::new();
        assert!(matches!(
            super::super::read_path_into(&pins.mem, ptr, &mut buf),
            super::super::PathRead::Found
        ));
        assert_eq!(buf, b"rauha-broker");
    }

    #[test]
    fn pins_are_close_on_exec() {
        // The shim forks and execs helpers; none of the pinned fds may
        // survive into them.
        let pins = TaskPins::open(std::process::id()).expect("pins for self");
        for fd in [
            pins.pidfd.as_raw_fd(),
            pins.mem.as_raw_fd(),
            pins.root.as_raw_fd(),
        ] {
            let flags = unsafe { libc::fcntl(fd, libc::F_GETFD) };
            assert!(
                flags & libc::FD_CLOEXEC != 0,
                "fd {fd} must be close-on-exec"
            );
        }
    }
}
