//! Enforcement event reader — drains the BPF ring buffer in a background task.
//!
//! Deny events from all 7 LSM hooks are streamed here, logged via tracing,
//! and broadcast to any gRPC WatchEvents subscribers.

use std::time::Duration;

use aya::maps::{MapData, RingBuf};
use rauha_ebpf_common::EnforcementEvent;
use tokio::sync::broadcast;

const HOOK_NAMES: [&str; 7] = [
    "file_open",
    "bprm_check",
    "ptrace_access_check",
    "task_kill",
    "cgroup_attach_task",
    "capable",
    "socket_connect",
];

/// A decoded enforcement event for userspace consumers.
#[derive(Clone, Debug)]
pub struct DecodedEvent {
    pub timestamp_ns: u64,
    pub pid: u32,
    pub hook: String,
    pub caller_zone: u32,
    pub target_zone: u32,
    pub context: u64,
}

/// Start the ring buffer reader as a background tokio task.
///
/// Returns a broadcast Sender that gRPC handlers can subscribe to.
pub fn spawn_event_reader(
    ring_buf: RingBuf<MapData>,
    cancel: tokio_util::sync::CancellationToken,
) -> broadcast::Sender<DecodedEvent> {
    let (tx, _) = broadcast::channel(1024);
    let tx_clone = tx.clone();

    tokio::spawn(async move {
        run_event_loop(ring_buf, cancel, tx_clone).await;
    });

    tx
}

async fn run_event_loop(
    mut ring_buf: RingBuf<MapData>,
    cancel: tokio_util::sync::CancellationToken,
    tx: broadcast::Sender<DecodedEvent>,
) {
    let mut interval = tokio::time::interval(Duration::from_millis(100));
    tracing::info!("enforcement event reader started");

    loop {
        tokio::select! {
            _ = cancel.cancelled() => {
                drain_events(&mut ring_buf, &tx);
                tracing::info!("enforcement event reader stopped");
                return;
            }
            _ = interval.tick() => {
                drain_events(&mut ring_buf, &tx);
            }
        }
    }
}

fn drain_events(ring_buf: &mut RingBuf<MapData>, tx: &broadcast::Sender<DecodedEvent>) {
    while let Some(item) = ring_buf.next() {
        if item.len() < std::mem::size_of::<EnforcementEvent>() {
            tracing::warn!(len = item.len(), "undersized enforcement event");
            continue;
        }

        let event: EnforcementEvent =
            unsafe { std::ptr::read_unaligned(item.as_ptr() as *const EnforcementEvent) };

        let hook = HOOK_NAMES
            .get(event.hook as usize)
            .unwrap_or(&"unknown");

        if event.decision == rauha_ebpf_common::DECISION_ERROR {
            tracing::error!(
                hook = hook,
                pid = event.pid,
                "enforcement ERROR — hook failed open, kernel read may have failed. \
                 Check if kernel struct offsets are correct for this kernel version."
            );
        } else {
            tracing::warn!(
                hook = hook,
                pid = event.pid,
                caller_zone = event.caller_zone,
                target_zone = event.target_zone,
                context = event.context,
                timestamp_ns = event.timestamp_ns,
                "enforcement DENY"
            );
        }

        // Best-effort broadcast — if no subscribers, the send is a no-op.
        let _ = tx.send(DecodedEvent {
            timestamp_ns: event.timestamp_ns,
            pid: event.pid,
            hook: hook.to_string(),
            caller_zone: event.caller_zone,
            target_zone: event.target_zone,
            context: event.context,
        });
    }
}
