//! Enforcement event reader — drains the BPF ring buffer in a background task.
//!
//! Raw eBPF records are normalized at this edge into evidence-schema events,
//! then broadcast to gRPC WatchEvents subscribers.

use std::time::Duration;

use aya::maps::{MapData, RingBuf};
use rauha_ebpf_common::EnforcementEvent;
use rauha_evidence::{
    event_name, pipeline_shed_event, FalseEvent, FalseEventBuilder, FieldValue, ResourceAttrs,
    Severity, BACKEND_LINUX_EBPF,
};
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

/// Start the ring buffer reader as a background tokio task.
///
/// Returns a broadcast Sender that gRPC handlers can subscribe to.
pub fn spawn_event_reader(
    ring_buf: RingBuf<MapData>,
    cancel: tokio_util::sync::CancellationToken,
) -> broadcast::Sender<FalseEvent> {
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
    tx: broadcast::Sender<FalseEvent>,
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

fn drain_events(ring_buf: &mut RingBuf<MapData>, tx: &broadcast::Sender<FalseEvent>) {
    while let Some(item) = ring_buf.next() {
        if item.len() < std::mem::size_of::<EnforcementEvent>() {
            let event = FalseEventBuilder::new(event_name::PIPELINE_SHED)
                .level(Severity::Warn)
                .zone("zone-unknown", None)
                .resource_attributes(ResourceAttrs::new(BACKEND_LINUX_EBPF))
                .field(
                    "reason",
                    FieldValue::String("undersized_enforcement_event".into()),
                )
                .field("bytes", FieldValue::U64(item.len() as u64))
                .build();
            if let Ok(event) = event {
                event.emit_tracing();
                let _ = tx.send(event);
            }
            continue;
        }

        let event: EnforcementEvent =
            unsafe { std::ptr::read_unaligned(item.as_ptr() as *const EnforcementEvent) };

        let evidence = normalize_enforcement_event(event);
        evidence.emit_tracing();

        // Best-effort broadcast. If subscribers lag, WatchEvents converts that
        // into a pipeline.shed evidence record; no drop is silent.
        let _ = tx.send(evidence);
    }
}

fn normalize_enforcement_event(event: EnforcementEvent) -> FalseEvent {
    let hook = HOOK_NAMES
        .get(event.hook as usize)
        .copied()
        .unwrap_or("unknown");
    let event_name = event_name_for(event.hook, event.decision);
    let level = if event.decision == rauha_ebpf_common::DECISION_ERROR {
        Severity::Error
    } else {
        severity_for_event(event_name)
    };
    let zone_id = if event.caller_zone == 0 {
        "zone-unassigned".to_string()
    } else {
        format!("zone-{}", event.caller_zone)
    };
    let resource = resource_for(event.hook, event.context);

    FalseEventBuilder::new(event_name)
        .level(level)
        .zone(zone_id, None)
        .actor(format!("pid:{}", event.pid), Vec::new())
        .resource(resource)
        .resource_attributes(ResourceAttrs::new(BACKEND_LINUX_EBPF))
        .field("pid", FieldValue::U64(event.pid as u64))
        .field("hook", FieldValue::String(hook.to_string()))
        .field(
            "decision",
            FieldValue::String(decision_name(event.decision).into()),
        )
        .field("caller_zone", FieldValue::U64(event.caller_zone as u64))
        .field("target_zone", FieldValue::U64(event.target_zone as u64))
        .field("source_timestamp_ns", FieldValue::U64(event.timestamp_ns))
        .field("context", FieldValue::U64(event.context))
        .build()
        .unwrap_or_else(|e| {
            tracing::error!(%e, "failed to normalize enforcement event");
            pipeline_shed_event("normalization_failed", BACKEND_LINUX_EBPF)
        })
}

fn event_name_for(hook: u8, decision: u8) -> &'static str {
    if decision == rauha_ebpf_common::DECISION_ERROR {
        return event_name::PIPELINE_SHED;
    }

    match hook {
        rauha_ebpf_common::HOOK_FILE_OPEN => event_name::ZONE_FILE_DENIED,
        rauha_ebpf_common::HOOK_BPRM_CHECK => event_name::ZONE_EXEC_DENIED,
        rauha_ebpf_common::HOOK_PTRACE_CHECK => event_name::ZONE_PTRACE_DENIED,
        rauha_ebpf_common::HOOK_TASK_KILL => event_name::ZONE_SIGNAL_DENIED,
        rauha_ebpf_common::HOOK_CGROUP_ATTACH => event_name::ZONE_ESCAPE_CGROUP_ATTACH,
        rauha_ebpf_common::HOOK_SOCKET_CONNECT => event_name::ZONE_NET_DENIED,
        rauha_ebpf_common::HOOK_CAPABLE => event_name::ZONE_MOUNT_DENIED,
        _ => event_name::PIPELINE_SHED,
    }
}

fn severity_for_event(event_name: &str) -> Severity {
    match event_name {
        event_name::ZONE_ESCAPE_CGROUP_ATTACH => Severity::Error,
        event_name::ZONE_FILE_DENIED
        | event_name::ZONE_EXEC_DENIED
        | event_name::ZONE_PTRACE_DENIED
        | event_name::ZONE_SIGNAL_DENIED
        | event_name::ZONE_MOUNT_DENIED
        | event_name::ZONE_IPC_DENIED
        | event_name::ZONE_NET_DENIED => Severity::Warn,
        _ => Severity::Info,
    }
}

fn resource_for(hook: u8, context: u64) -> String {
    match hook {
        rauha_ebpf_common::HOOK_FILE_OPEN | rauha_ebpf_common::HOOK_BPRM_CHECK => {
            format!("inode:{context}")
        }
        rauha_ebpf_common::HOOK_CGROUP_ATTACH => format!("cgroup:{context}"),
        rauha_ebpf_common::HOOK_SOCKET_CONNECT => format!("socket:{context}"),
        _ => "kernel-object:unknown".into(),
    }
}

fn decision_name(decision: u8) -> &'static str {
    match decision {
        rauha_ebpf_common::DECISION_ALLOW => "allow",
        rauha_ebpf_common::DECISION_DENY => "deny",
        rauha_ebpf_common::DECISION_ERROR => "error",
        _ => "unknown",
    }
}
