// Re-export the trait from common.
pub use rauha_common::backend::IsolationBackend;

#[cfg(target_os = "linux")]
pub mod linux;

/// Enforcement event broadcast sender type (Linux only).
#[cfg(target_os = "linux")]
pub type EventSender = tokio::sync::broadcast::Sender<rauha_evidence::FalseEvent>;

/// Create the platform-appropriate isolation backend.
///
/// Linux is the only supported platform. Other platforms compile but get a
/// runtime refusal — the workspace stays buildable and unit-testable on any
/// OS, while the daemon itself never starts without a real backend.
#[cfg(target_os = "linux")]
pub fn create_backend(
    root: &str,
) -> rauha_common::error::Result<(Box<dyn IsolationBackend>, Option<EventSender>)> {
    let backend = linux::LinuxBackend::new(root)?;
    let event_tx = backend.event_sender();
    Ok((Box::new(backend), event_tx))
}

#[cfg(not(target_os = "linux"))]
pub fn create_backend(_root: &str) -> rauha_common::error::Result<Box<dyn IsolationBackend>> {
    Err(rauha_common::error::RauhaError::UnsupportedPlatform(
        std::env::consts::OS.into(),
    ))
}
