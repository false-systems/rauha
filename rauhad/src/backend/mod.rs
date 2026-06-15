// Re-export the trait from common.
pub use rauha_common::backend::IsolationBackend;

#[cfg(target_os = "linux")]
pub mod linux;

#[cfg(target_os = "macos")]
pub mod macos;

/// Enforcement event broadcast sender type (Linux only).
#[cfg(target_os = "linux")]
pub type EventSender = tokio::sync::broadcast::Sender<rauha_evidence::FalseEvent>;

/// Create the platform-appropriate isolation backend.
#[cfg(target_os = "linux")]
pub fn create_backend(
    root: &str,
) -> rauha_common::error::Result<(Box<dyn IsolationBackend>, Option<EventSender>)> {
    let backend = linux::LinuxBackend::new(root)?;
    let event_tx = backend.event_sender();
    Ok((Box::new(backend), event_tx))
}

#[cfg(target_os = "macos")]
pub fn create_backend(
    root: &str,
) -> rauha_common::error::Result<Box<dyn IsolationBackend>> {
    Ok(Box::new(macos::MacosBackend::new(root)?))
}

#[cfg(not(any(target_os = "linux", target_os = "macos")))]
pub fn create_backend(
    root: &str,
) -> rauha_common::error::Result<Box<dyn IsolationBackend>> {
    Err(rauha_common::error::RauhaError::UnsupportedPlatform(
        std::env::consts::OS.into(),
    ))
}
