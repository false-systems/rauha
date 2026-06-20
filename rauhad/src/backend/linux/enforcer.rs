//! Adapter from Rauha's Linux eBPF implementation to `rauha-enforcer-api`.
//!
//! This is intentionally a wrapper around the existing in-repo eBPF manager and
//! BPF map helpers. It creates the enforcement seam first without moving the
//! kernel code or changing backend behavior.

use std::path::PathBuf;
use std::sync::Mutex;

use rauha_common::error::{RauhaError, Result};
use rauha_common::zone::{ZonePolicy, ZoneType};
use rauha_enforcer_api::{
    Capabilities, Decision, EnforcementPolicy, EnforcementStats, EnforcerBackend, EnforcerError,
    EventStream, Hook, HookSet, VerifyDiscrepancy, VerifyDiscrepancyKind, VerifyReport,
    ZoneEnforcement, ZoneId,
};

use super::ebpf::EbpfManager;
use super::events;
use super::lock_backend;
use super::maps::{enforcement_to_kernel, MapManager};

pub(super) struct LinuxEnforcer {
    root: String,
    ebpf: Mutex<Option<EbpfManager>>,
    event_reader_cancel: Option<tokio_util::sync::CancellationToken>,
    event_tx: Option<tokio::sync::broadcast::Sender<rauha_evidence::FalseEvent>>,
}

impl LinuxEnforcer {
    pub(super) fn new(root: &str) -> Result<Self> {
        let mut ebpf = Self::load_ebpf(root)?;
        tracing::info!("eBPF programs loaded — kernel enforcement active");

        let ring_buf = ebpf
            .take_event_ring_buf()
            .map_err(|e| RauhaError::EbpfError {
                message: format!("enforcement event ring buffer not available: {e}"),
                hint: "check the ENFORCEMENT_EVENTS ring buffer map was created".into(),
            })?;
        let event_reader_cancel = tokio_util::sync::CancellationToken::new();
        let event_tx = events::spawn_event_reader(ring_buf, event_reader_cancel.clone());

        Ok(Self {
            root: root.to_string(),
            ebpf: Mutex::new(Some(ebpf)),
            event_reader_cancel: Some(event_reader_cancel),
            event_tx: Some(event_tx),
        })
    }

    fn load_ebpf(root: &str) -> Result<EbpfManager> {
        for path in Self::ebpf_candidates(root) {
            if path.exists() {
                return EbpfManager::load(&path);
            }
        }

        Err(RauhaError::EbpfError {
            message: "eBPF object not found in any known location".into(),
            hint: "run `cargo xtask build-ebpf` to compile eBPF programs".into(),
        })
    }

    fn ebpf_candidates(root: &str) -> [PathBuf; 4] {
        let project_root = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .unwrap_or_else(|| std::path::Path::new("."))
            .to_path_buf();

        [
            PathBuf::from(root).join("rauha-ebpf"),
            PathBuf::from("/usr/lib/rauha/rauha-ebpf"),
            project_root.join("rauha-ebpf/target/bpfel-unknown-none/debug/rauha-ebpf"),
            project_root.join("rauha-ebpf/target/bpfel-unknown-none/release/rauha-ebpf"),
        ]
    }

    pub(super) fn event_sender(
        &self,
    ) -> Option<tokio::sync::broadcast::Sender<rauha_evidence::FalseEvent>> {
        self.event_tx.clone()
    }

    pub(super) fn set_zone_policy(&self, zone_id: u32, policy: &ZonePolicy) -> Result<()> {
        self.with_bpf("policy enforcement", |bpf| {
            MapManager::set_zone_policy(bpf, zone_id, policy)
        })
    }

    pub(super) fn hot_reload_policy(&self, zone_id: u32, policy: &ZonePolicy) -> Result<()> {
        self.with_bpf("policy hot reload", |bpf| {
            MapManager::hot_reload_policy(bpf, zone_id, policy)
        })
    }

    /// Apply zone-wide enforcement (the seam's `ZoneEnforcement`) to the kernel
    /// policy map.
    ///
    /// This is the shared synchronous core behind both the sync `LinuxBackend`
    /// policy path and the async `EnforcerBackend::apply_policy`. Keeping it
    /// sync lets the daemon's sync `enforce_policy` route through the seam
    /// vocabulary without blocking a tokio runtime.
    pub(super) fn apply_zone_enforcement(
        &self,
        zone_id: u32,
        zone: &ZoneEnforcement,
    ) -> Result<()> {
        self.with_bpf("zone enforcement", |bpf| {
            MapManager::set_zone_policy_kernel(bpf, zone_id, enforcement_to_kernel(zone))
        })
    }

    pub(super) fn add_zone_member(
        &self,
        cgroup_id: u64,
        zone_id: u32,
        zone_type: ZoneType,
    ) -> Result<()> {
        self.with_bpf("zone membership", |bpf| {
            MapManager::add_zone_member(bpf, cgroup_id, zone_id, zone_type)
        })
    }

    pub(super) fn remove_zone_member(&self, cgroup_id: u64) -> Result<()> {
        self.with_bpf("zone membership cleanup", |bpf| {
            MapManager::remove_zone_member(bpf, cgroup_id)
        })
    }

    pub(super) fn remove_zone_policy(&self, zone_id: u32) -> Result<()> {
        self.with_bpf("zone policy cleanup", |bpf| {
            MapManager::remove_zone_policy(bpf, zone_id)
        })
    }

    pub(super) fn insert_inodes(&self, inodes: &[u64], zone_id: u32) -> Result<Vec<u64>> {
        self.with_bpf("rootfs inode registration", |bpf| {
            MapManager::insert_inodes(bpf, inodes, zone_id)
        })
    }

    pub(super) fn remove_inodes(&self, inodes: &[u64]) -> Result<u32> {
        self.with_bpf("rootfs inode cleanup", |bpf| {
            MapManager::remove_inodes(bpf, inodes)
        })
    }

    pub(super) fn allow_zone_comm(&self, src_zone: u32, dst_zone: u32) -> Result<()> {
        self.with_bpf("allowed zone communication", |bpf| {
            MapManager::allow_zone_comm(bpf, src_zone, dst_zone)
        })
    }

    pub(super) fn deny_zone_comm(&self, src_zone: u32, dst_zone: u32) -> Result<()> {
        self.with_bpf("allowed zone communication cleanup", |bpf| {
            MapManager::deny_zone_comm(bpf, src_zone, dst_zone)
        })
    }

    pub(super) fn health_check(&self) -> Result<Vec<super::ebpf::ProgramStatus>> {
        let ebpf_guard = lock_backend(&self.ebpf, "linux_enforcer.ebpf")?;
        let ebpf = ebpf_guard.as_ref().ok_or_else(|| RauhaError::EbpfError {
            message: "eBPF manager not available during health check".into(),
            hint: "restart rauhad after restoring eBPF LSM support".into(),
        })?;
        ebpf.health_check()
    }

    pub(super) fn read_enforcement_counters(
        &self,
    ) -> Result<Vec<(String, rauha_ebpf_common::EnforcementCounters)>> {
        let ebpf_guard = lock_backend(&self.ebpf, "linux_enforcer.ebpf")?;
        let ebpf = ebpf_guard.as_ref().ok_or_else(|| RauhaError::EbpfError {
            message: "eBPF manager not available while reading counters".into(),
            hint: "restart rauhad after restoring eBPF LSM support".into(),
        })?;
        ebpf.read_enforcement_counters()
    }

    fn with_bpf<T>(
        &self,
        operation: &str,
        f: impl FnOnce(&mut aya::Bpf) -> Result<T>,
    ) -> Result<T> {
        let mut ebpf_guard = lock_backend(&self.ebpf, "linux_enforcer.ebpf")?;
        let ebpf = ebpf_guard.as_mut().ok_or_else(|| RauhaError::EbpfError {
            message: format!("eBPF manager not available during {operation}"),
            hint: "restart rauhad after restoring eBPF LSM support".into(),
        })?;
        f(ebpf.bpf_mut())
    }

    fn capabilities_static() -> Capabilities {
        Capabilities {
            kernel_enforcement: true,
            hooks: HookSet::from_hooks([
                Hook::FileOpen,
                Hook::BprmCheck,
                Hook::SocketConnect,
                Hook::PtraceAccess,
                Hook::Signal,
                Hook::CgroupAttach,
            ]),
            event_stream: true,
            counters: true,
        }
    }
}

impl Drop for LinuxEnforcer {
    fn drop(&mut self) {
        if let Some(cancel) = self.event_reader_cancel.take() {
            cancel.cancel();
        }
    }
}

impl EnforcerBackend for LinuxEnforcer {
    async fn load(&self) -> std::result::Result<(), EnforcerError> {
        let mut ebpf_guard = self
            .ebpf
            .lock()
            .map_err(|_| EnforcerError::Verifier("linux enforcer mutex poisoned".into()))?;
        if ebpf_guard.is_some() {
            return Ok(());
        }
        let ebpf = Self::load_ebpf(&self.root).map_err(to_enforcer_error)?;
        *ebpf_guard = Some(ebpf);
        Ok(())
    }

    async fn shutdown(&self) -> std::result::Result<(), EnforcerError> {
        let mut ebpf_guard = self
            .ebpf
            .lock()
            .map_err(|_| EnforcerError::Verifier("linux enforcer mutex poisoned".into()))?;
        if let Some(ebpf) = ebpf_guard.take() {
            ebpf.cleanup();
        }
        Ok(())
    }

    async fn create_zone(&self, _zone: ZoneId) -> std::result::Result<(), EnforcerError> {
        if self
            .ebpf
            .lock()
            .map_err(|_| EnforcerError::Verifier("linux enforcer mutex poisoned".into()))?
            .is_some()
        {
            Ok(())
        } else {
            Err(EnforcerError::NotLoaded)
        }
    }

    async fn delete_zone(&self, _zone: ZoneId) -> std::result::Result<(), EnforcerError> {
        if self
            .ebpf
            .lock()
            .map_err(|_| EnforcerError::Verifier("linux enforcer mutex poisoned".into()))?
            .is_some()
        {
            Ok(())
        } else {
            Err(EnforcerError::NotLoaded)
        }
    }

    async fn apply_policy(
        &self,
        zone: ZoneId,
        policy: &EnforcementPolicy,
    ) -> std::result::Result<(), EnforcerError> {
        if self
            .ebpf
            .lock()
            .map_err(|_| EnforcerError::Verifier("linux enforcer mutex poisoned".into()))?
            .is_none()
        {
            return Err(EnforcerError::NotLoaded);
        }

        let capabilities = self.capabilities();
        for rule in &policy.rules {
            if !capabilities.supports_rule(rule) {
                return Err(EnforcerError::PolicyUnenforceable {
                    zone,
                    rule: rule.id,
                    reason: format!("unsupported hook {:?}", rule.hook),
                });
            }
        }

        // Zone IDs cross the seam as u64 but Rauha's kernel-side IDs are the
        // compact u32 BPF map keys, so the caller passes `ZoneId(zone_id)`.
        self.apply_zone_enforcement(zone.0 as u32, &policy.zone)
            .map_err(to_enforcer_error)
    }

    fn watch_events(&self) -> EventStream {
        // Current Rauha uses normalized evidence events over a broadcast sender.
        // The raw `EnforcementEvent` stream is reserved for the future Syva/API
        // adapter, so this wrapper returns an empty stream for now.
        let (_tx, rx) = tokio::sync::mpsc::channel(1);
        rx
    }

    async fn stats(&self, _zone: ZoneId) -> std::result::Result<EnforcementStats, EnforcerError> {
        let counters = self
            .read_enforcement_counters()
            .map_err(to_enforcer_error)?;
        let mut stats = EnforcementStats::default();
        for (_, counter) in counters {
            stats.allowed += counter.allow;
            stats.denied += counter.deny;
            stats.errors += counter.error;
        }
        Ok(stats)
    }

    async fn verify(
        &self,
        _zone: ZoneId,
        policy: &EnforcementPolicy,
    ) -> std::result::Result<VerifyReport, EnforcerError> {
        let mut discrepancies = Vec::new();

        let statuses = self.health_check().map_err(to_enforcer_error)?;
        for status in statuses {
            if !status.loaded || !status.attached {
                discrepancies.push(VerifyDiscrepancy {
                    kind: VerifyDiscrepancyKind::HookInactive,
                    rule: None,
                    message: format!("program {} is not loaded and attached", status.name),
                });
            }
        }

        let capabilities = self.capabilities();
        for rule in &policy.rules {
            if !capabilities.supports_rule(rule) {
                discrepancies.push(VerifyDiscrepancy {
                    kind: VerifyDiscrepancyKind::RuleUnsupported,
                    rule: Some(rule.id),
                    message: format!("rule {:?} is unsupported", rule.id),
                });
            }
        }

        Ok(VerifyReport {
            ok: discrepancies.is_empty(),
            discrepancies,
        })
    }

    fn capabilities(&self) -> Capabilities {
        Self::capabilities_static()
    }
}

fn to_enforcer_error(error: RauhaError) -> EnforcerError {
    match error {
        RauhaError::EbpfError { message, .. } => EnforcerError::Verifier(message),
        RauhaError::ZoneNotFound(name) => {
            EnforcerError::Verifier(format!("zone not found in Rauha metadata: {name}"))
        }
        RauhaError::BackendError(message) => EnforcerError::Verifier(message),
        other => EnforcerError::Verifier(other.to_string()),
    }
}
