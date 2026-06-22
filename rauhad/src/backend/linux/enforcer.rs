//! Adapter from Rauha's Linux eBPF implementation to `rauha-enforcer-api`.
//!
//! This is intentionally a wrapper around the existing in-repo eBPF manager and
//! BPF map helpers. It creates the enforcement seam first without moving the
//! kernel code or changing backend behavior.

use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::Mutex;
use std::sync::atomic::{AtomicU32, Ordering};

use rauha_common::error::{RauhaError, Result};
use rauha_common::zone::{ZonePolicy, ZoneType};
use rauha_enforcer_api::{
    Capabilities, EnforcementPolicy, EnforcementStats, EnforcerBackend, EnforcerError, EventStream,
    Hook, HookSet, VerifyDiscrepancy, VerifyDiscrepancyKind, VerifyReport, ZoneEnforcement,
    ZoneKind, ZoneRef,
};

use super::ebpf::EbpfManager;
use super::events;
use super::lock_backend;
use super::maps::{MapManager, enforcement_to_kernel};

pub(super) struct LinuxEnforcer {
    root: String,
    ebpf: Mutex<Option<EbpfManager>>,
    event_reader_cancel: Option<tokio_util::sync::CancellationToken>,
    event_tx: Option<tokio::sync::broadcast::Sender<rauha_evidence::FalseEvent>>,
    /// Name -> (kernel zone id, zone type) registry backing the name-keyed
    /// `EnforcerBackend` trait. `LinuxBackend` currently keeps its own
    /// name<->id map and drives this enforcer through the inherent (id-keyed)
    /// methods, so this registry is only exercised when `LinuxEnforcer` is used
    /// directly as an `EnforcerBackend` — the `linux_enforcer_passes_basic_conformance`
    /// test below, and the future migration where `LinuxBackend` consumes the
    /// trait and this becomes the single map.
    trait_zones: Mutex<HashMap<String, (u32, ZoneType)>>,
    trait_next_zone_id: AtomicU32,
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
            trait_zones: Mutex::new(HashMap::new()),
            trait_next_zone_id: AtomicU32::new(1),
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

    fn lock_ebpf(
        &self,
    ) -> std::result::Result<std::sync::MutexGuard<'_, Option<EbpfManager>>, EnforcerError> {
        self.ebpf
            .lock()
            .map_err(|_| EnforcerError::Verifier("linux enforcer mutex poisoned".into()))
    }

    fn lock_trait_zones(
        &self,
    ) -> std::result::Result<
        std::sync::MutexGuard<'_, HashMap<String, (u32, ZoneType)>>,
        EnforcerError,
    > {
        self.trait_zones
            .lock()
            .map_err(|_| EnforcerError::Verifier("linux enforcer zone registry poisoned".into()))
    }

    /// Map the seam's neutral zone classification onto Rauha's kernel zone type.
    fn zone_type_for(kind: ZoneKind) -> ZoneType {
        match kind {
            ZoneKind::Privileged => ZoneType::Privileged,
            ZoneKind::Standard | ZoneKind::Isolated => ZoneType::NonGlobal,
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
        let mut ebpf_guard = self.lock_ebpf()?;
        if ebpf_guard.is_some() {
            return Ok(());
        }
        let ebpf = Self::load_ebpf(&self.root).map_err(to_enforcer_error)?;
        *ebpf_guard = Some(ebpf);
        Ok(())
    }

    async fn shutdown(&self) -> std::result::Result<(), EnforcerError> {
        if let Some(ebpf) = self.lock_ebpf()?.take() {
            ebpf.cleanup();
        }
        self.lock_trait_zones()?.clear();
        Ok(())
    }

    async fn register_zone(
        &self,
        name: &str,
        policy: &EnforcementPolicy,
    ) -> std::result::Result<u32, EnforcerError> {
        if self.lock_ebpf()?.is_none() {
            return Err(EnforcerError::NotLoaded);
        }
        let zone_type = Self::zone_type_for(policy.zone.kind);
        let kernel_id = {
            let mut zones = self.lock_trait_zones()?;
            if let Some((id, kind)) = zones.get_mut(name) {
                *kind = zone_type;
                *id
            } else {
                let id = self.trait_next_zone_id.fetch_add(1, Ordering::SeqCst);
                zones.insert(name.to_string(), (id, zone_type));
                id
            }
        };
        self.apply_zone_enforcement(kernel_id, &policy.zone)
            .map_err(to_enforcer_error)?;
        Ok(kernel_id)
    }

    async fn remove_zone(
        &self,
        name: &str,
        _drain: bool,
    ) -> std::result::Result<(), EnforcerError> {
        if self.lock_ebpf()?.is_none() {
            return Err(EnforcerError::NotLoaded);
        }
        let id = self.lock_trait_zones()?.remove(name).map(|(id, _)| id);
        if let Some(id) = id {
            self.remove_zone_policy(id).map_err(to_enforcer_error)?;
        }
        Ok(())
    }

    async fn apply_policy(
        &self,
        zone: &ZoneRef,
        policy: &EnforcementPolicy,
    ) -> std::result::Result<(), EnforcerError> {
        if self.lock_ebpf()?.is_none() {
            return Err(EnforcerError::NotLoaded);
        }

        let capabilities = self.capabilities();
        for rule in &policy.rules {
            if !capabilities.supports_rule(rule) {
                return Err(EnforcerError::PolicyUnenforceable {
                    zone: zone.name.clone(),
                    rule: rule.id,
                    reason: format!("unsupported hook {:?}", rule.hook),
                });
            }
        }

        self.apply_zone_enforcement(zone.kernel_id, &policy.zone)
            .map_err(to_enforcer_error)
    }

    async fn attach_container(
        &self,
        zone: &ZoneRef,
        _container_id: &str,
        cgroup_id: u64,
    ) -> std::result::Result<(), EnforcerError> {
        let zone_type = self
            .lock_trait_zones()?
            .get(&zone.name)
            .map(|(_, t)| *t)
            .unwrap_or(ZoneType::NonGlobal);
        self.add_zone_member(cgroup_id, zone.kernel_id, zone_type)
            .map_err(to_enforcer_error)
    }

    async fn detach_container(
        &self,
        _container_id: &str,
        cgroup_id: u64,
    ) -> std::result::Result<(), EnforcerError> {
        self.remove_zone_member(cgroup_id)
            .map_err(to_enforcer_error)
    }

    async fn register_host_path(
        &self,
        zone: &ZoneRef,
        path: &str,
        _recursive: bool,
    ) -> std::result::Result<u32, EnforcerError> {
        // The eBPF backend always claims the full tree under `path` (the rootfs
        // case), so `recursive` is implied; a non-recursive single-inode claim
        // is not distinguished today.
        let inodes = super::maps::collect_rootfs_inodes(
            std::path::Path::new(path),
            rauha_ebpf_common::MAX_INODES,
        );
        let inserted = self
            .insert_inodes(&inodes, zone.kernel_id)
            .map_err(to_enforcer_error)?;
        Ok(inserted.len() as u32)
    }

    async fn allow_comm(&self, a: &ZoneRef, b: &ZoneRef) -> std::result::Result<(), EnforcerError> {
        self.allow_zone_comm(a.kernel_id, b.kernel_id)
            .map_err(to_enforcer_error)?;
        self.allow_zone_comm(b.kernel_id, a.kernel_id)
            .map_err(to_enforcer_error)
    }

    async fn deny_comm(&self, a: &ZoneRef, b: &ZoneRef) -> std::result::Result<(), EnforcerError> {
        self.deny_zone_comm(a.kernel_id, b.kernel_id)
            .map_err(to_enforcer_error)?;
        self.deny_zone_comm(b.kernel_id, a.kernel_id)
            .map_err(to_enforcer_error)
    }

    fn watch_events(&self) -> EventStream {
        // Current Rauha uses normalized evidence events over a broadcast sender.
        // The raw `EnforcementEvent` stream is reserved for the future Syva/API
        // adapter, so this wrapper returns an empty stream for now.
        let (_tx, rx) = tokio::sync::mpsc::channel(1);
        rx
    }

    async fn stats(&self, _zone: &ZoneRef) -> std::result::Result<EnforcementStats, EnforcerError> {
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
        _zone: &ZoneRef,
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

#[cfg(test)]
mod tests {
    use super::*;
    use rauha_enforcer_api::conformance;
    use std::sync::Arc;

    /// The Linux eBPF backend must satisfy the same `EnforcerBackend` contract
    /// as every other backend. This runs the shared conformance suite against a
    /// real `LinuxEnforcer`.
    ///
    /// It is explicitly opt-in because loading the in-repo eBPF backend touches
    /// global kernel state under `/sys/fs/bpf/rauha`. This must never happen as
    /// a side effect of ordinary `cargo test`.
    #[tokio::test]
    async fn linux_enforcer_passes_basic_conformance() {
        if std::env::var("RAUHA_RUN_EBPF_CONFORMANCE").as_deref() != Ok("1") {
            eprintln!(
                "skipping linux_enforcer_passes_basic_conformance: set \
                 RAUHA_RUN_EBPF_CONFORMANCE=1 on an isolated enforcement-capable Linux host"
            );
            return;
        }

        if bpf_pin_dir_has_entries()
            && std::env::var("RAUHA_EBPF_CONFORMANCE_OVERWRITE_PINS").as_deref() != Ok("1")
        {
            eprintln!(
                "skipping linux_enforcer_passes_basic_conformance: /sys/fs/bpf/rauha \
                 already contains pinned state; stop rauhad or set \
                 RAUHA_EBPF_CONFORMANCE_OVERWRITE_PINS=1 on an isolated test host"
            );
            return;
        }

        let root = tempfile::tempdir().expect("temp root");
        let enforcer = match LinuxEnforcer::new(root.path().to_str().expect("utf-8 root")) {
            Ok(enforcer) => enforcer,
            Err(e) => {
                eprintln!(
                    "skipping linux_enforcer_passes_basic_conformance: \
                     eBPF enforcement unavailable in this environment ({e})"
                );
                return;
            }
        };
        let enforcer = Arc::new(enforcer);

        let conformance_enforcer = Arc::clone(&enforcer);
        let result = tokio::spawn(async move {
            conformance::run_basic_conformance(conformance_enforcer.as_ref()).await;
        })
        .await;

        if let Err(e) = enforcer.shutdown().await {
            eprintln!("linux_enforcer_passes_basic_conformance cleanup failed: {e}");
        }

        match result {
            Ok(()) => {}
            Err(e) if e.is_panic() => std::panic::resume_unwind(e.into_panic()),
            Err(e) => panic!("conformance task failed: {e}"),
        }
    }

    fn bpf_pin_dir_has_entries() -> bool {
        let path = std::path::Path::new("/sys/fs/bpf/rauha");
        std::fs::read_dir(path)
            .map(|mut entries| entries.next().is_some())
            .unwrap_or(false)
    }
}
