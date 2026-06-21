//! Enforcement backend boundary for Rauha.
//!
//! This crate intentionally has no eBPF or Syva dependencies. Rauha translates
//! its user-facing policy into these enforcement-facing types before calling an
//! implementation. Backends translate these types into their own control plane
//! or kernel state.

#![allow(async_fn_in_trait)]

use std::collections::{BTreeSet, HashMap};
use std::sync::{Mutex, MutexGuard};

use thiserror::Error;

/// Raw kernel-side zone id, as it appears in enforcement events.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
pub struct ZoneId(pub u64);

#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
pub struct RuleId(pub u64);

/// A handle to a zone the backend already knows about.
///
/// Carries both the stable `name` (the handle name-keyed backends like Syva
/// use) and the compact `kernel_id` (the BPF map key the in-repo eBPF backend
/// uses). Each backend keys on whichever it needs; callers obtain the
/// `kernel_id` from [`EnforcerBackend::register_zone`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ZoneRef {
    pub name: String,
    pub kernel_id: u32,
}

impl ZoneRef {
    pub fn new(name: impl Into<String>, kernel_id: u32) -> Self {
        Self {
            name: name.into(),
            kernel_id,
        }
    }
}

/// Zone classification in the seam's neutral vocabulary. `Standard` is the
/// default isolated zone; `Privileged` is granted elevated capability; the
/// backend maps this onto its own zone-type representation.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum ZoneKind {
    #[default]
    Standard,
    Privileged,
    Isolated,
}

/// Full replacement policy for one enforcement zone.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct EnforcementPolicy {
    /// Zone-wide enforcement state (capability allow-mask + coarse allow bits).
    /// This is the seam's own neutral vocabulary: Rauha translates its
    /// user-facing `ZonePolicy` into this before crossing the boundary, and
    /// backends translate it into kernel/control-plane state. Defaults to the
    /// most restrictive state (no capabilities, nothing allowed).
    pub zone: ZoneEnforcement,
    /// Fine-grained per-hook rules. Kept deliberately small for now; the
    /// zone-wide flags above carry the policy that today's Linux adapter
    /// actually enforces.
    pub rules: Vec<EnforcementRule>,
}

/// Zone-wide enforcement state in the seam's own vocabulary.
///
/// This deliberately mirrors the *meaning* of a kernel zone-policy record
/// without importing Rauha or eBPF types: a capability allow-mask plus coarse
/// allow bits. Backends map these onto their native representation (e.g. the
/// Linux adapter maps them onto `ZonePolicyKernel` flag bits). The `Default`
/// is the most restrictive state, matching a zeroed kernel policy record.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct ZoneEnforcement {
    /// Bitmask of Linux capabilities the zone is permitted to use.
    pub caps_mask: u64,
    /// Whether ptrace inside the zone is permitted.
    pub allow_ptrace: bool,
    /// Whether the zone may use host networking.
    pub allow_host_net: bool,
    /// Zone classification. Set at registration; backends that record a
    /// per-zone type (e.g. the eBPF membership map) read it from here.
    pub kind: ZoneKind,
}

/// One kernel/enforcer-facing rule.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EnforcementRule {
    pub id: RuleId,
    pub hook: Hook,
    pub matcher: Matcher,
    pub decision: Decision,
    /// True when the rule requires syscall/LSM-class enforcement. Backends that
    /// cannot provide kernel enforcement must reject these rules, not silently
    /// accept them.
    pub requires_kernel: bool,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Decision {
    Allow,
    Deny,
}

/// Enforcement hook vocabulary. This is not a Rauha policy type.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Hook {
    FileOpen,
    BprmCheck,
    SocketConnect,
    PtraceAccess,
    Signal,
    CgroupAttach,
}

/// Kernel-evaluable predicate payload.
///
/// PR 1 keeps this deliberately small. Linux/Syva adapters can refine the raw
/// payload into their native policy representation without leaking those
/// details into Rauha's user-facing policy model.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Matcher {
    Any,
    Raw(Vec<u8>),
}

/// Raw enforcement event. Rauha projects this into `rauha-evidence`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EnforcementEvent {
    pub zone: ZoneId,
    pub rule: RuleId,
    pub hook: Hook,
    pub decision: Decision,
    pub pid: u32,
    pub ts_ns: u64,
    pub target: Vec<u8>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Capabilities {
    pub kernel_enforcement: bool,
    pub hooks: HookSet,
    pub event_stream: bool,
    pub counters: bool,
}

impl Capabilities {
    pub fn noop() -> Self {
        Self {
            kernel_enforcement: false,
            hooks: HookSet::none(),
            event_stream: false,
            counters: false,
        }
    }

    pub fn supports_rule(&self, rule: &EnforcementRule) -> bool {
        if rule.requires_kernel && !self.kernel_enforcement {
            return false;
        }
        self.hooks.contains(rule.hook)
    }
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct HookSet {
    hooks: BTreeSet<Hook>,
}

impl HookSet {
    pub fn none() -> Self {
        Self {
            hooks: BTreeSet::new(),
        }
    }

    pub fn from_hooks(hooks: impl IntoIterator<Item = Hook>) -> Self {
        Self {
            hooks: hooks.into_iter().collect(),
        }
    }

    pub fn contains(&self, hook: Hook) -> bool {
        self.hooks.contains(&hook)
    }

    pub fn iter(&self) -> impl Iterator<Item = Hook> + '_ {
        self.hooks.iter().copied()
    }
}

#[derive(Debug, Error)]
pub enum EnforcerError {
    #[error("enforcer is not loaded")]
    NotLoaded,
    #[error("zone not found: {0}")]
    ZoneNotFound(String),
    #[error("policy rule {rule:?} cannot be enforced for zone {zone}: {reason}")]
    PolicyUnenforceable {
        zone: String,
        rule: RuleId,
        reason: String,
    },
    #[error("verifier failed: {0}")]
    Verifier(String),
    #[error("kernel error: {0}")]
    Kernel(#[from] std::io::Error),
}

pub type EventStream = tokio::sync::mpsc::Receiver<EnforcementEvent>;

/// The complete enforcement boundary for Rauha.
///
/// Rauha (the zone/sandbox runtime product) owns user-facing lifecycle and
/// policy; everything kernel-enforcement related crosses this trait. The
/// in-repo eBPF backend implements it today; an external Syva backend
/// (`syva.core.v1` over a Unix socket) is a drop-in implementation. The trait
/// is name-keyed because that is the stable handle both backends share —
/// `register_zone` returns the compact kernel id callers carry in [`ZoneRef`].
pub trait EnforcerBackend: Send + Sync {
    /// Bring the enforcer up (load programs / connect to the control plane).
    async fn load(&self) -> Result<(), EnforcerError>;
    /// Tear the enforcer down and release its state.
    async fn shutdown(&self) -> Result<(), EnforcerError>;

    /// Register a zone by name with its policy. Returns the compact kernel
    /// zone id the backend assigned, which the caller keeps for [`ZoneRef`].
    async fn register_zone(
        &self,
        name: &str,
        policy: &EnforcementPolicy,
    ) -> Result<u32, EnforcerError>;
    /// Remove a zone. `drain` evicts any still-attached containers; without it
    /// the backend may refuse while containers remain.
    async fn remove_zone(&self, name: &str, drain: bool) -> Result<(), EnforcerError>;
    /// Replace a zone's policy.
    async fn apply_policy(
        &self,
        zone: &ZoneRef,
        policy: &EnforcementPolicy,
    ) -> Result<(), EnforcerError>;

    /// Make a container a member of a zone so enforcement applies to its
    /// cgroup. The caller resolves `cgroup_id` itself.
    async fn attach_container(
        &self,
        zone: &ZoneRef,
        container_id: &str,
        cgroup_id: u64,
    ) -> Result<(), EnforcerError>;
    /// Remove a container from zone membership.
    async fn detach_container(
        &self,
        container_id: &str,
        cgroup_id: u64,
    ) -> Result<(), EnforcerError>;

    /// Register filesystem ownership for a zone, claiming the objects under
    /// `path`. Returns the number of filesystem objects (inodes) claimed.
    async fn register_host_path(
        &self,
        zone: &ZoneRef,
        path: &str,
        recursive: bool,
    ) -> Result<u32, EnforcerError>;

    /// Permit cross-zone communication between two zones (symmetric).
    async fn allow_comm(&self, a: &ZoneRef, b: &ZoneRef) -> Result<(), EnforcerError>;
    /// Revoke cross-zone communication between two zones (symmetric).
    async fn deny_comm(&self, a: &ZoneRef, b: &ZoneRef) -> Result<(), EnforcerError>;

    /// Subscribe to raw enforcement (deny) events.
    fn watch_events(&self) -> EventStream;
    /// Read enforcement counters for a zone.
    async fn stats(&self, zone: &ZoneRef) -> Result<EnforcementStats, EnforcerError>;
    /// Drift/parity self-check: does the backend's loaded state for the zone
    /// match the intended policy?
    async fn verify(
        &self,
        zone: &ZoneRef,
        policy: &EnforcementPolicy,
    ) -> Result<VerifyReport, EnforcerError>;
    /// What this backend can actually enforce.
    fn capabilities(&self) -> Capabilities;
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct EnforcementStats {
    pub allowed: u64,
    pub denied: u64,
    pub errors: u64,
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct VerifyReport {
    pub ok: bool,
    pub discrepancies: Vec<VerifyDiscrepancy>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VerifyDiscrepancy {
    pub kind: VerifyDiscrepancyKind,
    pub rule: Option<RuleId>,
    pub message: String,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum VerifyDiscrepancyKind {
    ZoneMissing,
    PolicyMissing,
    PolicyMismatch,
    RuleUnsupported,
    HookInactive,
    EventStreamUnhealthy,
    CounterUnhealthy,
    BackendUnloaded,
}

/// Backend with no kernel enforcement. It is honest: empty policies are fine,
/// but kernel-required rules are rejected instead of accepted silently. It
/// tracks zones and membership in memory so it satisfies the full boundary
/// contract (and the conformance suite) without ever touching a kernel.
#[derive(Debug, Default)]
pub struct NoopEnforcer {
    state: Mutex<NoopState>,
}

#[derive(Debug, Default)]
struct NoopState {
    loaded: bool,
    next_id: u32,
    /// zone name -> zone record
    zones: HashMap<String, NoopZone>,
    /// container id -> zone name
    members: HashMap<String, String>,
}

#[derive(Debug)]
struct NoopZone {
    kernel_id: u32,
    /// Recorded for fidelity with real backends; the noop never enforces it.
    #[allow(dead_code)]
    kind: ZoneKind,
}

impl NoopEnforcer {
    pub fn new() -> Self {
        Self::default()
    }

    fn lock(&self) -> MutexGuard<'_, NoopState> {
        self.state.lock().expect("noop enforcer mutex poisoned")
    }

    fn ensure_loaded(state: &NoopState) -> Result<(), EnforcerError> {
        if state.loaded {
            Ok(())
        } else {
            Err(EnforcerError::NotLoaded)
        }
    }

    fn ensure_zone(state: &NoopState, name: &str) -> Result<(), EnforcerError> {
        if state.zones.contains_key(name) {
            Ok(())
        } else {
            Err(EnforcerError::ZoneNotFound(name.to_string()))
        }
    }

    /// A backend with no kernel enforcement must reject any rule it cannot
    /// enforce rather than silently accept it.
    fn reject_unenforceable(
        name: &str,
        policy: &EnforcementPolicy,
        caps: &Capabilities,
    ) -> Result<(), EnforcerError> {
        for rule in &policy.rules {
            if !caps.supports_rule(rule) {
                return Err(EnforcerError::PolicyUnenforceable {
                    zone: name.to_string(),
                    rule: rule.id,
                    reason: if rule.requires_kernel {
                        "backend has no kernel enforcement".to_string()
                    } else {
                        format!("backend does not support hook {:?}", rule.hook)
                    },
                });
            }
        }
        Ok(())
    }
}

impl EnforcerBackend for NoopEnforcer {
    async fn load(&self) -> Result<(), EnforcerError> {
        self.lock().loaded = true;
        Ok(())
    }

    async fn shutdown(&self) -> Result<(), EnforcerError> {
        let mut state = self.lock();
        state.loaded = false;
        state.zones.clear();
        state.members.clear();
        Ok(())
    }

    async fn register_zone(
        &self,
        name: &str,
        policy: &EnforcementPolicy,
    ) -> Result<u32, EnforcerError> {
        let mut state = self.lock();
        Self::ensure_loaded(&state)?;
        Self::reject_unenforceable(name, policy, &self.capabilities())?;
        if let Some(zone) = state.zones.get_mut(name) {
            zone.kind = policy.zone.kind;
            return Ok(zone.kernel_id);
        }
        state.next_id += 1;
        let kernel_id = state.next_id;
        state.zones.insert(
            name.to_string(),
            NoopZone {
                kernel_id,
                kind: policy.zone.kind,
            },
        );
        Ok(kernel_id)
    }

    async fn remove_zone(&self, name: &str, drain: bool) -> Result<(), EnforcerError> {
        let mut state = self.lock();
        Self::ensure_loaded(&state)?;
        Self::ensure_zone(&state, name)?;
        let has_members = state.members.values().any(|z| z == name);
        if has_members && !drain {
            return Err(EnforcerError::Verifier(format!(
                "zone {name} still has attached containers (pass drain=true)"
            )));
        }
        state.members.retain(|_, z| z != name);
        state.zones.remove(name);
        Ok(())
    }

    async fn apply_policy(
        &self,
        zone: &ZoneRef,
        policy: &EnforcementPolicy,
    ) -> Result<(), EnforcerError> {
        let state = self.lock();
        Self::ensure_loaded(&state)?;
        Self::ensure_zone(&state, &zone.name)?;
        // `policy.zone` flags are intentionally ignored: this backend has no
        // kernel enforcement and says so via `capabilities()`. Kernel-required
        // rules are still rejected rather than silently accepted.
        Self::reject_unenforceable(&zone.name, policy, &self.capabilities())
    }

    async fn attach_container(
        &self,
        zone: &ZoneRef,
        container_id: &str,
        _cgroup_id: u64,
    ) -> Result<(), EnforcerError> {
        let mut state = self.lock();
        Self::ensure_loaded(&state)?;
        Self::ensure_zone(&state, &zone.name)?;
        state
            .members
            .insert(container_id.to_string(), zone.name.clone());
        Ok(())
    }

    async fn detach_container(
        &self,
        container_id: &str,
        _cgroup_id: u64,
    ) -> Result<(), EnforcerError> {
        let mut state = self.lock();
        Self::ensure_loaded(&state)?;
        // Idempotent: detaching an unknown container is not an error.
        state.members.remove(container_id);
        Ok(())
    }

    async fn register_host_path(
        &self,
        zone: &ZoneRef,
        _path: &str,
        _recursive: bool,
    ) -> Result<u32, EnforcerError> {
        let state = self.lock();
        Self::ensure_loaded(&state)?;
        Self::ensure_zone(&state, &zone.name)?;
        // No kernel: this backend claims no filesystem ownership.
        Ok(0)
    }

    async fn allow_comm(&self, a: &ZoneRef, b: &ZoneRef) -> Result<(), EnforcerError> {
        let state = self.lock();
        Self::ensure_loaded(&state)?;
        Self::ensure_zone(&state, &a.name)?;
        Self::ensure_zone(&state, &b.name)?;
        Ok(())
    }

    async fn deny_comm(&self, a: &ZoneRef, b: &ZoneRef) -> Result<(), EnforcerError> {
        let state = self.lock();
        Self::ensure_loaded(&state)?;
        Self::ensure_zone(&state, &a.name)?;
        Self::ensure_zone(&state, &b.name)?;
        Ok(())
    }

    fn watch_events(&self) -> EventStream {
        let (_tx, rx) = tokio::sync::mpsc::channel(1);
        rx
    }

    async fn stats(&self, zone: &ZoneRef) -> Result<EnforcementStats, EnforcerError> {
        let state = self.lock();
        Self::ensure_loaded(&state)?;
        Self::ensure_zone(&state, &zone.name)?;
        Ok(EnforcementStats::default())
    }

    async fn verify(
        &self,
        zone: &ZoneRef,
        policy: &EnforcementPolicy,
    ) -> Result<VerifyReport, EnforcerError> {
        let state = self.lock();
        if !state.loaded {
            return Ok(VerifyReport {
                ok: false,
                discrepancies: vec![VerifyDiscrepancy {
                    kind: VerifyDiscrepancyKind::BackendUnloaded,
                    rule: None,
                    message: "noop enforcer is not loaded".to_string(),
                }],
            });
        }
        if !state.zones.contains_key(&zone.name) {
            return Ok(VerifyReport {
                ok: false,
                discrepancies: vec![VerifyDiscrepancy {
                    kind: VerifyDiscrepancyKind::ZoneMissing,
                    rule: None,
                    message: format!("zone {} is not registered", zone.name),
                }],
            });
        }

        let capabilities = self.capabilities();
        let discrepancies: Vec<_> = policy
            .rules
            .iter()
            .filter(|rule| !capabilities.supports_rule(rule))
            .map(|rule| VerifyDiscrepancy {
                kind: VerifyDiscrepancyKind::RuleUnsupported,
                rule: Some(rule.id),
                message: format!("rule {:?} is unsupported by noop enforcer", rule.id),
            })
            .collect();

        Ok(VerifyReport {
            ok: discrepancies.is_empty(),
            discrepancies,
        })
    }

    fn capabilities(&self) -> Capabilities {
        Capabilities::noop()
    }
}

pub mod conformance {
    use super::*;

    /// Minimal behavioral contract every backend must satisfy: the full zone
    /// lifecycle, container membership, filesystem ownership, and observability
    /// round-trip with an empty (enforceable) policy.
    pub async fn run_basic_conformance<B: EnforcerBackend>(backend: &B) {
        backend.load().await.expect("load backend");

        let kernel_id = backend
            .register_zone("zone-7", &EnforcementPolicy::default())
            .await
            .expect("register zone");
        let zone = ZoneRef::new("zone-7", kernel_id);

        backend
            .apply_policy(&zone, &EnforcementPolicy::default())
            .await
            .expect("empty policy is enforceable");
        backend
            .attach_container(&zone, "container-1", 4242)
            .await
            .expect("attach container");
        backend
            .register_host_path(&zone, "/zones/zone-7/rootfs", true)
            .await
            .expect("register host path");
        backend.stats(&zone).await.expect("stats for registered zone");

        let report = backend
            .verify(&zone, &EnforcementPolicy::default())
            .await
            .expect("verify registered zone");
        assert!(report.ok, "empty policy should verify cleanly: {report:?}");

        backend
            .detach_container("container-1", 4242)
            .await
            .expect("detach container");
        backend
            .remove_zone("zone-7", true)
            .await
            .expect("remove zone");
        backend.shutdown().await.expect("shutdown backend");
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn kernel_rule() -> EnforcementRule {
        EnforcementRule {
            id: RuleId(1),
            hook: Hook::BprmCheck,
            matcher: Matcher::Any,
            decision: Decision::Deny,
            requires_kernel: true,
        }
    }

    #[tokio::test]
    async fn noop_passes_basic_conformance() {
        conformance::run_basic_conformance(&NoopEnforcer::new()).await;
    }

    async fn loaded_noop_with_zone(name: &str) -> (NoopEnforcer, ZoneRef) {
        let enforcer = NoopEnforcer::new();
        enforcer.load().await.unwrap();
        let id = enforcer
            .register_zone(name, &EnforcementPolicy::default())
            .await
            .unwrap();
        let zone = ZoneRef::new(name, id);
        (enforcer, zone)
    }

    #[tokio::test]
    async fn noop_rejects_kernel_required_policy() {
        let (enforcer, zone) = loaded_noop_with_zone("z").await;

        let err = enforcer
            .apply_policy(
                &zone,
                &EnforcementPolicy {
                    rules: vec![kernel_rule()],
                    ..Default::default()
                },
            )
            .await
            .unwrap_err();

        match err {
            EnforcerError::PolicyUnenforceable { zone, rule, .. } => {
                assert_eq!(zone, "z");
                assert_eq!(rule, RuleId(1));
            }
            other => panic!("expected PolicyUnenforceable, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn noop_verify_reports_unsupported_rules() {
        let (enforcer, zone) = loaded_noop_with_zone("z").await;

        let report = enforcer
            .verify(
                &zone,
                &EnforcementPolicy {
                    rules: vec![kernel_rule()],
                    ..Default::default()
                },
            )
            .await
            .unwrap();

        assert!(!report.ok);
        assert_eq!(report.discrepancies.len(), 1);
        assert_eq!(
            report.discrepancies[0].kind,
            VerifyDiscrepancyKind::RuleUnsupported
        );
        assert_eq!(report.discrepancies[0].rule, Some(RuleId(1)));
    }

    #[tokio::test]
    async fn noop_requires_load_before_zone_operations() {
        let enforcer = NoopEnforcer::new();
        let err = enforcer
            .register_zone("z", &EnforcementPolicy::default())
            .await
            .unwrap_err();
        assert!(matches!(err, EnforcerError::NotLoaded));
    }

    #[tokio::test]
    async fn noop_remove_zone_blocks_on_members_without_drain() {
        let (enforcer, zone) = loaded_noop_with_zone("z").await;
        enforcer
            .attach_container(&zone, "c1", 1)
            .await
            .unwrap();

        // Members present and drain=false -> refused.
        assert!(enforcer.remove_zone("z", false).await.is_err());
        // drain=true evicts members and removes the zone.
        enforcer.remove_zone("z", true).await.unwrap();
        // Zone is gone: operations against it now fail.
        assert!(matches!(
            enforcer.stats(&zone).await.unwrap_err(),
            EnforcerError::ZoneNotFound(_)
        ));
    }

    #[test]
    fn zone_enforcement_default_is_most_restrictive() {
        let z = ZoneEnforcement::default();
        assert_eq!(z.caps_mask, 0);
        assert!(!z.allow_ptrace);
        assert!(!z.allow_host_net);
        assert_eq!(z.kind, ZoneKind::Standard);
    }

    #[test]
    fn enforcement_policy_carries_zone_state() {
        let policy = EnforcementPolicy {
            zone: ZoneEnforcement {
                caps_mask: 0b101,
                allow_ptrace: true,
                allow_host_net: false,
                kind: ZoneKind::Privileged,
            },
            rules: Vec::new(),
        };
        assert_eq!(policy.zone.caps_mask, 0b101);
        assert!(policy.zone.allow_ptrace);
        assert_eq!(policy.zone.kind, ZoneKind::Privileged);
        // Default policy keeps the restrictive zone baseline.
        assert_eq!(EnforcementPolicy::default().zone, ZoneEnforcement::default());
    }

    #[tokio::test]
    async fn noop_accepts_zone_flags_without_enforcing_them() {
        // The noop has no kernel; it must not error on zone-wide flags, but it
        // also does not claim to enforce them (see `capabilities()`).
        let (enforcer, zone) = loaded_noop_with_zone("z").await;
        let policy = EnforcementPolicy {
            zone: ZoneEnforcement {
                caps_mask: 0xff,
                allow_ptrace: true,
                allow_host_net: true,
                kind: ZoneKind::Privileged,
            },
            rules: Vec::new(),
        };
        enforcer.apply_policy(&zone, &policy).await.unwrap();
        assert!(!enforcer.capabilities().kernel_enforcement);
    }
}
