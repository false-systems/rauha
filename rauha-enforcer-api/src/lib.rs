//! Enforcement backend boundary for Rauha.
//!
//! This crate intentionally has no eBPF or Syva dependencies. Rauha translates
//! its user-facing policy into these enforcement-facing types before calling an
//! implementation. Backends translate these types into their own control plane
//! or kernel state.

#![allow(async_fn_in_trait)]

use std::collections::{BTreeSet, HashSet};
use std::sync::Mutex;

use thiserror::Error;

#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
pub struct ZoneId(pub u64);

#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
pub struct RuleId(pub u64);

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
    #[error("zone not found: {0:?}")]
    ZoneNotFound(ZoneId),
    #[error("policy rule {rule:?} cannot be enforced for zone {zone:?}: {reason}")]
    PolicyUnenforceable {
        zone: ZoneId,
        rule: RuleId,
        reason: String,
    },
    #[error("verifier failed: {0}")]
    Verifier(String),
    #[error("kernel error: {0}")]
    Kernel(#[from] std::io::Error),
}

pub type EventStream = tokio::sync::mpsc::Receiver<EnforcementEvent>;

pub trait EnforcerBackend: Send + Sync {
    async fn load(&self) -> Result<(), EnforcerError>;
    async fn shutdown(&self) -> Result<(), EnforcerError>;
    async fn create_zone(&self, zone: ZoneId) -> Result<(), EnforcerError>;
    async fn delete_zone(&self, zone: ZoneId) -> Result<(), EnforcerError>;
    async fn apply_policy(
        &self,
        zone: ZoneId,
        policy: &EnforcementPolicy,
    ) -> Result<(), EnforcerError>;
    fn watch_events(&self) -> EventStream;
    async fn stats(&self, zone: ZoneId) -> Result<EnforcementStats, EnforcerError>;
    async fn verify(
        &self,
        zone: ZoneId,
        policy: &EnforcementPolicy,
    ) -> Result<VerifyReport, EnforcerError>;
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
/// but kernel-required rules are rejected instead of accepted silently.
#[derive(Debug, Default)]
pub struct NoopEnforcer {
    state: Mutex<NoopState>,
}

#[derive(Debug, Default)]
struct NoopState {
    loaded: bool,
    zones: HashSet<ZoneId>,
}

impl NoopEnforcer {
    pub fn new() -> Self {
        Self::default()
    }

    fn ensure_loaded(state: &NoopState) -> Result<(), EnforcerError> {
        if state.loaded {
            Ok(())
        } else {
            Err(EnforcerError::NotLoaded)
        }
    }

    fn ensure_zone(state: &NoopState, zone: ZoneId) -> Result<(), EnforcerError> {
        if state.zones.contains(&zone) {
            Ok(())
        } else {
            Err(EnforcerError::ZoneNotFound(zone))
        }
    }

    fn unsupported_rule(zone: ZoneId, rule: &EnforcementRule) -> EnforcerError {
        EnforcerError::PolicyUnenforceable {
            zone,
            rule: rule.id,
            reason: if rule.requires_kernel {
                "backend has no kernel enforcement".to_string()
            } else {
                format!("backend does not support hook {:?}", rule.hook)
            },
        }
    }
}

impl EnforcerBackend for NoopEnforcer {
    async fn load(&self) -> Result<(), EnforcerError> {
        let mut state = self.state.lock().expect("noop enforcer mutex poisoned");
        state.loaded = true;
        Ok(())
    }

    async fn shutdown(&self) -> Result<(), EnforcerError> {
        let mut state = self.state.lock().expect("noop enforcer mutex poisoned");
        state.loaded = false;
        state.zones.clear();
        Ok(())
    }

    async fn create_zone(&self, zone: ZoneId) -> Result<(), EnforcerError> {
        let mut state = self.state.lock().expect("noop enforcer mutex poisoned");
        Self::ensure_loaded(&state)?;
        state.zones.insert(zone);
        Ok(())
    }

    async fn delete_zone(&self, zone: ZoneId) -> Result<(), EnforcerError> {
        let mut state = self.state.lock().expect("noop enforcer mutex poisoned");
        Self::ensure_loaded(&state)?;
        if state.zones.remove(&zone) {
            Ok(())
        } else {
            Err(EnforcerError::ZoneNotFound(zone))
        }
    }

    async fn apply_policy(
        &self,
        zone: ZoneId,
        policy: &EnforcementPolicy,
    ) -> Result<(), EnforcerError> {
        let state = self.state.lock().expect("noop enforcer mutex poisoned");
        Self::ensure_loaded(&state)?;
        Self::ensure_zone(&state, zone)?;
        let capabilities = self.capabilities();
        // `policy.zone` flags are intentionally ignored: this backend has no
        // kernel enforcement and says so via `capabilities()`, so it neither
        // applies nor pretends to apply zone-wide flags. Kernel-required rules
        // are still rejected rather than silently accepted.
        for rule in &policy.rules {
            if !capabilities.supports_rule(rule) {
                return Err(Self::unsupported_rule(zone, rule));
            }
        }
        Ok(())
    }

    fn watch_events(&self) -> EventStream {
        let (_tx, rx) = tokio::sync::mpsc::channel(1);
        rx
    }

    async fn stats(&self, zone: ZoneId) -> Result<EnforcementStats, EnforcerError> {
        let state = self.state.lock().expect("noop enforcer mutex poisoned");
        Self::ensure_loaded(&state)?;
        Self::ensure_zone(&state, zone)?;
        Ok(EnforcementStats::default())
    }

    async fn verify(
        &self,
        zone: ZoneId,
        policy: &EnforcementPolicy,
    ) -> Result<VerifyReport, EnforcerError> {
        let state = self.state.lock().expect("noop enforcer mutex poisoned");
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
        if !state.zones.contains(&zone) {
            return Ok(VerifyReport {
                ok: false,
                discrepancies: vec![VerifyDiscrepancy {
                    kind: VerifyDiscrepancyKind::ZoneMissing,
                    rule: None,
                    message: format!("zone {:?} is not registered", zone),
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

    /// Minimal behavioral contract for all backends.
    pub async fn run_basic_conformance<B: EnforcerBackend>(backend: &B) {
        let zone = ZoneId(7);
        backend.load().await.expect("load backend");
        backend.create_zone(zone).await.expect("create zone");
        backend
            .apply_policy(zone, &EnforcementPolicy::default())
            .await
            .expect("empty policy is enforceable");
        backend
            .stats(zone)
            .await
            .expect("stats for registered zone");
        let report = backend
            .verify(zone, &EnforcementPolicy::default())
            .await
            .expect("verify registered zone");
        assert!(report.ok, "empty policy should verify cleanly: {report:?}");
        backend.delete_zone(zone).await.expect("delete zone");
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

    #[tokio::test]
    async fn noop_rejects_kernel_required_policy() {
        let enforcer = NoopEnforcer::new();
        let zone = ZoneId(1);
        enforcer.load().await.unwrap();
        enforcer.create_zone(zone).await.unwrap();

        let err = enforcer
            .apply_policy(
                zone,
                &EnforcementPolicy {
                    rules: vec![kernel_rule()],
                    ..Default::default()
                },
            )
            .await
            .unwrap_err();

        assert!(matches!(
            err,
            EnforcerError::PolicyUnenforceable {
                zone: ZoneId(1),
                rule: RuleId(1),
                ..
            }
        ));
    }

    #[tokio::test]
    async fn noop_verify_reports_unsupported_rules() {
        let enforcer = NoopEnforcer::new();
        let zone = ZoneId(1);
        enforcer.load().await.unwrap();
        enforcer.create_zone(zone).await.unwrap();

        let report = enforcer
            .verify(
                zone,
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
        let err = enforcer.create_zone(ZoneId(1)).await.unwrap_err();
        assert!(matches!(err, EnforcerError::NotLoaded));
    }

    #[test]
    fn zone_enforcement_default_is_most_restrictive() {
        let z = ZoneEnforcement::default();
        assert_eq!(z.caps_mask, 0);
        assert!(!z.allow_ptrace);
        assert!(!z.allow_host_net);
    }

    #[test]
    fn enforcement_policy_carries_zone_state() {
        let policy = EnforcementPolicy {
            zone: ZoneEnforcement {
                caps_mask: 0b101,
                allow_ptrace: true,
                allow_host_net: false,
            },
            rules: Vec::new(),
        };
        assert_eq!(policy.zone.caps_mask, 0b101);
        assert!(policy.zone.allow_ptrace);
        // Default policy keeps the restrictive zone baseline.
        assert_eq!(EnforcementPolicy::default().zone, ZoneEnforcement::default());
    }

    #[tokio::test]
    async fn noop_accepts_zone_flags_without_enforcing_them() {
        // The noop has no kernel; it must not error on zone-wide flags, but it
        // also does not claim to enforce them (see `capabilities()`).
        let enforcer = NoopEnforcer::new();
        let zone = ZoneId(1);
        enforcer.load().await.unwrap();
        enforcer.create_zone(zone).await.unwrap();
        let policy = EnforcementPolicy {
            zone: ZoneEnforcement {
                caps_mask: 0xff,
                allow_ptrace: true,
                allow_host_net: true,
            },
            rules: Vec::new(),
        };
        enforcer.apply_policy(zone, &policy).await.unwrap();
        assert!(!enforcer.capabilities().kernel_enforcement);
    }
}
