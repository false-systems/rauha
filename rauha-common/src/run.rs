//! Pure Run Protocol v0 lifecycle reduction (RP-1–RP-4).
//!
//! This checks lifecycle transitions only. The journal writer must authenticate
//! the emitter, validate event bodies and ownership, and persist events before
//! publishing the resulting state. No sandbox action is performed here.

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RunState {
    Preparing,
    Running,
    Waiting,
    Frozen,
    Delegated,
    Proving,
    Review,
    Accepted,
    Discarded,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Emitter {
    Supervisor,
    Custodian,
    Broker,
    Reducer,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Reduction {
    pub state: Option<RunState>,
    /// The caller must record `journal.unknown_event` with this offending kind.
    /// Already-recorded unknown-event markers do not generate another marker.
    pub unknown_event: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("Run protocol refuses {kind} from {emitter:?} in {state:?}")]
pub struct ProtocolError {
    pub state: Option<RunState>,
    pub kind: String,
    pub emitter: Emitter,
}

/// Reduce one event; `None` is the state before `run.created`.
/// Unknown kinds preserve state unless the Run is terminal (RP-3).
pub fn reduce(
    state: Option<RunState>,
    kind: &str,
    emitter: Emitter,
) -> Result<Reduction, ProtocolError> {
    use Emitter::*;
    use RunState::*;

    let refuse = || ProtocolError {
        state,
        kind: kind.to_owned(),
        emitter,
    };
    if matches!(state, Some(Accepted | Discarded))
        && !matches!(kind, "receipt.sealed" | "journal.compacted")
    {
        return Err(refuse());
    }

    // Keep the event catalogue explicit: a future event must be surfaced as
    // unknown, not silently accepted because it shares a namespace.
    let (source, next) = match kind {
        "run.created" if state.is_none() => (Supervisor, Some(Preparing)),
        "sandbox.ready" if state == Some(Preparing) => (Custodian, Some(Running)),
        "run.waiting" if state == Some(Running) => (Supervisor, Some(Waiting)),
        "run.resumed" if matches!(state, Some(Waiting | Frozen | Delegated)) => {
            (Supervisor, Some(Running))
        }
        "run.frozen"
            if matches!(
                state,
                Some(Preparing | Running | Waiting | Delegated | Proving)
            ) =>
        {
            (Custodian, Some(Frozen))
        }
        "run.delegated" if matches!(state, Some(Running | Waiting)) => {
            (Supervisor, Some(Delegated))
        }
        "proof.started" if matches!(state, Some(Running | Waiting | Delegated)) => {
            (Supervisor, Some(Proving))
        }
        "proof.finished" if state == Some(Proving) => (Supervisor, Some(Review)),
        "run.accepted" if state == Some(Review) => (Supervisor, Some(Accepted)),
        "run.discarded" if state.is_some() => (Supervisor, Some(Discarded)),
        "run.created" | "sandbox.ready" | "run.waiting" | "run.resumed" | "run.frozen"
        | "run.delegated" | "proof.started" | "proof.finished" | "run.accepted"
        | "run.discarded" => return Err(refuse()),
        "supervisor.claimed"
        | "supervisor.released"
        | "sandbox.materialized"
        | "sandbox.destroyed"
        | "capability.granted"
        | "capability.revoked"
        | "checkpoint.sealed"
        | "witness.attached"
        | "witness.observation"
        | "witness.loss"
        | "receipt.sealed"
        | "journal.compacted" => (Custodian, state),
        "effect.requested" | "effect.executing" | "effect.succeeded" | "effect.failed"
        | "effect.uncertain" | "effect.reconciled" => (Broker, state),
        "effect.authorized" | "child.finished" | "human.asked" | "human.answered" => {
            (Supervisor, state)
        }
        "journal.unknown_event" => (Reducer, state),
        _ => {
            return Ok(Reduction {
                state,
                unknown_event: Some(kind.to_owned()),
            });
        }
    };
    if emitter != source || (state.is_none() && kind != "run.created") {
        return Err(refuse());
    }
    Ok(Reduction {
        state: next,
        unknown_event: None,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use Emitter::*;
    use RunState::*;

    #[test]
    fn rp_lifecycle_replay_and_refusals() {
        let journal = [
            ("run.created", Supervisor, Preparing),
            ("sandbox.materialized", Custodian, Preparing),
            ("sandbox.ready", Custodian, Running),
            ("run.waiting", Supervisor, Waiting),
            ("run.delegated", Supervisor, Delegated),
            ("child.finished", Supervisor, Delegated),
            ("run.resumed", Supervisor, Running),
            ("run.frozen", Custodian, Frozen),
            ("run.resumed", Supervisor, Running),
            ("proof.started", Supervisor, Proving),
            ("proof.finished", Supervisor, Review),
            ("run.accepted", Supervisor, Accepted),
            ("receipt.sealed", Custodian, Accepted),
        ];
        for _ in 0..2 {
            let mut state = None;
            for (kind, emitter, expected) in journal {
                let result = reduce(state, kind, emitter).unwrap();
                assert_eq!(result.state, Some(expected));
                assert_eq!(result.unknown_event, None);
                state = result.state;
            }
        }

        for state in [
            Preparing, Running, Waiting, Frozen, Delegated, Proving, Review,
        ] {
            assert!(reduce(Some(state), "run.frozen", Supervisor).is_err());
            assert!(reduce(Some(state), "run.created", Supervisor).is_err());
            assert_eq!(
                reduce(Some(state), "run.discarded", Supervisor)
                    .unwrap()
                    .state,
                Some(Discarded)
            );
            let unknown = reduce(Some(state), "run.future", Supervisor).unwrap();
            assert_eq!(unknown.state, Some(state));
            assert_eq!(unknown.unknown_event.as_deref(), Some("run.future"));
            assert_eq!(
                reduce(Some(state), "journal.unknown_event", Reducer)
                    .unwrap()
                    .unknown_event,
                None
            );
        }
        for state in [Accepted, Discarded] {
            for (kind, emitter, _) in journal {
                if kind != "receipt.sealed" {
                    assert!(reduce(Some(state), kind, emitter).is_err(), "{kind}");
                }
            }
            assert!(reduce(Some(state), "run.future", Supervisor).is_err());
            for kind in ["receipt.sealed", "journal.compacted"] {
                assert_eq!(
                    reduce(Some(state), kind, Custodian).unwrap().state,
                    Some(state)
                );
                assert!(reduce(Some(state), kind, Supervisor).is_err());
            }
        }
        assert_eq!(
            reduce(Some(Delegated), "proof.started", Supervisor)
                .unwrap()
                .state,
            Some(Proving)
        );
        for (state, kind, emitter) in [
            (None, "sandbox.ready", Custodian),
            (None, "receipt.sealed", Custodian),
            (None, "run.created", Broker),
            (Some(Preparing), "sandbox.ready", Supervisor),
            (Some(Running), "run.accepted", Supervisor),
            (Some(Running), "proof.finished", Supervisor),
            (Some(Frozen), "proof.started", Supervisor),
            (Some(Frozen), "sandbox.ready", Custodian),
        ] {
            assert!(reduce(state, kind, emitter).is_err(), "{state:?}: {kind}");
        }
        assert_eq!(serde_json::to_string(&Frozen).unwrap(), "\"frozen\"");
    }
}
