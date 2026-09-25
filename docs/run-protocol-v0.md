# Run Protocol v0

Status: draft contract, 2026-08-27. Nothing here is implemented yet. The
purpose of this document is to fix the vocabulary and the invariants before
the tier-0 Rust supervisor, the OTP manager, and the tools that consume runs
(Ruuma, Kide, Ahti, Vartio) are built against them.

It builds on the *Run continuity* and *behaviour diff* sections of
[`positioning-and-roadmap.md`](positioning-and-roadmap.md) and uses their
words. Every invariant is numbered (`RP-n`) so that it can become one
conformance case executed against both supervisor implementations with the
same journals.

## 1. Vocabulary

| Term | Meaning |
|---|---|
| **Run** | The durable unit of agentic work: journal + head + artifacts + workspace lineage. The only truth. |
| **RunHead** | A CAS-controlled pointer to an immutable manifest of the Run's current state (see §5). |
| **Journal** | Append-only, hash-chained record of everything that happened to the Run (§3). |
| **Cell** | A replaceable materialization of a Run checkpoint: the zone, its workspace, its capability handles. A Cell may be destroyed and rebuilt at any time. |
| **Custodian** | The small trusted process beside the Cell (today: `rauhad` + `rauha-shim`). Owns the process/VM, capability handles, enforcement, freezing, and the fencing epoch. Present at every tier. |
| **Supervisor** | Owns the Run's lifecycle: reduces the journal into state, decides pause/resume/delegation, coordinates retries and humans. Rust in tier 0; OTP/Vartio remotely. |
| **Capability** | A brokered service outside the boundary (git, credentials/egress, services, proof gates, human, remote). The agent holds a handle, never the underlying secret. |
| **Effect** | An externally visible action performed through a capability (§6). |
| **Checkpoint** | A sealed journal prefix plus workspace snapshot from which a Cell can be materialized (§7). |
| **Receipt** | A signed seal of an immutable RunHead (`rauha.execution-receipt.v1` today; extended by this protocol). |
| **Epoch** | Monotonic ownership counter per Run, allocated by the custodian, carried by every effect (§5). |

One sentence: **the Run is truth, the Cell is cache, the supervisor is a
view, the custodian is the guard.**

Mapping to [`product-thesis.md`](product-thesis.md), which is the canonical
product vocabulary: the thesis's *local guardian* is this document's
**Custodian**; its *boundary-external witness* (False Agent) is §8's
**witness**; its effect outcomes `committed | failed | unknown` are the
journal's `succeeded | failed | uncertain` (§6); its *Zone* is the isolation
primitive inside a Cell and stays internal. Where the two disagree, the
thesis wins on product meaning and this document wins on wire format.

## 2. Lifecycle

```text
preparing → running → waiting → delegated → proving → review → accepted
                 ↘ frozen ↗                               ↘ discarded
```

| State | Meaning | Entered by |
|---|---|---|
| `preparing` | Run created; Cell being materialized; capabilities not yet granted. | `run.created` |
| `running` | Agent executing inside the Cell with granted capabilities. | `cell.ready`, `run.resumed` |
| `waiting` | Agent stopped on purpose: awaiting human input, an approval, a delegated child, or a lease renewal. | `run.waiting`, `run.frozen` |
| `frozen` | Custodian stopped the Cell (lease expired, disconnection, operator). Capabilities closed. Distinct from `waiting` because the agent did not choose it. | `run.frozen` |
| `delegated` | Control handed to one or more child Runs; parent resumes when they finish. | `run.delegated` |
| `proving` | Declared proof gates executing (tests, Kelpo, Sykli). | `proof.started` |
| `review` | Result awaiting a decision: code diff, behaviour diff, receipt. | `proof.finished` |
| `accepted` / `discarded` | Terminal. Workspace applied or dropped; Cell destroyed. | `run.accepted`, `run.discarded` |

- **RP-1** Every state transition is a journal event; the reducer never
  changes state without one.
- **RP-2** The reducer is a pure function `reduce(state, event) → state`,
  deterministic and total: an unknown event kind is recorded as
  `journal.unknown_event` and leaves the state unchanged, never panics.
- **RP-3** `accepted` and `discarded` are terminal; any further event except
  `receipt.sealed` and `journal.compacted` is a protocol error.
- **RP-4** `frozen` can only be entered by a custodian event, never by a
  supervisor event.

## 3. Journal

- Append-only file `journal.jsonl` in the Run directory; one JSON object per
  line; UTF-8; no in-place edits, ever.
- Each line carries `seq` (dense, starting at 1), `ts` (RFC 3339, custodian
  or supervisor clock — see RP-11), `kind`, `epoch`, `prev` (SHA-256 of the
  previous line's canonical form), `body`.
- Canonical form for hashing: JSON with keys sorted, no whitespace, `prev`
  included, `hash` excluded.

```json
{"seq":7,"ts":"2026-08-27T09:41:02Z","kind":"effect.requested","epoch":3,
 "prev":"sha256:…","body":{"effect_id":"e-91","capability":"git","op":"push",
 "args_sha256":"sha256:…"}}
```

- **RP-5** `seq` is dense and strictly increasing; a gap or duplicate is a
  corrupted journal and the Run is `frozen` until an operator resolves it.
- **RP-6** `prev` of line *n* equals the hash of line *n−1*; the first line's
  `prev` is the hash of the Run manifest (§4). Verification of the full chain
  is O(n) and requires no other file.
- **RP-7** Writers use append-then-fsync-then-advance-head; a line is not
  part of the Run until the RunHead references a `journal_root` that covers
  it.

### Event catalogue (v0)

| Kind | Emitted by | Body |
|---|---|---|
| `run.created` | supervisor | manifest hash, parent (if fork), agent, task |
| `supervisor.claimed` | custodian | `epoch`, supervisor id, lease seconds |
| `supervisor.released` | custodian | `epoch`, reason |
| `cell.materialized` / `cell.ready` / `cell.destroyed` | custodian | checkpoint id, zone id |
| `capability.granted` / `capability.revoked` | custodian | capability, grant id, scope |
| `effect.requested` … `effect.uncertain` | capability broker | see §6 |
| `run.waiting` / `run.resumed` / `run.frozen` | supervisor / custodian | reason, checkpoint id |
| `run.delegated` / `child.finished` | supervisor | child run ids |
| `checkpoint.sealed` | custodian | journal prefix hash, snapshot id |
| `proof.started` / `proof.finished` | supervisor | gate ids, outcomes, receipts |
| `witness.attached` / `witness.observation` / `witness.loss` | custodian | see §8 |
| `human.asked` / `human.answered` | supervisor | question id, actor |
| `run.accepted` / `run.discarded` | supervisor | decision actor, reason |
| `receipt.sealed` | custodian | receipt hash, signer |
| `journal.unknown_event` / `journal.compacted` | reducer / custodian | offending kind / new root |

Event kinds are namespaced `noun.verb`, lower-case, stable once published,
and mirror `rauha_evidence::event_name` conventions. New kinds may be added
in v0.x; kinds are never renamed or removed.

## 4. Run manifest and directory

```text
runs/<run-id>/
  manifest.json        immutable after run.created
  journal.jsonl        append-only (§3)
  head                 RunHead, replaced atomically (§5)
  checkpoints/<id>/    sealed prefix hash + workspace snapshot reference
  artifacts/           outputs referenced by hash
  receipts/            signed seals
```

`manifest.json` holds what the Run *is*: task text, agent command, image
digest, policy hash, workspace origin (repo, commit), declared proof gates,
requested capabilities, parent run and checkpoint if forked.

- **RP-8** The manifest is immutable; the first journal line's `prev` is its
  hash, so a manifest edit invalidates the whole chain.
- **RP-9** The Run directory is the complete contract between tiers: a
  tier-0 CLI, the OTP manager, Ruuma, and Ahti read the same files. No tier
  may depend on state that is not in the directory.

## 5. Ownership: custodian, supervisor, epoch, lease

The custodian is the fencing authority because it is the side that survives a
partition and holds the only real handles.

- **RP-10** Exactly one supervisor owns a Run at a time. Ownership is a
  `supervisor.claimed` event carrying a new `epoch`, allocated by the
  custodian, strictly greater than every previous epoch of that Run, and
  persisted in the journal before the supervisor learns it.
- **RP-11** The lease is measured on the custodian's clock. A supervisor that
  cannot renew is gone from the custodian's point of view; no coordination is
  needed during the partition.
- **RP-12** On lease expiry the custodian (a) revokes every capability grant
  (`capability.revoked`), (b) freezes the Cell — `cgroup.freeze` on Linux, VM
  pause in a future VM tier — (c) appends `run.frozen{reason: lease_expired}`. Order
  matters: no effect may slip out between (a) and (b).
- **RP-13** Every capability broker rejects an effect whose `epoch` is lower
  than the current claimed epoch. This is what stops a stale supervisor from
  using authority it already holds after a broken handoff.
- **RP-14** Adoption = new `supervisor.claimed` with a higher epoch, after the
  adopting supervisor has verified the RunHead and replayed the journal from
  the last checkpoint. Live OTP messages, UI streams, and observer
  notifications are hints; the head is verified before adopting, authorizing
  an effect, or sealing a receipt (*fast when healthy, correct when
  degraded*).
- **RP-15** The RunHead is replaced atomically (rename in tier 0, CAS in a
  remote store) and carries `previous_head`, `journal_root`, `sequence`,
  `ownership_epoch`, `checkpoint`, `workspace_snapshot`, `artifacts`,
  `policy`, `agent_session`. A head whose `ownership_epoch` is lower than the
  journal's latest `supervisor.claimed` is stale and must not be written.

## 6. Effects: effectively-once

An effect is any action through a capability that the outside world can see.

```text
requested → authorized → executing → succeeded | failed | uncertain
```

- **RP-16** Write-ahead: `effect.requested` and `effect.authorized` are in
  the journal *before* the broker performs the action; `effect.executing` is
  appended immediately before the provider call. A broker that cannot append
  must not execute.
- **RP-17** `authorized` is decided by the supervisor against the Run's
  grants and policy, and carries the epoch (RP-13). `requested` without
  `authorized` is a denied effect and is itself evidence.
- **RP-18** After recovery, an effect with `executing` but neither
  `succeeded` nor `failed` becomes `uncertain`. It is never replayed blindly.
  Resolution is one of: an idempotency key confirmed with the provider, a
  provider query, or a human decision — each journaled as
  `effect.reconciled{outcome}`.
- **RP-19** Preparation is not an effect: computing a diff, building a commit
  object, drafting a message may happen freely; the *publication* step
  (updating a ref, opening a PR, sending) is the effect.
- **RP-20** Infrastructure children (observers, proxies, brokers) restart
  automatically. The agent executor does not: on any restart of its
  supervisor or custodian it is frozen, enters `waiting`, and resumes only
  from a checkpoint via an explicit `run.resumed`.

## 7. Checkpoints and Cells

- **RP-21** A checkpoint seals a journal prefix hash and a workspace snapshot
  (`checkpoint.sealed`). The Cell can be destroyed after any checkpoint and
  rebuilt from it; TCP connections and half-executed instructions are not
  portable state and are never part of a checkpoint.
- **RP-22** Checkpoints bound replay cost; they never rewrite history. Every
  receipt that references an evidence chunk keeps that chunk retrievable.
- **RP-23** The recovery boundary is a committed checkpoint or an agent turn.
  Live migration may optimize the healthy path but is never the correctness
  mechanism.

## 8. Witness and completeness

- **RP-24** A result may be called *complete* only if `witness.attached` was
  journaled before the first `execve` of the agent in the Cell and every
  declared loss counter (`ringbuf.drop`, `pipeline.shed`, witness gaps) is
  zero at `proof.finished`. Otherwise the result carries
  `evidence_complete: false` and the reasons.
- **RP-25** Witness observations are facts about the Cell recorded by the
  custodian (process, file, network, capability activity, allowed and
  denied); the agent's own account is never an input to them.

## 9. Forks

- **RP-26** A fork is a new Run whose manifest references the parent's
  RunHead and a specific checkpoint. It inherits history (by reference, not
  by copy) and a workspace snapshot.
- **RP-27** A fork inherits **no authority**: no capability grants, no lease,
  no epoch. Grants are issued fresh to the child.
- **RP-28** A fork inherits no unresolved effects: an `uncertain` effect in
  the parent cannot be completed, reconciled, or claimed by the child.
- **RP-29** Two Runs with the same fork point are *comparable*; Ruuma's
  behaviour classes and `rauha compare` are defined over that relation.

## 10. Receipts

- **RP-30** A receipt seals an immutable RunHead: its hash, the journal root,
  the checkpoint, the policy hash, the enforcement totals, the loss counters,
  and `evidence_complete`. Signing is the custodian's job; supervisors and
  managers only verify.
- **RP-31** `digest_verified` (and any future "verified" flag) is true only
  when the corresponding verification actually ran for the artifact that
  executed (cf. `rauhad` `image_digest_pinned`).

## 11. Tiers

- **RP-32** Tier 0 (single binary, no network): immutable files, a
  single-writer lock, atomic head replacement, in-process Rust supervisor.
  All invariants above hold.
- **RP-33** The management addon adopts Runs through the same directory
  (RP-9) and the same events; it may move immutable objects to durable
  storage and update the head with CAS. The protocol does not change; only
  the storage does.
- **RP-34** Both supervisor implementations pass the same conformance suite:
  journals as inputs, expected states and expected refusals as outputs, plus
  seeded adoption races (DST style) for RP-10–RP-15.

## 12. Conformance case index

| Case | Invariants | Shape |
|---|---|---|
| `rp-lifecycle-*` | RP-1–RP-4 | journal → expected state; illegal transition → refusal |
| `rp-journal-*` | RP-5–RP-8 | tampered line / gap / edited manifest → verification failure |
| `rp-own-*` | RP-10–RP-15 | two supervisors, seeded interleavings → exactly one effect path survives; stale head write refused |
| `rp-effect-*` | RP-16–RP-20 | crash between `executing` and outcome → `uncertain`, no replay |
| `rp-fork-*` | RP-26–RP-29 | child attempts parent's grant / uncertain effect → refused |
| `rp-witness-*` | RP-24–RP-25 | late attach / nonzero loss → `evidence_complete: false` |
| `rp-tier-*` | RP-32–RP-34 | same journal, Rust and OTP reducers → identical state |

## Open questions (v0 → v0.1)

1. Clock: the journal's `ts` for supervisor-emitted events on a remote node
   vs. the custodian's clock — record both (`ts`, `custodian_ts`) or only the
   custodian's on ingestion?
2. Grant scoping vocabulary for capabilities (per-host allowlists for egress,
   per-ref for git) — shared with Tutka's authority map?
3. Whether `delegated` children live in the parent's Cell or their own; the
   protocol allows both, the first implementation should pick one.
4. Compaction (`journal.compacted`) semantics for very long runs without
   breaking RP-6 for old receipts.
