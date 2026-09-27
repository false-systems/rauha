# rauha-cp: the service that manages Rauha

Design (2026-09-26). `rauha-cp` is the fleet layer above `rauhad`: node
registry, policy distribution, evidence aggregation, run registry, placement.
It implements the invariants of `run-protocol-v0.md` and
`isolation-foundations.md` at fleet scale. Status markers: **shipped /
planned / open**.

> Position sentence: **the cp is the librarian and the dispatcher — it owns
> intent and history; the nodes own truth and force. It is built so you can
> unplug it in front of a customer without flinching.**

## Engineering concepts (borrowed, with provenance)

Nothing here is invented where a proven pattern exists. Novelty is spent
only where it is the product (see "The magic").

| Pattern | Provenance | Use here |
|---|---|---|
| thin control plane, fat autonomous agents, works-offline | Tailscale | rauhad enforces and records with the cp gone |
| level-triggered reconcile, idempotent desired state | Kubernetes controllers | policy/zone reconciliation without etcd in v0-v2 |
| content-addressed truth, append-only history | git; Run Protocol tier-zero | evidence CAS, run heads, policy versions |
| embedded single-writer state, zero ops | SQLite-generation tooling | redb/sqlite-class store inside the cp binary |
| library + daemon + shims, one binary many modes | containerd | `rauha dev` / `rauha-cp serve` / operator mode |
| crash-only design, state on disk | the rauhad kill -9 story | cp restarts are non-events; nodes never notice |
| level vs. event split (intent store vs. event pipeline) | kube-apiserver internals | CRDs for intent, gRPC→CAS for truth |
| verifiable health, not heartbeats | `rauha zone verify` | node liveness = capability card freshness |

## Principles

1. **The cp is never the boundary.** Enforcement, admission, and evidence
   signing live on nodes. A dead cp costs orchestration, never containment.
2. **Compartmentalize to the bone.** Each compartment below is independently
   testable, has its own failure mode, and its own honesty accounting.
3. **Lean and fast, with budgets**: one static binary, all modes; startup
   < 1s; resident memory < 50MB at dev scale; no external database required
   in any mode (filesystem CAS + embedded store; S3 optional).
4. **Novelty only where it is the product.** Everything else is boring,
   proven technology arranged for repairability.
5. **Never hardcode.** Every value that could differ between hosts — paths,
   addresses, subnets, DNS, binary locations, capacities, timeouts, caps —
   is config with a default, from one schema (`rauha.toml` + env overrides
   for CI), never a scattered constant. The test: *if it would differ on
   another machine, it is config.* Exactly two exemptions, both deliberate:
   **security invariants** (enrollment order, fail-closed, admission-local)
   are hardcoded by design and documented as invariants, not settings; and
   named physical constants. Anything else found as a magic literal in code
   is a bug. Capability cards are this principle at fleet scale: even what
   a node *is* is discovered, not assumed.

## Compartments

Each compartment states: owns / provides / never does / failure mode.

| # | Compartment | Owns | Never does | Failure mode |
|---|---|---|---|---|
| 1 | **Contract** (`proto/`) | object model, gRPC surface | behavior | compile-time; versioned, additive-only |
| 2 | **Node agent** (in rauhad) | registration, capability cards, heartbeats | enforcement decisions | node invisible until re-register; zones unaffected |
| 3 | **State** | embedded store (registries) + CAS handle | secrets, keys | single-writer lock; CAS is truth of record |
| 4 | **Evidence ingest** | append-only intake, verification, indexing | editing, reordering | declared-loss accounting per node; backpressure never blocks a node (buffer local, upload later) |
| 5 | **Policy store** | versioned signed `ZonePolicy` TOMLs, distribution | enforcing, weakening | old version keeps working until explicit re-admission |
| 6 | **Run registry** | journal refs, heads, checkpoint refs, uncertainty seals | running anything | runs seal `uncertain` on node loss (Run protocol epoch rules) |
| 7 | **Placement** | tier/posture/topology/density filter pipeline | overriding node admission | placement failure with reason; node refusal propagates up |
| 8 | **Baselines** | acceptance records (scope + strength), precedent queries | silent auto-acceptance | no baseline = no compare; diff degrades to full record |
| 9 | **Adapters** | `dev` embed, `serve`, k8s operator/CRDs | owning the contract | adapter dies → its tier's intent goes stale, nothing else |

## The contract (object sketch)

```text
NodeCard     { identity_key, tiers[], hooks[], posture{ smt, cache },
               zone_capacity, verify_checks[], epoch }
Policy        { version, hash, toml, signatures[], distribution_state }
ZoneSpec      { class, policy_ref, tier, graph_edges[], placement_hints }
RunHead       { previous_head, journal_ref, checkpoint_ref, sequence,
                ownership_epoch, status }               // per Run Protocol v0
Receipt       { node-signed DSSE artifact, CAS address } // never edited, only referenced
Baseline      { accepted_run_ref, scope{ run|class|agent|lineage },
                strength, comparable_run_count }          // precedent, Part IV §6
Budget        { subject, allowances, spend_counters }
```

The churn rule (isolation-foundations discipline applied to fleet state):
**intent objects** (Policy, ZoneSpec, Budget) are low-churn, declarative,
and CRD-wrappable; **truth objects** (RunHead transitions, Receipts,
events) are high-churn, node-signed, and ride gRPC→CAS only — never the
intent store, never etcd.

## Deployment modes — same binary

| Mode | Command | Shape | State |
|---|---|---|---|
| local | `rauha dev` | rauhad + embedded cp, one process | file CAS + embedded store |
| server | `rauha-cp serve` | cp + N rauhads | embedded store + shared CAS (dir or S3) |
| k8s | operator mode | DaemonSet rauhad + operator + CRDs | etcd (intent) + object-store CAS (truth) |

Format policy (revises the old "no YAML" rule): **policy is TOML forever**
— the policy hash is inside the receipt; the format is part of the trust
artifact. Orchestration may be YAML at the deployment edge (CRs, manifests,
Helm). Core config TOML.

## Failure and security model

- **cp dead (any tier):** nodes enforce, run, and buffer evidence locally;
  no new orchestration. `rauha dev` trivially survives; operator death
  leaves stale CRDs, not dead zones.
- **node dead:** its runs seal `uncertain`; card goes stale; epoch fencing
  on re-register (already specified by Run protocol).
- **compromised cp — the damage bound:** it may stop orchestration and read
  evidence. It cannot weaken a running zone (admission is local), forge a
  receipt (node keys), or edit history (append-only CAS). This bound is a
  design invariant, tested adversarially like everything else.
- **split brain:** single-writer lock + CAS head replacement (Run protocol
  tier-zero mechanism).
- **Self-hosting (planned):** the cp runs inside a zone on a rauha-managed
  node; its own behaviour is recorded and receipted. The ouroboros demo is
  also a claim: the controller is a supervised workload like any other.

## The magic (differentiators, from the research line)

1. **Capability cards make strict admission a scheduling input.** Nodes
   publish what they can honestly enforce (tiers, hooks, SMT/cache
   posture); placement never routes a strict workload somewhere it would
   have to degrade. RuntimeClass everywhere else is fire-and-forget.
2. **Receipts are the state currency.** The cp's "logs" are signed,
   verifiable artifacts — an evidence library, not an ops log. Queries over
   receipts are queries over ground truth.
3. **The precedent corpus lives here.** Acceptance with scope and strength
   (Part IV §6); `rauha learn` baselines (observed-behavior → policy) ship
   through the same store. The cp is the first control plane whose policy
   layer is fed by signed history.
4. **Attention economics as a dashboard primitive.** reviewer-bits-per-run,
   budget spend, baseline drift — the reviewer is part of the system, so
   the system measures the reviewer's load.
5. **Unplug-ability as a demo.** `kill -9 rauha-cp` during a workload is
   the fleet-tier twin of the daemon crash probe.
6. **Tier/brand-aware placement.** kernel vs microvm zones are placement
   facts, not re-platforming.
7. **`rauha dev` as the on-ramp.** Zero infra, same contract, the research
   vehicle and the fun vehicle in one command.

## Sequencing

- **v0 — `rauha dev` (planned, first build):** embedded cp, node
  self-registration, evidence aggregation to file CAS, receipt queries.
  Forces the contract into existence with zero infrastructure; immediately
  the demo/research default. Read-only authority.
- **v1 — `rauha-cp serve`:** multi-node registry, signed policy
  distribution, run registry with uncertainty seals. Server tier exists
  the moment two nodes matter.
- **v2 — placement + budgets + baselines:** filter pipeline, capability
  cards as scheduling facts, precedent queries.
- **v3 — k8s adapter:** DaemonSet + operator + CRD set; evidence never
  touches etcd; receipt refs in pod status.

## Non-goals (what the cp never becomes)

- a general scheduler or a ConfigMap-shaped config system
- a secret store or key manager (keys stay with nodes / provisioning CA)
- a message bus or metrics pipeline (it references evidence, it does not
  relay telemetry)
- an enforcement path — ever
