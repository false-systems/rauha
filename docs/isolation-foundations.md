# Isolation Foundations: Heritage, Tiers, Hard Limits, Epistemology

Research synthesis (2026-09-26). This doc is the *why* under the architecture:
where the zone idea comes from, what the tier options really trade, the
four limits no isolation architecture escapes, and — at the bottom — what
an honest runtime can ever *know*. Claims about Rauha are marked
**shipped / planned / open**. Companion to `positioning-and-roadmap.md`.

## Part I — Heritage: Solaris Zones (2005)

The zone was an **OS partition**, not a machine: one kernel, many OS
instances. Global zone = the real OS *and* the control plane; non-global
zones see only themselves. Asymmetric visibility **is** the security model —
Rauha's phrasing: "the agent's account of its own actions is not evidence."

What the zone idea actually consisted of:

- **First-class object with a lifecycle**: `zonecfg` declares it; `zoneadm`
  drives configured → installed → ready → running. A managed boundary, not
  "a process with namespaces."
- **Declarative, honest configuration**: resources map one-to-one onto the
  isolation surface — `net`, `fs`/`dataset`, `rctl`/`capped-memory`,
  `device`, **`limitpriv`** (per-zone privilege set, a decade before
  "capabilities per container"), **`brand`** (pluggable executor
  personality: native, solaris10, lx).
- **Sparse-root zones**: read-only shares of the global zone's `/usr` —
  image attested *by construction*. Zone footprint in tens of MB, boot in
  seconds, up to 8,191 zones/host.
- **`zoneadm clone` via ZFS**: golden image + CoW clone = instant zone.
- **Observer above the boundary**: `prstat -Z`, per-zone accounting,
  DTrace into zones from the global zone, **per-zone BSM audit trails**
  (the ancestor of rauha-evidence).
- **Process contracts (ctfs)**: kernel-guaranteed supervision of all
  descendants, even reparented ones.
- **What killed it**: shared kernel (0days crossed zones), and kernel-first
  in-tree design — when Sun died, zones died with the platform.

### Mapping to Rauha

| Zone concept | Rauha | Status |
|---|---|---|
| zone as first-class object | `Zone` in redb, kernel zone ids, `reconcile()` | shipped |
| `zonecfg` contract | `ZonePolicy` TOML | shipped |
| strict admission / `limitpriv` | `admission = "strict"` refuses unenforceable controls | shipped — stricter than zonecfg ever was |
| `zlogin` | `rauha exec` / `attach` | shipped |
| `prstat -Z` / DTrace / BSM | `top`, `events`, evidence schema, receipts | shipped (receipts go beyond Solaris) |
| sparse-root read-only image | read-only rootfs + `writable_paths` | shipped (Landlock closes the rest: planned) |
| exclusive-IP / VNICs | netns + veth + nftables default-deny | shipped |
| process contracts | subreaper + pidfd + `cgroup.kill` | shipped |
| `zoneadm clone` | OCI snapshotter; 12ms warm bundle launch (gate-measured) | shipped |
| attachable, not in-tree | eBPF-LSM + cgroup-keyed BPF maps | shipped — the answer to how Sun died |
| `brand` | tier field (Part II) | planned |
| `detach/attach` | Run object / checkpoints | planned |

One-sentence identity: **Solaris put zones in the kernel because it owned
the kernel; Rauha puts zones on top of the kernel via eBPF-LSM because
Linux owns the kernel — and adds the thing Solaris never had: evidence.**

## Part II — Tiers are brands: the no-shared-kernel question

The real question is the TCB. A zone's boundary is eBPF-LSM hooks *inside*
the host kernel; one kernel exploit from inside the zone bypasses the hooks
that live in the thing just pwned. Surface reduction (seccomp, Landlock)
shrinks reachability but the kernel remains reachable by design.

| Tier | Syscalls served by | TCB | Observability by Rauha |
|---|---|---|---|
| zone (shared kernel) | host kernel + BPF-LSM | whole host kernel | ✅ by construction |
| gVisor | sentry (userspace) | sentry + host kernel | ❌ host LSM sees the sentry, not the workload — **wrong tier for this thesis** |
| microVM (FC/krun/CH) | guest kernel | VMM + KVM + virtio + guest kernel (two independent exploits to escape) | ✅ *if* the same eBPF stack runs in the guest |
| confidential VM | guest kernel, encrypted | + hardware-attested boot | ✅ + boot attestation |

### The rule this repo already paid for

The macOS VM backend died because it **could confine but not observe** — no
deny events, no counters, no receipts. Generalized:

> Any tier where enforcement evidence cannot flow from *below* the workload
> is dead on arrival: confinement without proof is not this product.

Therefore the microVM tier is **the same Linux stack inside the VM**: guest
kernel with `lsm=...,bpf`, the same eBPF programs, same enrollment
discipline, evidence out via vsock; the host reduces to a boring VMM.
One policy, one receipt schema, N executors. In Solaris terms this is a
**brand**: `tier = "kernel" | "microvm"` in `ZonePolicy`, validated by
strict admission (microvm requires KVM; kernel requires BPF-LSM).

### The plot twist: snapshots

Firecracker CoW memory snapshots = atomic, millisecond-restore committed
checkpoints — exactly the recovery boundary the Run protocol declares
(`Run Protocol v0`: "Fork = new Run referencing parent head + checkpoint").
**Zones cannot fork live state; microVMs can.** The microVM brand is not
the paranoid tier; it is the *Run-protocol tier*.

Sequencing: (1) formalize `tier` in policy/admission/receipts first;
(2) krun spike (`run.oci.handler=krun` — the shim already delegates to
crun) as the cheapest honest measurement; (3) Firecracker only when
fork/compare needs snapshots. Do **not**: gVisor tier, Kata-under-Rauha
layering, or live migration (checkpoints, not streaming — fast when
healthy, correct when degraded).

## Part III — Four hard limits no architecture escapes

### 1. The kernel boundary is not the syscall table

Entry points beyond classic syscalls: `mmap(MAP_SHARED)`/`mprotect`
(authority exercised **after** the open, with zero further syscalls),
io_uring, vDSO (no entry, harmless), ioctl surfaces (DRM/KVM), FUSE/
userfaultfd (confused deputies), zero-copy networking (connect hooked,
per-packet flows not — nftables covers L3/L4).

**Known hole (open)**: open a shared-memory file in an allowed writable
path, `mmap PROT_WRITE|MAP_SHARED`, write forever — `file_open` fired once.
Enforcement completeness = surface reduction × hook coverage ×
**object-lifetime tracking**. The fix judges `prot & PROT_WRITE` at
mmap/mprotect against `INODE_ZONE_MAP` — the map exists, the lifecycle
logic does not (planned).

### 2. Names are not objects — ambient authority vs capabilities

Linux is ambient authority: rights looked up at use time in global tables
(UID × path). Confinement is unprovable there (Lampson 1973; Buhr &
Hensgen; Mark Miller, *Robust Composition*); it holds in capability
systems where authority is an unforgeable reference you hold, never look up.

- Rauha's inode-keyed maps bind policy to **kernel objects, not names** —
  the correct side of the argument (why AppArmor-class systems are
  structurally weaker than label/DTE-class ones).
- `ZONE_ALLOWED_COMMS` `(src_zone, dst_zone)` is a **domain-and-type
  enforcement matrix** (Boebert-Kain → SELinux lineage; Trusted Solaris
  compartments). Generalizing pairs → a label lattice is the policy-model
  direction: subsumes peers, egress, writable-paths in one formalism.
- The roadmap's `SCMP_ACT_NOTIFY` FD-brokering is the **capability wedge**
  (Capsicum lineage, FreeBSD 9.0): the workload never names the path; the
  broker grants a handle. Theoretically load-bearing, not a nicety.

### 3. Isolation was never binary — declared channel posture

MLS systems (Orange Book A1, Trusted Solaris) required *measuring and
bounding covert channels*. Spectre-class made channels cross-VM; SMT,
shared LLC, DRAM stay shared even under microVMs. Nobody in the market
table declares channel posture.

**Move (open, nearly free)**: `zone verify` + receipt state
`isolation_class: containment | partitioned`, `smt: on|off`,
`cache: partitioned|shared` from sysfs facts. An honest sentence no
competitor can emit. The hardware knobs (core pinning + resctrl/CAT,
SMT off) are a possible third brand; the *declaration* is a day of work.

### 4. The observer is in the TCB

The Solaris global zone was trusted by construction; rauhad is trusted by
administration — a weaker statement. The ladder (ascending): node-generated
signing key (today, `load_or_create`) → key certified by a provisioning CA
→ **BPF program hash + offsets-manifest SHA inside the receipt** (the
sidecar machinery already exists) → measured boot/TPM → confidential-VM
attestation binding the guest key. Plus a **hash-chained event log** (each
event carries `prev_hash`) to make post-hoc forgery detectable off-host.
Honest limit: full tamper-proofing against a root-compromised daemon on the
same host is not achievable — which is why receipts must verify *off* the
host (DSSE/in-toto, already roadmap gap #1).

### Provenance: the half-solved core

Whole-system provenance research (ULTRAVIS, CamFlow, SPADE, LPM) hit one
wall: capture is lossy under load, adversarially so. Rauha's
`ringbuf.drop` / `pipeline.shed` = declared-loss design; "complete only if
witness attached before first exec and drop counters zero" is a
**conditional completeness claim** — the strongest anyone in this
literature can make. Two holes to close (open):

- **Identity recycling**: `i_ino` reuse lets a new file inherit a dead
  zone binding. PIDs were solved with pidfds; inodes have none.
  Generation-aware keys or eviction discipline.
- **Lineage**: forked children inherit fds (capabilities) legitimately;
  exec_id/parent chains (roadmap item 3) make the record interpretable,
  not just countable.

## Part IV — The epistemology of the run

Parts I–III were physics: what boundaries exist, what they cost, where they
leak. This part is what is knowable *through* that physics — the theory of
what an honest runtime can claim about a run. Seven results, each with an
engineering consequence.

### 1. Rice's theorem: conditional completeness is optimal

Every non-trivial semantic property of programs is undecidable. No runtime
can decide "this run is safe" — or even "this behaviour matches that one" —
in general. Any matcher is a heuristic over a chosen representation: sound
for its language, never complete over all possible behaviour.

Consequence: the conditional-completeness claim (complete iff witness
attached before first exec and drop counters zero) is **not an engineering
compromise — it is the optimum**. Strict admission and declared loss are not
humility; they are correctness. Any system claiming unconditional knowledge
of what a run did is claiming something undecidable, and has simply not yet
met its adversarial user.

### 2. The diff is a language choice (Kolmogorov / MDL)

What is "the same behaviour"? Formally, the diff between run B and accepted
run A is the conditional description length **K(B | A)** — the bits needed
to describe B given A as context. Normalization (stripping PIDs, timestamps,
scheduling noise) is not cleanup; it is **choosing the description language**,
and the language decides what counts as information. Nothing is noise except
relative to a language.

Consequences:

- The normalization schema is part of the receipt's **trust boundary**. A
diff computed under language v1 and one under v2 are different claims — the
receipt must carry the normalization version the way it carries the policy
hash (**planned**). Miss this and the artifact is a signature on an
unverifiable statement.
- The research question "what is the right behavioural quotient?" is
precisely a search of the language space for one where benign variance
compresses and security-relevant change does not — an MDL-style criterion
that can be optimized and measured, not argued.

### 3. Confinement requires determinism (Miller)

*Robust Composition* (Mark Miller): capability discipline plus deterministic
semantics is what makes confinement composable; remove determinism and you
get covert channels and unreproducible behaviour. For Rauha this cuts twice:

- **Soundness of compare.** If the same task under the same conditions
produces drifting behaviour records, "same" is undefined and the diff cries
wolf. The determinism experiment (hermetic twin runs: no clock drift, pinned
CPU, no ASLR, seeded state) is therefore not periphery — it **measures the
noise floor that bounds compare/accept's false-positive rate**.
- **Channels.** Nondeterminism (timing, scheduling) is the medium of every
covert channel in Part III §3. Determinism work and channel-posture work
are the same work.

### 4. Goodhart: the adversary inside the envelope

The moment an envelope is accepted, the envelope becomes the adversary's
map. A sufficiently capable agent does not violate the policy — it **complies
maliciously**: exfiltrating through allowed files, encoding data in timing,
in syscall ordering, in *which* allowed resources it touches. Steganography
through conformance. This marks the exact limit of the diff: it catches
deviation, not subversion-through-conformance.

Consequences: the arena gains a Goodhart level — an attack that stays inside
policy and asks whether the *evidence* still shows the anomaly (access-pattern
oddity, timing regularity) (**planned**); the receipt's residual-risk
statement names this class explicitly; and this is why the code diff and the
behaviour diff must always ship together — the code review sees
intent-shaped things the behaviour record cannot.

### 5. The counterfactual gap — the strongest honest sentence

Three objects, three tenses: the **behaviour record** (what it did), the
**artifact diff** (what persists), and **intent** (what it will do). Dormant
semantics live in the gaps between them — code that ran but left no artifact,
behaviour that looks benign but plants state that acts later. No combination
of the first two certifies the third. The strongest sentence the product can
ever honestly emit is therefore:

> **"This run is consistent with accepted history, under language L, with
> declared coverage C and declared losses D."**

Not "safe" — never "safe" (result 1). The receipt that states its own scope
is the only trustworthy artifact in the market; that is not a weakness of
the thesis, it is the thesis. This sentence is the product's constitution:
every feature must preserve it.

### 6. Acceptance is precedent, not matching

Executions do not recur; "accepting a run" cannot mean matching one. It
establishes a **norm** — behaviour of this shape is acceptable for this
class of task. That is case law: the run ledger is a precedent corpus, the
diff engine is precedent retrieval, and acceptance scopes (this run /
this task class / this agent / this workspace lineage) are precedent
*strength*. Over-broad acceptance compounds exactly like bad precedent —
which is why `run-protocol-v0.md` already requires explicit acceptance plus
enough comparable runs before a baseline is trusted (stare decisis with a
quorum).

Consequence: acceptance needs explicit **scope and strength semantics** in
the Run protocol — never a boolean (**planned**). "Accept" without a scope
is an unforced error the system will eventually commit against its user.

### 7. The diff is an attention router (Simon)

"A wealth of information creates a poverty of attention" (Herbert Simon,
1971). The reviewer's attention is the genuinely scarce resource of the
whole system; the receipt, the diff, and the delta-first view are all
**attention allocation mechanisms** — the complete record retained for
depth, the PR foregrounding only the delta because the reviewer has minutes.

Consequence: measure the product in **reviewer-bits-per-run** — how much
human attention certifying a run consumes. It is a real, optimizable metric
that no competitor has, because nobody else treats the reviewer as part of
the system. Agent budgets (actions, I/O, energy) are the same idea from the
other side: price attention, and make honest behaviour the cheap strategy.

### Engineering consequences of Part IV (planned)

1. Receipt schema: normalization-language version, acceptance scope,
   residual-risk class. Three fields, all correctness.
2. Run protocol: acceptance = scoped norm (strength + class + lineage).
3. Determinism and Goodhart experiments promoted from periphery to
   foundational soundness experiments.
4. The constitution sentence adopted as the canonical claim in positioning.

## The lattice

| Axis | gVisor | Firecracker/Kata | ECI/Sysbox | Rauha today → thesis |
|---|---|---|---|---|
| kernel disjointness | partial | ✅ | ✅ | tier-branded |
| authority model | ambient | ambient | ambient | ambient → object-keyed DTE, capability wedge |
| observability | ❌ | ❌ | ❌ | conditional-complete, declared-loss |
| channel posture declared | ❌ | ❌ | ❌ | ❌ → ✅ nearly free |
| observer TCB anchored | ❌ | boot only | ❌ | node-key → hash-chained, program-hash-in-receipt |

The industry raced one axis (disjointness). The other three are unclaimed
territory, and Rauha already stands on two without having named them.

## The five moves (cheapest first)

1. `mmap`/`mprotect` hooks against `INODE_ZONE_MAP` — closes the largest
   hole in the completeness claim.
2. Channel-posture declaration in `zone verify` + receipts.
3. Hash-chained event log + BPF program hash in the receipt.
4. Inode generation handling (correctness before `MAX_INODES` bites).
5. Name the DTE: write the label-lattice generalization as the
   policy-model direction.

The sentence everything reduces to: **isolation was never a wall — it is a
claim about authority flows over kernel objects, and the product is the
signed, honest statement of what the wall covered.**

And the floor under that sentence: **a runtime cannot certify safety — it
can certify history. Build the system that tells the truth about that limit,
and it is the only artifact in this market that cannot be falsified by its
own output.** Walls get copied; theorem-backed honesty does not.
