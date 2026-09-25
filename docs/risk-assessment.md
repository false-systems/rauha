# Risk Assessment: Four Critiques, Researched

Research snapshot: 2026-08-27. Each of the four risk critiques was investigated
against the actual code and CI, with file:line evidence. Verdicts: **confirmed**,
**sharpened** (worse than stated), **softened** (engineering moved past the
critique), **partially confirmed** (holds with caveats).

---

## Risk 1: Breadth vs. depth — **CONFIRMED, sharpened: macOS has no CI at all**

### What the code says

| Crate | LOC | Role |
|---|---|---|
| rauhad | 12,408 | daemon (47% of the codebase) |
| rauha-oci | 3,036 | image pull / content store |
| rauha-common | 1,759 | shared types, backend trait |
| rauha-cli | 1,978 | CLI |
| rauha-shim | 1,489 | per-zone supervisor (Linux) |
| rauha-guest-agent | 1,255 | **macOS-only** |
| rauha-evidence | 1,605 | evidence schema + receipts |
| rauha-enforce | 1,182 | legacy (superseded by Syva) |
| rauha-ebpf-common | 650 | shared kernel types |
| rauha-ebpf | 766 | kernel-side programs |
| rauha-enforcer-api | 784 | enforcement trait seam |
| containerd-shim-rauha-v2 | 579 | K8s bridge |
| xtask | 316 | build helper |

Total ≈ 26.5k LOC. macOS-specific code ≈ 2.9k LOC (~11%):
`rauhad/src/backend/macos/{vm,mod,pf,apfs,vsock}.rs` (~1.5k) plus the whole
`rauha-guest-agent`.

### The sharpened finding

`.github/workflows/ci.yml` and `privileged.yml` run on `ubuntu-24.04-arm` and
self-hosted `arc-arm64` only. **`grep -c macos .github/workflows/ci.yml` = 0.**
The macOS backend — Virtualization.framework ObjC wrappers, APFS clonefile,
pf rule generation, vsock relay, the guest agent — is *never compiled in CI*.
It compiles exactly where a developer happens to run it. The critique said
"works on my machine"; the truth is closer to **"compiles on my machine."**

Test asymmetry compounds it:

| Crate | unit tests | notes |
|---|---|---|
| rauhad | 103 | mostly platform-neutral (registry, server, policy) |
| rauha-oci | 56 | platform-neutral |
| rauha-common | 22 | platform-neutral |
| rauha-evidence | 6 | receipt round-trip |
| rauha-cli | 7 | |
| **rauha-shim** | **3** | the security-critical fork/enroll/exec path |

The shim's real coverage comes from `tests/security/` — which is Linux-only,
root-only, BPF-LSM-only. The macOS path has **no adversarial equivalent** and
never will (no BPF LSM on Darwin; the VM is the boundary — but nothing probes
the pf rules, the vsock relay, or the guest agent on a schedule either).

### What's actually fine

- Platform gating is clean: 17 `cfg(target_os = "macos")` / 19
  `cfg(target_os = "linux")` attributes in rauhad, one `IsolationBackend` seam.
- The legacy `rauha-enforce` crate is fenced off ("do not extend") — dead
  weight but not active surface.
- The positioning doc already frames macOS as the "proof point" for a future
  microVM tier, not a co-equal product platform.

### Recommendation (cheapest first)

> **Decision (2026-09-26):** the macOS backend was **removed entirely**
> (crate `rauha-guest-agent`, `rauhad/src/backend/macos/`, pf/vsock/APFS code,
> `rauha setup`, xtask guest-agent/initramfs builds, entitlements). During the
> removal it emerged that `cargo check --workspace` had been failing on macOS
> for some time (ungated `aya` dep in `rauha-enforce` + Linux-only libc items),
> unnoticed because CI is Linux-only — the strongest possible confirmation of
> this risk. The workspace now compiles and unit-tests on any OS again; the
> daemon refuses to start on non-Linux. If a VM tier returns, the shape is the
> same Linux stack inside a VM, not a parallel macOS backend. Items 2–3 below
> remain valid for the Linux-only world.

1. ~~**Add a macOS compile+test job to ci.yml**~~ (superseded by removal)
2. Treat `rauha-shim` unit-test count (3) as a bug: the enrollment sequence
   (create → pidfd → cgroup.procs → start) is invariant-heavy and deserves
   unit tests that don't need root (state transitions, fail-closed paths).
3. Longer term: keep the Linux-only claim loud in README and verify steps.

---

## Risk 2: Hardcoded kernel offsets — **SOFTENED: the critique is outdated; ops burden remains**

### What has changed since the critique

The current scheme is not "hardcoded defaults for Linux 6.1+" (that is what
CLAUDE.md still says — it has drifted). What ships now:

1. **Build-time resolution from BTF.** `cargo xtask build-ebpf` runs pahole
   against the target kernel, generates `offsets.rs`, and compiles it in via
   `include!(env!("RAUHA_EBPF_OFFSETS"))` behind the `generated-offsets`
   feature (`rauha-ebpf/src/main.rs:83-89`, `xtask/src/main.rs:83-160`).
   The fallback `offsets_default.rs` is only for plain crate builds that are
   explicitly "not production artifacts."
2. **Sidecar manifest binding object to offsets.** The build writes
   `<object>.offsets.json` containing the object's SHA-256 plus every offset
   (`rauha-ebpf-common/src/offsets.rs`, `render_offsets_sidecar`). The daemon
   reads it back and re-hashes the object (`ebpf.rs:522-554`) — you cannot mix
   an object with a foreign manifest.
3. **Load-time validation against the local kernel.** Before loading, the
   daemon re-resolves offsets from the *local* kernel's BTF and refuses on
   mismatch (`ebpf.rs:104-120`). Fail-closed with a hint.
4. **Runtime self-test.** First `file_open` compares
   `bpf_get_current_cgroup_id()` against the offset-chain-derived cgroup id
   (`SELF_TEST` map, `ebpf.rs:281,366-432`). Divergence ⇒ error, not silence.

So the soundness story is: wrong offsets cannot produce silent mis-enforcement.
The remaining risk is operational, not correctness:

| Residual risk | Detail |
|---|---|
| **pahole required on production hosts** | `resolve_kernel_offsets_map()` shells out to pahole at *daemon start* (`offsets.rs:64-72`). No dwarves ⇒ no eBPF ⇒ (on Linux) no daemon. An ops dependency where a pure-Rust parser would do — and Syva already wrote one: `syva-core/src/btf.rs` is a minimal native BTF parser ("replaces pahole subprocess calls"). Port it into `rauha-ebpf-common` and the dependency disappears. |
| **Per-kernel builds** | Offsets are baked at build time against the build host's kernel. Distribute a binary to a different kernel and it fails closed ⇒ you must run `xtask build-ebpf` on (or for) each target kernel. Fine for the current deployment model; friction for packaging. |
| **`BPRM_FILE` heuristic** | `field_names: &["file", "executable"]` resolves first-match (`offsets.rs:74-80`). Kernel-version-dependent semantics folded into a preference list — correct today, subtle forever. |
| **Doc drift** | CLAUDE.md still describes the old hardcoded-defaults scheme with "sensible defaults for Linux 6.1+." The code moved; the doc didn't. Someone trusting CLAUDE.md will mis-assess this risk — as the original critique did. |

### Recommendation

1. Port Syva's `btf.rs` (native BTF parse, no pahole) into `rauha-ebpf-common`,
   keep pahole as fallback. One less production dependency, same guarantees.
2. Update CLAUDE.md's eBPF section to the generated-offsets + sidecar scheme.
3. Keep the Syva extraction on track: kernel-coupled enforcement code belongs
   behind that boundary, where Syva's conformance harness can churn with
   kernels without dragging Rauha releases.

---

## Risk 3: "Planned" vs. shipped — **PARTIALLY CONFIRMED: the gap is real but the receipts bridge is further along than the critique credited**

### What is actually shipped (verified in code)

- `rauha sandbox` end-to-end (`RunSandbox`, exit-code mirroring, enforcement
  events in the result) — shipped, integration-tested
  (`tests/integration/test-sandbox.sh`).
- **Signed execution receipts** — shipped, and the critique didn't know:
  - `ExecutionReceiptPayload` (`rauha-evidence/src/receipt.rs:33-47`):
    image admission (digest-verified logic with a recent fix at
    `server.rs:1864` — "may claim verified only when the caller pinned a
    digest"), `policy_sha256`, `inputs_sha256`, `outputs_sha256`, exit code,
    enforcement totals, `unavailable_controls`.
  - Ed25519 signing key persisted at `metadata/receipt.ed25519` with published
    public key (`main.rs:122-126`).
  - CLI `rauha receipt verify` plus `verify_trusted` with a pinned public key
    (`rauha-cli/src/commands/receipt.rs`).

### What is genuinely still paper

- **DSSE/in-toto envelope** — the receipt is signed JSON, not a DSSE
  statement; `cosign verify-attestation` cannot consume it yet. Roadmap gap
  #1 (`positioning-and-roadmap.md`, "Eight exploitable gaps").
- **The Run Protocol** — `docs/run-protocol-v0.md` opens with: *"Status: draft
  contract... Nothing here is implemented yet."* No journal, no head, no
  checkpoints, no fork/compare/accept, no behaviour diff. `rauha-evidence`
  contains exactly `lib.rs` + `receipt.rs`.
- **Egress evidence, process lineage, IPv6 default-off** — all marked planned.

### The honesty ledger (this is the project's real defense)

The positioning doc does not oversell: the flagship example is immediately
followed by *"This is the planned product experience, not a claim about
today's event stream,"* and the milestone section ends with *"Until
adversarial probes pass, the honest message is promising architecture,
incomplete containment."* Every differentiator is tagged
shipped/planned/milestone. The README risk the critique identified — story
outrunning reality — is actively policed in the docs.

The remaining risk is **sequencing**, not honesty: `rauha run` + behaviour
diff is a much larger machine (journal, reducer, witness completeness
guarantees — RP-1..RP-n) than receipts were, and it depends on the "witness
attached before first exec, all loss counters zero" completeness property
that today's event stream explicitly cannot provide.

### Recommendation

1. Land the DSSE envelope (small lift, big ecosystem unlock — gap #1) before
   starting Run Protocol implementation; it makes every future receipt
   cosign/Witness-consumable for free.
2. Treat `run-protocol-v0.md`'s numbered invariants (`RP-n`) as oracle cases
   *first* (the doc itself suggests this — §12 conformance case index), so
   the supervisor gets built against conformance, not vibes.
3. Keep the planned/shipped tagging discipline in every doc; it is currently
   the project's most credible asset against the "vaporware" reading.

---

## Risk 4: redb + postcard schema fragility — **CONFIRMED and sharpened: the container path is a hard failure, not a skip**

### What the code says

No schema version exists anywhere in the store
(`rauhad/src/metadata/db.rs`, 381 lines, two tables, raw postcard blobs).
Postcard is non-self-describing: adding *or removing* any field in
`Zone`/`Container` breaks deserialization of every existing entry. Any schema
change effectively requires deleting `rauha.redb` (the code's own warning
says: "delete stale db or re-create the zone").

The two paths handle the break **asymmetrically**:

| Path | Behavior on incompatible entry |
|---|---|
| `get_zone` / `list_zones` (`db.rs:76-89, 131-145`) | **skip with warning** — zone treated as absent |
| `get_container` (`db.rs:196-203`) | **hard error** — `Err(MetadataError)` |
| `list_containers` (`db.rs:236-247`) | **hard error — one bad entry poisons the entire listing** |

Blast radius of the container-side failure:

- `registry.rs:366` (`reap_zone`) — reaping stops working; a corrupt entry
  wedges lifecycle management for *other* zones' containers too when listing
  unfiltered (`registry.rs:754-762`, `server.rs:255` delete flow,
  `server.rs:605-618` ListContainers RPC).
- `reconcile()` then sees a partially-failed world on every restart.

The zone-side "skip" is safer than it looks but not free. A skipped zone with
live processes is retained **fail-closed** by `cleanup_orphans`
(`backend/linux/mod.rs:777-810`: "retaining live orphan cgroup and its
fail-closed membership" when `zone_has_processes`) — the boundary holds, which
is the right security posture. But the zone becomes a *ghost*: invisible to
`zone list`, undeletable via API (`ZoneNotFound`), no logs/exec — manual
surgery required, forever, until the db is deleted.

Also noted: `redb = "2"` is semver-open. redb has changed its file format
across minor releases before; an upstream bump can brick existing databases
the same way a schema change does.

### Recommendation (concrete, ranked)

1. **Symmetrize the skip-guard**: make `list_containers`/`get_container`
   skip-with-warning like zones. Small diff, removes the hard-failure wedge.
2. **Version the envelope**: serialize `{schema_version: u16, data}` (or a
   magic + version prefix) so incompatible entries are *detectable as
   versioned-and-old* instead of indistinguishable from corruption. This is
   the prerequisite for ever writing a migration.
3. **Pin redb** (`redb = "=2.x.y"`) until an envelope version exists; upgrades
   become a conscious act instead of a `cargo update` surprise.
4. Longer-term: since the store is small (zones/containers only, counts in
   the tens), self-describing JSON values in redb cost almost nothing and
   make every future field addition backward-compatible. Postcard's win
   (size) is irrelevant at this cardinality. Alternatively keep postcard but
   add a `rauha migrate` subcommand before the first real schema change.
5. Add a unit test that round-trips a *frozen old-format blob* through the
   current deserializer — the regression test for schema evolution that
   currently can't exist because no version marker exists to freeze against.

---

## Summary verdict table

| # | Critique | Verdict | One-line evidence |
|---|---|---|---|
| 1 | Breadth vs. depth, macOS second platform | **Confirmed, sharpened** | Zero macOS jobs in CI; macOS backend never compiled anywhere but dev laptops; shim (security-critical) has 3 unit tests |
| 2 | Hardcoded kernel offsets | **Softened — outdated** | Offsets now generated from BTF at build + sidecar-bound + load-validated + runtime self-tested; residual risk is pahole-on-hosts and per-kernel builds (Syva's native BTF parser is the in-house fix) |
| 3 | Planned (`rauha run`) vs. shipped | **Partially confirmed** | Run Protocol explicitly "nothing implemented yet"; but signed Ed25519 receipts *are* shipped and every doc claim is tagged shipped/planned — the gap is sequencing risk, not honesty risk |
| 4 | redb + postcard fragility | **Confirmed, sharpened** | No schema version; containers hard-fail (one bad entry poisons all listings) while zones silently skip into ghost-unmanageable state; redb semver-open |

## Cross-cutting observation

The strongest pattern in this codebase is **fail-closed with a named, testable
check** (enrollment ordering, offset self-test, strict admission, retained
live orphans). The weakest pattern is **secondary state that nothing re-derives**
(schema evolution, CI coverage of platform #2, doc drift in CLAUDE.md). Every
recommendation above is an application of the codebase's own first pattern to
its second.
