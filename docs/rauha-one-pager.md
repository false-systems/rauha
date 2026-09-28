# Rauha — One Pager

**Run an agent through Rauha. Review the code it produced — and the short
list of what it actually did.**

## What it is

Rauha is an agent sandbox runtime built on **zones**: kernel-enforced
execution boundaries for workloads you don't trust, with a **signed receipt**
of what each run did and what the boundary actually covered. It is the
Solaris Zones idea rebuilt attachable — eBPF-LSM instead of in-kernel
structures — plus the thing Solaris never had: evidence.

## The problem

Agent workloads run today with ambient trust. Trail of Bits gave an LLM
agent twelve hours against a standard container; it escaped three times.
The industry's answer is walls — gVisor, Firecracker, per-session microVMs
— racing on wall price and wall speed. **No runtime on the market can prove
what a run did.** When the 2am postmortem asks *"what did the agent
touch?"*, every one of them hands over a frozen machine. Nobody hands over
an answer.

## What ships today (verified, not promised)

- **Zones via eBPF-LSM** — seven kernel hooks, fail-closed on read errors,
  build-time kernel-offset self-test; crun enrollment invariant: no image
  code executes before the workload is inside its zone's enforcement
  boundary.
- **`rauha sandbox -- <cmd>`** — the one-command product: pulls the image,
  runs the task in a temporary zone, mirrors the exit code, sub-second warm.
- **Strict admission** — a requested control is enforced, audited, or the
  zone is refused. Nothing degrades silently; degradations print in the
  result itself.
- **Evidence-grade output** — enforcement events with declared loss
  (ring-buffer drops are reported, never hidden), `zone verify` self-checks,
  and **Ed25519 receipts, now as DSSE/in-toto envelopes** — image digest,
  policy hash, enforcement totals, exit, time window — verifiable offline by
  `rauha receipt` and standard in-toto tooling.
- **Production plumbing** — `rauha.toml` config (never hardcode), crash
  recovery that never un-enforces a running zone, adversarial host-impact
  probes as the release gate, a containerd shim for the Kubernetes path.

## The thesis

Isolation was never a wall — it's a **claim about authority flows over
kernel objects**, and the product is the signed, honest statement of what
the wall covered. Everyone races one axis (kernel disjointness). The
unclaimed axes — observability, honest admission, declared posture — are
where Rauha stands, and they're theorem-backed: conditional completeness
("complete iff the witness attached before first exec and all declared loss
counters are zero") is not a compromise, it's the optimum. A receipt that
states its own scope is the only artifact in this market that can't be
falsified by its own output.

## What we're building next

1. **The Run** — journal, head, checkpoint protocol; fork / compare /
   accept. Two runs of the same task, normalized, diffed: *the code looks
   fine, the run does not* (+ opened `.env.production`, + connected
   `db-prod:5432`).
2. **`rauha learn`** — policy synthesis from observed behaviour: first runs
   learn the envelope, later runs are contained by exactly what the agent
   needed. Accepting a behaviour becomes accepting its policy.
3. **Tiers as brands** — a microVM tier (krun) running the same Linux stack
   inside the guest, same receipts; snapshots make the Run forkable.
4. **`rauha-cp`** — the control plane: librarian and dispatcher, never the
   boundary; unplug it mid-workload and no zone notices. `rauha dev` first.
5. **Kernel depth** — mmap-boundary hooks, Landlock, device BPF: erase the
   last honest refusals. Receipt hardening: cosign/Rekor adapters.

## How we work

Never hardcode (config with defaults, one schema; security invariants stay
invariant). Honesty by construction (declared loss, strict admission,
channel posture). Fast when healthy, correct when degraded. And the
boundary without the observer is not a product — confinement without proof
is decoration.
