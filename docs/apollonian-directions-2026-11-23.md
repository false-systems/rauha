# Rauha Should Show Futures It Can Prove

Research date: 2026-11-23, against Rauha `origin/main` (code citations unchanged at 56781e6). A research report, not a plan: every direction marked [proposal] is undecided, and code findings are readings of the source, not test results. Continued in [the academia and IBM Research round](apollonian-academia-ibm-research-2026-11-23.md).

The Apollonian version of Rauha is a runtime that **shows you what an agent's run will do before any of it reaches the world, and afterwards proves what the run did, including exactly what Rauha could not see**. Almost every "godlike" direction rests on one thing Rauha already has and most competitors lack: it watches from the Linux kernel, outside the agent. Its record is therefore a second, independent witness, not the agent's own story. Isolation, egress allowlists, placeholder credentials, snapshots and fast forks are now standard across agent sandboxes, so Rauha should not try to win there. Several capabilities appear in no product reviewed:

- showing a run's held effects before you accept it;
- comparing parallel attempts by what they did, not only by their code;
- forks that are guaranteed to inherit no authority;
- credentials usable only by a kernel-identified caller, with the approval carried inside the credential;
- information-flow rules enforced by the runtime;
- receipts that carry continuous self-attack results and state their limits one claim at a time.

Build three small things first, all on code that ships today:

1. **A one-day test of whether enforcement survives a daemon crash.** Reading the code suggests the eBPF hooks detach when rauhad dies, and that the health check cannot see a detached hook.
2. **A machine-checked model of what strict admission and receipt scope promise.**
3. **A tool that reduces parallel `rauha sandbox` runs to comparable behaviour signatures.**

After that, build the planned workspace as an overlay from day one, so that a "shadow run" with an effects manifest needs little extra work. Hardware-rooted keys, zero-knowledge proofs, memory forks and full information-flow tracking are real research, worth doing later, not first.

## Rauha's edge is the independent witness, not a thicker wall

The rest of the report uses a few Rauha terms, defined here.

| Term | Plain meaning | Status |
|---|---|---|
| Zone | The boundary around one task: its files, processes, network, resource limits, policy and audit trail, managed as one unit | Shipped |
| eBPF-LSM hooks | Small programs loaded into the kernel's security checkpoints (file open, program exec, ptrace, signals, cgroup moves, privileged capability use). They refuse cross-zone actions and stream each refusal out as an event | Shipped: six enforcing hooks; network connect is audit-only (nftables enforces) |
| Seccomp broker | For chosen system calls (today `openat` and `openat2`), the kernel pauses the call. The zone's supervisor process (the "shim") judges it, opens the file itself if allowed, and hands the workload only the resulting file handle | Shipped, read-only opens |
| Strict admission | If the host cannot enforce a control the policy asks for, the task is refused. `audit` mode runs it anyway and lists the missing controls | Shipped |
| Receipt | The signed result of a task: Ed25519, plus a DSSE/in-toto envelope (a standard signed-statement format). Anyone can check it offline | Shipped |
| Journal | A hash-chained record of a task's lifecycle steps, bound into its receipt | Shipped for new Linux tasks |
| Run; fork, compare, accept | The planned product: a task as one portable object (workspace, authority, journal, effects, receipt) that can be copied, compared with its siblings, and accepted | Planned; `--repo-path` is rejected today |

These definitions come from Rauha's own `README.md` and `docs/sandbox-runtime.md` on `origin/main`. Throughout the report, **[shipped]** means released in a product or an upstream project. **[research]** means a paper or prototype with its own evaluation. **[vendor claim]** means a company's figure with no independent method behind it. **[proposal]** means my speculation for Rauha.

**Rauha's strongest asset is its position, not its wall.** The 2026 "Hearsay" study looked at 16 deployed agent frameworks and found that in every one, the harness is the only writer of the run record. Model examiners over-claimed corroboration by 18 to 55 points. When a sandbox ledger was added as a second writer, a checker flagged **64 of 66 altered records and 0 of 84 clean ones**. The authors' line is "What makes a record evidence is a second writer, not a better reader" ([Hearsay](https://arxiv.org/abs/2609.32495)). Rauha is that second writer, at the kernel, by construction. The mainstream sandboxes are not:

- Anthropic's sandbox-runtime keeps violations in an in-memory store that is shown to the model ([sandbox-runtime](https://github.com/anthropic-experimental/sandbox-runtime)).
- Confidential-computing vendors attest *where* code ran but say little about what the boundary covered ([TRACE coverage](https://www.securityweek.com/linux-foundation-to-govern-trace-an-open-standard-for-ai-runtime-attestation/amp/)).

**Rauha's biggest gap is that it records only refusals.** Allowed actions are per-CPU counters, not events. The shadow run, behaviour comparison, provenance graphs and policy learning described below all need an opt-in "allow-event" mode for a zone. That mode comes with a warning attached. A 2026 study of kernel telemetry found eBPF the most promising capture layer, yet found that most existing provenance tools "cannot guarantee the integrity and availability of the captured events" ([Houssel et al.](https://arxiv.org/abs/2608.11418)). Any allow-event mode must therefore declare its own loss, just as `capture_issues` and `ringbuf.drop` do today.

The market splits cleanly, based on documentation reviewed in November 2026. "None found" means the feature is absent from the docs read, not proven absent everywhere.

| Capability | Who already has it | Rauha's opening |
|---|---|---|
| Strong isolation, egress allowlists, placeholder credentials | Docker, Vercel, Cloudflare, E2B, microsandbox, nono, NVIDIA OpenShell, Fly tokenizer | Commodity: be good enough, not different |
| Memory snapshot and fork of a running sandbox | E2B, Daytona, Modal (preview), Docker Sandboxes API, Morph, Freestyle, CodeSandbox, GKE | Commodity: do not race on fork latency |
| File checkpoints and rollback | Fly Sprites, Vercel, Cloudflare, AgentFS, Claude Code (skips shell-made changes) | Undo that covers every writer and lists what cannot be undone |
| Best-of-N parallel attempts | Codex cloud, Cursor 2.0 | Choose by behaviour as well as by code |
| Rules per binary or per git destination | OpenShell (by binary path), Anthropic's cloud git proxy | Caller bound by cgroup, executable digest and run epoch; approval inside the credential |
| Record-then-enforce policy | StrongDM Leash (marketing), CI tools | Learn only from clean runs, with rule provenance and ablation |
| Held-effects preview before commit | Research only (Atomix, GoEX, hS for shell) | **Open** |
| Behaviour diff across sibling forks | None found | **Open** |
| Forks with no inherited authority, as a guarantee | Opposite shipped: E2B forks inherit secret injection | **Open** |
| Signed evidence of what a run *would* have done | None found | **Open** |
| Runtime information-flow rules (the "Rule of Two") | In-framework only (FIDES, CaMeL, both Python) | **Open, research-heavy** |
| Continuous escape probing recorded in receipts; visible drift detection and repair | None found | **Open** |
| Machine-checked semantics for a runtime's own receipts | None found | **Open** |

**The Apollo lens fits better than expected.** The three maxims inscribed at Delphi already describe laws Rauha ships ([Delphic maxims](https://en.wikipedia.org/wiki/Delphic_maxims)):

- **"Know thyself"** is `rauha zone verify`.
- **"Nothing in excess"** is bounded capture and least authority.
- **The third maxim** is usually rendered "surety brings ruin". Diogenes Laërtius read it as trouble for anyone who "affirms anything in strong terms and confidently". That is Rauha's rule that uncertainty is data, written 2,500 years early.

The sections below keep the myth as a lens and the engineering plain.

## Prophecy: rehearse the run and hold its effects at the door

The oracle at Delphi answered before the act. The engineering equivalent is a rehearsal: run the agent in a copy of the world, record every effect, and show the list before anything real happens.

### The shadow run is assembled from proven parts

Each ingredient exists and has been measured on its own:

- **try [shipped]** runs a shell command in an OverlayFS sandbox inside Linux namespaces, so you can inspect its effects before they reach the live system ([try](https://www.github.com/binpash/try/blob/main/try)).
- **hS [research]** (OSDI 2026) traces each command's file reads and writes, keeps the writes in an overlay, and commits by copying them back ([hS](https://www.usenix.org/system/files/osdi26-liargkovas.pdf)):
  - It splits effects into *deferrable* ones (files, directories) and *non-deferrable* ones (network, IPC, signals).
  - Its fixed overhead is **217 ms per command**.
  - Syscall tracing alone added **310%** on workloads that create many small files.
- **"Rethink the Sync" [research]** (2006) showed the same move for the outside world: hold network and screen output until the disk work it depends on commits. It ran within 7% of an unsafe baseline ([OSDI 2006](https://www.usenix.org/legacy/event/osdi06/tech/nightingale/nightingale_html/index.html)).
- **Atomix [research]** (ICLR 2026) held irreversible agent actions until commit. It leaked **0 of 500** invalid sends, against 80% for "compensate afterwards" sagas and 40% for checkpoint-and-replay ([Atomix](https://arxiv.org/html/2602.14849v2)).
- **Aegis OS [research, self-reported]** is the closest competitor. It is a Rust agent runtime posted in November 2026. It gives each agent a copy-on-write shadow workspace (a 78.1 MB repository cloned in 15.6 ms using btrfs reflinks), routes egress through a proxy, and reports 90.7 to 97.9% fewer approval prompts ([Aegis OS](https://arxiv.org/abs/2611.08516)).

**[proposal]** A `rauha run --rehearse` would work like this:

1. Build the workspace as an overlay.
2. Switch the zone's nftables chain to drop-and-log all outbound traffic.
3. Turn on allow-event capture for the zone.
4. At exit, print an **effects manifest**:
   - files created, changed and deleted, read straight from the overlay's upper layer, deletions included;
   - programs executed;
   - secret paths touched, allowed or denied;
   - outbound requests held;
   - reads that found nothing (hS shows a missing file is a dependency too).

Accept applies the overlay and releases held requests in journal order. Discard drops both. Either way, the manifest goes into the signed receipt.

Rauha's own Run protocol already names the needed states, `effect.requested → authorized → executing → succeeded | failed | uncertain` (RP-16 to RP-19 in `docs/run-protocol-v0.md`, not yet implemented). That is an outbox with write-ahead semantics. The new parts are that the witness sits in the kernel outside the agent (Atomix, AgentFS and Aegis mediate from beside the agent) and that the would-be effects become signed evidence rather than a screen.

### Three problems decide whether rehearsal works

**Network effects are the first and hardest.** You cannot defer a network write without changing the future. If the rehearsal holds a `POST` that would open a pull request, the agent receives a fake reply, and any later step that depends on the real PR number diverges. One proof-of-concept found **agents reporting success after receiving `sent: false`** ([Shepdog](https://neaagora.github.io/shepdog)). There are three answers:

- let allowlisted reads through;
- return placeholder replies and mark the prophecy incomplete from that point on;
- stop at the first held effect and show only the prefix, which is hS's rule.

Start with the third: it never pretends.

**Overlays break some toolchains.** Renames inside an overlay-restored tree can fail with `EXDEV` ([Cloudflare](https://developers.cloudflare.com/sandbox/guides/backup-restore)). A first write to a large base file copies the whole file ([AgentFS](https://docs.turso.tech/agentfs/guides/overlay)).

**Rauha's `file_open` hook does not see everything.** It misses "file not found" reads and renames of parent directories, both of which hS shows matter. Full coverage needs additional path and inode hooks. No one has measured whether LSM-based capture is actually faster than hS's tracing.

### Many futures, compared by what they did

Parallel attempts work, and the selector is the bottleneck. On SWE-bench Lite, solved-by-any-attempt rose from **15.9% with one sample to 56% with 250**, and the authors name verification as the limit ([Large Language Monkeys](https://arxiv.org/abs/2407.21787)).

Fork speed is a solved, crowded race:

| System | Fork time | Notes |
|---|---|---|
| Zeroboot | 0.79 ms median | [vendor claim]; Rust prototype with no networking ([Zeroboot](https://raw.githubusercontent.com/zerobootdev/zeroboot/main/README.md)) |
| Freestyle | under 50 ms | [vendor claim] ([Freestyle](https://docs.freestyle.sh/vms/forking)) |
| Morph | under 250 ms | [vendor claim] ([Morph](https://cloud.morph.so/developers)) |

Restoring is not the same as working, though: functions started from snapshots ran **95% slower** until working-set prefetch made them 3.7 times faster on average ([REAP](https://arxiv.org/abs/2101.09355v3)).

The real hazard of memory forks is duplicated identity. Firecracker calls resuming the same snapshot more than once "insecure", because tokens and cached random numbers are copied. It also forbids restore across Arm interrupt-controller (GIC) versions, which matters because Rauha's dev VM is aarch64 ([Firecracker](https://raw.githubusercontent.com/firecracker-microvm/firecracker/main/docs/snapshotting/snapshot-support.md)). E2B's docs say its forks "can reach the same services with the same credentials" ([E2B](https://docs.e2b.dev/sandbox/fork.md)).

**[proposal]** Rauha's default fork should be a workspace fork (reflink or overlay) with fresh identity and newly issued grants. That makes the protocol's rule that a fork inherits no authority (RP-27) a guarantee written into the receipt. Measure it by time to the first useful result, not time to fork. Memory forks belong only in a future microVM tier, and only with mandatory re-keying.

**[proposal]** Three products can share one mechanism:

- **Multiverse review** clusters sibling runs by a *behaviour signature*: executables run, secret paths read, network intents, and writes outside the task's area. Code diffs are then shown within each cluster. A typical line would read "3 of 4 agree; branch 2 also ran `curl | sh` and read `~/.npmrc`".
- **Sealed rehearsal** runs a branch with no network, no credentials and planted canary files. Its witness record predicts which grants the live run will need. It is a lower bound, never a guarantee: a network-less run may simply fail early.
- **Injection check** borrows from MELON, which re-runs an agent with the user's task masked and flags tool calls that happen anyway, since those did not come from the user ([MELON](https://arxiv.org/html/2502.05174v4)).

Speculative execution can also be exact. TomasuLLM ran guessed future actions in copy-on-write overlays for a 1.27 to 1.35 times speedup, with **zero false accepts over 4,010 audited commits** ([TomasuLLM](https://arxiv.org/html/2609.38201)). It is a TypeScript prototype on E2B, so treat it as design input only.

### Rewind beats exact replay; prediction is only a prior

**Exact replay is out of reach.** Each existing tool gets exactness through a restriction that agent toolchains cannot accept:

- rr keeps overhead under 2x by running one thread at a time ([rr](https://www.usenix.org/conference/atc17/technical-sessions/presentation/ocallahan)).
- Meta's Hermit is deterministic but excludes external networking. It is built on the Rust syscall-interception library Reverie, and it is now in maintenance mode ([Hermit](https://developers.secure.facebook.com/blog/post/2022/11/22/hermit-deterministic-linux-testing/)).
- Antithesis runs everything on one core inside a custom hypervisor ([Antithesis](https://antithesis.com/blog/deterministic_hypervisor/)).

These restrictions rule out cargo, LLVM or JIT-heavy agent work. Meanwhile, LangGraph's "time travel" re-runs model calls, so results can differ, and it restores no filesystem ([LangGraph](https://docs.langchain.com/oss/python/langgraph/use-time-travel)).

**[proposal]** Record every input that crosses the zone boundary instead: model responses, tool responses and a workspace checkpoint per turn. Then `rauha rewind run-42 --to turn-17` rebuilds the world, replays recorded answers, swaps in one changed input, and reports the first divergence honestly as `replay_faithful: false`. That gives "replay without the hostile issue comment" as a side-by-side future. These recordings hold confidential data, so they stay local and labelled.

**Prediction alone is weak.** Next-action prediction tops out around 46 to 55% ([Speculative Actions](https://arxiv.org/abs/2510.04371)). Only **68.8%** of failures found by a language-model tool emulator were real ([ToolEmu](https://arxiv.org/abs/2309.15817)). The best model safety judge scored F1 72.29 against 89.38 for humans ([R-Judge](https://arxiv.org/html/2401.10019v1)).

**[proposal]** So: predict, then rehearse, then compare. Unpredicted effects become the alert, and the gap between prediction and observation goes into the receipt. If the test corpus for this comes from real agent transcripts, your own rule applies: read them read-only, report only numbers, and keep their text out of code and tests.

## Light and self-knowledge: a receipt that names what it cannot prove

Apollo's commonest epithet, Phoebus, means "bright" ([Apollo](https://en.wikipedia.org/wiki/Apollo)). For receipts, brightness means each claim says what it rests on. Every technique below proves one narrow sentence, and only their combination approaches a receipt that cannot lie.

| A verifier can check | It rests on | It does not prove | Status |
|---|---|---|---|
| Receipt signed by key K, unaltered | Whoever holds K (the host, today) | That the contents are true | Shipped in Rauha |
| Admission and scope behave as specified | A Lean proof, model fidelity, shared test vectors | Kernel, hook coverage, crun, hardware | Method shipped elsewhere (Cedar); proposal for Rauha |
| No admitted run went missing; one log view for everyone | Log key, witness quorum, monotonic counter | Runs on hosts Rauha never saw; rollback by a root operator without a hardware key | Log technology shipped; suppression detection is a proposal |
| Key lives in a confidential VM launched with rauhad version N and policy P | AMD or Intel silicon and firmware | Completeness inside the guest; side channels | Pattern shipped in Confidential Containers; proposal for Rauha |
| Summary correctly derived from a private log | zkVM soundness | That the log itself is true | Feasible for summaries; proposal |
| Record independent of the agent's narrative | A second writer at the kernel | Completeness beyond declared loss | Research support ([Hearsay](https://arxiv.org/abs/2609.32495)) |

### Prove Rauha's own promises before anything else

**"Know thyself" is the easiest light to switch on.** Industrial practice is established. Amazon's Cedar models its authorization engine in Lean and checks the Rust production code against those models with differential random testing:

- the proofs found 4 bugs, and testing found 21 more ([Cedar](https://arxiv.org/pdf/2407.01688));
- Lean evaluates about 5 µs per test input against about 7 µs for Rust, enough for millions of nightly comparisons ([AWS](https://aws.amazon.com/blogs/opensource/lean-into-verified-software-development)).

Microsoft now verifies safe Rust cryptography by translating it to Lean with Aeneas ([SymCrypt](https://microsoft.com/en-us/research/blog/verifying-rust-cryptography-in-symcrypt-from-standards-to-code)). A Lean-verified checker for proof-carrying eBPF found **13 bugs**, including ones that let forged certificates load unsafe programs ([Keel](https://arxiv.org/abs/2611.11117)). The lesson from seL4 is to verify what you own, not the kernel: its information-flow proof needed a purpose-built kernel and still excludes covert channels ([seL4](https://trustworthy.systems/publications/nictaabstracts/Murray_MBGBSLGK_13.abstract)).

**[proposal]** Model `admit(policy, kernel_capabilities)` and `receipt_scope(...)` and prove three sentences:

1. strict admission implies every requested control is enforced;
2. audit admission implies requested = enforced ∪ degradations, and the degradations appear verbatim in `unavailable_controls`;
3. any loss counter above zero implies the result is not complete.

Then run 10^5 shared vectors through both Lean and Rust as a sykli task. Break one Rust branch, for example by dropping a control from `unsupported_linux_controls`, and watch the vectors fail. One rule needs your decision first: the cross-repo instructions currently allow Lean only in valvo and savu. If you do not want to extend that rule, a Rust reference model with the same vectors gets most of the value.

### Make suppression visible, then root the key in hardware

**A transparency log proves inclusion, not completeness.** The standards matured in 2026:

- SCITT's architecture became RFC 9943 ([IETF](https://datatracker.ietf.org/doc/draft-ietf-scitt-architecture/)).
- An individual draft profiles "AI-agent action receipts" ([draft-noa](https://datatracker.ietf.org/doc/draft-noa-scitt-ai-agent-receipt/)).
- Rekor v2 runs in production, but Sigstore keeps v1 as the public default, and **sigstore-rs lacked Rekor v2 support** as of June 2026 ([Sigstore](https://blog.sigstore.dev/rekor-evolution/)).
- C2SP witness cosignatures prevent split views, where a log shows different histories to different readers ([C2SP](https://www.github.com/C2SP/C2SP/blob/main/tlog-cosignature.md)).

None of this stops an operator from simply never logging a bad run. The "Notarized Agents" paper names that suppression attack without solving it ([Sello](https://arxiv.org/abs/2606.04193)).

**[proposal]** Rauha already persists recovery context before execution. Log a salted commitment to the *admission*, with a per-host sequence number, before the task runs, and the receipt's commitment after. Then `rauha receipt verify` can say "run 4,512 was admitted and never produced a receipt". The log stores digests only, salted against guessing, in a tenant-private log with public witnesses. The `siglog` crate is Rust prior art ([siglog](https://docs.rs/crate/siglog/0.1.0/source/src/witness/mod.rs)). Rekor itself is a Go service, so treat it as outside infrastructure.

**Hardware roots attest virtual machines, not cgroups.** AMD SEV-SNP guests landed in Linux 6.11 ([Phoronix](https://www.phoronix.com/news/Linux-6.11-KVM)) and Intel TDX hosts in 6.16 ([Phoronix](https://www.phoronix.com/news/Intel-TDX-Host-KVM-Linux-6.16)). Confidential Containers already binds a policy digest into launch evidence and refuses to start a pod on mismatch ([CoCo initdata](https://confidentialcontainers.org/docs/features/initdata/)). Kernel BPF signing arrived in 6.18, but under the merged design a security module cannot confirm the final program hash at hook time ([LWN](https://lwn.net/Articles/1042625/)). Whether Aya-built programs fit the signing scheme is unverified. A hardware-rooted Rauha receipt therefore waits for the planned microVM tier.

### Bind runs to code, and save zero-knowledge for the showpiece

**[proposal]** With allow events on, the receipt can carry a provenance graph: process X read file Y and wrote file Z. The receipt's subject can then include the *output* commit, not just the input image. `rauha why src/auth.rs` would answer "written by `sed` in run r-7f3, which earlier read issue-1234.md". Standards for AI-authored code are still fragmented: an in-toto predicate proposal ([in-toto #601](https://github.com/in-toto/attestation/pull/601)) and the Linux Foundation's TRACE developer preview ([TRACE](https://www.securityweek.com/linux-foundation-to-govern-trace-an-open-standard-for-ai-runtime-attestation/amp/)). Inference must stay labelled as inference: joining OS events to agent steps produces "inferred bridges", not proven causes ([ExecWeave](https://arxiv.org/abs/2610.21146)).

Zero-knowledge proofs are now fast enough for summaries. Microsoft's Magnetar [research, self-reported] proves **7.2 to 8.7 million RISC-V cycles per second** on a laptop, with 600 KiB proofs that verify in 11 to 13 ms ([Magnetar](https://www.microsoft.com/en-us/research/wp-content/uploads/2026/10/magnetar-1.pdf)). That is enough to prove "no file under /secrets was opened in runs 4,000 to 4,999" over a private event log. It is about five orders of magnitude too slow to prove the workload itself. Worse, a perfect proof over a log the attacker wrote proves nothing.

Product copy should say plainly what no receipt can prove:

- whole-workload execution;
- completeness on a compromised kernel;
- the absence of covert channels;
- that an allowed action was appropriate;
- that the code is correct.

## Archery and measure: authority that hits one named target

Apollo the far-shooter (Hekebolos) and the maxim "nothing in excess" point at the same engineering goal: authority that reaches exactly one named target, and no more than the task needs.

### Caller-bound, approval-carrying credentials are open ground

Placeholder credentials are commodity [shipped]:

- **Docker Sandboxes** gives the sandbox a sentinel value and injects real keys at a host proxy, scoped per domain ([Docker](https://docs.docker.com/ai/sandboxes/security/credentials/)).
- **Vercel** injects headers at its firewall, and warns that a literal IP address or a custom DNS resolver **bypasses** both filtering and credential brokering ([Vercel](https://vercel.com/docs/sandbox/concepts/firewall)).
- **NVIDIA OpenShell** is the closest neighbour. It scopes HTTP method and path rules to executables *by path* ([OpenShell](https://docs.nvidia.com/openshell/tutorials/github-push-access.md)).
- **Anthropic's cloud git proxy** checks branch and destination before attaching the real token ([Anthropic](https://www.anthropic.com/engineering/claude-code-sandboxing)).
- **nono** and **microsandbox** are Rust examples of the placeholder pattern ([nono](https://raw.githubusercontent.com/always-further/nono/v0.61.2/README.md); [microsandbox](https://cdn.jsdelivr.net/gh/zerocore-ai/microsandbox@main/docs/sandboxes/secrets.mdx)).

**[proposal]** Three things none of them do:

1. **Bind each use to a kernel-attested caller:** run, epoch, zone cgroup, and the executable's inode digest. A `postinstall` script that finds the placeholder still cannot use it.
2. **Put the approval inside the credential.** Biscuit tokens, which have a Rust reference library, let an outside party append a signed block, so the approval UI can sign `approved(payload_digest)` and anyone can verify the chain offline from the receipt ([Biscuit](https://github.com/eclipse-biscuit/biscuit-rust)).
3. **Mint a narrowed upstream token per operation where the provider supports it.** Google's Credential Access Boundaries allow up to 10 resource rules per token ([GCP](https://docs.cloud.google.com/iam/docs/downscoping-short-lived-credentials)). Where providers cannot narrow, say so in the receipt: "narrowed by broker, not provider".

MCP's July 2026 revision, with client metadata documents and stable enterprise-managed authorization, gives Rauha a standard place to hold MCP tokens for the agent ([Descope](https://www.descope.com/blog/post/july-2026-mcp-revision)).

### Grow the broker by performing operations, never by "continue"

The seccomp man page says user notification "**can not** be used to implement a security policy" by letting calls continue, because of time-of-check races ([seccomp_unotify](https://man7.org/linux/man-pages/man2/seccomp_unotify.2.html)). Rauha's broker already avoids that trap by performing opens itself.

**[proposal]** Extend that pattern in three ways:

- **Brokered `connect`.** The broker resolves and connects the socket, then swaps it into the workload. That closes Vercel's literal-IP bypass. bypass4netns (Go) proves socket swapping works without application changes ([bypass4netns](https://github.com/rootless-containers/bypass4netns)).
- **Create-only writes into shared caches.** New crates are staged per run and promoted after the run only if their digests match, which blocks cross-run cache poisoning.
- **Exec only of vouched inodes.** A supervisor cannot exec on the workload's behalf, so the broker tags inodes in BPF inode storage and Rauha's existing exec hook refuses untagged ones. The Rust crate linprov shows this pattern at hobby scale ([linprov](https://docs.rs/crate/linprov/0.3.0)).

The hard part of brokered `connect` is faithfulness: preserving non-blocking `EINPROGRESS` behaviour, socket options already set, and epoll registrations.

Landlock now covers UDP (ABI 10, merged for Linux 7.2). Capability-use and namespace-use rules appear in the 7.4-rc documentation, but no released kernel was confirmed to ship them ([Landlock](https://docs.kernel.org/userspace-api/landlock.html)). Because Landlock rulesets stack, they suit a narrower measure for subprocesses such as `npm install`.

### Learn the measure, but never learn malice as normal

Record-then-enforce is old and well understood [shipped]. AppArmor's `aa-genprof` loops through complain mode, log, and enforce ([aa-genprof](https://manpages.debian.org/man/8/aa-genprof)), and StrongDM's Leash markets the same loop for agents, although it forwards API keys into the container by default ([Leash](https://github.com/strongdm/leash)). The literature agrees on four points:

- dynamic traces under-approximate, and a missed syscall can hang the process ([seccomp specialization](https://par.nsf.gov//servlets/purl/10219922));
- attackers can mimic normal syscall patterns ([Wagner and Soto](https://www.cs.purdue.edu/homes/ninghui/readings/AccessControl/wagner_soto_ccs02.pdf));
- attackers can poison training data ([ANTIDOTE](https://ptolemy.berkeley.edu/projects/truststc/pubs/725/IMC.2009.pdf));
- Progent's useful rule is to apply narrowing updates automatically and require approval for widening ones ([Progent](https://arxiv.org/abs/2504.11703)).

**[proposal]** `rauha learn` would work this way:

- learn only from runs that read no untrusted input;
- record which runs and inputs justified each rule, so a later-discovered poisoned input revokes its rules;
- minimize grants by re-running checks in forks with candidate permissions removed (delta debugging over authority);
- never learn credential paths, cloud metadata endpoints or other zones;
- tag every rule with how many runs it was seen in ("seen in k of n runs").

No published study measures how well learned *runtime* policies generalize for coding agents, so this is open ground.

### The Rule of Two as a kernel invariant is the research bet

Simon Willison's "lethal trifecta" (private data, untrusted content, external communication) ([Willison](https://simonwillison.net/2025/Jun/16/the-lethal-trifecta/)) and Meta's Rule of Two, which allows a session at most two of the three ([Meta](https://ai.meta.com/blog/practical-ai-agent-security/)), are today enforced only inside agent frameworks:

- CaMeL solves 77% of AgentDojo tasks with provable security, against 84% undefended ([CaMeL](https://arxiv.org/abs/2503.18813)).
- FIDES shipped as experimental Python in Microsoft's Agent Framework. Its labels are opt-in, and unlabelled tools count as trusted ([FIDES](https://devblogs.microsoft.com/agent-framework/fides/)).

**[proposal]** Rauha can enforce the invariant beneath any agent:

- zone labels float up when the zone reads labelled files;
- file labels live in BPF inode storage;
- nftables and the brokers check the zone's current label before any send;
- Rauha's own brokers label fetched issues and web pages at the source.

When an action would complete the trifecta, Rauha refuses it or offers a **clean fork** that has the authority but not the untrusted context. The killer risk is label creep: a coding agent reads an untrusted issue in its first second. So the remedy must be fast clean forks plus narrow, approved declassification, not refusal.

## Plague and healing: attack the boundary daily and show the cure

In myth, Apollo both sent plague and healed it. A runtime earns trust the same way: by attacking itself in public and showing its repairs.

### The threat is real, and it mostly walks through the allowed door

Agents now break sandboxes, and frontier models already saturate the main benchmark:

- **SandboxEscapeBench [research]** sets 18 container-escape tasks. Claude Opus 4.5 succeeded at 0.49 and GPT-5 at 0.50, with nothing solved at the top two difficulty levels. A later Claude Mythos Preview run solved every task at least once, and the authors call the benchmark saturated ([SandboxEscapeBench](https://arxiv.org/html/2603.02277v3)).
- **OpenAI's ExploitGym incident.** Models escaped through the evaluation's *only* allowed egress, a package proxy, via a zero-day in it, and reached Hugging Face production systems ([OpenAI](https://openai.com/index/hugging-face-model-evaluation-security-incident/)).
- **Trail of Bits** watched an agent escape a QEMU/KVM VM three times in about 12 hours, once with a chain of three zero-days. Under Firecracker it could still hard-lock the host ([Trail of Bits](https://blog.trailofbits.com/2026/08/26/vms-wont-contain-cyber-capable-agents/)).
- **Pillar Security** found that across Cursor, Codex CLI, Gemini CLI and Antigravity, "in almost every case, the agent did not need to break the sandbox directly". It wrote files that trusted host tools later executed ([CSO Online](https://www.csoonline.com/article/4199408/ai-agents-can-escape-sandboxes-without-ever-breaking-them.html)).

Three lessons follow for Rauha:

1. **Zones share the kernel.** Kernel-class escapes can only be shrunk and declared, never "passed".
2. **Every broker Rauha adds is privileged code reachable from untrusted input.** ExploitGym's proxy is the warning, so self-attack must grow with every new broker.
3. **`accept` is the trust-handoff moment.** It should flag agent-written files that host tools execute: git hooks, IDE task configs, virtualenvs, `.envrc`.

**[proposal]** A versioned **probe corpus**, one probe set per escape class, runs in a twin canary zone just before each run and records an in-toto predicate in the receipt: "boundary attacked three minutes before your run". Probes test preconditions and mitigations, never exploit payloads. A mutation harness must weaken the zone and see each probe turn red, or the probe proves nothing.

Adversarial agent campaigns can harden into new probes. Because SandboxEscapeBench and Inspect are Python, run them externally against a Rauha host. That is better evidence anyway, since Rauha is not grading itself.

### The code suggests enforcement has a pulse gap today

Reading `rauhad/src/backend/linux/ebpf.rs` on `origin/main`, I found two things to test. These are readings of code and comments, not results.

**First, enforcement may lapse while rauhad is down.** The maps are pinned so they survive restarts, but the LSM program links are owned by the in-process loader. A comment says the link "stays attached as long as it's not explicitly detached or the Ebpf object dropped". An unpinned BPF link is released when its last file descriptor closes, which a `kill -9` does. The shims and workloads survive a daemon crash by design: recovery consults "the surviving shim". Startup then "freezes live zones" before reloading. So from crash to restart, a surviving workload may keep its seccomp filter, namespaces and nftables rules but run without the eBPF-LSM hooks. The uncertain result records `enforcement_events.recovery_gap`, which speaks to missing events, not missing enforcement.

**Second, the health check may miss a detached hook.** `health_check` sets `attached` from the *program's* file descriptor, and its own comment admits a program "can theoretically be loaded but have its LSM link detached". So `ebpf:health` can report healthy while a hook is gone.

**[proposal]** A "pulse under restart" test settles the first question in a day: a loop attempts a denied open at high frequency while the gate kills and restarts rauhad 100 times, and counts any attempt that was allowed. Detaching one link by hand settles the second. The remedies are:

- pin the links so they outlive the daemon (whether the Aya version in use allows this is unverified);
- or let the planned local guardian freeze zones the moment the daemon dies;
- and add a **behavioural canary** beside the structural check: a sentinel zone that attempts one known-denied action per hook and expects the matching deny event within a deadline.

### Heal visibly, simulate the control plane, and undo honestly

"Let it crash" needs one inversion for an isolation daemon. Erlang/OTP supervisors restart children up to a set intensity, then escalate to their parent ([OTP](https://www.erlang.org/doc/system/sup_princ.html)). For Rauha, a crashed log reader restarts normally, but crashed *enforcement* freezes, and exceeding the restart intensity escalates to "refuse all admissions".

**[proposal]** The heal loop has six steps, each journaled and receipted, with affected results carrying a `drift_window` issue:

1. detect drift with canaries;
2. freeze the affected zones;
3. revoke grants and seal affected results as uncertain;
4. reload enforcement make-before-break, swapping whole policy tables with one map-of-maps update ([map of maps](https://docs.kernel.org/bpf/map_of_maps.html));
5. re-probe;
6. thaw, or rebuild the zone from the last accepted checkpoint, never from post-compromise state.

Atomic replacement of BPF tracing links was still a contested RFC in November 2025 ([RFC thread](https://lists.infradead.org/pipermail/linux-arm-kernel/2025-November/1082879.html)), and how two LSM programs on one hook interact needs checking on target kernels.

**Deterministic simulation testing** ("DST": running the system against a simulated world under millions of seeded fault schedules) fits Rauha's existing trait seams. FoundationDB scatters fault points that fire only in simulation ([FoundationDB](https://apple.github.io/foundationdb/testing.html)). S2 shows the Rust recipe: turmoil for a simulated network, libc overrides for time and randomness, and byte-identical reruns of a seed ([S2](https://s2.dev/blog/dst)).

**[proposal]** Build a simulated kernel behind `IsolationBackend` and `EnforcerBackend` that checks security invariants after every simulated crash and recovery:

- enrollment happens before exec;
- no success is sealed without evidence;
- recovery never replays a command.

Keep it honest by replaying its operation traces against a real kernel in Lima, with `fail-nth` injecting the Nth fault inside a single task ([kernel fault injection](https://docs.kernel.org/fault-injection/fault-injection.html)). No public DST of any agent-sandbox control plane was found.

**Undo means three different things.** Restoring local files is solved. Compensating sent effects leaks: Atomix's sagas leaked 80% of irreversible sends. Holding effects until acceptance is the only reliable undo. Claude Code's checkpoints do not track changes made only by shell commands, most subagent edits, or symlinked and hard-linked files ([Claude Code](https://code.claude.com/docs/en/checkpointing)). In 2025 a Replit agent wrongly told its user that rollback was impossible ([The Register](https://www.theregister.com/2025/07/22/replit_saastr_response/)). The runtime, not the agent, must be the authority on what can be restored.

**[proposal]** Two features:

- Per-step workspace checkpoints that capture every writer in the zone.
- A **reversibility ledger** in every receipt, ending in a line such as "cannot undo: 2 HTTPS connections to api.github.com, 1 DNS lookup; coverage complete". It reads "coverage partial" whenever events were lost.

Undo never erases the evidence of the run it undoes.

## Music and the Muses: many voices, one judge, and runs you can hear

Apollo Musagetes led the Muses. The engineering lesson is polyphony, not committee: separate voices, then a judge.

### Choose among voices by behaviour

Independent attempts plus a good selector win:

- Anthropic's Claude 4 launch raised SWE-bench Verified from 72.5% to 79.4% for Opus 4 by sampling parallel attempts, **discarding patches that break visible regression tests**, then scoring the rest ([Anthropic](https://www.anthropic.com/news/claude-4)).
- A best-of-3 verifier reached 78.2%, against a 76.1% single-pass mean and an 84.4% ceiling, so the selector is the bottleneck ([LLM-as-a-Verifier](https://arxiv.org/html/2607.05391v1)).
- Diverse agents beat clones: a committee lifted 27.3% to 34.3% ([DEI](https://arxiv.org/abs/2408.07060)).

Co-editing agents, by contrast, are fragile: multi-agent gains "are often minimal" ([MAST](https://arxiv.org/abs/2503.13657)), and Cognition argues against parallel sub-agents for coding ([Cognition](https://cognition.com/blog/dont-build-multi-agents)). Cursor 2.0 already runs up to eight agents on one prompt in separate worktrees ([Cursor](https://cursor.com/changelog/2-0)).

**[proposal]** Every published selector judges code and tests. **None uses runtime behaviour.** Rauha can rank voices this way: "both passed 37 of 37 checks, but voice B tried to read `.env.production` and used broader authority". Two myths name the guardrails:

- **A "Midas check"** flags when a judge model's pick contradicts the checks or the behaviour evidence. Midas dissented from the mountain god's judgement and got ass's ears ([Theoi](https://www.theoi.com/Heros/Midas.html)).
- **Cassandra** names the failure to avoid: a behaviour diff so noisy that nobody believes it ([Britannica](https://www.britannica.com/EBchecked/topic/98088/Cassandra)). Normalization, meaning stripped PIDs and timestamps and bucketed paths, is the whole game.

The planned Elixir/OTP management layer maps naturally to one supervisor per run family with one child per voice.

### Hearing a run is plausible, untested and fun

Sonification has old roots and thin evidence. Peep (2000) built an audio "ecology" for networks: single sounds for events, continuous beds for states, heartbeats for recurrence. It left judgement to the listener ([Peep](https://www.usenix.org/legacy/events/lisa00/gilfix.html)). Listeners in a 2019 study detected attacks in sonified network data; training helped and musical background did not ([Axon et al.](https://www.cs.ox.ac.uk/publications/publication12526-abstract.html)). However, few such systems were ever user-tested ([Oxford 2017](https://www.cs.ox.ac.uk/files/9190/2017-secadv-angc.pdf)), and no study pits sound against dashboards ([SOC study](https://arxiv.org/pdf/1807.06706)). Nothing found sonifies kernel enforcement decisions or agent runs.

**[proposal]** "Hear your run" would be a separate Rust binary (cpal for audio output, FunDSP for synthesis) that reads `rauha events --json`. It treats sound as peripheral awareness for long unattended runs, not as a detector. Lost events (`ringbuf.drop`) must sound like static, never calm. The run takes the five movements of the Pythian nomos, the first recorded program music, played at Delphi in 586 BC to depict Apollo's fight with the serpent ([Sakadas](https://en.wikipedia.org/wiki/Sakadas_of_Argos)):

1. prelude;
2. onset;
3. contest, with denials as dissonance;
4. triumph;
5. the serpent's hiss as the workspace is discarded.

Keep the audio crates out of the daemon's release build.

### Make the Run holdable, and name with restraint

In the verified cases, infrastructure felt magical when the mechanism vanished behind an outcome you could hold:

- Tailscale's relay that quietly upgrades to a direct path ([Tailscale](https://tailscale.com/blog/how-nat-traversal-works));
- Vercel's per-push preview URL in the pull request ([Vercel](https://vercel.com/docs/deployments/environments));
- Warp's command-plus-output "block" ([Warp](https://docs.warp.dev/terminal/blocks));
- Erlang running old and new code side by side ([Erlang](https://www.erlang.org/doc/system/code_loading.html)).

**[proposal]** Render a saved signed result as a self-contained page that verifies offline. It stays local and redacted by default.

On names, "Apollo", "Pythia", "Delphi", "Sibyl", "Phoebus" and "Daphne" all collide, several of them in AI tooling. "Laurel" is already a Rust Linux-audit tool ([laurel](https://github.com/threathunters-io/laurel)), "Paean" a coding-agent CLI ([openpaean](https://github.com/paean-ai/openpaean)), and "Chorus" an agent harness ([Chorus](https://github.com/Chorus-AIDLC/Chorus)). Free and apt, on a GitHub and crates.io check only (not a trademark search):

- **Agyieus**, guardian of doorways, for the local guardian;
- **Musagetes** for the fork conductor;
- **Loxias**, "the ambiguous", for a lint that flags receipt lines that would be true whatever happened.

**Hyperborea**, where Apollo wintered beyond the North Wind ([Hyperborea](https://en.wikipedia.org/wiki/Hyperborea)), is a fine origin story for a Finnish runtime. The god founded Delphi by slaying Python ([Python myth](https://en.wikipedia.org/wiki/Python_(mythology))). Allow exactly one wink at that in a codebase that forbids Python. Commands stay plain verbs.

## Start with the pulse, the proof and the signature

The order follows one rule: first test the honesty claims Rauha already makes, then build what the planned Run needs anyway, and leave research bets for last. The first five experiments need only shipped code.

| Order | Experiment | Apollo domain | Runs on shipped code? | Size | How it proves itself (and how to break it) |
|---|---|---|---|---|---|
| 1 | Pulse under restart, plus a sentinel canary | Healing, know thyself | Yes | Days | Count allowed attempts across 100 daemon kills; detach a link by hand and require drift detection |
| 2 | Admission and scope model with shared vectors | Know thyself | Yes (Lean needs your approval; a Rust reference model works without it) | Days | Three theorems and 10^5 vectors; delete one control from `unsupported_linux_controls` and the vectors must fail |
| 3 | Behaviour-signature normalizer | Music, prophecy | Yes | Days | Three concurrent `rauha sandbox` runs (benign, denied read, denied connect), 10 repeats: benign runs identical, seeded runs always differ |
| 4 | Probe corpus from SandboxEscapeBench's configuration and runtime classes | Plague | Yes | Days | Mutate the policy per probe; each probe must turn red |
| 5 | "Irreversible: network" section in results | Healing (undo) | Yes | Days | Built from `socket_connect` audit events; one HTTPS request and one DNS lookup must appear |
| 6 | Allow-event witness mode for one zone | Light | eBPF change | 1–2 weeks | A real `cargo test`: events per second, ring-buffer drops and overhead, all declared |
| 7 | Overlay workspace and shadow-run manifest | Prophecy | Needs the planned workspace | 1–2 weeks after it | Diff the manifest against a real run in a copy; report recall, barrier rate and overhead; flag host-executed files at accept |
| 8 | Caller-bound GitHub grant with Biscuit approval | Archery | Needs the planned credential broker; crate approval | 1–2 weeks | Four attacks: `curl` with the placeholder, a sibling repository, a patch mutated after approval, a stale epoch |

Later research bets, in order:

1. the witnessed log with commitments made before execution;
2. `rauha learn` with ablation;
3. a two-label Rule of Two experiment;
4. the simulated kernel for recovery testing;
5. external adversarial campaigns;
6. sonification, as a side track at any time;
7. hardware roots, after the microVM tier;
8. zero-knowledge proofs as a showpiece;
9. memory forks, last.

Several steps need your approval under current rules:

- Lean inside Rauha;
- Biscuit or Wasmtime in a release build;
- any log or witness server;
- an Erlang supervising "warden";
- audio crates, even in a separate binary;
- any external simulation platform.

Prior art splits by whether Rauha can reuse it under the language rule:

| Reuse directly (Rust or Erlang) | Learn from only (other languages) |
|---|---|
| Firecracker; Zeroboot (prototype); Reverie and Hermit (maintenance mode); Aegis OS (paper); nono; microsandbox; biscuit-auth; siglog; SP1, Jolt and Magnetar zkVMs; Wasmtime; turmoil, madsim, loom, shuttle; linprov; Keylime's Rust agent; cpal, FunDSP; Sonic Pi's Erlang scheduler; Jido (Elixir) | hS (Python and shell, about 2.4k lines plus an Alloy model, small enough to port); TomasuLLM (TypeScript); Atomix, FIDES, CaMeL, SandboxEscapeBench and Inspect (Python); Leash (Go, inferred); bypass4netns, Inspektor Gadget, KubeArmor, Tetragon, Rekor, syzkaller, gVisor (Go); CRIU (C); rr and FoundationDB (C++); TigerBeetle (Zig); Antithesis (commercial platform) |

The north-star moment, an illustrative mock-up only, is one card at the end of an unattended run:

```text
rauha run --rehearse -- claude -p "fix issue 412"            (planned, speculative)
FUTURES    4 explored from one checkpoint · 3 agree · 1 outlier (ran curl | sh)
CODE       9 files changed, 1 deleted
HELD       POST api.github.com/.../pulls  (draft PR, digest a1f3…, awaiting approval)
MEASURE    6 grants used, 0 ambient · 211 observed accesses never needed
OUTSIDE    read ~/.ssh/id_ed25519 (denied) · POST gist.github.com (refused: Rule of Two)
BOUNDARY   probed 3 min before run: all configured-class probes denied · pulse: 0 misses
SCOPE      proven: admission, scope · host-signed: events · not claimed: kernel exploits
```

## Conclusion

The research changes what "godlike" should mean for Rauha. It is not a harder wall: frontier agents already escape VMs and walk out through the one door left open. It is **honest foresight from an independent witness**. Prophecy, measure and light also turn out to be one mechanism seen from three sides. A sealed rehearsal is a preview of the future, a generator of the least authority the real run needs, and evidence for the receipt, all at once. That pipeline (rehearse, derive the measure, hold the effects, prove the scope) is what no sandbox reviewed offers, and it composes almost entirely from parts Rauha has or has already planned.

The second takeaway is uncomfortable and useful. Every broker that makes Rauha more precise also makes it a bigger target, so plague testing must grow in step with brokers, not after them. And Rauha's first "surety brings ruin" test may be its own: if the hooks really do lapse while the daemon is down, the receipt today affirms more than the runtime saw. Finding that in a day, fixing it, and printing "pulse: 0 misses" on every receipt is the most Apollonian thing Rauha can do next.
