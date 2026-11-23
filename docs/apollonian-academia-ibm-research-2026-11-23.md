# Become the Runtime the Papers Assume

Research date: 2026-11-23, against Rauha `origin/main` (code citations unchanged at 56781e6). Second round of [Apollonian directions for Rauha](apollonian-directions-2026-11-23.md) ("the first report" below), going deeper into academic research and IBM Research. A research report, not a plan: every direction marked [proposal] is undecided.

The way for Rauha to become Apollonian is not a thicker wall. It is to become **the floor the newest agent-security research quietly assumes and nobody has built**: a Linux runtime, below any agent framework, that enforces authority in the kernel, writes its own record of what happened, and says plainly what that record cannot prove. Since late 2025 the academic consensus has been that the model is untrusted and enforcement belongs in deterministic systems code. Yet almost every published defense enforces at the tool-call layer, so it holds only if every effect passes through that layer, which stops being true the moment an agent runs a shell. Only two prototypes move enforcement to the operating-system boundary: Kairos, a microVM design that cannot tell which process acted, and ZTAC, a macOS broker. Every IBM Research agent framework examined hands isolation to "your container runtime", and one IBM library states in its own code that its network and filesystem limits are not enforced. Theory also draws hard edges. No single run can show that no information leaked, a monitor that judges one action at a time provably misses violations that only appear when two runs are compared, and covert channels on a shared kernel can be bounded but never ruled out. Mapped to Apollo's domains, the deeper version of Rauha looks like this:

| Apollo's domain | Direction for Rauha |
|---|---|
| Prophecy | Twin runs in which only the run that never saw your secrets may speak in public. This is sound without deterministic models |
| Light | A witness that records compact flows, hashes every binary a run executes, and splits its receipt by kind of leak |
| Archery | Authority bound to one object and one epoch, revoked in the kernel from losing siblings at accept |
| Healing | Repair of poisoned runs by forking them, never by rewriting history |

Four experiments come first, each a few days on shipped code:

1. A daemon-restart test of whether enforcement survives, with IMA's rule of spoiling the record when it cannot vouch.
2. A run epoch in the kernel map that revokes a sibling run's authority.
3. A receipt that states an upper bound on outbound traffic and says "covert channels: not covered".
4. A relational property test of the broker's decision.

## Every agent defense assumes a floor that nobody has built

### Terms and labels used below

| Term | Plain meaning | Status in Rauha |
|---|---|---|
| Zone | The boundary around one task: its files, processes, network, resource limits, policy and audit trail, managed as one unit | Shipped |
| eBPF-LSM hooks | Small programs in the kernel's security checkpoints (file open, exec, ptrace, signals, cgroup moves, privileged capabilities). They refuse cross-zone actions and stream each refusal out as an event | Shipped. Six hooks enforce; network connect is only audited, and nftables enforces it |
| Seccomp broker | For chosen system calls (today `openat` and `openat2`), the kernel pauses the call. The zone's supervisor (the "shim") judges it, opens the file itself, and hands back only the file handle | Shipped, read-only opens |
| Strict admission | A task whose policy asks for a control the host cannot enforce is refused rather than run | Shipped |
| Receipt | The signed result of a task: Ed25519 plus a DSSE/in-toto envelope, checkable offline | Shipped |
| Allow events | Records of *permitted* actions. Today only refusals become events; permitted actions are bare counters | Missing |
| Run, fork, accept; RP-xx | The planned product: a task as a portable object that can be forked, compared and accepted. RP-xx are numbered rules in `docs/run-protocol-v0.md`, for example RP-27 "a fork inherits no authority" | Planned |
| Epoch | A generation number on a Run's authority. Brokers reject effects stamped with an older epoch (RP-13) | Planned |

**Labels.** **[theorem]** is a proved result, given with its assumptions. **[measured]** is a number from an evaluation, nearly always the authors' own; "preprint" means it has not been peer-reviewed. **[claim]** is an author's or vendor's statement with no proof or measurement behind it. **[shipped]** means released upstream or in a product. **[proposal]** is my speculation for Rauha. Rauha facts come from `origin/main`.

### The literature agrees the model is untrusted, then trusts the dispatcher

**[claim]** The December 2025 systematization of knowledge (SoK) on agentic computing says that "building provable defenses on probabilistic and non-deterministic TCB is a challenging—perhaps impossible—task", where the TCB is the trusted computing base. It also names information-flow control and least privilege as open problems ([SoK](https://arxiv.org/html/2512.01295v2)). A NeurIPS 2026 oral paper puts it bluntly: the model "must be treated as an untrusted component" ([Agent Security is a Systems Problem](https://arxiv.org/abs/2605.18991)).

Detection-style defenses failed under adaptive attack. **[measured]** "The Attacker Moves Second" (USENIX Security 2026) bypassed **12 published defenses, most at above 90% attack success**. It beat MELON, the masked re-execution detector the first report borrowed from, with **instructions that fire in the first run and stay silent in the second** ([Nasr et al.](https://arxiv.org/html/2510.09023v1)).

**[theorem]** "Local Allow, Global Deny" (IEEE TPS 2026) proves that some purpose violations are two-run properties. A monitor that judges actions one at a time "detects none of them". **[measured]** In the same paper, nine model judges approved the offending actions one by one and flagged them when shown both executions side by side ([arXiv 2610.27620](https://arxiv.org/abs/2610.27620)).

The structural defenses mostly enforce at the tool-dispatch or gateway layer: CaMeL, FIDES, Progent, APPA, PORTICO, ACE, Conseca and IsolateGPT. Each holds only if every effect passes through the dispatcher. APPA, for example, assumes all effects cross its tool dispatch or MCP gateway ([APPA](https://arxiv.org/abs/2607.24625)). For a coding agent, one generated `curl` walks around all of them.

Only two 2026 preprints build their own boundary below the tools:

| | Kairos (Oct 2026) | ZTAC (Oct 2026) |
|---|---|---|
| Mechanism | Unmodified agent in a microVM; OverlayFS; a TLS proxy that stalls state-changing requests | ~3.2k lines of trusted Rust on **macOS**; the broker resolves each request to the object it will act on and decides on that object |
| Result **[measured, preprint]** | AgentDojo attack success **47.0% → 2.7%** | Lost **2 of 74** attacks, against 66 for a tool allowlist and 56 for an allowlist plus a typical command sandbox |
| Admitted limits | Cannot tell which process issued an effect; cannot tell an attacker's value from an identical trusted one; **one speculative scope at a time** | Both losses encoded a secret into traffic to an *allowed* endpoint |
| Source | [Kairos](https://arxiv.org/html/2610.18457) | [ZTAC](https://arxiv.org/abs/2610.14488) |

Neither is a Linux runtime that attributes effects to processes and signs its evidence. Mind the name collision: the agent-boundary Kairos is unrelated to the 2024 Kairos provenance intrusion detector cited later.

### The agent-OS papers and IBM's stack say the same thing in different words

The new "agent operating system" literature splits in two:

- **Resource managers.** AIOS's "kernel" is a library whose access control is a hashmap from agent ID to privilege groups ([AIOS](https://arxiv.org/html/2403.16971v5)).
- **Authority-and-evidence libraries.** Agent libOS separates operation admission, information-flow admission and evidence, then states that it "does not provide kernel-grade sandboxing" ([Agent libOS](https://arxiv.org/abs/2606.03895)).

**[claim]** IBM T.J. Watson's Steinder and Franke propose 13 agent-OS primitives, argue that "reliability and safety in agent-based systems are infrastructure properties, not model properties", and call for "transactional filesystem sandboxing with copy-on-write" ([Steinder & Franke](https://arxiv.org/html/2607.25076)). The field now has its own workshop: AgenticOS at ASPLOS and SOSP 2026. Its SOSP program lists "Externalization Barriers" and "OS-Level Intent-Driven Capabilities" by title only, and eBPF appears nowhere on the page ([AgenticOS 2026](https://os-for-agent.github.io/)).

IBM Research's own agent code hands the wall to someone else, every time:

| IBM project | Where isolation goes |
|---|---|
| BeeAI code interpreter | Production needs "a secure container runtime (gVisor, Kata Containers, Firecracker, etc.)"; now unmaintained ([BeeAI](https://github.com/i-am-bee/beeai-code-interpreter)) |
| ContextForge | Tells users to "Always use a sandbox, container, or microVM" ([ContextForge](https://raw.githubusercontent.com/IBM/mcp-context-forge/main/README.md)) |
| CUGA | Defaults to `native` local execution ([CUGA](https://github.com/cuga-project/cuga-agent/blob/main/docs/readme/configuration-guide.md)) |
| Mellea | Declares network, filesystem and subprocess limits with companion flags `ENFORCED_… = False`, calling it an "honest gap" ([Mellea](https://github.com/generative-computing/mellea/blob/main/mellea/stdlib/tools/execution_policy.py)) |
| Rossoctl (formerly Kagenti) | Its security model says "Traffic that avoids the sidecar … is outside the model" ([Rossoctl](https://github.com/rossoctl/rossoctl/blob/main/docs/security/index.md)) |

IBM's AI Ethics Board names privilege escalation, covert channels, untraceable actions and non-reversibility as agent risks. Its mitigations are guardrails, observability and least-tool design, with no sandboxing named ([IBM AI Ethics Board](https://www-api.ibm.com/adobe/assets/urn:aaid:aem:16555813-4485-4bd5-bdfe-79e5266aebcb/original/as/ai-agents-opportunities-risks-and-mitigations.pdf)).

Put together, the picture is consistent. Academia and IBM have built the upper floors (planners, labels, tool guards, identity, evaluation) on an assumed floor. Rauha already is a floor of the right kind, with one property none of them has: it is a second writer. The first report's Hearsay result still anchors that point. With a sandbox ledger as a second writer, a checker flagged **64 of 66 altered records and 0 of 84 clean ones** ([Hearsay](https://arxiv.org/abs/2609.32495)).

### What this round adds to, changes in, or overturns from the first report

| First report said | This round finds | Verdict |
|---|---|---|
| An "injection check" that borrows MELON's masked re-run | MELON fell to conditional triggers. Comparing agent behaviour is advisory, never a guarantee | **Overturns** |
| The Rule of Two enforced by labels that float up as a zone reads sensitive data | Enforcement from outside a process, without seeing inside it, takes exponential time in the number of principals **[theorem]**. Twin-zone secure multi-execution, and a three-zone split for integrity, give the guarantee structurally. Labels become secondary, and a differential-taint check fights label creep | **Changes the primary mechanism** |
| Prove admission and receipt scope in Lean (needs your approval) | Verus proves Rust code itself (Atmosphere: ~6k lines). The targets widen to authority confinement and decision independence, which a relational property test covers with no new toolchain | **Changes the tool and widens the target** |
| An allow-event mode that emits allowed actions as events | Emit IBM SysFlow-style *flows* aggregated in the kernel, on a separate ring buffer, never using reductions that delete exfiltration evidence | **Changes the design** |
| Receipts must not claim covert-channel freedom | Theory now says why: no-leak guarantees are two-run properties. Receipts should split claims by channel class and state an overt-capacity bound | **Adds a foundation** |
| A future microVM tier for stronger isolation | In 2021 measurements Firecracker reached the *most* host-kernel code of any platform tested. A VM tier must be measured, not assumed safer | **Corrects an assumption** |
| Pulse-under-restart test | Add IMA's fail-safe rule: when enforcement continuity cannot be proven, receipts must say "gap" | **Adds** |
| Shadow run with held effects | Adds Speculator-style "keep working while held", Fabric-style validation of what the run read at accept, and kernel-enforced revocation of sibling authority | **Adds** |
| Undo means three things | Three decades of intrusion-recovery work say disclosures can never be undone; repair should fork, not rewrite; and 2026 attacks on agent rollback validate RP-13, RP-16 to RP-18 and RP-26/27 | **Adds; validates the protocol** |
| Aegis OS is the closest competitor ([Aegis OS](https://arxiv.org/abs/2611.08516)) | Kairos and ZTAC are closer: both enforce at an OS boundary | **Changes** |
| Sonification as a side track | Nothing new | Unchanged |

### What remains unclaimed

The capabilities below appear in no system found in either round. My confidence comes from abstracts and titles. The full texts of several AgenticOS 2026 talks ("Externalization Barriers", "Intent-Driven Capabilities", "Agate", "Isolation in the Age of Agents") were not available, and any of them may overlap.

| Unclaimed capability | Nearest prior art, and why it falls short |
|---|---|
| A Linux runtime that attributes effects to processes and sits below agent frameworks as their reference monitor | Kairos (microVM, no process attribution); ZTAC (macOS); every tool-layer defense assumes it |
| Secure multi-execution as a *release rule* for LLM agents at process-tree level | MELON (a detector, broken); TightLip (2007, lockstep twins, no LLM) |
| A kernel-visible Run whose epoch and mode revoke losing siblings' authority at accept | Fork, Explore, Commit invalidates sibling *files* only and is not a security boundary |
| A kernel-witnessed action history graph, repair as a fork, declared loss, and signed receipts for both the original and the healed run | Retro, Warp and Aire (no loss declaration, no LLM actors); the agent-rewind artifact (Python, harness-level) |
| Receipts split by Lampson's channel classes, with an overt-capacity bound | Kairos and ZTAC put covert channels out of scope |
| A formal confinement theorem for the runtime's own decision code, with kernel assumptions printed in the receipt | ZTAC has 3.2k lines of trusted Rust and no proof |
| A per-run list of executed-binary hashes on a stock kernel | IMA namespaces are unmerged; VIMA is out of tree |
| Validating at accept that what the run read has not changed | No agent sandbox found does this |
| A rollback-attack conformance suite shipped by the runtime | ACRFence and "Safe to Resume?" show that frameworks fail |
| A published, per-policy kernel-exposure number for an agent sandbox | None found |
| A two-layer red-team score: did the agent comply, and did the effect happen? | ARES judges from text only |

## Theory caps every receipt at authority and the size of the door

The Delphic maxims "know thyself" and "nothing in excess" already describe `rauha zone verify` and least authority ([Delphic maxims](https://en.wikipedia.org/wiki/Delphic_maxims)). Theory adds the hard part of self-knowledge: knowing which sentences a receipt is allowed to say.

### Fifty years of confinement theory say what no receipt may claim

**[claim]** Lampson's 1973 confinement paper split leaks into three classes:

- **storage** channels: shared objects such as files;
- **legitimate** (overt) channels: the outputs a program is supposed to produce;
- **covert** channels: effects such as system load or lock state.

He warned there is "not likely to be any rigorous way of identifying every channel in any system of even moderate complexity". He offered a fallback: "bound the capacity of the covert channels" ([Lampson 1973](https://crypto.stanford.edu/cs155old/cs155-spring11/papers/confinement.pdf)).

**[theorem]** Clarkson and Schneider classify noninterference (the property that secret inputs never influence public outputs) as a **2-safety hyperproperty**. A violation shows up only as a *pair* of runs that differ in secrets yet look different to a public observer, so no record of one run can certify it ([Clarkson & Schneider](https://ecommons.cornell.edu/bitstream/1813/11660/4/hyperproperties-tr.pdf)).

Even the best verified kernels prove only part of this:

| Kernel | What is proved | Conditions |
|---|---|---|
| seL4 **[theorem]** | Information-flow security over 8,830 lines of C | A static round-robin scheduler, DMA off, no device interrupts; "excludes timing channels" ([seL4](https://sel4.systems/Research/pdfs/sel4-from-general-purpose-to-proof-information-flow-enforcement.pdf)) |
| mCertiKOS | Isolation | IPC disabled entirely ([mCertiKOS](https://flint.cs.yale.edu/flint/publications/pldi16-security/paper-security.pdf)) |
| Komodo | Its enclave guarantees | A single core ([Komodo](https://www.andrew.cmu.edu/user/bparno/papers/komodo.pdf)) |

Rauha's zones share a Linux kernel with none of these conditions, and that kernel is porous:

- **[measured]** ContainerLeaks, co-authored by IBM Research, found host state leaking into containers through incomplete namespacing ([ContainerLeaks](https://research.ibm.com/publications/containerleaks-emerging-security-threats-of-information-leakages-in-container-clouds)).
- A 2021 study counted **1,010 abstract kernel resources shared by containers, 501 of them consumable at run time** ([Demons in the Shared Kernel](https://wenboshen.github.io/publications/papers/LogicalDoS.pdf)).
- Outside the host, **7 of 17 model providers shared prompt caches across users or organizations**, which creates a timing side channel ([Prompt-cache audit](https://arxiv.org/abs/2502.07776)).

**[proposal]** Write every receipt in Lampson's vocabulary:

| Receipt section | May claim, if the evidence holds | Must never claim |
|---|---|---|
| Authority | Every handle, path, endpoint and capability the zone held was within the grant set | That an allowed action was appropriate |
| Storage channels | No writable object was shared with other zones or the host, except those listed | That the kernel has no shared state |
| Overt egress | At most N requests, B bytes and D DNS names left the zone, to endpoints E | That those bytes carried no encoded secret (ZTAC's two losses) |
| Covert and timing | "Not covered", by name; optional mitigations named *as* mitigations | Any freedom from covert channels |
| Noninterference | Only for a twin-run pair: "public outputs came from a run that held no secret, except k declassified bits" | Noninterference from a single run |
| Model provider | The provider was a declared recipient | Anything about provider caching or retention |

The overt-capacity bound is Lampson's "bound the capacity" applied to the channel everyone forgets is a channel. Today's nftables counters and broker logs can compute it. It would make Rauha **the first sandbox found that tells its user the size of the door**. Its risk is perception: "at most 2.1 KB left" reads to some people as "2.1 KB leaked".

### Prove Rauha's own decisions, and treat the kernel as an assumption under attack

The verified-OS literature shows what is provable at all: storage channels, static configurations, one core, no timing. The honest move is to verify *Rauha's* logic against an abstract model of Linux objects, and to keep re-testing the kernel assumptions.

**[proposal]** Four statements, from easiest to hardest:

| Statement | What it says | How to check it |
|---|---|---|
| P1, authority confinement | In every reachable state, the objects a zone can reach are within its grants. This is the style of the EROS confinement verification, co-authored at IBM T.J. Watson ([EROS](https://www.cs.yale.edu/flint/cs428/doc/eros-verify.pdf)) | Proof, or a model with shared test vectors |
| P2, decision independence | The broker's verdict depends only on policy, request and the resolved object's metadata, never on the contents of ungranted objects or other zones | Because the decision function is pure, run it twice on states that differ only outside the grant and require identical verdicts. This is ordinary property testing |
| P3, twin-run orchestration | The secure multi-execution guarantee described in the next section | Proof over a model of the orchestrator |
| P4, receipt soundness | The first report's three admission sentences | Proof, or shared test vectors |

Each statement rests on named kernel assumptions:

- **K1:** Linux implements the documented `openat2` and seccomp fd-injection semantics.
- **K2:** the hooks are attached. That is exactly the open "pulse" question.
- **K3:** no storage channel crosses between twins.

**[measured]** On tooling, Atmosphere verified a ~6k-line Rust kernel with Verus at a **3.32:1 proof-to-code ratio, rechecked in under 20 seconds** ([Atmosphere](https://mars-research.github.io/doc/2025-sosp-atmo.pdf)). That fits Rauha's Rust-only rule better than Lean, which the cross-repository rules currently allow only in two other repositories. **[measured]** Serval's lesson is to expect bugs, not just certificates: retrofitting verification found **18 new bugs in the Keystone monitor and the Linux BPF JIT compilers** ([Serval](https://www.cs.columbia.edu/~rgu/publications/sosp19-nelson.pdf)). The receipt line then reads like seL4's assumptions page: "P2 checked at commit abc; K2 re-probed 3 min before run; timing: not covered."

### Measure the excess, and place Rauha honestly among isolation classes

IBM's James Bottomley coined the **Horizontal Attack Profile (HAP)**: how much host-kernel code a tenant can reach. **[measured]** A Middleware 2021 study traced it with ftrace and found ([van Rijn & Rellermeyer](https://arxiv.org/pdf/2110.11462)):

- Firecracker "calls into the host kernel most often of all platforms";
- containers ranked among the lowest;
- the metric "fails to capture the defense-in-depth isolation platforms provide".

**[measured]** IBM Research's Nabla work showed a process-based boundary can be very narrow. Unikernels running as seccomp-confined processes issue three syscalls in steady state and reach **98% fewer kernel functions under fuzzing**. Recompiling every image killed adoption ([Unikernels as Processes](https://people.cs.vt.edu/djwillia/papers/socc18-unikernels_as_processes.pdf)). **[measured, preprint]** Later IBM-led work on stateful seccomp filters cut early-phase attack surface by up to **55.4%** through "temporal specialization" ([seccomp-eBPF](https://arxiv.org/abs/2302.10366)). It was never merged, but plain stacked seccomp filters can express phases.

| Axis | Rauha zone today | Honest sentence |
|---|---|---|
| Host-kernel reach (horizontal) | Container class: the host syscalls minus crun's default filter. Per-zone `syscalls.deny` is refused by strict admission as unsupported | "Container-class kernel exposure" |
| Policy layer (vertical) | BPF-LSM on six hooks, inode ownership, nftables, the seccomp broker | Stronger than a plain container |
| Kernel memory-corruption exploit | Not contained | "Shared kernel: not claimed" |
| Independent evidence of actions | Deny events, broker log, signed receipts | Unique among the four platform classes compared |

**[proposal]** Publish a measured kernel-function count per policy: "this run touched N kernel functions; the policy permits M syscalls". Then narrow by *allowlists* learned from clean runs, plus a second seccomp filter stacked at a declared phase boundary, rather than by deny lists.

Three pieces of IBM history sharpen self-knowledge:

- **Keep the control program small.** CP/CMS's designer kept only what virtual machines need inside the control program and pushed "unessential function" into guests ([Creasy 1981](https://lass.cs.umass.edu/~shenoy/courses/fall07/papers/vm370.pdf)). Asterinas confined all unsafe Rust to **14% of its code, against 44% to 66% for earlier Rust OSes** ([Asterinas](https://arxiv.org/html/2506.03876v1)). Rauha can publish its privileged-code percentage the same way.
- **Name what cannot be revoked.** System/38 made revocability an explicit per-object choice: "authorized pointers" skip the check and "cannot be revoked later" ([Levy ch. 8](https://homes.cs.washington.edu/~levy/capabook/Chapter8.pdf)). A file descriptor injected by Rauha's broker is exactly such a pointer, so receipts should list grants that were "irrevocable once delivered".
- **Never reuse IDs.** System/38 never reused object IDs. Rauha should test that its compact u32 kernel zone IDs are never reused while a stale BPF map entry could still point at one.

## Prophecy speaks only through the run that never saw the secret

The oracle answered before the act. The deeper version is an oracle that speaks twice, where only the uninitiated voice may speak in public. Apollo the far-shooter adds the rule that authority hits one named object, in one epoch, and nothing else.

### Secure multi-execution is sound without deterministic models

**[theorem]** Secure multi-execution (SME) runs a program once per security level, and each run receives only inputs at or below its level. The public run never receives secrets, so its outputs cannot depend on them, whatever the program does ([Devriese & Piessens](https://lirias.kuleuven.be/retrieve/107152)). SME enforces the termination-sensitive form of noninterference ([Bielova & Rezk](https://www-sop.inria.fr/members/Nataliia.Bielova/papers/BIEL-REZK-16-ESORICS.pdf)).

This is the decisive difference from the comparison schemes:

- **MELON** needs its two runs to *agree*, and adaptive attacks broke it.
- **TightLip** (NSDI 2007) needs lockstep twins. It ran Apache within 5% and "never exceeded 30%" overhead, on a uniprocessor design ([TightLip](https://static.usenix.org/event/nsdi07/tech/full_papers/yumerefendi/yumerefendi_html/index.html)).

**[measured]** Model sampling destroys agreement. Thinking Machines drew **1,000 samples at temperature 0 and got 80 distinct completions**, because inference kernels are not batch-invariant ([Thinking Machines](https://thinkingmachines.ai/blog/defeating-nondeterminism-in-llm-inference/)). Under SME, non-determinism lowers usefulness, never soundness. **[theorem]** There is a hard limit, though. Any enforcement that watches a program only from the outside takes time exponential in the number of principals (Algehed and Flanagan), so Rauha's lattice must stay at about two levels per axis ([Algehed & Flanagan](https://arxiv.org/abs/2005.12345)).

**[proposal]** A twin-zone Run has two zones and one release rule:

- **Zone L** sees placeholders instead of secrets and may reach public outputs such as a PR comment.
- **Zone H** holds the real secrets and has no public egress. Public data it needs is served from L's recorded responses.
- **Ordering:** L runs to completion before H starts. That removes the load channel and the provider-cache channel between the twins.
- **Release:** H's results reach public outputs only through a declassifier that records its size in the receipt, for example "1 bit: tests passed, approved". This is the Rafnsson–Sabelfeld style of declassification ([CSF 2013](https://www.cse.chalmers.se/~andrei/csf13.pdf)).

Given those rules, L's public outputs are a function of public inputs, L's own randomness and the declassified bits. That is probabilistic noninterference by construction, timing excluded. An injection that knows which twin it is in can still misuse L's *public* authority, but it cannot leak what L never received.

Four things break it:

- tasks whose public output genuinely needs the secret;
- new public reads requested by H;
- once-only actions that need secrets, such as a deploy, which become approved actions in H;
- twice the model calls and wall time.

The model provider also sees H's secrets, so the receipt must name it as a recipient.

The integrity mirror makes the first report's Rule of Two structural. Three zones each hold at most two of the three dangerous legs (private data, untrusted content, outside communication):

- a privileged zone that never sees untrusted content;
- a quarantine zone with no egress;
- a public zone with no secrets.

Label creep, the killer risk named in the first report, gets a black-box remedy: **differential taint**. Run one tool command twice, with real and with scrubbed secrets. If stdout, stderr and the file diff match, that output may enter the model's context without raising the zone's label. One sample only shows this is possible, not that it is safe in general.

### Speculate past a held effect, then validate what the run read before accepting

**[measured]** Speculator (SOSP 2005) let processes continue on a predicted result:

- checkpoints took **52 µs** for a small process and **6.3 ms** for a 64 MB one;
- dependencies propagated through IPC and files;
- all output to the outside was blocked until the speculation resolved;
- NFS became **more than 2× faster on a LAN and more than 14× at 30 ms latency** ([Speculator](https://web.eecs.umich.edu/~pmchen/papers/nightingale05.pdf)).

**[proposal]** When a Run hits a held effect such as `git push`:

1. Seal a checkpoint.
2. Return a typed "held, pending approval" result, never a fake success. The first report found agents treating `sent: false` as success.
3. Let the agent continue, and taint every turn that consumed the provisional result.
4. On rejection, fork from the checkpoint and replay only the untainted turns.

For agents, one externalization is new: every model API call carries the provisional outcome to the provider, so the receipt must list that disclosure. Kairos can hold only one speculative scope at a time, because OverlayFS allows one writable upper layer per mount. Per-zone overlays would let Rauha hold many.

**[measured]** IBM's Hyperledger Fabric (EuroSys 2018) is the closest production precedent for accept ([Fabric](https://arxiv.org/pdf/1801.10228v2)):

- endorsers *simulate* a transaction and sign a readset of (key, version) pairs and a writeset;
- validation rejects the transaction if any read version has changed, and re-runs range queries to catch "phantom" reads;
- rejected transactions stay in the ledger, marked invalid;
- Fabric chose execute-first precisely because order-first designs broke on non-deterministic code, and agents are maximally non-deterministic.

**[proposal]** `rauha accept` re-checks a readset: `(path, dev, ino, mtime, size)` for workspace files the run read, plus the paths it found missing, plus hashes of the directories it listed. Accept refuses if any of them changed, for example "src/lib.rs changed after the run read it". Refused accepts stay in the journal. Acceptance itself becomes a Fabric-style formula over evidence, such as `tests ∧ (human ∨ 2-of-3 siblings agree)`. No agent sandbox reviewed checks for stale reads at commit. One limit: Rauha's `file_open` hook misses failed lookups and directory listings.

### Make the Run a kernel object so losing siblings lose their authority

Fork speed is solved, again:

- **[measured]** DeltaBox checkpoints in **10.83 ms and restores in 1.86 ms**, against **1,072 ms and 424.7 ms** for E2B's diff snapshots. It also keeps live model sockets in a proxy outside anything that gets forked ([DeltaBox](https://arxiv.org/html/2605.22781)).
- **[measured, preprint]** BranchFS creates a branch in **292 to 317 µs**. Its paper's `branch()` syscall "is not yet implemented", and it is explicitly not a security boundary ([Fork, Explore, Commit](https://arxiv.org/html/2602.08199v2)).

What nobody revokes is *authority*.

**[proposal]** Add `run_id`, `epoch` and `mode` to the per-zone BPF record. The modes are `rehearse`, `live`, `sealed`, `committed` and `invalidated`, starting with only two of them. Every hook and broker decision reads the mode. Accepting one sibling flips the others to `invalidated` in one map update, after which the hooks deny their opens, execs and connects, and the brokers refuse pending requests after re-checking the epoch.

Branch context applies first-commit-wins to files; this applies it to authority, enforced in the kernel, with evidence. Hubris uses the same generation-number idea for restartable tasks ([Hubris](https://hubris.oxide.computer/reference/)). Two things are unverified: whether map-of-maps swaps stay atomic while hooks run concurrently, and whether the pinned Aya version supports the needed map types.

### Archery: bind authority to objects, epochs and callers

Rauha's broker is already **object-bound by construction**: it resolves the path with `openat2` and injects the resulting handle. That is ZTAC's central lesson ("approvals must bind objects, not names") on Linux. **[measured, preprint]** PORTICO adds epochs: handles removed when a subgoal closes **rejected 10 of 10 reuses after closure**, where a comparator allowed all 10 ([PORTICO](https://arxiv.org/abs/2606.22504)).

**[measured]** Shill (OSDI 2014) is the best precedent for a capability-safe shell. Each native command ran in a sandbox built only from the capabilities passed to it, mostly within **1.21×** overhead. One script that created **15,292 sandboxes** ran at 6.01× ([Shill](https://users.cs.northwestern.edu/~chrdimo/pubs/osdi14-mdkc.pdf)). Shill runs only on FreeBSD, its Linux predecessor Plash is long dead, and ZTAC runs on macOS.

**[proposal]** `rauha cap-exec --ro <dirfd> --rw <dirfd> -- cmd` would build a nested Landlock domain from the passed handles only. The receipt then lists exactly what each command held, and shows that `git` never touched `.git/hooks`.

Two older ideas help here. "Capability Myths Demolished" notes that revocation comes from adding indirection ([Miller, Yee, Shapiro](https://papers.agoric.com/papers/capability-myths-demolished/full-text/)), so revocable grants need a broker-held proxy, not an injected handle. System/38's "profile adoption" without propagation is the right shape for the first report's caller-bound credentials: the credential broker temporarily lends authority the agent lacks, and a `postinstall` child does not inherit it.

## Light and healing: record flows, hash binaries, repair by forking

Phoebus means "bright" ([Apollo](https://en.wikipedia.org/wiki/Apollo)). For Rauha, brightness means a witness that records permitted actions as well as refusals and declares its own losses. Apollo also both sent plague and healed it, so the second half of this section is about repair that never hides the wound.

### Allow events are affordable when recorded as flows at the LSM layer

**[measured]** Capture at Linux security hooks, where Rauha's programs already sit, has been light for over a decade:

| System | Overhead |
|---|---|
| Hi-Fi | **under 1% for most syscalls, 3% on a representative workload** ([Hi-Fi](https://www.cise.ufl.edu/%7Ebutler/pubs/acsac12b.pdf)) |
| Linux Provenance Modules | **as little as 2.7%** ([LPM](https://usenix.org/conference/usenixsecurity15/technical-sessions/presentation/bates)) |
| eAudit (eBPF) | **4 to 5%**, median 48 ns per syscall ([eAudit](https://par.nsf.gov/servlets/purl/10554458)) |
| Common collectors, measured by the eAudit authors | Slow workloads **2× to 8×** and lose most events under sustained load ([eAudit](https://par.nsf.gov/servlets/purl/10554458)) |

The volume to expect is set by Retro's kernel build: **5.7 million recorded actions in 761 MB**, roughly 19,000 actions per second ([Retro](https://people.csail.mit.edu/nickolai/papers/kim-retro.pdf)). That rate is derived from Retro's table, not measured by Retro.

IBM Research's SysFlow gives the format ([SysFlow](https://arxiv.org/pdf/2101.10474)). Each entity (process, file, endpoint) is emitted once and referenced by ID. Single events are kept only for rare acts such as exec, unlink and rename. High-volume file and network activity is folded into **flows** with operation flags and counters, exported on close, exit or timeout. **[measured]** On a MySQL workload this gave a **0.09 MB** trace, against 2,592 MB for Sysdig and 327 MB for go-audit. The collector itself is C++ and has gone quiet.

**[proposal]** Aggregate the flows *in the kernel*, in a BPF hash map keyed by zone, thread and inode (or connection), and attach each flow's enforcement outcome: allowed, denied or brokered. Write them to a ring buffer separate from denials, so a flood of allows can never shed a deny. Every claim built on flows then states its order resolution, for example "order known to within T seconds". One warning from the 2023 provenance SoK must become a rule: one log-reduction technique, LogGC, pruned network activity from closed sockets, deleting exactly the evidence of exfiltration ([Provenance SoK](https://par.nsf.gov/servlets/purl/10443648)). Only causality-preserving or lossless reductions are allowed, and any approximation becomes a declared capture issue.

### Hash every binary a run executes, and spoil the record when you cannot vouch

IMA, Linux's integrity measurement architecture, was born at IBM Watson. **[measured]** Sailer's 2004 design found that a workstation accumulates **no more than 500 measurement entries**, and a clean cache hit takes **0.08 µs** ([Sailer et al.](https://www.usenix.org/legacy/publications/library/proceedings/sec04/tech/full_papers/sailer/sailer.pdf)). Its most useful idea is fail-safe poisoning. When measurement "is potentially being bypassed", IMA does not block anything. It extends the TPM aggregate with random values, so the machine can no longer attest successfully until reboot.

IMA namespaces, IBM's long effort to measure per container, are **still not in mainline as of v7.4-rc4**. Mainline does let *sleepable* BPF-LSM programs call `bpf_ima_file_hash`, and the sleepable hooks include `bprm_check_security`, `mmap_file`, `file_open` and `socket_connect` ([bpf_lsm.c](https://github.com/torvalds/linux/blob/master/kernel/bpf/bpf_lsm.c); [IMA dir](https://github.com/torvalds/linux/tree/master/security/integrity/ima)).

**[proposal]** A per-zone measurement list would add sleepable exec and library-load programs beside the enforcing hooks, which stay non-sleepable. Each run's receipt then gains a line like "executed 213 distinct binaries; 7 not in the image". That catches `curl | sh` and downloaded tools structurally, not heuristically. Three points are unverified:

- whether the helper reuses IMA's cache when no IMA policy covers the file;
- which maps sleepable programs may use;
- whether Aya supports sleepable LSM programs.

**[proposal]** The same poisoning rule settles how to report the first report's pulse gap honestly. A re-read of `origin/main` today shows the same picture the first report described: the LSM links belong to the in-process loader, and the health check reads the program's file descriptor rather than its link. That is a reading of code, not a result.

Until links are pinned and proven to survive a daemon crash:

1. Any zone that outlived a daemon death gets a `pulse.lost` journal record.
2. Every later receipt for that zone must say `enforcement: gap (t0..t1)`.
3. On TPM hosts, the run's measurement register is extended with randomness, so no quote can ever vouch for that run.

The recovery-oriented computing work behind "crash-only software" says to restart the smallest failing component ([Crash-only](https://www.usenix.org/conference/hotos-ix/crash-only-software)). Rauha's RP-20 already does that for the agent. For the daemon, the corollary is that restarting `rauhad` must restart the observer, never the wall.

### Thirty years of intrusion recovery say: undo the cause, keep the timeline, fork the cure

**[measured]** An MIT and Toronto line of work solved "undo the attacker, keep the legitimate work" between 2005 and 2013:

| System | What it did | Measured |
|---|---|---|
| Taser | Taint over processes, files and sockets, then selective replay | 0.6% auditing overhead on a kernel compile, but it rolled back "hundreds or thousands of files" by mistake ([Taser](https://www.eecg.utoronto.ca/~ashvin/publications/sosp-2005.pdf); [Retro](https://people.csail.mit.edu/nickolai/papers/kim-retro.pdf)) |
| Retro | Recorded an *action history graph* with btrfs snapshots and hashes of data read | **89 to 127%** overhead on one core for syscall-heavy loads (18 to 33% with a spare core); repairs in **0.3 s**, and still 4.7 s beside a log 10,000× larger ([Retro](https://people.csail.mit.edu/nickolai/papers/kim-retro.pdf)) |
| Warp | Applied a security patch "to the past" and re-executed only past requests that ran the patched code | One repair re-ran **14 of 1,011** page visits ([Warp](https://people.csail.mit.edu/nickolai/papers/chandra-warp.pdf)) |

Every system in the line hit the same three walls:

- external output can only be compensated, never undone;
- **"WARP cannot undo disclosures of private data"**, and Aire likewise "cannot undo damage resulting from unauthorized reads" ([Aire](https://people.csail.mit.edu/nickolai/papers/chandra-aire.pdf));
- someone must name the intrusion point, unless the trigger is a retroactive patch.

Berkeley's operator undo adds the principle Rauha's RP-22 already states: preserve the timeline ([Brown & Patterson](https://static.usenix.org/events/usenix03/tech/brown/brown_html/index.html)).

**[proposal]** Give each Run an action history graph. Objects are files keyed by (dev, inode, generation), processes, endpoints, grants, model turns and tool calls. Each edge is marked `observed` (kernel-witnessed) or `inferred`. Two queries follow:

- `rauha why src/auth.rs` walks backwards;
- `rauha blast-radius <input-hash>` walks forwards across Runs.

Agent loops have the "dependency explosion" problem of long-lived processes, where every output depends on every earlier input. BEEP's fix was to partition execution into units ([BEEP](https://www.cs.purdue.edu/homes/dxu/pubs/NDSS13.pdf)). Rauha can partition by *turn*, without instrumenting the binary, because the Run journal knows turn boundaries.

Retroactive patching then becomes two products:

- **The fast first step** is a retroactive policy audit: declare an input malicious after the fact ("`left-pad-ng@2.1` is bad") and list every affected Run and effect from recorded witness data alone.
- **The heavier step is healing.** Fork from the last checkpoint before the first tainted edge, replace the input, reuse recorded model responses for unaffected turns, and issue a *new* Run with its own receipt. Already-released effects get *drafted* repairs, such as a revert PR, that need fresh authorization, since a fork inherits no authority.

**[measured, self-reported]** The hard limit is the model's non-determinism. The agent-rewind artifact re-ran **4.7 steps selectively, against 22.5 for a restart**, yet saw almost no gain on one workflow (ratio 0.94) ([agent-rewind](https://github.com/Yitang233/agent-rewind)).

**[measured, preprint]** Rollback is also an attack surface now:

- ACRFence names **Action Replay** and **Authority Resurrection**. After restore, agents re-synthesize slightly different requests, which lets them double-pay and reuse consumed credentials ([ACRFence](https://arxiv.org/abs/2603.20625)).
- "Safe to Resume?" shows that "correct rollback does not imply secure recovery", with end-to-end attacks on Hermes, Cline and LangGraph ([Safe to Resume?](https://arxiv.org/abs/2608.29381)).

Rauha's RP-13, RP-16 to RP-18 and RP-26/27 block these by design: epochs, write-ahead effects, no blind replay, and forks with no authority. The papers add one requirement: a checkpoint must list the facts it depends on, and how fresh they are, so that a resumed Run re-validates "scan passed" instead of inheriting it. **[proposal]** Ship that mapping as a conformance suite with one test per attack class, each broken once on purpose. One 2026 survey says agent provenance today supports "explanation more than intervention" ([Agent traces survey](https://arxiv.org/html/2606.04990v4)). This is intervention.

### Make the truth last: rollback-evident receipt chains and hybrid signatures

**[proposal]** IBM Research Zurich's LCM showed that clients holding a few bytes of state can detect a server that rolls back or forks its history ([LCM](https://arxiv.org/pdf/1701.00981)). Applied to Rauha, each CLI keeps the last receipt-chain head it saw per host and warns, for example "receipt chain rolled back: seq 4512 → 4498". That closes part of the first report's suppression gap with no log server.

Receipts are meant to outlive today's keys, and a broken Ed25519 lets anyone forge old receipts later. Three standards facts matter:

- IBM researchers co-developed ML-DSA ([IBM Research](https://research.ibm.com/blog/nist-pqc-standards)).
- The IETF published composite ML-DSA-65 + Ed25519 signatures in November 2026 ([RFC 10073 draft record](https://datatracker.ietf.org/doc/draft-ietf-lamps-pq-composite-sigs/)).
- DSSE already allows several signatures per envelope ([DSSE](https://github.com/secure-systems-lab/dsse/blob/master/envelope.md)).

**[proposal]** Add a second, post-quantum DSSE signature and a verifier that requires both, which guards against the signature-stripping concern Sigstore raised ([Sigstore](https://blog.sigstore.dev/post-quantum-2025/)). Keep it behind a non-default feature for now. The RustCrypto `ml-dsa` crate says it "has never been independently audited" ([ml-dsa](https://github.com/RustCrypto/signatures/tree/master/ml-dsa)).

Fully homomorphic encryption is the dead end here. Agents use secrets as bearer tokens, not as data to compute on, and IBM's HElib has been quiet since August 2024 ([HElib](https://github.com/homenc/HElib)). Brokered credentials stay the answer.

## IBM's agent stack delegates the wall, so score every attack twice

Apollo Musagetes led the Muses: many voices, one judge. Applied to Rauha, that means two things. Siblings and evaluators are judged on evidence Rauha writes itself. Plague-testing measures whether an attack reached the world, not just whether the agent agreed to it.

IBM is converging its agent stack onto open standards. ACP merged into A2A in 2025, and A2A joined the Agentic AI Foundation in August 2026 with "signed agent cards for cryptographic identity verification" ([AAIF](https://aaif.io/blog/a2a-joins-aaif)). Signed cards attest *who* an agent is, not what any runtime enforced during its run. IBM's June 2026 "trace layer" article asks for a per-run record of side effects but never mentions tamper-evidence or signatures ([IBM Think](https://www.ibm.com/think/insights/action-accountability-ai-agent-needs-trace-layer)). CUGA ships an unsigned, off-by-default "Run Receipt", a usage summary, which is a naming collision worth knowing about.

These are the durable seams. All of them meet IBM at protocols, policy files or evidence formats, so no Python enters Rauha:

| IBM item (status) | Rauha's role | Smallest experiment | Needs approval? |
|---|---|---|---|
| Mellea `CapabilityPolicy` with `ENFORCED_* = False` (v0.9.0, Nov 2026) | The tier where those flags become true, with a signed receipt | A Rust test in Lima: a stock image tries each of Mellea's six declared capabilities under a matching Rauha policy; the output is a compatibility row in Mellea's vocabulary | Only if Rauha runs Mellea's Python, even as an image |
| Rossoctl sidecar identity (v0.8.0, Oct 2026) | Make "traffic that avoids the sidecar" impossible, and evidenced | A zone whose nftables chain allows one proxy port; assert a deny event for a direct connect | Kubernetes fit untested; a cluster needs approval |
| STRATUS Transactional No-Regression, NeurIPS 2025 ([STRATUS](https://arxiv.org/html/2506.02009v2)) | Replace its "rule-based confinement may not be perfect" with read-only zones; map its assumptions (exclusive writer, faithful undo, bounded risk window) onto one accepting fork, overlay discard and held effects | A diagnosis agent in a zone with no writable paths; the receipt shows 0 writes and N attempted writes denied | No |
| FactSheets, 2018 ([FactSheets](https://arxiv.org/abs/1808.07261)) | A "run FactSheet" in-toto predicate: FactSheet headings filled from the receipt, plus a mandatory "not provable" section | A Rust converter from a saved result, and a test that the "not provable" section is never empty | No |
| Exgentic and the Open Agent Leaderboard (May 2026) | Receipt-backed leaderboard entries. The same model swung from **0.83 to 0.00** across agent architectures on τ2-Bench, so *how* a score was produced matters ([Exgentic](https://arxiv.org/abs/2602.22953)) | Run one benchmark session image as a `rauha sandbox` workload and verify the receipt offline | Yes: the image is Python |
| ARES red-teaming (v0.2.3, Nov 2026) ([ARES](https://github.com/IBM/ares)) | The ground truth for "did the effect happen" | See the two-layer score below | Yes: ARES is Python, run externally |
| Granite Guardian 4.1 ([model card](https://huggingface.co/ibm-granite/granite-guardian-4.1-8b)) | Record its verdicts as labelled inference, beside kernel facts. Its own function-calling accuracy is **0.79 balanced accuracy**, and its card warns of adversarial attacks | A receipt-schema test that a judge entry can never set a kernel-evidence field | No |

**[proposal]** The two-layer red-team score is the most fun of these. ARES judges success from text, using keywords or model judges. Rauha knows whether a canary file was opened or a connection left the zone. Each attack lands in one of four cells:

| | Effect blocked | Effect achieved |
|---|---|---|
| **Agent complied** | The cell only Rauha can evidence | A real escape |
| **Agent resisted** | A true negative | Exposes a false negative in the judge |

A release note could then read "41% of exfiltration prompts succeeded at the agent; 0% reached the network". Running ARES externally also keeps Rauha from grading itself.

**[measured]** Comparison should drive presentation, not verdicts. A USENIX Security 2025 re-evaluation found **eight host-wide provenance intrusion detectors "not viable for practical deployment"**, with a simple network matching them on 5 of 7 datasets ([Bilot et al.](https://www.usenix.org/conference/usenixsecurity25/presentation/bilot)). An industrial study saw false-positive rates **above 23%** when benign behaviour changed ([arXiv 2603.22982](https://arxiv.org/abs/2603.22982)). ORTHRUS reframed success as "quality of attribution": how many nodes a human must inspect to explain an alert ([ORTHRUS](https://www.usenix.org/conference/usenixsecurity25/presentation/jiang-baoxiang)).

Rauha manufactures what host detectors never have: *sibling runs doing the same task*. Ranking the edges that appear in only a minority of siblings, and measuring how many nodes a human must look at, is the right detector. MELON's fate means it stays advisory. Fabric's endorsement formulas, a "Midas check" for a judge model that contradicts the evidence, and the theorem that relational violations need cross-run comparison together make fork/compare a mechanism that theory *requires*, not a convenience.

Finally, a score others can play. The SOSP 2026 AgenticOS keynote argues that agents need "a POSIX before a kernel", and IBM asks the field to "specify their semantics precisely". **[proposal]** Rauha's RP rules plus its 55-case oracle are already a specification with a conformance harness. Tag each oracle case with the RP rule it checks, publish the untested rules, and offer the vectors to other runtimes.

**[proposal]** A small "reference-monitor contract" over the existing gRPC would let in-framework defenses such as CaMeL, FIDES or PORTICO delegate to the zone:

- `label` and `declassify`;
- `grant` and `revoke` by epoch;
- `fork_clean` and `compare`.

Zone labels act as the upper bound: a framework may be more precise, but never less safe.

## Start with the pulse, the epoch and the size of the door

The order follows one rule. First test the honesty claims Rauha already makes. Next, build the kernel primitives the Run needs anyway. Research bets come last. All Linux work runs in the Lima `linux-dev` VM.

| # | Experiment | Apollo domain | On shipped code? | Size | Proof, and how to break it once |
|---|---|---|---|---|---|
| 1 | Pulse under restart, with IMA-style poisoning, a state-spill inventory and a zone-ID reuse test | Healing; know thyself | Yes | Days | Across 100 `kill -9` cycles, count denied opens that succeeded; receipts must say `gap` until links are pinned. Detach a link by hand; force a u32 reuse |
| 2 | Run epoch in the kernel record and broker, plus the Authority Resurrection test | Archery; prophecy | Small eBPF and broker change | Days | Invalidate sibling B: its next brokered open and exec are denied within one loop period. Skip the broker's epoch check, and the test must fail |
| 3 | Receipt split by channel class, with an overt-egress bound | Know thyself; measure | Yes | Days | A DNS tunnel must raise the bound, and "covert: not covered" must stay |
| 4 | Decision-independence property test of the broker (P2) | Know thyself | Yes | Days | Two filesystems identical on granted paths must give identical verdicts. Make the verdict depend on a sibling file's size, and the test must fail |
| 5 | Kernel-function count per policy (HAP) | Measure | Yes, with `trace-cmd` in Lima | Days | Under `standard.toml` and `broker.toml` against runc; widen seccomp and the count must rise |
| 6 | Receipt-chain rollback detection (LCM) | Light | Yes | Days | Restore an older redb, and the CLI warns. Skip the previous-hash check, and the test must fail |
| 7 | In-kernel zone flows on a separate ring buffer | Light | eBPF change | 1–2 weeks | `cargo build` and `npm install`: events/s, bytes, drops and overhead, against the 3–5% (eAudit) and 35–127% (Retro) bands. Shrink the buffer, and the receipt must flip to incomplete |
| 8 | Per-zone measurement list (sleepable `bprm_check_security` + `bpf_ima_file_hash`) | Light | eBPF change | ~1 week | Compare against the host IMA log. Corrupt one chained digest, and `rauha receipt` must fail |
| 9 | Differential taint, then a sequential twin-zone run | Prophecy | Differential taint yes; twins need placeholders | 1–2 weeks | Canary leakage to public outputs must be 0. Give L a read path to the real `.env`, and the canary must appear |
| 10 | Readset check at accept | Prophecy | Partly, via `broker.log` under a broker policy | Days | Touch a file the run read, and accept must refuse |

Later, in order:

1. The action history graph with `rauha why`, then retroactive policy audit, then healing forks.
2. The rollback-attack conformance suite.
3. Speculative continuation past held effects.
4. `cap-exec` with nested Landlock.
5. Verus proofs of P1 and the RESOLVE-flag rule.
6. Hybrid post-quantum receipts.
7. The two-layer red-team score and the Mellea and Rossoctl seams.
8. A per-tenant "system zone" for shared caches.
9. The witness on its own cores.
10. The microVM tier, measured with HAP before any claim.

Several steps need your approval under current rules:

| Step | Why it needs approval | Lighter path that does not |
|---|---|---|
| Verus in the gate, or Lean inside Rauha | A new toolchain; the cross-repository rule allows Lean only in two other repositories | A proptest relational harness (dev-only), or Kani |
| `ml-dsa`, `fips204` or `libcrux-ml-dsa` in a release build | A crate in a release build; `ml-dsa` is unaudited | A non-default feature exercised only in tests |
| An A2A endpoint, a `/v1/execute` facade, a ContextForge gRPC plugin server, a witness or log server, or system-zone services (cache proxy, git mirror) | New servers or daemons | Offline converters (result → A2A Task JSON, result → run FactSheet) need no server |
| Running ARES, AgentDojo, Exgentic or Inspect, even externally or as workload images | Your rule forbids Python, even for tests | Rust-scripted agents for every first experiment |
| A Kubernetes cluster in Lima for the Rossoctl test | Server infrastructure | The single-proxy-port nftables test |
| Biscuit, Wasmtime, an Erlang warden, audio crates (carried over from the first report) | Release-build crates, a daemon | Unchanged |

Prior art splits by whether Rauha may reuse it under the language rule:

| Reuse directly (Rust or Erlang) | Learn from only (other languages) |
|---|---|
| Verus and Atmosphere; Asterinas; Hubris; Tock; cap-std; BranchFS (Rust, FUSE); AgentSight (Rust and C, MIT, ~2.9% overhead) ([AgentSight](https://arxiv.org/html/2508.02736v2)); Hyperlight; Firecracker; rust-keylime; Confidential Containers' Rust attesters (including IBM's Secure Execution module); RustCrypto `ml-dsa`, `fips204`, `libcrux-ml-dsa`; ZTAC (Rust, but macOS) | Retro (C and Python), Warp, Aire, Taser, Speculator and TightLip (C kernel patches); Hi-Fi, LPM, CamFlow (kernel patches); eAudit (C eBPF, techniques portable); SysFlow (C++, Go); Kestrel, ARES, ART, Mellea, CUGA, BeeAI, PDL, Exgentic, ContextForge (Python); Rossoctl (Go, TypeScript); Fabric (Go); Shill (Racket on FreeBSD); MELON, CaMeL, FIDES, APPA, DRIFT, AIOS, MemGPT, agent-rewind, Kairos/ORTHRUS detectors (Python); DeltaBox (C and Python); Kairos agent boundary (language unstated; uses Python mitmproxy); seL4, mCertiKOS, Komodo, Nickel, Serval (C with Isabelle, Coq, Dafny, Racket); Nabla runnc (Go, archived); Solo5 (C); IBM TSS and swtpm (C) |

To avoid: an in-process "agent kernel" (AIOS), context management (MemGPT), unikernel images (Nabla's adoption blocker), language-only isolation for untrusted toolchains, memory forks before a VM tier with re-keying, and any claim of VM-class isolation for a shared-kernel zone.

The north-star moment, as an illustrative mock-up of what these experiments would print together:

```text
rauha run --twin -- agent "fix issue 412"                 (mock-up; none of this ships today)
PUBLIC     written by run L, which never held a secret · 1 declassified bit (tests passed, you approved)
SIBLINGS   4 explored · accepted b2 · b1,b3,b4 authority revoked in kernel (epoch 7→8) · 2 late attempts denied
READSET    37 workspace files re-checked at accept · 0 changed since read
BINARIES   213 executed · 7 not in image (build scripts ×6, /tmp/x ×1)
EGRESS     overt ≤ 3 requests / 2,148 B to api.github.com · covert and timing: not covered (shared kernel)
WITNESS    1.84 M file flows, 0 dropped · complete
PULSE      rauhad restarted once · enforcement continuous (links pinned, verified)
PROOF      broker decision independence: property-tested at abc123 · kernel assumptions K1–K3 re-probed
```

## Conclusion

The deeper round turns "godlike" from ambition into a job description. The research community and IBM have each built upper floors (planners, labels, tool guards, identity, benchmarks) on a floor they assume or delegate. Rauha's power is to make their assumptions true, and to say in signed words when it cannot. Theory turned out to be a design guide, not a threat. The 2-safety result and the per-action-monitor theorem mean that fork and compare are the *only* runtime-level answer to violations that live between runs. The Run stops being a convenience and becomes the security mechanism the proofs demand, while Lampson's channel classes dictate the shape of an honest receipt.

The other surprise is where the best designs come from. Speculator (2005), Retro and Warp (2010–2011), Fabric (2018), SysFlow (2020) and IMA (2004) already solved, measured and published most of what 2026's agent papers are rediscovering. Rauha can stand on them and add the parts they never had: a kernel witness, declared loss, and authority that dies at accept. The most Apollonian first act is still the humblest one, the restart test. If the hooks lapse when the daemon dies, then today's receipts affirm more than the runtime saw, and IMA's 2004 rule says exactly what to print until that is fixed.
