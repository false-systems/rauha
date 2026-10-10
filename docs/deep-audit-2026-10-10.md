# Rauha repository audit

What this repo does: Rauha runs Linux workloads inside policy-controlled zones and returns signed execution evidence. Its runtime, recovery, and journal foundations are substantial, but the complete agent workspace and supervision product is not shipped. This audit assumes one host serving concurrent tasks, hostile images and workloads, and potentially untrusted local users.

Audit date: 2026-10-10. Source revision: `20fce5d1c0b00ef4126daa57ea7c113ef4a9cc35`. Author: Monsti. This is a point-in-time report, not a live capability specification. Runtime code was not changed.

The first priority is image/rootfs safety, then truthful enforcement and evidence. Removing stale documentation and unsupported product surfaces is useful, but does not substitute for those fixes.

## Evidence and scope

- **Reproduced:** an isolated Rust harness exercised the relevant behavior on macOS. Linux-only enforcement was not exercised.
- **Source confirmed:** the complete relevant call path establishes a defect or a concrete failure interleaving. The described Linux scenario still needs a privileged regression test.
- **Follow-up:** a concern needing additional evidence; not counted as a confirmed finding.

The review covered CLI and RPC entry points; image resolution, storage, extraction and overlay assembly; policy creation and reload; zone/container deletion; task recovery and result storage; journal integration; shim IPC and interactive exec; selected BPF map and hook paths; containerd lifecycle translation; CI and security gates; and current versus historical documentation. It was risk-directed, not a line-by-line review of every file.

Line references below refer to the audited revision. Findings 1–7 retain their earlier conversational numbers. Earlier documentation, placeholder-command and tooling findings 8–10 are now 14–16; new findings occupy 8–13.

## What is implemented

| Area | Actual state |
| --- | --- |
| Linux runtime | OCI images, crun, one shim per zone, cgroups, namespaces, rootfs assembly, networking and policy admission exist. |
| Enforcement | In-repo BPF-LSM, nftables and read-only seccomp-notify opens exist. This is not an external enforcement backend in production. |
| Policy controls | Syscall denial is emitted into OCI seccomp. Selected device nodes and validated writable paths are implemented. Support is narrower than arbitrary devices/paths, but broader than the README says. |
| Task evidence | Bounded output, capture-loss reporting, retained results, disconnect survival, crash recovery, Ed25519 receipts and DSSE envelopes exist. |
| Run foundations | A lifecycle reducer, durable journal, replay validation, result sealing and journal-bound receipts are connected to Linux task execution. |
| Complete Run product | Workspace provisioning, brokered credentials, supervisor services, ownership transfer and fork/compare/accept remain incomplete or planned. Defining states in a reducer does not implement those workflows. |
| Enforcer replacement | The neutral API and conformance harness exist; production uses LinuxEnforcer's synchronous methods rather than the asynchronous interchangeable trait. |
| Interactive operations | PTY exec exists with restrictions. Seccomp-filtered containers explicitly refuse interactive exec. Attach to the existing non-PTY container is explicitly unsupported. |
| Kubernetes | The adapter is incomplete and has concrete lifecycle defects, not merely missing installation documentation. |
| macOS | No supported daemon backend. Portable compilation and test fallback code remain useful development support. |

## Must fix

### 1 Image controlled paths redirect the root daemon write

Priority: critical before hostile-image use. Evidence: reproduced image extraction and portable preparation; Linux daemon path source confirmed.

- **What this is:** DNS setup writes `etc/resolv.conf` beneath the prepared rootfs before the workload starts.
- **Problem:** An image can contain an absolute symlink at that location, or a symlinked ancestor. `std::fs::write` resolves it in the host process and writes outside the rootfs with daemon privileges; the payload is DNS configuration, not arbitrary attacker-selected bytes.
- **Fix:** Open and create the destination through a rootfs-confined directory handle, accounting for every path component. Do not rely on a leaf-only symlink check or check-then-open sequence.
- **If skipped:** Merely preparing an image can overwrite a host file before workload isolation applies.

Sources: `rauhad/src/backend/linux/mod.rs:1404`, `rauha-oci/src/image.rs:686`, `rauha-oci/src/snapshotter.rs:39`.

Reproduction: build a gzip tar with `etc/resolv.conf` pointing to an absolute temporary file outside the test rootfs; pass it through `OverlayfsSnapshotter::prepare_layers` and the macOS `mount_overlay` fallback; perform the same DNS write. The outside file changed. No real host configuration file was touched. The Linux overlay syscall itself was not tested.

Regression needed: malicious final symlink and malicious parent symlink through the real Linux create-container path; assert the outside sentinel remains unchanged and unsafe preparation fails or stays confined.

### 2 Overlay preparation discards image deletion markers

Priority: high. Evidence: reproduced with production layer preparation and portable merge; Linux overlay consequence source confirmed.

- **What this is:** OCI whiteouts are markers indicating that a later layer deletes an earlier file or hides a directory's earlier contents.
- **Problem:** `prepare_layers` extracts each layer independently through `unpack_layer`, which consumes whiteouts as immediate deletions in that one directory. The earlier file is in a different layer, so no overlay deletion representation remains.
- **Fix:** Preserve whiteout and opaque-directory semantics in an overlay-compatible representation. Keep merged-tree extraction separate from independent lower-layer preparation where their semantics differ.
- **If skipped:** Deleted files reappear, including files deliberately removed for security reasons.

Sources: `rauha-oci/src/snapshotter.rs:39`, `rauha-oci/src/snapshotter.rs:178`, `rauha-oci/src/image.rs:703`.

Reproduction: lower tar contains `removed-file`; upper tar contains `.wh.removed-file`. After actual preparation the lower file exists and the upper directory is empty. The portable merge exposes the deleted file. Linux lowerdir assembly receives the same missing deletion information.

Regression needed: real overlay mounts covering file whiteout, opaque directory, and replacement of a deleted path in a later layer.

### 3 Policy reload accepts restrictions that existing containers never receive

Priority: high. Evidence: source confirmed.

- **What this is:** `policy apply` changes a zone's declared policy.
- **Problem:** Reload updates BPF, network rules and cgroup resources, while syscall filters, device exposure and writable mounts are constructed at container creation. Adding a denied syscall or changing writable paths can return success without updating existing containers.
- **Fix:** Classify creation-time policy fields and reject incompatible changes while affected containers exist, unless an explicit recreation workflow applies them.
- **If skipped:** Persisted policy and effective protection disagree; later receipts can imply restrictions that were never installed on the process.

Sources: `rauhad/src/server.rs:282`, `rauhad/src/zone/registry.rs:471`, `rauhad/src/backend/linux/mod.rs:1309`, `rauhad/src/backend/linux/mod.rs:1454`.

Regression needed: create a running container, add a denial for an otherwise permitted syscall, and require either rejection of reload or enforcement in that same container. Also cover containers created but not yet started.

### 4 The privileged control API has no caller authorization

Priority: high on shared hosts or remotely bound endpoints. Evidence: source confirmed.

- **What this is:** gRPC provides runtime administration, task execution and result access.
- **Problem:** The default loopback TCP listener does not authenticate the operating-system user. Another local account can invoke administrative methods; configuration also accepts non-loopback addresses without adding authentication.
- **Fix:** Use a permission-controlled Unix socket for local administration and refuse unauthenticated remote binding. Remote access, if required, needs an explicit authenticated design rather than a listener-address change.
- **If skipped:** Any client able to reach the endpoint can administer zones and read or delete task results.

Sources: `rauhad/src/main.rs:185`, `rauhad/src/config.rs:324`, `rauhad/src/server.rs:198`, `rauhad/src/server.rs:2226`.

This is an administrative access-control issue, not proof that an isolated workload can reach host loopback. A strictly single-trust host reduces exposure but does not make loopback user authentication.

Regression needed: an unauthorized local UID cannot use the administrative socket; non-loopback unauthenticated configurations fail validation.

### 5 Repository path is accepted but never provisioned

Priority: high for the advertised agent workflow. Evidence: whole-tree caller search and execution-path tracing.

- **What this is:** The primary example passes `--repo-path .` to run tests on a checkout.
- **Problem:** `repo_path` reaches observability and the input hash but not rootfs or workspace preparation. `execute_task` creates a spec from image, command, environment and working directory only; the checkout does not become available through this option.
- **Fix:** Reject the unused option and correct the example until explicit isolated workspace provisioning is implemented. Do not silently replace it with an unrestricted host bind mount.
- **If skipped:** Users may believe a task tested their checkout when it ran only against image content.

Sources: `rauha-cli/src/commands/sandbox.rs:81`, `rauhad/src/server.rs:1373`, `rauhad/src/server.rs:2072`, `rauhad/src/server.rs:2361`, `README.md:32`.

Also, the execution path expects the image to have been pulled already. The main example should state this precondition.

Regression needed: put a unique sentinel in a temporary checkout and prove it appears only in the intended isolated workspace, with the intended write/export behavior.

### 6 Receipt image identity is resolved after preparation

Priority: high for evidence correctness. Evidence: source-confirmed race.

- **What this is:** The signed result identifies the manifest used to build the task's filesystem.
- **Problem:** Layer preparation resolves a mutable reference, then receipt construction looks up that reference again. If a concurrent pull changes a tag between those operations, the task can run image A while the receipt names image B.
- **Fix:** Resolve the manifest once and carry its digest and selected layers through creation into the receipt. Do not reread a mutable tag to establish historical provenance.
- **If skipped:** A cryptographically valid receipt can identify the wrong image.

Sources: `rauhad/src/zone/registry.rs:555`, `rauha-oci/src/image.rs:358`, `rauhad/src/server.rs:1401`.

Regression needed: pause creation after resolving layers, replace the tag, then complete execution; the receipt must still identify the originally resolved manifest.

### 7 The containerd adapter is not a reliable lifecycle implementation

Priority: high if advertised or deployed. Evidence: source confirmed.

- **What this is:** The containerd Task bridge intended for Kubernetes integration.
- **Problem:** Create uses the task ID as the image reference instead of consuming the supplied bundle rootfs. Start reports the shim's PID; Wait checks lowercase states against the daemon's capitalized state and hardcodes success if its exit branch is reached; kill/delete failures are ignored.
- **Fix:** Mark the integration unsupported and remove it from the default supported product surface. Retire it if not required, otherwise implement bundle handling, real lifecycle/status translation and containerd-backed tests before release.
- **If skipped:** Tasks may fail creation, waits hang, failures appear successful and cleanup is lost.

Sources: `containerd-shim-rauha-v2/src/task.rs:234`, `containerd-shim-rauha-v2/src/task.rs:292`, `containerd-shim-rauha-v2/src/task.rs:403`, `rauhad/src/server.rs:625`.

Additional evidence: the publisher argument is unused, statistics return an empty response, and deletion removes local state before establishing successful daemon cleanup. Ordinary tests for this binary report zero tests; that does not establish runtime compatibility.

Regression needed: actual containerd create/start/wait/delete using exit codes 0 and 7, an unavailable daemon, and a valid bundle whose task ID is not an image reference.

### 8 Distinct image names overwrite the same cache entry

Priority: high. Evidence: reproduced through the actual parser and content store.

- **What this is:** Image-reference names map to manifest files by replacing `/` and `:` with `_`.
- **Problem:** `ghcr.io/team/a_b:latest` and `ghcr.io/team/a/b:latest` are distinct accepted references but produce the same manifest filename. Storing B makes a lookup of A return B's manifest.
- **Fix:** Use a collision-resistant key of the complete canonical reference, or an injective encoding. Account for migration of existing references rather than retaining the ambiguous filename as authoritative.
- **If skipped:** Pulling one image can silently redirect another image's cached identity and subsequent execution.

Sources: `rauha-oci/src/content.rs:95`, `rauha-oci/src/content.rs:126`, `rauha-oci/src/reference.rs:16`, `rauha-oci/src/image.rs:391`.

Minimal reproduced operation sequence: parse both names; `put_manifest(A, "manifest A")`; `put_manifest(B, "manifest B")`; `get_manifest(A)` returns `manifest B`. Dummy bytes suffice because the bug occurs below manifest parsing.

Regression needed: retain separate values for colliding old encodings and cover migrated cache entries. Review the related image directory encoding at the same time.

### 9 Concurrent layer preparation modifies the same extraction directory

Priority: high for concurrent tasks sharing a zone/image. Evidence: source-confirmed interleaving, not a stress-test result.

- **What this is:** Multiple container creations can prepare identical cached layers.
- **Problem:** `prepare_layers` checks a completion marker, removes a partial directory and extracts directly into the final directory without a lock. Two creators can both observe no marker; one can remove or modify the other's in-progress extraction, or a late creator can replace a layer another has just published.
- **Fix:** Serialize extraction for a complete layer identity and publish only completed directories. Readers must never consume a directory another writer can remove as partial work.
- **If skipped:** Concurrent creation can fail unpredictably or use incomplete/mutating image contents.

Sources: `rauha-oci/src/snapshotter.rs:39`, `rauhad/src/zone/registry.rs:555`.

The `ImageService.extracting` mutex does not protect this path: Linux calls the snapshotter directly. Per-zone storage narrows the collision to the same zone, but named zones explicitly allow multiple containers.

Regression needed: barrier-controlled concurrent preparation of one layer, asserting both results contain the full tree and that no published tree changes.

### 10 Deletion leaves runtime filesystem storage behind

Priority: high for sustained task use. Evidence: deletion and orphan-cleanup paths source confirmed; retained Linux mounts need live measurement.

- **What this is:** Completed temporary tasks and deleted containers should release their execution resources.
- **Problem:** Individual container deletion attempts an overlay unmount but retains its filesystem directories; forced zone deletion does not walk container overlays through that path. Backend zone deletion removes cgroups/network/maps, not zone rootfs storage, and orphan cleanup does not reclaim these directories or mounts.
- **Fix:** After stopping executors, explicitly and retryably unmount container rootfs mounts and remove owned per-container/per-zone storage. Keep durable task results and journals under their separate retention contract, and preserve cleanup metadata when cleanup fails.
- **If skipped:** Repeated disposable tasks accumulate extracted layers, writable data and potentially host mounts despite reporting cleanup success, eventually exhausting host resources.

Sources: `rauhad/src/zone/registry.rs:367`, `rauhad/src/zone/registry.rs:738`, `rauhad/src/backend/linux/mod.rs:1207`, `rauhad/src/backend/linux/mod.rs:1018`, `rauha-shim/src/state.rs:199`, `rauha-shim/src/container.rs:151`.

crun's runtime deletion is not a deletion of the caller-created zone storage tree. The daemon creates the overlay mount in the host before handing the bundle to crun.

Regression needed: compare `findmnt` and owned storage before/after repeated temporary tasks, individual deletion, forced zone deletion and interrupted cleanup. Preserve results while removing execution storage.

### 11 Policy updates are not atomic across enforcement and metadata

Priority: high for policy correctness. Evidence: source-confirmed failure and concurrency paths.

- **What this is:** One policy update changes BPF, communication permissions, nftables, resource settings and redb metadata.
- **Problem:** These writes occur sequentially, and metadata is committed last. A metadata failure after a relaxation leaves the relaxed enforcement active with the old stored policy; rollback failures are only logged. Concurrent updates take shared handle guards and can interleave the individual enforcement writes.
- **Fix:** Serialize updates per zone and make partial failure fail closed. Define a recoverable update boundary, preserving the previous effective policy or stopping/freezing affected execution if restoration cannot be established; metadata-first alone is not an atomicity fix.
- **If skipped:** A failed update can still weaken live protection, or two successful updates can leave a mixture of their controls.

Sources: `rauhad/src/zone/registry.rs:471`, `rauhad/src/backend/linux/mod.rs:1309`, `SECURITY.md:103`.

This is separate from finding 3: even controls that support live reload can disagree across stores. The security document's claim that the crash window is never less restrictive is not established by this update order.

Regression needed: inject failure at every enforcement/metadata boundary, including rollback; run two conflicting updates under barriers; require a known complete effective policy or stopped execution.

### 12 File ownership uses an inode number without filesystem identity

Priority: high for kernel enforcement correctness across filesystems. Evidence: source-confirmed identity collision; no live cross-filesystem BPF reproduction.

- **What this is:** The global BPF ownership map decides which zone owns a file.
- **Problem:** Its key is only `u64 i_ino`; inode numbers are unique within a filesystem, not globally. Two files on different filesystems with the same number share one map entry, allowing ownership overwrite, false denials and removal of another file's tracking during cleanup.
- **Fix:** Use the same filesystem-plus-inode identity in userspace registration, kernel lookup, verification and removal. Also handle ownership lifetime/reuse rather than assuming a number remains globally unique.
- **If skipped:** File enforcement and verification can attribute files to the wrong zone; removing one zone can erase another file's ownership record.

Sources: `rauha-ebpf/src/main.rs:33`, `rauha-ebpf/src/main.rs:140`, `rauha-ebpf/src/file_guard.rs:51`, `rauhad/src/backend/linux/maps.rs:199`, `rauhad/src/backend/linux/maps.rs:400`.

This is not a claim that namespace isolation is bypassed by itself. File lookup still depends on reachable paths; the demonstrated design defect is the ownership identity used by the additional BPF protection.

Regression needed: two Linux filesystems with matching inode numbers and distinct owners; confirm independent enforcement, verification and teardown.

### 13 Image pulls buffer an unbounded layer in daemon memory

Priority: high for large or hostile images. Evidence: source confirmed.

- **What this is:** Image downloading runs in the privileged daemon.
- **Problem:** The response is read as a stream but every chunk is appended to one `Vec`; digest validation and storage happen after the full body arrives. There is no configured request/body bound here, and the HTTP client installs no explicit request timeout, so one huge response or several concurrent pulls can exhaust daemon memory.
- **Fix:** Stream into an exclusive temporary blob while hashing, enforce a download bound and timeout, then atomically publish only a verified digest. Apply appropriate limits to manifest/token responses and decompressed extraction as well.
- **If skipped:** An image pull can terminate or indefinitely occupy the daemon independently of workload cgroup limits.

Sources: `rauha-oci/src/distribution.rs:83`, `rauha-oci/src/distribution.rs:196`, `rauha-oci/src/distribution.rs:227`, `rauha-oci/src/content.rs:83`.

Regression needed: oversized and never-ending response fixtures; bounded memory; interrupted download leaves no visible valid blob; concurrent readers never consume a partially written blob.

## Should fix

### 14 Active documentation mixes removed planned and implemented behavior

Evidence: source/document comparison.

- **What this is:** README, security guidance, architecture summaries and old measurement/audit reports.
- **Problem:** The README calls implemented controls unsupported and drop counting future work; product abilities still describe macOS VMs; security guidance describes target-zone checks as absent even though the kernel code performs them. Historical reports mention removed crates and earlier unimplemented sandbox behavior.
- **Fix:** Reconcile current guidance with code and explicitly archive dated historical material. Keep design intent separate from a small authoritative supported-capability list.
- **If skipped:** Operators rely on false guarantees, and contributors repeat completed work or build against removed architecture.

Sources: `README.md:250`, `SECURITY.md:122`, `docs/rauha-product-abilities.md:19`, `rauhad/src/server.rs:1855`, `rauha-ebpf/src/main.rs:213`, `BASELINE.md`, `RESULTS.md`, `docs/observability-audit.md`.

Do not replace the old blanket unsupported-control statement with an unlimited support claim: device/path admission is deliberately restricted, and live reload has finding 3.

### 15 Placeholder commands remain on the supported CLI surface

Evidence: source confirmed.

- **What this is:** `rauha trace` and `rauha top`.
- **Problem:** Trace always errors; top prints that it is not implemented and returns success. Existing-container attach is also explicitly unsupported rather than a general working attach facility.
- **Fix:** Remove or clearly demote unfinished commands. At minimum, unsupported operations must return failure consistently; do not implement a new monitoring subsystem just to retain a placeholder.
- **If skipped:** Help output advertises unavailable functionality and scripts can receive false success.

Sources: `rauha-cli/src/commands/trace.rs:29`, `rauha-cli/src/main.rs:50`, `rauha-shim/src/main.rs:248`.

### 16 Validation tooling retains prohibited language and shell logic debt

Evidence: whole-tree script search and gate inspection.

- **What this is:** Existing integration/security scripts, demonstration code and Wasm experiments.
- **Problem:** The inspected scripts total about 1,730 lines, with substantial branching/orchestration and Python invocations for an HTTP fixture and Wasm bytes. Repository rules explicitly require Rust or Elixir/Erlang for this logic; this is existing debt, not precedent for adding more.
- **Fix:** Move necessary fixtures and orchestration into existing Rust tests or `xtask`, retaining thin launchers. Retire obsolete experiments only after preserving their relevant conclusions.
- **If skipped:** Security validation continues depending on tooling outside the repository's stated implementation policy.

Sources: `tests/security/linux-gate.sh:14`, `tests/integration/test-zone-networking.sh:133`, `eval/wasm-tier-probe.sh:22`, `AGENTS.md`.

The line count is inventory, not a proposed blanket deletion. The scenarios themselves are valuable and must survive a rewrite.

## Cleanup decisions

| Item | Decision and reason |
| --- | --- |
| `BASELINE.md` and `RESULTS.md` | Archive as historical measurements. They describe removed binaries and prior implementation stages; do not rewrite old numbers as present measurements. |
| `docs/observability-audit.md` | Archive or clearly mark superseded after preserving unresolved issues. Update the link from `OBSERVABILITY.md`. |
| `docs/risk-assessment.md` | Keep useful decisions, but retire stale summary tables or explicitly label their historical scope. Some removal decisions are already recorded there. |
| `containerd-shim-rauha-v2` | Remove production-support claims now. Retiring the crate is a product decision, not an automatic dead-code deletion: workspace and docs reference it. |
| `trace` and `top` | Remove/demote placeholders rather than expanding scope just to justify them. |
| Legacy receipt verification | Keep until a deliberate compatibility retirement. Existing saved receipts use it. |
| Legacy veth/rootfs recovery | Keep until persisted installations are migrated and tested. These are referenced recovery paths. |
| Run reducer and journal | Keep. Linux execution and recovery now call them; they are not speculative unused scaffolding. |
| Non-Linux compilation/fallbacks | Keep useful development support; do not confuse it with a supported macOS daemon. |
| Enforcer API and conformance | Keep the contract/tests. Finish the production routing decision before deleting adapters or duplicate state. |
| Integration/security probes | Preserve coverage while replacing implementation debt. |
| Wasm probe | Experimental, not a shipping Wasm tier. Keep as historical evidence or retire together with its result document; do not imply runtime support. |

The three historical reports above total 940 lines. Archiving moves those lines out of active guidance; it does not reduce runtime code or total stored text. No dependency-removal savings were measured.

## Checks that prevented false findings

- Interactive exec does not silently omit an admitted seccomp filter: `rauha-shim/src/attach.rs:364` explicitly rejects containers with one. This is a feature restriction, not the suspected bypass.
- Shim IPC decoding has a 1 MiB frame limit (`rauha-common/src/shim.rs:118`). It is not an unbounded allocation from an arbitrary length prefix.
- The daemon attempts to make its runtime directory root-only before launching shims (`rauhad/src/backend/linux/mod.rs:221`). A missing socket-level credential check alone does not prove arbitrary local users can reach that socket; the TCP API issue is separate.
- Inode batch insertion skips failures internally, but strict container admission checks whether all collected inodes were registered (`rauhad/src/backend/linux/mod.rs:1530`). Do not report this as an unconditional silent strict-mode bypass.
- Recovery stops unfinished executors before checking their journals, retains results before cleanup, and refuses command replay (`rauhad/src/server/recovery.rs:24`). Journal corruption causing refusal is not evidence that a command reruns.
- Broadcast lag is counted in task capture and surfaced in watch events. The README's statement that counting remains future work is stale; completeness of all kernel events is a separate issue.
- Offline receipt verification requires an explicit trusted public key. Automatic sandbox display verifies against the receipt-supplied key; that establishes consistency, not independently pinned server identity, and depends on the transport trust boundary.

## Follow-up investigations not counted as confirmed findings

- **Fork safety:** the shim spawns output/broker/session threads and later forks for interactive exec. Post-fork setup includes libc environment manipulation. The README's synchronous-shim explanation does not establish single-threaded fork safety; inspect async-signal-safety and test for deadlocks under concurrent output before making a definitive failure claim.
- **Layer cache identities:** snapshotter directory names truncate digests to 12 hex characters. Distinct valid digests sharing that prefix alias an extracted directory; use full digests when fixing cache publication. No actual SHA-256 collision pair was generated in this audit.
- **BPF event completeness:** ring-buffer emission can drop events before daemon broadcast. Per-hook totals and broadcast loss do not automatically yield a complete task-level history. Review attribution for multiple tasks sharing one zone.
- **Process/namespace races:** PID/pidfd lifetime, interactive exec enrollment and broker task pinning deserve dedicated hostile Linux tests; selected code review is not a full proof.
- **Extraction resource limits:** decompression ratio, sparse files and disk exhaustion were not stress-tested. Bounded stdout/result storage does not bound image storage.
- **Crash durability of image storage:** blob/reference writes use ordinary writes rather than the journal's atomic publication protocol. Partial writes and concurrent pull/read need targeted fault tests, alongside finding 13.

## Verification record

The source revision was unchanged between the initial audit and deeper pass; existing broad test results were reused rather than rerun without a code change.

| Check | Result and boundary |
| --- | --- |
| `cargo +1.98 test --workspace --offline` | Passed on macOS: 203 tests passed, 5 ignored. Linux-gated runtime/BPF code and live ignored tests are not covered by this result. |
| `cargo fmt --all -- --check` | Passed. |
| Default `cargo test --workspace --offline` | Failed with installed Rust 1.89 on test-only `AtomicUsize::try_update`; installed Rust 1.98 passed. No minimum Rust version/toolchain declaration was found at workspace root. |
| Original symlink harness | Confirmed ordinary rootfs-relative writing follows an absolute symlink outside the rootfs. |
| Deeper image symlink harness | Confirmed real tar extraction plus portable rootfs preparation preserves the redirecting image symlink. |
| Whiteout harness | Confirmed real independent-layer extraction loses the deletion marker and portable merge exposes the deleted file. |
| Image reference harness | Confirmed two accepted canonical references overwrite the same content-store manifest entry. |
| Repository diff | Only this report was added; no runtime fixes or cleanup deletions were applied. |

Temporary Rust harnesses used the compiled Rust 1.98 libraries, asserted outcomes, and removed their temporary fixture directories. The important fixtures and assertions are specified under findings 1, 2 and 8 so temporary `/tmp` files are not the only record of the evidence. They were not committed as regression tests because this work authorized an audit/report, not an implementation change.

## Recommended sequence

1. Close rootfs path escape and image-content correctness defects: 1, 2, 8 and 9.
2. Make the control boundary and policy changes truthful: 4, 3 and 11.
3. Bind evidence to exact execution inputs and correct kernel identity: 6 and 12.
4. Prove teardown and bound image ingestion: 10 and 13.
5. Narrow the supported product surface and correct its example: 5, 7 and 15.
6. Reconcile documentation and migrate tooling without removing its tests: 14 and 16.

Verdict: substantial runtime foundations, but not ready to treat hostile-image execution and every advertised integration as proven safe. Fix rootfs safety first.

Lean: 940 lines can leave active documentation through archiving; runtime-line and dependency savings are unmeasured.

Not checked: privileged Linux integration/security gates, live BPF enforcement, the running-daemon oracle, actual containerd execution, complete broker/ABI correctness, production load, current remote CI results, and every dependency vulnerability. No live Linux exploit is claimed by the portable reproductions.
