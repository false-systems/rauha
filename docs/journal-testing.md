# Journal failure tests

The standalone journal is tested on Linux. Run its ordinary suite in Lima:

```sh
limactl shell syva-dev -- sh -lc 'cd /Users/yair/projects/rauha && CARGO_TARGET_DIR=/tmp/rauha-run-target cargo test -p rauha-evidence journal:: -- --nocapture'
```

The tests use real files and real subprocesses:

- EIO and ENOSPC are injected through seccomp at journal write, partial write,
  journal sync, head write, head sync, head rename and directory sync.
- RLIMIT_FSIZE allows one byte of a write, then forces EFBIG on its retry.
  Both a false success and rewriting the previously committed prefix fail
  the test. Three successive reopens must preserve the head, tail and staging
  file. An error after head rename may still expose the new head on reopening.
- Four contending processes commit 100 distinct events. The resulting chain
  must be dense and contain every event exactly once.
- One Run survives 41 successive SIGKILLs across append and recovery. A final
  partial tail stays unchanged and blocks writes through further restarts.
- A raw-fork regression holds an inherited descriptor open while its parent
  drops the writer. Explicit unlock must release ownership immediately.
  Closing the parent descriptor alone does not release an inherited
  [Linux flock](https://man7.org/linux/man-pages/man2/flock.2.html).

The subprocess helpers are marked ignored so the test harness does not run
them without their environment. Their parent tests explicitly execute them.
`power_cut_child` is separate: it needs a disposable VM and a host-side oracle.

## Disposable VM power cuts

Use a new VM with no host mounts. Never power-cut a shared development or CI
VM. Build the test executable on Linux first (`cargo test -p rauha-evidence
--no-run` prints its path), then copy that executable into the disposable VM.
The VM must match the binary's architecture and support its libc version.

```sh
limactl create --name=rauha-journal-power --vm-type=vz --cpus=2 --memory=2 --disk=8 --mount-none --containerd=none --tty=false template:ubuntu
limactl start rauha-journal-power --tty=false
# Substitute the Linux test executable path printed by Cargo.
limactl copy syva-dev:/tmp/rauha-run-target/debug/deps/rauha_evidence-HASH /tmp/rauha-journal-power-probe
limactl copy /tmp/rauha-journal-power-probe rauha-journal-power:/var/tmp/probe
limactl shell rauha-journal-power -- chmod +x /var/tmp/probe
```

Prepare a fresh Run. Save its head **outside** the VM before an unacknowledged
append; this is the recovery oracle, never a head copied after recovery.

```sh
limactl shell rauha-journal-power -- env RAUHA_JOURNAL_TEST_PATH=/var/tmp/run RAUHA_JOURNAL_POWER_ACTION=prepare /var/tmp/probe --exact journal::tests::faults::power_cut_child --ignored --nocapture
limactl copy rauha-journal-power:/var/tmp/run/head /tmp/rauha-power-oracle.json
```

In one terminal, start an append paused at the chosen boundary:

```sh
limactl shell rauha-journal-power -- env RAUHA_JOURNAL_TEST_PATH=/var/tmp/run RAUHA_JOURNAL_POWER_ACTION=append RAUHA_JOURNAL_CRASH_AT=head_renamed RAUHA_JOURNAL_CRASH_MARKER=/dev/stdout /var/tmp/probe --exact journal::tests::faults::power_cut_child --ignored --nocapture
```

Wait until the boundary name appears. In another terminal, cut the VM without
a guest shutdown, restart it, and copy back the saved oracle:

```sh
limactl stop --force rauha-journal-power
limactl start rauha-journal-power --tty=false
limactl copy /tmp/rauha-power-oracle.json rauha-journal-power:/var/tmp/oracle.json
limactl shell rauha-journal-power -- env RAUHA_JOURNAL_TEST_PATH=/var/tmp/run RAUHA_JOURNAL_POWER_ACTION=verify RAUHA_JOURNAL_ORACLE=/var/tmp/oracle.json /var/tmp/probe --exact journal::tests::faults::power_cut_child --ignored --nocapture
```

Copy the oracle back from the host after **every** restart, including a second
cut during recovery. Its previous unsynced guest copy may be empty or missing.
The probe verifies the acknowledged prefix against the external head, checks
the complete recovered chain and refuses writes if a tail survived. Repeat
with fresh Run paths for these cases:

| Cut | Oracle and required result |
| --- | --- |
| After append returns `ACK` | Omit `RAUHA_JOURNAL_CRASH_AT`; the probe parks after printing ACK. Copy the new head to the host before cutting. Verify with `RAUHA_JOURNAL_REQUIRE_EXACT=1`. |
| `partial_append` | Save the old head before starting. Verify with `RAUHA_JOURNAL_REQUIRE_EXACT=1`; unflushed tail bytes may disappear with the guest cache. |
| `head_renamed` | Save the old head before starting. Either old or new head may survive; every acknowledged entry must remain. |
| `recovery_verified` | After a head-rename cut, run `verify` with this crash boundary and cut again before its directory sync. Then verify without the boundary. |

After testing, remove only this disposable VM:

```sh
limactl stop --force rauha-journal-power
limactl delete --force rauha-journal-power
```

These are guest power-cut tests: SIGKILL of the VM driver discards guest
memory without a clean guest shutdown. The host and physical drive remain
powered. This does not certify physical-device cache behavior, every write
reordering, or network filesystems. Seccomp errors also do not simulate every
possible partial device failure; the tests establish the specific cases above.

## Observed run, 2026-10-03

A disposable aarch64 VZ VM ran Ubuntu with Linux 7.0.0-28 and ext4 on its own
virtual disk (`commit=30`, no host mounts). Four driver SIGKILLs covered the
acknowledged append, partial append, head rename and interrupted recovery.

```text
PASS POWER CUT: acknowledged sequence 2 preserved; recovered sequence 2; tail 0
PASS POWER CUT: acknowledged sequence 1 preserved; recovered sequence 1; tail 0
PASS POWER CUT: acknowledged sequence 1 preserved; recovered sequence 2; tail 0
```

The partial unflushed append disappeared. The renamed head survived, including
a second power cut before recovery's sync. Each acknowledged prefix matched
its host oracle. The earlier acknowledged Run also verified after all four
cuts. Unsynced guest oracle copies did disappear; verification used fresh
copies of the originals retained on the host.
