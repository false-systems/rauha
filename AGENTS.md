# AGENTS.md

## Languages

Prefer **Rust, or Elixir/Erlang**. Python and Go are allowed but not preferred:
use them when they clearly fit the job (an existing tool, a library or prior
art), not by default.

## Lessons

<!-- This repository's accepted knowledge: one line per node, each marked with its id, written here through a pull request when a person accepts one. A line changed here by hand is replaced the next time it is written: change a lesson where it is decided. -->

- <!-- lesson: rauha-linux-only --> **decision**: Rauha product work is Linux-only. Do not plan or implement macOS support or a macOS-first launch. Earlier macOS requirements in product documents are superseded. (as of 2026-10-27)
- <!-- lesson: rauha-ci-leftover-daemon-port-9876 --> **fact**: Rauha's privileged CI can fail because an idle rauha daemon left over from an earlier run still holds its default port 9876 on the runner. Check that no workload or active CI job owns that daemon, stop only that daemon, and rerun the failed job. Do not change the gate. (as of 2026-10-27)
