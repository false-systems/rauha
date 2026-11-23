# AGENTS.md

## Languages

Code in this repository is **Rust, or Elixir/Erlang**. Never add Python, Go
or Node (JavaScript/TypeScript): not for tools, scripts, CI helpers, tests,
dashboards or glue. A thin shell step in a CI workflow is fine; anything with
logic is Rust. Existing Python or Node files are debt to be rewritten, not
precedent to follow.

## Lessons

<!-- This repository's accepted knowledge: one line per node, each marked with its id, written here through a pull request when a person accepts one. A line changed here by hand is replaced the next time it is written: change a lesson where it is decided. -->

- <!-- lesson: rauha-linux-only --> **decision**: Rauha product work is Linux-only. Do not plan or implement macOS support or a macOS-first launch. Earlier macOS requirements in product documents are superseded. (as of 2026-10-27)
- <!-- lesson: rauha-ci-leftover-daemon-port-9876 --> **fact**: Rauha's privileged CI can fail because an idle rauha daemon left over from an earlier run still holds its default port 9876 on the runner. Check that no workload or active CI job owns that daemon, stop only that daemon, and rerun the failed job. Do not change the gate. (as of 2026-10-27)
