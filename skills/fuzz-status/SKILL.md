---
name: fuzz-status
description: Print campaign status (coverage, fuzzer stats, findings, decision) without invoking any LLM agent. Cheap and safe to run between ticks.
argument-hint: "(no arguments — pure-shell status, safe between ticks)"
---

Under ctxctl the top-level thread cannot run Bash directly. Dispatch **ops-runner** to run the status script.

## Steps

1. Dispatch `Agent(subagent_type: "ops-runner", prompt: "Run ${CLAUDE_PLUGIN_ROOT}/scripts/status.sh and return the full output verbatim. This is a pure-shell read-only script; no LLM dispatch involved.")`.
2. Print the Agent's return verbatim to the user.

`status.sh` reads `fuzz/state/current.json`, `fuzz/state/fuzzer.log`, and the most recent snapshots, and prints a compact status digest. It does not invoke any agent or model. Safe to run freely between ticks. No header.txt refresh is needed (the script reads state directly).
