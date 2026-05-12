---
description: Print campaign status (coverage, fuzzer stats, findings, decision) without invoking any LLM agent. Cheap and safe to run between ticks.
allowed-tools: Bash
---

Run `${CLAUDE_PLUGIN_ROOT}/scripts/status.sh` and print the result verbatim.

This is a pure-shell script that reads `fuzz/state/current.json`, `fuzz/state/fuzzer.log`, and the most recent snapshots. It does not invoke any agent or model. Use it freely to check progress without triggering tick logic.
