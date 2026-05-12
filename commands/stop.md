---
description: Stop the running fuzzer cleanly and exit the campaign loop.
allowed-tools: Bash
---

Stop all `/loop` processes that are running and terminate the scheduled loop. Then run `${CLAUDE_PLUGIN_ROOT}/scripts/stop-fuzzer.sh` to send SIGTERM to the fuzzer, wait for it to exit, then SIGKILL if needed. Then summarize the final state from `fuzz/state/`:

- Total runtime
- Final coverage
- Total crashes (and unique deduplicated count from `findings.jsonl`)
- LLM spend from `budget.json` (if present)

Do not delete state files — the user may want to inspect them or resume.
