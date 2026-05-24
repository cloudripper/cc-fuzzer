---
name: stop
description: "Stop the running fuzzer cleanly and exit the campaign loop. — usage: [--slot <name>]   (default: all slots)"
argument-hint: "[--slot <name>]   (default: all slots)"
allowed-tools: Bash
disable-model-invocation: true
---

First, disable YOLO if it was enabled — `/cc-fuzzer:stop` is the escape hatch:

```bash
${CLAUDE_PLUGIN_ROOT}/scripts/yolo-state.sh disable --reason "campaign stopped by user via /cc-fuzzer:stop"
```

This sets `fuzz-config.json:yolo.enabled=false` so any future ScheduleWakeup the orchestrator might consider will short-circuit. (Pending platform-side wakes that were already scheduled before this stop must be cancelled by the platform's own loop-cancellation; we cannot force-recall them from a slash command.)

Stop all `/loop` processes that are running and terminate the scheduled loop. Then run `${CLAUDE_PLUGIN_ROOT}/scripts/stop-fuzzer.sh` to send SIGTERM to the fuzzer, wait for it to exit, then SIGKILL if needed. Then summarize the final state from `fuzz/state/`:

- Total runtime
- Final coverage
- Total crashes (and unique deduplicated count from `findings.jsonl`)
- LLM spend from `budget.json` (if present)

Do not delete state files — the user may want to inspect them or resume.
