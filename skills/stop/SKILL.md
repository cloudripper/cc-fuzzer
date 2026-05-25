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

This sets `fuzz-config.json:yolo.enabled=false`, which ends the self-loop: the next chained tick that fires sees YOLO inactive (`YOLO_NEXT: inactive`) and doesn't reschedule. A wakeup that's already pending can't be force-cancelled from a slash command, so at most one more tick fires — and it's a cheap no-op. (If you also started a manual `/loop`, exit it; the YOLO chain itself is just `ScheduleWakeup`, no process to kill.)

Then run `${CLAUDE_PLUGIN_ROOT}/scripts/stop-fuzzer.sh` to send SIGTERM to the fuzzer, wait for it to exit, then SIGKILL if needed. Then summarize the final state from `fuzz/state/`:

- Total runtime
- Final coverage
- Total crashes (and unique deduplicated count from `findings.jsonl`)
- LLM spend from `budget.json` (if present)

Do not delete state files — the user may want to inspect them or resume.
