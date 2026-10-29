---
name: fuzz-stop
description: "Stop the running fuzzer cleanly and exit the campaign loop. — usage: [--slot <name>]   (default: all slots)"
argument-hint: "[--slot <name>]   (default: all slots)"
---

`/fuzz-stop` is the campaign-loop escape hatch. It disables YOLO (so the self-loop ends — the next chained tick will see `yolo_state.active=false`, emit `YOLO_NEXT: inactive`, and not reschedule), then stops the running fuzzer.

Under ctxctl the top-level thread cannot run Bash directly. Dispatch **ops-runner** for the script invocations and report what it returns.

## Steps

1. Dispatch `Agent(subagent_type: "ops-runner", prompt: "Run this two-step shell sequence and report the final state. Step 1: ${CLAUDE_PLUGIN_ROOT}/scripts/yolo-state.sh disable --reason 'campaign stopped by user via /fuzz-stop'. Step 2: ${CLAUDE_PLUGIN_ROOT}/scripts/stop-fuzzer.sh ${ARGUMENTS}. Return the captured output as plain text.")`.
2. Read the Agent's return text (it appears as conversation, no Bash needed on the main thread).
3. Report to the user: a one-line summary of what stopped, plus whatever final-state data the script surfaced (total runtime, final coverage %, total/unique crashes, LLM spend if `budget.json` was present).

`stop-fuzzer.sh` sends SIGTERM to the fuzzer, waits for it to exit, then SIGKILL if needed. Do not delete state files — the user may want to inspect them or resume with `/cc-fuzzer:resume-campaign`.

A slash command can't cancel the YOLO loop's pending wakeup, so at most one more tick may fire after this — and it's a cheap no-op: it sees YOLO disabled and ends the loop with `ScheduleWakeup(stop: true)`. To stop the loop at once, press Esc while it waits for its next iteration. YOLO is a self-paced `/loop` of `/cc-fuzzer:tick`, so there is no process to kill.
