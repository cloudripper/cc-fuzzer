---
name: tick
description: Advance the fuzzing loop by one tick. Use when running a campaign manually, or as the unit the YOLO self-loop chains.
argument-hint: "(no arguments — advance one WARM tick)"
disable-model-invocation: true
---

Dispatches the **fuzz-orchestrator** subagent to perform exactly one WARM-tick iteration (its WARM-mode procedure owns the steps). Then, if YOLO is active, chain the next tick (below). One invocation = one tick — the chaining, not a loop inside this skill, is what advances the campaign.

Useful manually for inspecting each LLM decision before the next fires, running where you can't leave a long session open, or debugging the orchestrator's decision logic.

## YOLO self-loop — chain the next tick

When YOLO is on, the campaign self-drives as a **chain of ticks on the main thread**: each tick schedules the next via `ScheduleWakeup`. (The orchestrator is a subagent and can't do this itself — a wakeup it scheduled would die with it — so it only *recommends* the delay.) After the subagent returns, read the **last `YOLO_NEXT:` line** of its output and act:

| `YOLO_NEXT:` line | Main-thread action |
|---|---|
| `schedule delay=<n> prompt=/cc-fuzzer:tick reason="…"` | Call `ScheduleWakeup(delaySeconds=<n>, prompt="/cc-fuzzer:tick", reason="<the reason>")`. That re-invokes this conversation when it's idle, firing the next tick — which chains the one after, and so on. (Runtime clamps the delay to [60, 3600].) |
| `halt reason="…"` | A hard halt fired (the orchestrator already disabled YOLO). Do **not** reschedule — that ends the chain. Surface the halt reason + next step (e.g. `/cc-fuzzer:report`). |
| `inactive` | YOLO is off (e.g. `/cc-fuzzer:yolo off` or `/cc-fuzzer:stop` ran). Do **not** reschedule — the chain ends here. |

That is the entire loop: `schedule → fire → schedule → …` until a halt or `inactive` breaks it. No `/loop`, no cron — `ScheduleWakeup` re-invokes the conversation on its own (validated: it fires and chains outside any `/loop`). The chain runs while the session is idle; a fired tick won't interrupt you mid-message.

If YOLO is **off** and you ran this manually, just report the tick result and stop — no scheduling.
