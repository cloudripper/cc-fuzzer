---
name: tick
description: Advance the fuzzing loop by one tick. Use when running a campaign manually, or as the unit the YOLO self-loop chains.
argument-hint: "(no arguments — advance one WARM tick)"
---

Dispatches the **fuzz-orchestrator** subagent to perform exactly one WARM-tick iteration (its WARM-mode procedure owns the steps). Then, if YOLO is active, chain the next tick (below). One invocation = one tick — the chaining, not a loop inside this skill, is what advances the campaign.

## Dispatch prompt — keep it minimal

When you invoke fuzz-orchestrator, pass a SHORT prompt. The orchestrator reads `fuzz/state/current.json` itself; repeating state in the prompt wastes its context window and causes stalls.

**Correct:**
```
Advance one WARM tick. Campaign root: <abs-path>.
```

**Never do this:**
```
Advance one WARM tick. Campaign root: <abs-path>.
Current state: {... pasted JSON ...}
Next steps: 1. Run update-current.sh 2. Read current.json 3. ...
Env vars: CC_FUZZER_PROJECT_ROOT=... FUZZ_STATE_DIR=...
```

No JSON blobs, no step lists, no env-var dumps. One sentence + root path is enough. The orchestrator is the WARM-tick expert; trust it.

## Stall recovery

If the orchestrator subagent stalls or returns without completing a tick step:
1. **Diagnose**: read the last few lines of its output. Is it stuck waiting for input? Did it hit a policy filter? Did a tool call fail?
2. **Redirect** (preferred): use `SendMessage` with a short correction (e.g. "Skip the triage step — pass only the directory path, not crash contents").
3. **Restart** (if redirect fails): re-dispatch with a fresh minimal prompt. Never absorb the work into the main context or try to complete the tick yourself.

Useful manually for inspecting each LLM decision before the next fires, running where you can't leave a long session open, or debugging the orchestrator's decision logic.

## YOLO self-loop — chain the next tick

When YOLO is on, the campaign self-drives as a **chain of ticks on the main thread**: each tick schedules the next via `ScheduleWakeup`. (The orchestrator is a subagent and can't do this itself — a wakeup it scheduled would die with it — so it only *recommends* the delay.) After the subagent returns, read the **last `YOLO_NEXT:` line** of its output and act:

| `YOLO_NEXT:` line | Main-thread action |
|---|---|
| `schedule delay=<n> prompt=/cc-fuzzer:tick reason="…"` | Call `ScheduleWakeup(delaySeconds=<n>, prompt="/cc-fuzzer:tick", reason="<the reason>")`. That re-invokes this conversation when it's idle, firing the next tick — which chains the one after, and so on. (Runtime clamps the delay to [60, 3600].) |
| `halt reason="…"` | A hard halt fired (the orchestrator already disabled YOLO). Do **not** reschedule — that ends the chain. Surface the halt reason + next step (e.g. `/cc-fuzzer:report`). |
| `inactive` | YOLO is off (e.g. `/cc-fuzzer:yolo off` or `/cc-fuzzer:stop` ran). Do **not** reschedule — the chain ends here. |

That is the entire loop: `schedule → fire → schedule → …` until a halt or `inactive` breaks it. No `/loop`, no cron — `ScheduleWakeup` re-invokes the conversation on its own (validated: it fires and chains outside any `/loop`). The chain runs while the session is idle; a fired tick won't interrupt you mid-message.

### Missing `YOLO_NEXT:` line — recover, don't re-dispatch

If the orchestrator's output has **no `YOLO_NEXT:` line** (it did the tick work but ended on its status block), the tick itself already happened — only the next-tick directive is missing. Do **not** re-dispatch the orchestrator just to get the line; that burns a second full Opus dispatch (~25k tokens, minutes) for one line. Instead recover it deterministically from state:

```bash
${CLAUDE_PLUGIN_ROOT}/scripts/yolo-state.sh next-tick
```

It prints exactly one `YOLO_NEXT:` line (`inactive` / `halt …` / `schedule delay=<base interval> …`) derived from `current.json.yolo_state`, and disables YOLO itself if a halt is due. Act on that line with the table above. The only thing lost versus the orchestrator emitting it directly is the disposition-aware backoff (you get the base interval) — a fine trade for skipping a redundant dispatch. Only re-dispatch the orchestrator if it stalled **before** completing the tick steps (see Stall recovery above), not merely because the trailing line is absent.

If YOLO is **off** and you ran this manually, just report the tick result and stop — no scheduling.
