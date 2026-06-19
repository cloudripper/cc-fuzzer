---
name: tick
description: Advance the fuzzing loop by one tick. Use when running a campaign manually, or as the unit the YOLO self-loop chains.
argument-hint: "(no arguments — advance one WARM tick)"
---

Advances the campaign by exactly one WARM tick. The main thread dispatches the **fuzz-orchestrator** subagent to *decide* the tick action; the orchestrator returns a single `YOLO_NEXT:` directive as its last line, and **the main thread performs the action** (dispatch a specialist, run a bash lever via ops-runner, `ScheduleWakeup`, or stop), then re-enters the loop. Under YOLO that re-entry is what self-drives the campaign — a chain of orchestrator-decision → main-dispatch steps, not a loop inside this skill.

**The orchestrator cannot dispatch anything.** Under ctxctl the top-level thread is the only context with the `Agent` tool, and no cc-fuzzer agent carries it — so every specialist dispatch happens here, on the main thread. The orchestrator and ops-runner are the only contexts that run Bash. The full directive vocabulary is in `${CLAUDE_PLUGIN_ROOT}/STATE_SCHEMA.md` ("The `YOLO_NEXT:` next-action directive").

## Steps

1. **Refresh the campaign-header digest** (so the orchestrator and any specialists see current shared context). Dispatch `Agent(subagent_type: "ops-runner", prompt: "Run ${CLAUDE_PLUGIN_ROOT}/scripts/campaign-header.sh > ${FUZZ_STATE_DIR}/header.txt and report the captured header. If FUZZ_STATE_DIR is unset, the path-anchor resolves it to fuzz/state/.")`.
2. **Dispatch the orchestrator** for the WARM tick decision. Keep the prompt minimal — the orchestrator reads `fuzz/state/current.json` itself; repeating state in the prompt wastes its context window and causes stalls.

   Correct:
   ```
   Advance one WARM tick. Campaign root: <abs-path>.
   ```

   Never:
   ```
   Advance one WARM tick. Campaign root: <abs-path>.
   Current state: {... pasted JSON ...}
   Next steps: 1. Run update-current.sh 2. Read current.json 3. ...
   Env vars: CC_FUZZER_PROJECT_ROOT=... FUZZ_STATE_DIR=...
   ```

   No JSON blobs, no step lists, no env-var dumps. One sentence + root path is enough. The orchestrator is the WARM-tick expert; trust it.
3. **Read the orchestrator's return text** (it appears as conversation; no Bash needed).
4. **Parse the `YOLO_NEXT:` directive** from the last non-blank line of the orchestrator's return, and **perform it** per the table below. Then re-enter the loop as the directive dictates.

## Performing the directive

| `YOLO_NEXT:` line | Main-thread action |
|---|---|
| `dispatch agent=<type> args="<args>" reason="…"` | The tick's action is to run a specialist. Dispatch it: `Agent(subagent_type: "<type>", prompt: "<args>. Campaign root: <abs-path>.")`. After it returns, **re-enter the loop**: re-run this `/cc-fuzzer:tick` flow from step 1 (the next orchestrator decision will then emit the `schedule` that paces the YOLO cadence, or the next action). For a manual (non-YOLO) tick, performing the one dispatch is the tick — report and stop. |
| `run script="<script + args>" reason="…"` | The action is a bash lever. Dispatch `Agent(subagent_type: "ops-runner", prompt: "Run ${CLAUDE_PLUGIN_ROOT}/scripts/<script + args> and report the output.")` — or, when the script is a slash skill (e.g. `/fuzz-review`), invoke that skill directly. Then re-enter the loop as for `dispatch`. |
| `schedule delay=<n> prompt=/cc-fuzzer:tick reason="…"` | See "YOLO self-loop" below — call `ScheduleWakeup`. |
| `orchestrator reason="…"` | The next move needs a fresh orchestrator decision — re-run this flow from step 1. (Mostly emitted by `yolo-route.sh`, not the orchestrator itself.) |
| `halt reason="…"` / `inactive` / `done reason="…"` | Stop. Do **not** reschedule. Surface the reason (for `halt`, the next step e.g. `/cc-fuzzer:report`). |

A `dispatch`/`run` directive is an **act** step: perform it, then the loop continues with another orchestrator decision. A `schedule` directive is the **wait/cadence** step that fires the next tick after a delay.

## YOLO self-loop — chain the next tick

When YOLO is on, the campaign self-drives as a **chain on the main thread**: each orchestrator decision either *acts* (a `dispatch`/`run` directive you perform, then re-enter for the next decision) or *waits* (a `schedule` directive that fires the next tick after a delay). The orchestrator can't schedule or dispatch itself — a wakeup it scheduled would die with it, and it has no `Agent` tool — so it only *decides*; the main thread performs and chains.

On a `schedule delay=<n> prompt=/cc-fuzzer:tick reason="…"` directive, call `ScheduleWakeup(delaySeconds=<n>, prompt="/cc-fuzzer:tick", reason="<the reason>")`. That re-invokes this conversation when it's idle, firing the next tick — which chains the one after. (Runtime clamps the delay to [60, 3600].) On `halt`/`inactive`/`done`, do **not** reschedule — the chain ends. On `dispatch`/`run`, perform the action then re-enter the flow (see "Performing the directive" above).

That is the entire loop: `decide → act-and-reenter` or `decide → schedule → fire → …` until a halt/inactive/done breaks it. No `/loop`, no cron — `ScheduleWakeup` re-invokes the conversation on its own. The chain runs while the session is idle; a fired tick won't interrupt the user mid-message.

### Missing `YOLO_NEXT:` line — recover, don't re-dispatch

If the orchestrator's output has **no `YOLO_NEXT:` line** (it did the tick work but ended on its status block), the tick itself already happened — only the next-tick directive is missing. Do **not** re-dispatch the orchestrator just to get the line; that burns a second full Opus dispatch (~25k tokens, minutes) for one line.

Instead recover it deterministically by dispatching ops-runner:

```
Agent(subagent_type: "ops-runner",
      prompt: "Run ${CLAUDE_PLUGIN_ROOT}/scripts/yolo-state.sh next-tick. Return its single YOLO_NEXT: line as the last non-blank line of your reply.")
```

It prints exactly one `YOLO_NEXT:` line (`inactive` / `halt …` / `schedule delay=<base interval> …`) derived from `current.json.yolo_state`, and disables YOLO itself if a halt is due. Read the line from the ops-runner return and act on it with the table above. The only thing lost versus the orchestrator emitting it directly is the disposition-aware backoff (you get the base interval) — a fine trade for skipping a redundant Opus dispatch. Only re-dispatch the orchestrator if it stalled **before** completing the tick steps (see Stall recovery below), not merely because the trailing line is absent.

If YOLO is **off** and you ran this manually, just report the tick result and stop — no scheduling.

## Stall recovery

If the orchestrator subagent stalls or returns without completing a tick step:
1. **Diagnose**: read the last few lines of its output. Is it stuck waiting for input? Did it hit a policy filter? Did a tool call fail?
2. **Redirect** (preferred): use `SendMessage` with a short correction (e.g. "Skip the triage step — pass only the directory path, not crash contents").
3. **Restart** (if redirect fails): re-dispatch with a fresh minimal prompt. Never absorb the work into the main context or try to complete the tick yourself.

Useful manually for inspecting each LLM decision before the next fires, running where you can't leave a long session open, or debugging the orchestrator's decision logic.
