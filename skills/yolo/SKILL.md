---
name: yolo
description: "Toggle YOLO mode (auto-tick self-looping). Off by default — `/cc-fuzzer:yolo on` opts in. When active, the orchestrator schedules its own next tick and follows the operator stance for the chosen mode (guided / hybrid / self_loop). — usage: on [--mode guided|hybrid|self_loop] [--interval 30m] [--max-ticks N] [--max-cost USD] | off [--reason \"...\"] | status"
argument-hint: "on [--mode guided|hybrid|self_loop] [--interval 30m] [--max-ticks N] [--max-cost USD] | off [--reason \"...\"] | status"
allowed-tools: Bash, Read
disable-model-invocation: true
---

**YOLO is off by default — opt in with `/cc-fuzzer:yolo on`.** The plugin's default tick driver is manual (`/cc-fuzzer:tick` or `/loop`). YOLO is a separate, explicit commitment to letting the orchestrator self-pace.

Parse `$ARGUMENTS`. The first positional decides the action:

### `on` — enable YOLO

Flags (defaults shown):

| Flag | Default | Meaning |
|---|---|---|
| `--mode <m>` | `hybrid` | `guided` / `hybrid` / `self_loop` — how each tick decides what to do (see below) |
| `--interval <duration>` | `1800` (30m) | Accepts `30m`, `1800`, `2h`. Minimum 60s. |
| `--max-ticks <N>` | `24` | Hard tick cap |
| `--max-cost <USD>` | `10.0` | Soft cost cap from `events.jsonl` token totals |
| `--stop-on-no-progress <N>` | `30` | Halt after N consecutive zero-delta ticks |
| `--crash-storm-threshold <N>` | `10` | Halt when one interval yields > N new findings |
| `--redundancy-threshold <N>` | `2` | (hybrid/self_loop) suppress an agent after N unproductive dispatches |
| `--soft-cost-fraction <F>` | `0.6` | (hybrid/self_loop) fraction of max-cost where Opus agents get throttled |

### Modes

Every mode shares the same hard halts (tick / cost / no-progress / crash-storm) and the same deterministic `yolo_state.evaluation` signals (cost posture, per-agent redundancy ledger, progress). They differ in **how the tick decides**:

- **`guided`** — the legacy deterministic precedence table; `sleep` is the last resort. Predictable, no per-tick reasoning.
- **`hybrid`** (default) — the orchestrator reasons over the evaluation signals each tick to choose **wait / act / consult** and which action; the table is a fallback. Waiting (with adaptive backoff) is first-class — it lets the fuzzer run when it's still climbing, and defers Opus agents when cost is throttling or an agent is looping without results.
- **`self_loop`** — the orchestrator reasons freely toward the goal from the signals + `plan.md`, pursuing multi-step strategy across ticks; the table is just a menu. Maximum autonomy, still fenced by the hard caps and the redundancy/cost ledger (it won't re-dispatch a looping agent or over-spend on Opus).

### `off [--reason "<text>"]` — disable YOLO

Sets `yolo.enabled: false` in `fuzz/state/fuzz-config.json`. The orchestrator stops scheduling wakeups. `/cc-fuzzer:stop` also disables YOLO as a side effect.

### `status` — print current configuration and runtime state

## Invocation

Translate the parsed action into a `${CLAUDE_PLUGIN_ROOT}/scripts/yolo-state.sh` call (convert human-readable intervals to seconds first), then run `${CLAUDE_PLUGIN_ROOT}/scripts/update-current.sh` so `current.json:yolo_state` reflects the change before the next tick reads it.

For the operator-stance behavior during active YOLO ticks (auto-pilot survey, action precedence, halt conditions, `ScheduleWakeup` mechanics), see the "YOLO operator stance" section in `${CLAUDE_PLUGIN_ROOT}/agents/fuzz-orchestrator.md`.
