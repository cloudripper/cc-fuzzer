---
name: yolo
description: "Toggle YOLO — a self-driving fuzzing loop. `/cc-fuzzer:yolo on` is set-and-forget: it sets the per-tick auto-pilot posture (guided / hybrid / self_loop + aggressiveness), runs a tick immediately, and chains each next tick via ScheduleWakeup so the campaign advances unattended until a hard halt or `/cc-fuzzer:yolo off`. No /loop, no babysitting. — usage: on [--mode guided|hybrid|self_loop] [--aggressiveness conservative|balanced|aggressive] [--no-cap] [--interval 30m] [--max-ticks N] [--max-cost USD] | off [--reason \"...\"] | status"
argument-hint: "on [--mode guided|hybrid|self_loop] [--aggressiveness conservative|balanced|aggressive] [--no-cap] [--interval 30m] [--max-ticks N] [--max-cost USD] | off [--reason \"...\"] | status"
disable-model-invocation: true
---

**YOLO is off by default — opt in with `/cc-fuzzer:yolo on`.** Without it, advance the campaign manually with `/cc-fuzzer:tick`. `yolo on` is the **set-and-forget** path: it starts a self-driving loop (one command, no `/loop`) that runs ticks automatically until a hard halt or you turn it off.

Parse `$ARGUMENTS`. The first positional decides the action:

### `on` — enable YOLO

Flags (defaults shown):

| Flag | Default | Meaning |
|---|---|---|
| `--mode <m>` | `hybrid` | `guided` / `hybrid` / `self_loop` — how each tick decides what to do (see below) |
| `--aggressiveness <a>` | from mode | `conservative` / `balanced` / `aggressive` — how readily a tick acts vs waits. Defaults from `--mode` (guided→conservative, hybrid→balanced, self_loop→aggressive); pass this to override independently. |
| `--interval <duration>` | `1800` (30m) | Accepts `30m`, `1800`, `2h`. Minimum 60s. |
| `--max-ticks <N>` | `24` | Hard tick cap |
| `--max-cost <USD>` | `10.0` | Soft cost cap from `events.jsonl` token totals |
| `--stop-on-no-progress <N>` | `30` | Halt after N consecutive zero-delta ticks |
| `--crash-storm-threshold <N>` | `10` | Halt when one interval yields > N new findings |
| `--redundancy-threshold <N>` | `2` | (hybrid/self_loop) suppress an agent after N unproductive dispatches |
| `--soft-cost-fraction <F>` | `0.6` (`0.8` if aggressive) | (hybrid/self_loop) fraction of max-cost where Opus agents get throttled |
| `--no-cap` | (cap on) | Remove cost as a constraint entirely — **no** soft Opus throttle **and no** hard `--max-cost` halt. The campaign runs until a non-cost halt fires (tick cap / no-progress / crash-storm) or you stop it. `--cap` re-enables. |

### Modes

Every mode shares the same hard halts (tick / cost / no-progress / crash-storm) and the same deterministic `yolo_state.evaluation` signals (cost posture, per-agent redundancy ledger, progress). They differ in **how the tick decides** — and each carries a default **aggressiveness** posture (override with `--aggressiveness`):

- **`guided`** (→ `conservative`) — the legacy deterministic precedence table; `sleep` is the last resort. Predictable, no per-tick reasoning.
- **`hybrid`** (default, → `balanced`) — the orchestrator reasons over the evaluation signals each tick to choose **wait / act / consult** and which action; the table is a fallback. It acts on a concrete gap move even while the fuzzer climbs, and waits (with adaptive backoff) when there's no gap move, when an agent is looping, or when cost is throttling Opus.
- **`self_loop`** (→ `aggressive`) — the orchestrator reasons freely toward the goal from the signals + `plan.md`, pursuing multi-step strategy across ticks; the table is just a menu. A self-climbing fuzzer is **not** a reason to idle — when no gap move remains it pursues the strategic toolbox (harness/CVE/review/PoC/plan) in parallel, and the wait-backoff does not compound so priorities never go stale. Maximum autonomy, still fenced by the hard caps and the redundancy/cost ledger.

### Toolbox board (anti-tunnel-vision)

Every tick the evaluation block carries `toolbox` — the **whole known lever set, materialized deterministically** (`_lib/toolbox_eval.py`) so the orchestrator can't tunnel-vision on seedgen/concolic. It lists each `eligible` lever with its `cost_tier` and `idle_ticks`, flags `neglected_levers` (eligible but idle), and sets `tunnel_vision` + `suggested_lever` when the campaign has been riding one lever family — under `aggressive` the disposition is steered onto the neglected lever to force breadth. The board is explicitly **`non_exhaustive` (a floor, not a ceiling)**: `references` surfaces `fuzz/guidance.md`, `fuzz/docs/`, and `fuzz/state/cve-patterns.md` (the CVE-review output, when present) so the orchestrator folds in operator domain knowledge and the CVE intel it already paid for, and invents moves the catalog can't express. When `references.cve_patterns_md` is set, read that file instead of re-dispatching the `cve_refresh` lever. Drop reference material in `fuzz/docs/` and write `fuzz/guidance.md` to steer the creative reasoning.

### Aggressiveness posture

`--aggressiveness` decouples "how hard does a tick push to act" from the mode. It shapes two things deterministically (in `_lib/yolo_evaluate.py`):

- **`conservative`** — a self-climbing fuzzer or an empty gap-branch ⇒ `wait` (legacy). Backoff compounds up to `--max-backoff-multiplier`.
- **`balanced`** — acts on a concrete, affordable gap move even while climbing; waits when there's no gap move. Backoff compounds.
- **`aggressive`** — never idles on a self-climbing fuzzer; an empty gap-branch becomes "pursue the strategic toolbox"; throttle defers Opus but still prefers a non-Opus lever over waiting; backoff does **not** compound; `--soft-cost-fraction` defaults to `0.8` so strategic Opus levers stay available longer.

### `off [--reason "<text>"]` — disable YOLO

Sets `yolo.enabled: false` in `fuzz/state/fuzz-config.json`. A pending wakeup can't be force-cancelled, so the self-loop stops on the **next** fired tick — it sees `yolo_state.active=false`, the orchestrator emits `YOLO_NEXT: inactive`, and the tick skill doesn't reschedule. `/cc-fuzzer:stop` also disables YOLO as a side effect.

### `status` — print current configuration and runtime state

## Invocation

Translate the parsed action into a `${CLAUDE_PLUGIN_ROOT}/scripts/yolo-state.sh` call (convert human-readable intervals to seconds first), then run `${CLAUDE_PLUGIN_ROOT}/scripts/update-current.sh` so `current.json:yolo_state` reflects the change before the next tick reads it.

## Starting the self-loop (action `on`)

YOLO self-drives from the **main thread**: each tick schedules the next via `ScheduleWakeup`, so once started the campaign advances unattended — no `/loop`, no cron, no babysitting. (The orchestrator is a subagent and only *recommends* each delay via its `YOLO_NEXT:` line; the main thread owns the `ScheduleWakeup` call. This works because a main-thread `ScheduleWakeup` fires and chains even outside a `/loop` — validated.)

**Before enabling**, read `fuzz/state/fuzz-config.json` and note whether `yolo.enabled` was already `true`. Then, after the `yolo-state.sh enable` + `update-current.sh` steps:

1. **Was already enabled (settings update)** — a chain is presumably already live. Do **not** start another (parallel chains waste cost). Just report the updated config. If the user believes the loop died (e.g. after a session restart), tell them to run `/cc-fuzzer:yolo off` then `on` to restart it cleanly.
2. **Campaign is running, fresh enable** — start the loop NOW: perform one tick immediately by following the `/cc-fuzzer:tick` flow (dispatch `fuzz-orchestrator` for one WARM tick, then chain via `ScheduleWakeup` per its `YOLO_NEXT:` line). Then tell the user: *"YOLO `<mode>` is self-driving — first tick ran now, next in ~`<interval>`. It continues unattended until a hard halt (tick / cost / no-progress / crash-storm cap) or `/cc-fuzzer:yolo off` / `/cc-fuzzer:stop`."*
3. **No campaign running yet, fresh enable** — don't tick. Tell the user the loop will start automatically when the campaign launches (`/cc-fuzzer:campaign` repeats this bootstrap once COLD setup completes).

Determine campaign state with `${CLAUDE_PLUGIN_ROOT}/scripts/check-campaign-state.sh`.

For the operator-stance behavior during active YOLO ticks (auto-pilot survey, action precedence, halt conditions, and the `YOLO_NEXT:` next-tick directive the tick skill consumes to chain the loop), see the "YOLO operator stance" / "Halt-or-schedule decision" sections in `${CLAUDE_PLUGIN_ROOT}/agents/fuzz-orchestrator.md`.
