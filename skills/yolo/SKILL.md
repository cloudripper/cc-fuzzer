---
name: yolo
description: "Toggle YOLO mode (auto-tick self-looping). Off by default — `/cc-fuzzer:yolo on` opts in. When active, the orchestrator schedules its own next tick and follows the operator stance for the chosen mode (guided / hybrid / self_loop) and aggressiveness posture (conservative / balanced / aggressive, defaulted from the mode). — usage: on [--mode guided|hybrid|self_loop] [--aggressiveness conservative|balanced|aggressive] [--no-cap] [--interval 30m] [--max-ticks N] [--max-cost USD] | off [--reason \"...\"] | status"
argument-hint: "on [--mode guided|hybrid|self_loop] [--aggressiveness conservative|balanced|aggressive] [--no-cap] [--interval 30m] [--max-ticks N] [--max-cost USD] | off [--reason \"...\"] | status"
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

Sets `yolo.enabled: false` in `fuzz/state/fuzz-config.json`. The orchestrator stops scheduling wakeups. `/cc-fuzzer:stop` also disables YOLO as a side effect.

### `status` — print current configuration and runtime state

## Invocation

Translate the parsed action into a `${CLAUDE_PLUGIN_ROOT}/scripts/yolo-state.sh` call (convert human-readable intervals to seconds first), then run `${CLAUDE_PLUGIN_ROOT}/scripts/update-current.sh` so `current.json:yolo_state` reflects the change before the next tick reads it.

For the operator-stance behavior during active YOLO ticks (auto-pilot survey, action precedence, halt conditions, `ScheduleWakeup` mechanics), see the "YOLO operator stance" section in `${CLAUDE_PLUGIN_ROOT}/agents/fuzz-orchestrator.md`.
