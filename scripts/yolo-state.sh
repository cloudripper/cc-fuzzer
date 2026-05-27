#!/usr/bin/env bash
# yolo-state.sh
#
# Manages the YOLO (user-defined self-looping) state block in
# fuzz/state/fuzz-config.json. Used by the /cc-fuzzer:yolo slash command and
# by the orchestrator's end-of-tick check.
#
# YOLO is opt-in and self-driving. `/cc-fuzzer:yolo on` runs a tick and chains:
# each WARM tick emits a YOLO_NEXT: directive that the main-thread
# /cc-fuzzer:tick skill turns into a ScheduleWakeup for the next tick (the
# orchestrator is a subagent and cannot reschedule the main conversation, so
# the skill owns the call). Hard halts protect against runaway: tick cap, cost
# cap, no-progress detector, crash-storm guard.
#
# Subcommands:
#   yolo-state.sh enable    [--mode guided|hybrid|self_loop] [--aggressiveness conservative|balanced|aggressive]
#                           [--interval SEC] [--max-ticks N] [--max-cost USD]
#                           [--stop-on-no-progress N] [--crash-storm-threshold N]
#                           [--redundancy-threshold N] [--soft-cost-fraction F] [--max-backoff-multiplier N]
#       Set yolo.enabled=true, optionally override defaults. Records
#       enabled_at_ts and enabled_at_tick from current.json.
#
#       --mode selects how each tick decides what to do:
#         guided    deterministic precedence table (legacy)
#         hybrid    orchestrator reasons over the evaluation signals; the table
#                   is a fallback (default)
#         self_loop orchestrator reasons freely from signals + plan; the table
#                   is a menu. Hard caps + the redundancy/cost ledger still bind.
#
#       --aggressiveness shapes the deterministic disposition (act vs wait) and
#       the wait-backoff. Defaults from --mode when omitted (guided→conservative,
#       hybrid→balanced, self_loop→aggressive):
#         conservative  self-climbing fuzzer or no gap move ⇒ wait (legacy)
#         balanced      act on a concrete gap move even while climbing
#         aggressive    never idle on a self-climbing fuzzer; pursue the
#                       strategic toolbox when no gap move remains; backoff does
#                       not compound; soft_cost default rises to 0.8
#
#       --no-cap removes cost as a constraint entirely: no soft throttle (the
#       `throttle` posture that defers Opus past soft_cost_fraction) AND no hard
#       --max-cost halt. The campaign then runs until a non-cost halt fires
#       (tick cap / no-progress / crash-storm) or you stop it. --cap re-enables.
#
#   yolo-state.sh disable [--reason TEXT]
#       Set yolo.enabled=false. Records last_halt_reason.
#
#   yolo-state.sh status
#       Print one-line summary of the current yolo block.
#
#   yolo-state.sh check-halt
#       Inspect current.json:yolo_state and decide whether a halt is due.
#       Exit 0 = continue (no halt). Exit 1 = halt due. Prints the reason
#       to stdout regardless. Used by the orchestrator before emitting YOLO_NEXT.
#
#   yolo-state.sh next-tick
#       Print the YOLO_NEXT: directive line derived deterministically from
#       current.json:yolo_state (inactive / halt / schedule at the base
#       interval). This is the main-thread tick skill's FALLBACK for when the
#       orchestrator subagent returned without emitting its own YOLO_NEXT line
#       — it recovers the next-tick decision without paying for a second full
#       Opus dispatch. On halt it also disables YOLO (mirrors the orchestrator)
#       so the state sticks. Always exits 0; prints exactly one YOLO_NEXT: line.
#
# Defaults (when fields are absent):
#   mode:                        hybrid
#   aggressiveness:              derived from mode (balanced for hybrid)
#   interval_seconds:            1800 (30 min)
#   max_ticks:                   24
#   max_cost_usd:                10.0
#   stop_on_no_progress_ticks:   30
#   crash_storm_threshold:       10
#   redundancy_threshold:        2
#   soft_cost_fraction:          0.6 (0.8 when aggressiveness=aggressive)
#   max_backoff_multiplier:      4

set -u

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
. "$SCRIPT_DIR/_lib/path-anchor.sh"

STATE_DIR="${FUZZ_STATE_DIR:-$FUZZ_ROOT/state}"
CFG_FILE="$STATE_DIR/fuzz-config.json"
CURRENT_FILE="$STATE_DIR/current.json"

# Defaults applied by `enable` when no override is given AND no value is
# already in the config.
DEFAULT_MODE=hybrid
DEFAULT_INTERVAL=1800
DEFAULT_MAX_TICKS=24
DEFAULT_MAX_COST=10.0
DEFAULT_STOP_NO_PROGRESS=30
DEFAULT_CRASH_STORM=10
DEFAULT_REDUNDANCY=2
DEFAULT_SOFT_COST=0.6
DEFAULT_MAX_BACKOFF=4

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------
_have_config() {
  [ -f "$CFG_FILE" ] || {
    echo "ERROR: $CFG_FILE not found. Initialize the campaign first." >&2
    exit 2
  }
}

# enable runs this instead of _have_config: YOLO is a posture you can set BEFORE
# a campaign exists ("yolo on" then "campaign"). If there's no fuzz-config.json
# yet, create a minimal singular one to hold the yolo block — the COLD start
# (harness-set.sh init) preserves the yolo block while upgrading the config to
# multi, and the campaign auto-starts the self-loop because yolo.enabled is set.
_ensure_config() {
  [ -f "$CFG_FILE" ] && return 0
  mkdir -p "$(dirname "$CFG_FILE")"
  cat > "$CFG_FILE" <<'EOF'
{
  "schema": "fuzz-config/v2",
  "fuzz_forks": 2
}
EOF
  echo "note: no campaign yet — created $CFG_FILE to hold the YOLO config." >&2
  echo "      The next /cc-fuzzer:campaign (COLD) reads yolo.enabled and starts the self-loop automatically." >&2
}

# Atomic JSON edit: merge KEY=VALUE pairs into fuzz-config.yolo, writing
# only if the result differs.
_yolo_merge() {
  local merge_json="$1"
  CFG="$CFG_FILE" MERGE="$merge_json" python3 - <<'PY'
import json, os, sys
cfg_path = os.environ["CFG"]
merge = json.loads(os.environ["MERGE"])
with open(cfg_path) as f:
    cfg = json.load(f)
yolo = cfg.get("yolo") or {}
yolo.update(merge)
cfg["yolo"] = yolo
tmp = cfg_path + ".tmp"
with open(tmp, "w") as f:
    json.dump(cfg, f, indent=2)
    f.write("\n")
os.replace(tmp, cfg_path)
PY
}

_current_tick() {
  if [ -f "$CURRENT_FILE" ]; then
    python3 -c "
import json
try: print(json.load(open('$CURRENT_FILE')).get('tick_number', 0))
except: print(0)
" 2>/dev/null || echo 0
  else
    echo 0
  fi
}

# ---------------------------------------------------------------------------
# enable
# ---------------------------------------------------------------------------
_cmd_enable() {
  _ensure_config
  local mode="" aggressiveness="" interval="" max_ticks="" max_cost="" stop_no_prog="" crash_storm=""
  local redundancy="" soft_cost="" max_backoff="" cost_cap=""
  while [ $# -gt 0 ]; do
    case "$1" in
      --mode)                   mode="${2:-}";        shift 2 ;;
      --aggressiveness)         aggressiveness="${2:-}"; shift 2 ;;
      --no-cap)                 cost_cap="false";     shift 1 ;;
      --cap)                    cost_cap="true";      shift 1 ;;
      --interval)               interval="${2:-}";    shift 2 ;;
      --max-ticks)              max_ticks="${2:-}";   shift 2 ;;
      --max-cost)               max_cost="${2:-}";    shift 2 ;;
      --stop-on-no-progress)    stop_no_prog="${2:-}";shift 2 ;;
      --crash-storm-threshold)  crash_storm="${2:-}"; shift 2 ;;
      --redundancy-threshold)   redundancy="${2:-}";  shift 2 ;;
      --soft-cost-fraction)     soft_cost="${2:-}";   shift 2 ;;
      --max-backoff-multiplier) max_backoff="${2:-}"; shift 2 ;;
      *) echo "ERROR: enable: unknown arg '$1'" >&2; exit 2 ;;
    esac
  done

  case "$mode" in
    ""|guided|hybrid|self_loop) ;;
    *) echo "ERROR: --mode must be guided, hybrid, or self_loop (got '$mode')" >&2; exit 2 ;;
  esac

  case "$aggressiveness" in
    ""|conservative|balanced|aggressive) ;;
    *) echo "ERROR: --aggressiveness must be conservative, balanced, or aggressive (got '$aggressiveness')" >&2; exit 2 ;;
  esac

  # Read current values from the config so we only override fields the user
  # explicitly provided, while filling defaults for genuinely-missing ones.
  local now tick
  now=$(date +%s)
  tick=$(_current_tick)

  MODE="$mode" AGGR="$aggressiveness" COST_CAP="$cost_cap" INTERVAL="$interval" MAX_TICKS="$max_ticks" MAX_COST="$max_cost" \
  STOP_NO_PROG="$stop_no_prog" CRASH_STORM="$crash_storm" \
  REDUNDANCY="$redundancy" SOFT_COST="$soft_cost" MAX_BACKOFF="$max_backoff" \
  NOW="$now" TICK="$tick" \
  DEF_MODE="$DEFAULT_MODE" DEF_INTERVAL="$DEFAULT_INTERVAL" DEF_MAX_TICKS="$DEFAULT_MAX_TICKS" \
  DEF_MAX_COST="$DEFAULT_MAX_COST" DEF_STOP_NO_PROG="$DEFAULT_STOP_NO_PROGRESS" \
  DEF_CRASH_STORM="$DEFAULT_CRASH_STORM" DEF_REDUNDANCY="$DEFAULT_REDUNDANCY" \
  DEF_SOFT_COST="$DEFAULT_SOFT_COST" DEF_MAX_BACKOFF="$DEFAULT_MAX_BACKOFF" \
  CFG="$CFG_FILE" \
  python3 - <<'PY'
import json, os
cfg_path = os.environ["CFG"]
with open(cfg_path) as f:
    cfg = json.load(f)
yolo = cfg.get("yolo") or {}

def _override(field, env, default, cast):
    v = os.environ.get(env, "")
    if v:
        try:
            yolo[field] = cast(v)
            return
        except Exception:
            pass
    if field not in yolo:
        yolo[field] = cast(default)

_override("mode",                     "MODE",         os.environ["DEF_MODE"],         str)

# aggressiveness: explicit --aggressiveness wins; else keep an existing value;
# else derive from the (now-resolved) mode. self_loop ships aggressive.
_MODE_POSTURE = {"guided": "conservative", "hybrid": "balanced", "self_loop": "aggressive"}
_aggr = os.environ.get("AGGR", "")
if _aggr in ("conservative", "balanced", "aggressive"):
    yolo["aggressiveness"] = _aggr
elif "aggressiveness" not in yolo:
    yolo["aggressiveness"] = _MODE_POSTURE.get(yolo.get("mode", "hybrid"), "balanced")

# soft_cost default tracks posture: aggressive throttles Opus later (0.8).
_soft_default = 0.8 if yolo["aggressiveness"] == "aggressive" else float(os.environ["DEF_SOFT_COST"])

# cost_cap_enabled: --no-cap ⇒ false, --cap ⇒ true, else keep/default true.
# Removes BOTH the soft throttle posture and the hard max_cost halt.
_cost_cap = os.environ.get("COST_CAP", "")
if _cost_cap == "false":
    yolo["cost_cap_enabled"] = False
elif _cost_cap == "true":
    yolo["cost_cap_enabled"] = True
elif "cost_cap_enabled" not in yolo:
    yolo["cost_cap_enabled"] = True

_override("interval_seconds",         "INTERVAL",     os.environ["DEF_INTERVAL"],     int)
_override("max_ticks",                "MAX_TICKS",    os.environ["DEF_MAX_TICKS"],    int)
_override("max_cost_usd",             "MAX_COST",     os.environ["DEF_MAX_COST"],     float)
_override("stop_on_no_progress_ticks","STOP_NO_PROG", os.environ["DEF_STOP_NO_PROG"], int)
_override("crash_storm_threshold",    "CRASH_STORM",  os.environ["DEF_CRASH_STORM"],  int)
_override("redundancy_threshold",     "REDUNDANCY",   os.environ["DEF_REDUNDANCY"],   int)
_override("soft_cost_fraction",       "SOFT_COST",    _soft_default,                  float)
_override("max_backoff_multiplier",   "MAX_BACKOFF",  os.environ["DEF_MAX_BACKOFF"],  int)

yolo["enabled"]         = True
yolo["enabled_at_ts"]   = int(os.environ["NOW"])
yolo["enabled_at_tick"] = int(os.environ["TICK"])
yolo["last_halt_reason"] = None

cfg["yolo"] = yolo
tmp = cfg_path + ".tmp"
with open(tmp, "w") as f:
    json.dump(cfg, f, indent=2)
    f.write("\n")
os.replace(tmp, cfg_path)

print(f"yolo enabled mode={yolo['mode']} aggressiveness={yolo['aggressiveness']} "
      f"at tick={yolo['enabled_at_tick']} "
      f"interval={yolo['interval_seconds']}s "
      f"max_ticks={yolo['max_ticks']} "
      f"max_cost=${yolo['max_cost_usd']:.2f} "
      f"stop_on_no_progress={yolo['stop_on_no_progress_ticks']} "
      f"redundancy={yolo['redundancy_threshold']} "
      f"soft_cost={yolo['soft_cost_fraction']} "
      f"cost_cap={'on' if yolo.get('cost_cap_enabled', True) else 'OFF'}")
PY
}

# ---------------------------------------------------------------------------
# disable
# ---------------------------------------------------------------------------
_cmd_disable() {
  _have_config
  local reason=""
  while [ $# -gt 0 ]; do
    case "$1" in
      --reason) reason="${2:-}"; shift 2 ;;
      *) echo "ERROR: disable: unknown arg '$1'" >&2; exit 2 ;;
    esac
  done

  REASON="$reason" CFG="$CFG_FILE" python3 - <<'PY'
import json, os
cfg_path = os.environ["CFG"]
with open(cfg_path) as f:
    cfg = json.load(f)
yolo = cfg.get("yolo") or {}
was_enabled = bool(yolo.get("enabled"))
yolo["enabled"] = False
reason = os.environ.get("REASON", "")
if reason:
    yolo["last_halt_reason"] = reason
cfg["yolo"] = yolo
tmp = cfg_path + ".tmp"
with open(tmp, "w") as f:
    json.dump(cfg, f, indent=2)
    f.write("\n")
os.replace(tmp, cfg_path)
print(f"yolo disabled{' (was: enabled)' if was_enabled else ' (was: already disabled)'}"
      + (f" reason: {reason}" if reason else ""))
PY
}

# ---------------------------------------------------------------------------
# status
# ---------------------------------------------------------------------------
_cmd_status() {
  if [ ! -f "$CFG_FILE" ]; then
    echo "yolo: not configured (no fuzz-config.json)"
    return 0
  fi
  CFG="$CFG_FILE" python3 - <<'PY'
import json, os
with open(os.environ["CFG"]) as f:
    cfg = json.load(f)
y = cfg.get("yolo") or {}
if not y:
    print("yolo: not configured")
else:
    state = "ENABLED" if y.get("enabled") else "disabled"
    print(f"yolo: {state}")
    if y.get("enabled"):
        print(f"  mode:                     {y.get('mode', 'hybrid')}")
        print(f"  aggressiveness:           {y.get('aggressiveness', 'balanced')}")
        print(f"  interval:                 {y.get('interval_seconds', '?')}s")
        print(f"  max_ticks:                {y.get('max_ticks', '?')}")
        print(f"  max_cost_usd:             ${y.get('max_cost_usd', 0):.2f}")
        print(f"  stop_on_no_progress:      {y.get('stop_on_no_progress_ticks', '?')} ticks")
        print(f"  crash_storm_threshold:    {y.get('crash_storm_threshold', '?')} findings/tick")
        print(f"  redundancy_threshold:     {y.get('redundancy_threshold', 2)} unproductive dispatches")
        _cap = y.get('cost_cap_enabled', True)
        print(f"  soft_cost_fraction:       {y.get('soft_cost_fraction', 0.6)} of max_cost (throttle Opus)" + ("" if _cap else " [DISABLED via --no-cap]"))
        print(f"  cost_cap:                 {'on' if _cap else 'OFF (--no-cap: no soft throttle and no hard max_cost halt; other halts still apply)'}")
        print(f"  enabled_at_tick:          {y.get('enabled_at_tick', '?')}")
        print(f"  enabled_at_ts:            {y.get('enabled_at_ts', '?')}")
    halt = y.get("last_halt_reason")
    if halt:
        print(f"  last_halt_reason:         {halt}")
PY
}

# ---------------------------------------------------------------------------
# check-halt — inspects current.json.yolo_state.halt_triggered + halt_reason.
# Exit 0 if no halt due (yolo continues). Exit 1 if halt due (orchestrator
# must call `disable --reason ...` and NOT schedule the next wake).
# ---------------------------------------------------------------------------
_cmd_check_halt() {
  if [ ! -f "$CURRENT_FILE" ]; then
    echo "no current.json — halt (cannot evaluate)"; return 1
  fi
  CURRENT="$CURRENT_FILE" python3 - <<'PY'
import json, os, sys
with open(os.environ["CURRENT"]) as f:
    cur = json.load(f)
ys = cur.get("yolo_state") or {}
if not ys.get("active"):
    print("not_active")
    sys.exit(0)
if ys.get("halt_triggered"):
    print(ys.get("halt_reason") or "halt_triggered_no_reason")
    sys.exit(1)
# Active and no halt yet → continue.
print(f"continue tick={ys.get('tick_quota_used', '?')}/{ys.get('tick_quota_used',0)+ys.get('tick_quota_remaining',0)} "
      f"cost=${ys.get('estimated_cost_usd', 0):.2f}/${ys.get('estimated_cost_usd',0)+ys.get('cost_quota_remaining_usd',0):.2f}")
sys.exit(0)
PY
}

# ---------------------------------------------------------------------------
# next-tick — emit the YOLO_NEXT: directive deterministically from
# current.json.yolo_state. The main-thread tick skill's fallback for a missing
# orchestrator YOLO_NEXT line. Read-only except: disables YOLO on halt so the
# halt sticks (matches the orchestrator). Always exits 0; one YOLO_NEXT: line.
# ---------------------------------------------------------------------------
_cmd_next_tick() {
  if [ ! -f "$CURRENT_FILE" ]; then
    echo "YOLO_NEXT: inactive"
    return 0
  fi
  local line reason
  line=$(CURRENT="$CURRENT_FILE" python3 - <<'PY'
import json, os
with open(os.environ["CURRENT"]) as f:
    cur = json.load(f)
ys = cur.get("yolo_state") or {}
if not ys.get("active"):
    print("YOLO_NEXT: inactive")
elif ys.get("halt_triggered"):
    r = (ys.get("halt_reason") or "halt_triggered_no_reason").replace('"', "'")
    print(f'YOLO_NEXT: halt reason="{r}"')
    print(f'__HALT__\t{r}')  # signal to the shell to disable; stripped below
else:
    # Conservative recovery: base interval, no disposition-aware backoff (we
    # don't know this tick's disposition from state alone). Runtime clamps.
    delay = ys.get("interval_seconds") or 1800
    used = ys.get("tick_quota_used", 0)
    total = used + ys.get("tick_quota_remaining", 0)
    print(f'YOLO_NEXT: schedule delay={delay} prompt=/cc-fuzzer:tick '
          f'reason="yolo tick {used + 1}/{total} (recovered: orchestrator omitted YOLO_NEXT)"')
PY
)
  # If the halt sentinel is present, disable YOLO so it sticks, then strip it.
  if printf '%s\n' "$line" | grep -q '^__HALT__'; then
    reason=$(printf '%s\n' "$line" | sed -n 's/^__HALT__\t//p')
    _cmd_disable --reason "$reason" >/dev/null 2>&1 || true
    printf '%s\n' "$line" | grep -v '^__HALT__'
  else
    printf '%s\n' "$line"
  fi
}

# ---------------------------------------------------------------------------
# Dispatch
# ---------------------------------------------------------------------------
cmd="${1:-help}"
shift || true
case "$cmd" in
  enable)     _cmd_enable "$@" ;;
  disable)    _cmd_disable "$@" ;;
  status)     _cmd_status ;;
  check-halt) _cmd_check_halt ;;
  next-tick)  _cmd_next_tick ;;
  help|-h|--help)
    sed -n '2,/^$/p' "$0" | sed 's/^# \?//'
    ;;
  *)
    echo "ERROR: unknown subcommand '$cmd' (try: enable | disable | status | check-halt | next-tick)" >&2
    exit 2
    ;;
esac
