#!/usr/bin/env bash
# check-slot-liveness.sh
#
# Per-slot auto-restart for multi-fuzzer campaigns. Walks the slot list
# declared in fuzz/state/fuzz-config.json against the live manifest at
# fuzz/state/fuzzers.json. For each declared slot whose PID is dead (or
# missing), relaunches it via launch-fuzzer-slot.sh and increments the
# slot's restart_count.
#
# Per-slot anti-flap: if a slot has been restarted more than 3 times in
# the last 60 seconds, this script refuses to restart it again and emits
# an error event so the orchestrator can surface the issue. The slot
# entry stays in fuzzers.json with `dead_reason` and zero PID — the user
# decides whether to fix-and-relaunch or remove from fuzz-config.json.
#
# This script does NOT auto-restart anything if fuzz/state/fuzzers.json
# does not exist. That's the post-stop / pre-launch state, and we don't
# want auto-restart to fight against a deliberate stop.
#
# Usage:
#   check-slot-liveness.sh           # restart any dead-but-declared slots
#   check-slot-liveness.sh --dry-run # just report state, no restarts
#
# Output: one line per slot
#   slot=<name> engine=<eng> state=<alive|restarted|deadlocked|dead> [info]

set -u

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
. "$SCRIPT_DIR/_lib/path-anchor.sh"
. "$SCRIPT_DIR/_lib/harness-path.sh"
STATE_DIR="${FUZZ_STATE_DIR:-$FUZZ_ROOT/state}"
CONFIG="$STATE_DIR/fuzz-config.json"
MANIFEST="$STATE_DIR/fuzzers.json"

DRY_RUN=0
[ "${1:-}" = "--dry-run" ] && DRY_RUN=1

# Pre-flight: no manifest -> nothing to do (post-stop / pre-launch state)
if [ ! -f "$MANIFEST" ]; then
  echo "(no fuzzers.json — nothing to check)"
  exit 0
fi

# In singular mode the harness binary is fixed campaign-wide; resolve it once.
# In multi mode each slot binds to its own harness, so we resolve per-slot below.
HARNESS_BIN_SINGULAR=""
if ! is_multi; then
  if [ -f "$STATE_DIR/harness-built.json" ]; then
    HARNESS_BIN_SINGULAR=$(python3 -c "
import json
try: print(json.load(open('$STATE_DIR/harness-built.json')).get('harness_binary',''))
except: pass" 2>/dev/null)
  fi
  if [ -z "$HARNESS_BIN_SINGULAR" ] || [ ! -x "$HARNESS_BIN_SINGULAR" ]; then
    echo "ERROR: harness binary unavailable; cannot restart slots" >&2
    exit 1
  fi
fi

# Build the union of declared + live slot names. Anything declared in
# fuzz-config.json but missing from fuzzers.json is treated as "should be
# running" and will be launched. Each row includes the slot's harness binding
# (empty in singular mode) so per-slot launches resolve the right binary.
SLOT_PLAN=$(python3 - <<PY
import json
config_path = '$CONFIG'
manifest_path = '$MANIFEST'

declared = []
try:
    c = json.load(open(config_path))
    declared = c.get('fuzzer_slots') or []
except Exception:
    pass

live = {}
try:
    m = json.load(open(manifest_path))
    for s in m.get('slots', []):
        live[s['slot']] = s
except Exception:
    pass

if not declared:
    declared = [{'slot': s['slot'], 'engine': s['engine'],
                 'role': s.get('role'),
                 'afl_power_schedule': s.get('afl_power_schedule'),
                 'timeout_ms': s.get('timeout_ms'),
                 'harness': s.get('harness','')}
                for s in live.values()]

out = []
for d in declared:
    name = d.get('slot','main')
    cur  = live.get(name, {})
    out.append('|'.join([
        name,
        d.get('engine','auto'),
        (d.get('role') or '') or '',
        (d.get('afl_power_schedule') or '') or '',
        str(d.get('libfuzzer_forks','') if d.get('libfuzzer_forks') is not None else ''),
        str(cur.get('pid','') or ''),
        str(cur.get('restart_count', 0) or 0),
        str(cur.get('last_restart_at') or ''),
        d.get('harness','') or '',
        str(d.get('timeout_ms','') if d.get('timeout_ms') is not None else ''),
    ]))
print('\n'.join(out))
PY
)

ANY_RESTARTED=0
while IFS='|' read -r slot engine role schedule lf_forks cur_pid restart_count last_restart_at slot_harness timeout_ms; do
  [ -z "$slot" ] && continue

  # Liveness check
  ALIVE=0
  if [ -n "$cur_pid" ] && kill -0 "$cur_pid" 2>/dev/null; then
    ALIVE=1
  fi

  if [ "$ALIVE" -eq 1 ]; then
    echo "slot=$slot engine=$engine state=alive pid=$cur_pid${slot_harness:+ harness=$slot_harness}"
    continue
  fi

  # Anti-flap: refuse to restart if 3+ restarts in last 60s
  THROTTLED=$(python3 -c "
import sys
from datetime import datetime, timezone, timedelta
cnt = int('$restart_count' or 0)
lr = '$last_restart_at'
if cnt < 3 or not lr:
    print('no')
    sys.exit(0)
try:
    dt = datetime.fromisoformat(lr.replace('Z','+00:00'))
    age = (datetime.now(timezone.utc) - dt).total_seconds()
    print('yes' if age < 60 else 'no')
except:
    print('no')
")
  if [ "$THROTTLED" = "yes" ]; then
    echo "slot=$slot engine=$engine state=deadlocked restart_count=$restart_count (3+ restarts in <60s — leaving dead)"
    if [ -x "$SCRIPT_DIR/events.sh" ]; then
      bash "$SCRIPT_DIR/events.sh" error \
        --error-message "slot $slot deadlocked: $restart_count restarts in <60s" \
        >/dev/null 2>&1 || true
    fi
    continue
  fi

  if [ "$DRY_RUN" -eq 1 ]; then
    echo "slot=$slot engine=$engine state=dead would_restart=1 restart_count=$restart_count${slot_harness:+ harness=$slot_harness}"
    continue
  fi

  # Resolve the per-slot binary. In multi mode, look up the slot's harness's
  # binary; in singular mode, use the campaign-wide binary computed at top.
  if is_multi; then
    if [ -z "$slot_harness" ]; then
      echo "slot=$slot engine=$engine state=dead launch_failed=no-harness-binding (multi mode but slot has no harness)"
      continue
    fi
    slot_bin=$(harness_binary "$slot_harness")
    if [ -z "$slot_bin" ] || [ ! -x "$slot_bin" ]; then
      echo "slot=$slot engine=$engine harness=$slot_harness state=dead launch_failed=no-binary-for-harness"
      continue
    fi
  else
    slot_bin="$HARNESS_BIN_SINGULAR"
  fi

  # Restart
  args=(--slot "$slot" --engine "$engine" --binary "$slot_bin" --restart-of "$slot")
  [ -n "$role" ]         && args+=(--role "$role")
  [ -n "$schedule" ]     && args+=(--power-schedule "$schedule")
  [ -n "$lf_forks" ]     && args+=(--libfuzzer-forks "$lf_forks")
  [ -n "$timeout_ms" ]   && args+=(--timeout-ms "$timeout_ms")
  [ -n "$slot_harness" ] && args+=(--harness "$slot_harness")

  if bash "$SCRIPT_DIR/launch-fuzzer-slot.sh" "${args[@]}" >/dev/null 2>&1; then
    new_pid=$(cat "$STATE_DIR/fuzzer-$slot.pid" 2>/dev/null || echo "?")
    echo "slot=$slot engine=$engine state=restarted pid=$new_pid prior_restart_count=$restart_count${slot_harness:+ harness=$slot_harness}"
    ANY_RESTARTED=1
    if [ -x "$SCRIPT_DIR/events.sh" ]; then
      bash "$SCRIPT_DIR/events.sh" agent_call \
        --agent-called "check-slot-liveness" \
        --tokens-in 0 --tokens-out 0 \
        >/dev/null 2>&1 || true
    fi
  else
    echo "slot=$slot engine=$engine state=dead launch_failed=1 restart_count=$restart_count${slot_harness:+ harness=$slot_harness}"
  fi
done <<< "$SLOT_PLAN"

# Refresh current.json so the orchestrator sees the new liveness state
if [ "$ANY_RESTARTED" -eq 1 ] && [ -x "$SCRIPT_DIR/update-current.sh" ]; then
  FUZZ_STATE_DIR="$STATE_DIR" bash "$SCRIPT_DIR/update-current.sh" >/dev/null 2>&1 || true
fi
