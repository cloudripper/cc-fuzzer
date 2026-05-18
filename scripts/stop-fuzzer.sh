#!/usr/bin/env bash
# stop-fuzzer.sh - cleanly stop fuzzer slot(s) and all harness processes.
#
# Usage:
#   stop-fuzzer.sh                 # stop ALL slots (default; v0.16 behavior)
#   stop-fuzzer.sh --slot <name>   # stop just the named slot
#   stop-fuzzer.sh --all           # explicit "stop all" (same as no args)
#
# Delegates to kill-harness-processes.sh for comprehensive teardown including
# bash-forked child processes that a simple kill-by-PID would miss.
set -u

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
. "$SCRIPT_DIR/_lib/path-anchor.sh"
STATE_DIR="${FUZZ_STATE_DIR:-fuzz/state}"

TARGET_SLOT=""
while [ $# -gt 0 ]; do
  case "$1" in
    --slot) TARGET_SLOT="${2:-}"; shift 2 ;;
    --all)  TARGET_SLOT=""; shift ;;
    -h|--help)
      sed -n '2,/^$/p' "$0" | sed 's/^# \?//'
      exit 0
      ;;
    *) echo "ERROR: unknown arg '$1'" >&2; exit 2 ;;
  esac
done

# Single-slot path: stop just this slot's PID + PGID. Don't touch other slots.
if [ -n "$TARGET_SLOT" ]; then
  PID_FILE="$STATE_DIR/fuzzer-$TARGET_SLOT.pid"
  if [ ! -f "$PID_FILE" ]; then
    echo "No running slot '$TARGET_SLOT' (no $PID_FILE)."
    exit 0
  fi
  PID=$(cat "$PID_FILE" | tr -d ' \n')
  if [ -z "$PID" ] || ! kill -0 "$PID" 2>/dev/null; then
    echo "Slot '$TARGET_SLOT' is not running (stale pid file). Cleaning up."
    rm -f "$PID_FILE" "$STATE_DIR/fuzzer-$TARGET_SLOT.engine"
    # Drop the entry from fuzzers.json
    if [ -f "$STATE_DIR/fuzzers.json" ]; then
      python3 - <<PY
import json, os
mf = '$STATE_DIR/fuzzers.json'
try:
    d = json.load(open(mf))
    d['slots'] = [s for s in d.get('slots',[]) if s.get('slot') != '$TARGET_SLOT']
    with open(mf+'.tmp','w') as f: json.dump(d, f, indent=2)
    os.replace(mf+'.tmp', mf)
except: pass
PY
    fi
    exit 0
  fi
  PGID=$(ps -o pgid= -p "$PID" 2>/dev/null | tr -d ' ')
  echo "Stopping slot '$TARGET_SLOT' (PID $PID, PGID $PGID)..."
  [ -n "$PGID" ] && kill -TERM -- "-$PGID" 2>/dev/null || true
  kill -TERM "$PID" 2>/dev/null || true
  for _ in 1 2 3; do
    kill -0 "$PID" 2>/dev/null || break
    sleep 1
  done
  if kill -0 "$PID" 2>/dev/null; then
    [ -n "$PGID" ] && kill -KILL -- "-$PGID" 2>/dev/null || true
    kill -KILL "$PID" 2>/dev/null || true
  fi
  rm -f "$PID_FILE" "$STATE_DIR/fuzzer-$TARGET_SLOT.engine"
  if [ -f "$STATE_DIR/fuzzers.json" ]; then
    python3 - <<PY
import json, os
mf = '$STATE_DIR/fuzzers.json'
try:
    d = json.load(open(mf))
    d['slots'] = [s for s in d.get('slots',[]) if s.get('slot') != '$TARGET_SLOT']
    with open(mf+'.tmp','w') as f: json.dump(d, f, indent=2)
    os.replace(mf+'.tmp', mf)
except: pass
PY
  fi
  echo "Stopped slot '$TARGET_SLOT'."
  exit 0
fi

# Stop-all path: nothing to do if no slot has a pid file
HAVE_SLOTS=0
for pidf in "$STATE_DIR"/fuzzer-*.pid; do
  [ -f "$pidf" ] && HAVE_SLOTS=1 && break
done
if [ "$HAVE_SLOTS" -eq 0 ] && [ ! -f "$STATE_DIR/fuzzer.pid" ]; then
  echo "No running fuzzer (no pid files)."
  # Still run kill-harness-processes.sh to scrub any stray processes
  if [ -x "$SCRIPT_DIR/kill-harness-processes.sh" ]; then
    bash "$SCRIPT_DIR/kill-harness-processes.sh" --quiet >/dev/null 2>&1 || true
  fi
  # Clean up the manifest
  rm -f "$STATE_DIR/fuzzers.json"
  exit 0
fi

echo "Stopping all fuzzer slots and harness processes..."

# Delegate to kill-harness-processes.sh which handles PGID expansion etc.
RESULT=$(bash "$SCRIPT_DIR/kill-harness-processes.sh" 2>/dev/null)
OK=$(echo "$RESULT" | python3 -c "import json,sys; d=json.load(sys.stdin); print('true' if d.get('ok') else 'false')" 2>/dev/null || echo "true")
KILLED=$(echo "$RESULT" | python3 -c "import json,sys; d=json.load(sys.stdin); print(len(d.get('killed',[])))" 2>/dev/null || echo "0")

# Clean up the manifest now that the slots are dead.
rm -f "$STATE_DIR/fuzzers.json"

if [ "$OK" = "true" ]; then
  echo "Stopped. ($KILLED processes terminated)"
else
  ALIVE=$(echo "$RESULT" | python3 -c "import json,sys; d=json.load(sys.stdin); print(' '.join(d.get('still_alive',[])))" 2>/dev/null || echo "?")
  echo "WARNING: some processes may still be running: $ALIVE" >&2
  echo "         Try: kill -9 $ALIVE" >&2
  exit 1
fi
