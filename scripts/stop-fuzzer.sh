#!/usr/bin/env bash
# stop-fuzzer.sh - cleanly stop the running fuzzer and all harness processes.
# Delegates to kill-harness-processes.sh for comprehensive teardown including
# bash-forked child processes that a simple kill-by-PID would miss.
set -u

# Path anchor - refuses cwd inside fuzz/, refuses recursive fuzz/fuzz/
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
. "$SCRIPT_DIR/_lib/path-anchor.sh"
STATE_DIR="${FUZZ_STATE_DIR:-fuzz/state}"

if [ ! -f "$STATE_DIR/fuzzer.pid" ]; then
  echo "No running fuzzer (no $STATE_DIR/fuzzer.pid)."
  # Still run kill-harness-processes.sh to scrub any stray processes
  # that might exist without a pid file (e.g. after a crash recovery).
  if [ -x "$SCRIPT_DIR/kill-harness-processes.sh" ]; then
    bash "$SCRIPT_DIR/kill-harness-processes.sh" --quiet >/dev/null 2>&1 || true
  fi
  exit 0
fi

PID=$(cat "$STATE_DIR/fuzzer.pid")
echo "Stopping fuzzer (PID $PID) and all harness processes..."

# Delegate to kill-harness-processes.sh which handles:
# - PGID expansion to catch bash-forked children
# - pgrep scan for harness binary paths
# - SIGTERM + wait + SIGKILL sequence
# - PID file cleanup
RESULT=$(bash "$SCRIPT_DIR/kill-harness-processes.sh" 2>/dev/null)
OK=$(echo "$RESULT" | python3 -c "import json,sys; d=json.load(sys.stdin); print('true' if d.get('ok') else 'false')" 2>/dev/null || echo "true")
KILLED=$(echo "$RESULT" | python3 -c "import json,sys; d=json.load(sys.stdin); print(len(d.get('killed',[])))" 2>/dev/null || echo "0")

if [ "$OK" = "true" ]; then
  echo "Stopped. ($KILLED processes terminated)"
else
  ALIVE=$(echo "$RESULT" | python3 -c "import json,sys; d=json.load(sys.stdin); print(' '.join(d.get('still_alive',[])))" 2>/dev/null || echo "?")
  echo "WARNING: some processes may still be running: $ALIVE" >&2
  echo "         Try: kill -9 $ALIVE" >&2
  exit 1
fi
