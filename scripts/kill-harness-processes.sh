#!/usr/bin/env bash
# kill-harness-processes.sh
#
# Comprehensive teardown of fuzzer + harness processes.
# Used before harness rebuilds and by stop-fuzzer.sh.
#
# Usage: kill-harness-processes.sh [--quiet]
#
# Output: JSON { "killed": [...], "still_alive": [...], "ok": true|false }
# Exit 0: all processes dead.
# Exit 1: survivors remain (do NOT rebuild — surface to user).

set -u

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
. "$SCRIPT_DIR/_lib/path-anchor.sh"
FUZZ_ROOT="${FUZZ_ROOT:-fuzz}"
STATE_DIR="$FUZZ_ROOT/state"
HARNESS_DIR="$FUZZ_ROOT/harness"

QUIET=0
[ "${1:-}" = "--quiet" ] && QUIET=1
log() { [ "$QUIET" -eq 1 ] || echo "$@" >&2; }

SELF_PID=$$
SELF_PPID=$PPID

# Step 1: Read fuzzer.pid (the recorded master)
PRIMARY_PIDS=()
if [ -f "$STATE_DIR/fuzzer.pid" ]; then
  P=$(cat "$STATE_DIR/fuzzer.pid" 2>/dev/null | tr -d ' \n')
  [ -n "$P" ] && PRIMARY_PIDS+=("$P")
fi

# Step 2: For each primary PID, expand to its PGID to catch bash-fork children
PGIDS=()
for p in "${PRIMARY_PIDS[@]}"; do
  pgid=$(ps -o pgid= -p "$p" 2>/dev/null | tr -d ' ')
  if [ -n "$pgid" ] && [ "$pgid" != "$SELF_PID" ] && [ "$pgid" != "$SELF_PPID" ]; then
    PGIDS+=("$pgid")
    log "Found PGID $pgid for PID $p"
  fi
done

# Step 3: Scan for harness binary paths from harness-built.json
HARNESS_BINS=()
if [ -f "$STATE_DIR/harness-built.json" ]; then
  while IFS= read -r b; do
    [ -n "$b" ] && HARNESS_BINS+=("$b")
  done < <(python3 -c "
import json
try:
  d = json.load(open('$STATE_DIR/harness-built.json'))
  for k in ('harness_binary','coverage_binary','cmplog_binary','symcc_binary'):
    v = d.get(k)
    if v: print(v)
except: pass
" 2>/dev/null)
fi

# Step 4: pgrep for each harness binary and the harness directory
EXTRA_PIDS=()
for bin in "${HARNESS_BINS[@]}"; do
  while IFS= read -r p; do
    [ -n "$p" ] && EXTRA_PIDS+=("$p")
  done < <(pgrep -f -- "$bin" 2>/dev/null || true)
done

# Catch any process whose cmdline contains the harness directory path
ABS_HARNESS_DIR="$(cd "$HARNESS_DIR" 2>/dev/null && pwd || echo "$HARNESS_DIR")"
for needle in "$HARNESS_DIR" "$ABS_HARNESS_DIR"; do
  while IFS= read -r p; do
    [ -n "$p" ] && EXTRA_PIDS+=("$p")
  done < <(pgrep -f -- "$needle" 2>/dev/null || true)
done

# Catch known fuzzer engines by exact name
for engine in afl-fuzz; do
  while IFS= read -r p; do
    [ -n "$p" ] && EXTRA_PIDS+=("$p")
  done < <(pgrep -x -- "$engine" 2>/dev/null || true)
done

# Step 5: Build deduped target set — exclude our own PID/PPID
declare -A _SEEN
ALL_PIDS=()
for p in "${PRIMARY_PIDS[@]}" "${EXTRA_PIDS[@]}"; do
  p=$(echo "$p" | tr -d ' ')
  [ -z "$p" ] && continue
  [ "$p" = "$SELF_PID" ] && continue
  [ "$p" = "$SELF_PPID" ] && continue
  [ -n "${_SEEN[$p]:-}" ] && continue
  _SEEN[$p]=1
  # Verify it's still a running process before adding
  kill -0 "$p" 2>/dev/null && ALL_PIDS+=("$p")
done

if [ "${#ALL_PIDS[@]}" -eq 0 ] && [ "${#PGIDS[@]}" -eq 0 ]; then
  log "No fuzzer processes found."
  rm -f "$STATE_DIR/fuzzer.pid"
  echo '{"killed":[],"still_alive":[],"ok":true}'
  exit 0
fi

log "Found ${#ALL_PIDS[@]} individual PIDs and ${#PGIDS[@]} PGIDs to kill"

# Step 6: SIGTERM by PGID first (kills bash-forked children in one shot)
for pg in "${PGIDS[@]}"; do
  log "SIGTERM PGID -$pg"
  kill -TERM -- "-$pg" 2>/dev/null || true
done
# Also SIGTERM individual PIDs
for p in "${ALL_PIDS[@]}"; do
  log "SIGTERM PID $p"
  kill -TERM "$p" 2>/dev/null || true
done

# Step 7: Wait up to 3 seconds for graceful exit
for _ in 1 2 3; do
  STILL_RUNNING=0
  for p in "${ALL_PIDS[@]}"; do
    kill -0 "$p" 2>/dev/null && STILL_RUNNING=1 && break
  done
  [ "$STILL_RUNNING" -eq 0 ] && break
  sleep 1
done

# Step 8: SIGKILL stragglers
for pg in "${PGIDS[@]}"; do
  kill -KILL -- "-$pg" 2>/dev/null || true
done
for p in "${ALL_PIDS[@]}"; do
  kill -KILL "$p" 2>/dev/null || true
done

# Step 9: Brief pause then verify
sleep 1
STILL_ALIVE=()
for p in "${ALL_PIDS[@]}"; do
  kill -0 "$p" 2>/dev/null && STILL_ALIVE+=("$p")
done

# Step 10: Remove PID file regardless
rm -f "$STATE_DIR/fuzzer.pid"

# Step 11: Emit JSON result
KILLED_JSON=$(python3 -c "
import json
pids = [$(printf '"%s",' "${ALL_PIDS[@]}" | sed 's/,$//')]
print(json.dumps(pids))" 2>/dev/null || echo "[]")

ALIVE_JSON=$(python3 -c "
import json
pids = [$(printf '"%s",' "${STILL_ALIVE[@]:-}" | sed 's/,$//')]
print(json.dumps(pids))" 2>/dev/null || echo "[]")

OK="true"
[ "${#STILL_ALIVE[@]}" -gt 0 ] && OK="false"

if [ "$OK" = "false" ]; then
  log "WARNING: ${#STILL_ALIVE[@]} processes still alive after SIGKILL: ${STILL_ALIVE[*]}"
fi

cat <<JSON
{"killed":${KILLED_JSON},"still_alive":${ALIVE_JSON},"ok":${OK}}
JSON

[ "$OK" = "true" ]
