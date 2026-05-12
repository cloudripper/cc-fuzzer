#!/usr/bin/env bash
# update-current.sh
#
# Atomically rewrites fuzz/state/current.json with everything the orchestrator
# needs to make a tick decision. Called after any state change (snapshot,
# triage, seed gen). The orchestrator reads ONLY this file on warm ticks -
# no source code, no harness inspection, no walking history.
#
# This is the efficiency lever. If the orchestrator can decide from this one
# file, a tick costs 1-3k tokens instead of 30-50k.

set -u

# Path anchor - refuses cwd inside fuzz/, refuses recursive fuzz/fuzz/
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
. "$SCRIPT_DIR/_lib/path-anchor.sh"
STATE_DIR="${FUZZ_STATE_DIR:-fuzz/state}"
SNAPSHOTS_DIR="$STATE_DIR/snapshots"
mkdir -p "$STATE_DIR" "$SNAPSHOTS_DIR"

OUT="$STATE_DIR/current.json"
TMP="$STATE_DIR/.current.json.tmp"

# Default values when files are missing
FUZZER_PID=""
FUZZER_RUNNING=false
ENGINE="unknown"
HARNESS_BIN=""
SYMCC_AVAILABLE=false
SYMCC_BIN=""
LATEST_COV_FILE=""
LATEST_COV_TS=0
LINES_COV=0
LINES_TOTAL=0
LINE_PCT=0
EXECS=0
EXECS_PER_SEC=0
PATHS=0
CRASHES_TOTAL=0
NEW_CRASHES_COUNT=0
UNIQUE_FINDINGS=0
LAST_PROGRESS_TS=0
SECONDS_SINCE_PROGRESS=0
PLATEAU=false
TICK_NUMBER=0
LATEST_GAP_FILE=""
GAPS_PENDING=0
GAPS_FOR_CONCOLIC=0
GAPS_FOR_SEEDGEN=0
GAPS_FOR_HARNESS=0
GAPS_FOR_MUTATOR=0
GAPS_DIRECT_COMPARE=0
RECOMMENDED_BRANCH="sleep"
RECOMMENDED_REASON=""

# 1. Fuzzer state
if [ -f "$STATE_DIR/fuzzer.pid" ]; then
  FUZZER_PID=$(cat "$STATE_DIR/fuzzer.pid")
  if kill -0 "$FUZZER_PID" 2>/dev/null; then
    FUZZER_RUNNING=true
  fi
fi
[ -f "$STATE_DIR/fuzzer.engine" ] && ENGINE=$(cat "$STATE_DIR/fuzzer.engine")

# 2. Harness state - read once, cache forever
if [ -f "$STATE_DIR/harness-built.json" ]; then
  HARNESS_BIN=$(python3 -c "
import json
d = json.load(open('$STATE_DIR/harness-built.json'))
print(d.get('harness_binary', ''))
" 2>/dev/null)
  SYMCC_BIN=$(python3 -c "
import json
d = json.load(open('$STATE_DIR/harness-built.json'))
print(d.get('symcc_binary', ''))
" 2>/dev/null)
  [ -n "$SYMCC_BIN" ] && [ -x "$SYMCC_BIN" ] && SYMCC_AVAILABLE=true
fi

# 3. Latest coverage snapshot - pick by content timestamp, not file mtime
LATEST_COV_FILE=$(python3 -c "
import json, glob, os
best = None; best_ts = -1
for f in glob.glob('$SNAPSHOTS_DIR/coverage-*.json'):
    try:
        d = json.load(open(f))
        ts = d.get('timestamp', 0)
        if ts > best_ts:
            best_ts = ts; best = f
    except Exception:
        continue
print(best or '')
" 2>/dev/null)
if [ -n "$LATEST_COV_FILE" ]; then
  LATEST_COV_TS=$(basename "$LATEST_COV_FILE" | sed 's/coverage-//;s/.json//')
  read LINES_COV LINES_TOTAL LINE_PCT EXECS EXECS_PER_SEC PATHS CRASHES_TOTAL NEW_CRASHES_COUNT < <(python3 -c "
import json
d = json.load(open('$LATEST_COV_FILE'))
c = d.get('coverage', {})
f = d.get('fuzzer_stats', {})
nc = d.get('new_crashes_since_previous', [])
print(c.get('lines_covered', 0), c.get('lines_total', 0), c.get('line_pct', 0),
      f.get('execs', 0), f.get('execs_per_sec', 0), f.get('paths', 0),
      f.get('crashes', 0), len(nc))
" 2>/dev/null)
fi

# 4. Findings
if [ -f "$STATE_DIR/findings.jsonl" ]; then
  UNIQUE_FINDINGS=$(wc -l < "$STATE_DIR/findings.jsonl" | tr -d ' ')
fi

# 5. Plateau detection - 3 most recent snapshots by content timestamp
PLATEAU_RESULT=$(python3 <<PY 2>/dev/null
import json, glob
files = []
for f in glob.glob("$SNAPSHOTS_DIR/coverage-*.json"):
    try:
        d = json.load(open(f))
        files.append((d.get('timestamp', 0), f, d))
    except Exception:
        pass
files.sort(reverse=True)
if len(files) < 3:
    print("false 0")
else:
    recent = files[0][2].get('coverage', {}).get('lines_covered', 0)
    oldest = files[2][2].get('coverage', {}).get('lines_covered', 0)
    delta_pct = ((recent - oldest) / max(oldest, 1)) * 100 if oldest else 0
    plateau = "true" if abs(delta_pct) < 1.0 else "false"
    last_progress_ts = files[0][0] if recent > oldest else files[2][0]
    print(f"{plateau} {last_progress_ts}")
PY
)
if [ -n "$PLATEAU_RESULT" ]; then
  PLATEAU=$(echo "$PLATEAU_RESULT" | awk '{print $1}')
  LAST_PROGRESS_TS=$(echo "$PLATEAU_RESULT" | awk '{print $2}')
fi

NOW=$(date +%s)
if [ "$LAST_PROGRESS_TS" -gt 0 ]; then
  SECONDS_SINCE_PROGRESS=$((NOW - LAST_PROGRESS_TS))
fi

# 6. Tick number from events log
if [ -f "$STATE_DIR/events.jsonl" ]; then
# 6. Tick number - count "event":"tick" entries in events.jsonl.
# Use python so the count is guaranteed integer; grep -c can produce
# unexpected output when events.jsonl contains binary/UTF-8 from fuzzed inputs
# stored in error_message fields, leading to JSON corruption.
TICK_NUMBER=0
if [ -f "$STATE_DIR/events.jsonl" ]; then
  TICK_NUMBER=$(python3 -c "
import json
n = 0
try:
    with open('$STATE_DIR/events.jsonl') as f:
        for line in f:
            line = line.strip()
            if not line: continue
            try:
                if json.loads(line).get('event') == 'tick':
                    n += 1
            except:
                pass
except:
    pass
print(n)
" 2>/dev/null)
  TICK_NUMBER=${TICK_NUMBER:-0}
  # Ensure it's a clean integer
  case "$TICK_NUMBER" in
    ''|*[!0-9]*) TICK_NUMBER=0 ;;
  esac
fi
fi

# 7. Pending gaps from latest gap report (snapshots/ is canonical, but warn if found in legacy state/ root)
LATEST_GAP_FILE=$(ls -t "$SNAPSHOTS_DIR"/gaps-*.json 2>/dev/null | head -1)
STRAY_GAPS=$(ls -t "$STATE_DIR"/gaps-*.json 2>/dev/null | head -1)
if [ -z "$LATEST_GAP_FILE" ] && [ -n "$STRAY_GAPS" ]; then
  # Fallback: agent wrote to wrong path. Use it but flag for migration.
  LATEST_GAP_FILE="$STRAY_GAPS"
  echo "WARN: gap report at $STRAY_GAPS - should be in $SNAPSHOTS_DIR/. Move it." >&2
fi
if [ -n "$LATEST_GAP_FILE" ]; then
  read GAPS_PENDING GAPS_FOR_CONCOLIC GAPS_FOR_SEEDGEN GAPS_FOR_HARNESS GAPS_FOR_MUTATOR GAPS_DIRECT_COMPARE < <(python3 -c "
import json
d = json.load(open('$LATEST_GAP_FILE'))
gaps = d.get('gaps', [])
total = len(gaps)
# v0.13: direct_compare gaps are cmplog-handled at runtime; they are
# reported for visibility but never trigger a specialist dispatch.
direct = sum(1 for g in gaps if g.get('reason') == 'direct_compare')
concolic = sum(1 for g in gaps if g.get('reason') in ('checksum_barrier', 'deep_path_condition'))
seedgen = sum(1 for g in gaps if g.get('reason') in ('format_barrier', 'value_constraint'))
harness = sum(1 for g in gaps if g.get('reason') in ('harness_gap', 'state_precondition'))
mutator = sum(1 for g in gaps if g.get('recommended_agent') == 'mutator')
print(total, concolic, seedgen, harness, mutator, direct)
" 2>/dev/null)
fi

# Read instrumentation status from latest snapshot to detect broken coverage
INSTRUMENTATION_OK=true
INSTRUMENTATION_TRACKING=false
if [ -n "$LATEST_COV_FILE" ] && [ -f "$LATEST_COV_FILE" ]; then
  read INSTRUMENTATION_OK INSTRUMENTATION_TRACKING < <(python3 -c "
import json
try:
    d = json.load(open('$LATEST_COV_FILE'))
    inst = d.get('instrumentation', {})
    print(str(inst.get('ok', True)).lower(), str(inst.get('tracking_enabled', False)).lower())
except:
    print('true false')
" 2>/dev/null)
fi

# 8. Recommended decision branch
if [ "$FUZZER_RUNNING" != "true" ]; then
  RECOMMENDED_BRANCH="restart_fuzzer"
  RECOMMENDED_REASON="fuzzer process is not running"
elif [ "$INSTRUMENTATION_TRACKING" = "true" ] && [ "$INSTRUMENTATION_OK" = "false" ]; then
  RECOMMENDED_BRANCH="fix_instrumentation"
  RECOMMENDED_REASON="coverage tracking enabled but instrumentation broken - cannot make decisions on bogus zeros"
elif [ "$NEW_CRASHES_COUNT" -gt 0 ]; then
  RECOMMENDED_BRANCH="triage"
  RECOMMENDED_REASON="$NEW_CRASHES_COUNT new crash files since last snapshot"
elif [ "$PLATEAU" = "true" ] && [ "$GAPS_FOR_CONCOLIC" -gt 0 ] && [ "$SYMCC_AVAILABLE" = "true" ]; then
  RECOMMENDED_BRANCH="concolic"
  RECOMMENDED_REASON="plateau, $GAPS_FOR_CONCOLIC concolic-eligible gaps, SymCC available"
elif [ "$PLATEAU" = "true" ] && [ -z "$LATEST_GAP_FILE" ]; then
  RECOMMENDED_BRANCH="analyze_gaps"
  RECOMMENDED_REASON="plateau detected, no gap report yet"
elif [ "$PLATEAU" = "true" ] && [ "$GAPS_FOR_SEEDGEN" -gt 0 ]; then
  RECOMMENDED_BRANCH="generate_seeds"
  RECOMMENDED_REASON="plateau, $GAPS_FOR_SEEDGEN seedgen-eligible gaps pending"
elif [ "$PLATEAU" = "true" ] && [ "$SECONDS_SINCE_PROGRESS" -gt 1800 ]; then
  RECOMMENDED_BRANCH="reanalyze_gaps"
  RECOMMENDED_REASON="plateau >30min, gap report stale, refresh"
else
  RECOMMENDED_BRANCH="sleep"
  RECOMMENDED_REASON="coverage climbing or recent progress, no action needed"
fi

# 9. Write atomically
cat > "$TMP" <<EOF
{
  "schema": "cc-fuzzer-current/v1",
  "now": $NOW,
  "tick_number": $TICK_NUMBER,
  "fuzzer": {
    "pid": "$FUZZER_PID",
    "running": $FUZZER_RUNNING,
    "engine": "$ENGINE"
  },
  "harness": {
    "binary": "$HARNESS_BIN",
    "symcc_binary": "$SYMCC_BIN",
    "symcc_available": $SYMCC_AVAILABLE
  },
  "coverage": {
    "snapshot_file": "$LATEST_COV_FILE",
    "snapshot_ts": $LATEST_COV_TS,
    "lines_covered": $LINES_COV,
    "lines_total": $LINES_TOTAL,
    "line_pct": $LINE_PCT,
    "plateau": $PLATEAU,
    "seconds_since_progress": $SECONDS_SINCE_PROGRESS
  },
  "fuzzer_stats": {
    "execs": $EXECS,
    "execs_per_sec": $EXECS_PER_SEC,
    "paths": $PATHS,
    "crashes_total": $CRASHES_TOTAL,
    "new_crashes_since_previous": $NEW_CRASHES_COUNT
  },
  "findings": {
    "unique_count": $UNIQUE_FINDINGS,
    "file": "$STATE_DIR/findings.jsonl"
  },
  "gaps": {
    "latest_report": "$LATEST_GAP_FILE",
    "total_pending": $GAPS_PENDING,
    "for_concolic": $GAPS_FOR_CONCOLIC,
    "for_seedgen": $GAPS_FOR_SEEDGEN,
    "for_harness": $GAPS_FOR_HARNESS,
    "for_mutator": $GAPS_FOR_MUTATOR,
    "direct_compare": $GAPS_DIRECT_COMPARE
  },
  "recommendation": {
    "branch": "$RECOMMENDED_BRANCH",
    "reason": "$RECOMMENDED_REASON"
  }
}
EOF

mv "$TMP" "$OUT"
echo "$OUT"
