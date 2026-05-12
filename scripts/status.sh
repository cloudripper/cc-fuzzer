#!/usr/bin/env bash
# status.sh
#
# Prints campaign status from current.json + fuzzer.log. No LLM, no agent.
# Cost: a few hundred bytes of output, runs in <100ms.
#
# Use this between ticks to monitor a running campaign without invoking
# the orchestrator.

set -u

# Path anchor - refuses cwd inside fuzz/, refuses recursive fuzz/fuzz/
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
. "$SCRIPT_DIR/_lib/path-anchor.sh"
FUZZ_ROOT="${FUZZ_ROOT:-fuzz}"
STATE_DIR="$FUZZ_ROOT/state"
CURRENT="$STATE_DIR/current.json"
LOG="$STATE_DIR/fuzzer.log"

if [ ! -f "$CURRENT" ]; then
  echo "no campaign (current.json not found)"
  exit 0
fi

# Top-level status block
python3 - <<PY
import json, time
d = json.load(open("$CURRENT"))
now = int(time.time())

fuzzer = d.get("fuzzer", {})
cov = d.get("coverage", {})
fs = d.get("fuzzer_stats", {})
fnd = d.get("findings", {})
gaps = d.get("gaps", {})
rec = d.get("recommendation", {})
hbi = d.get("harness", {})
inst = d.get("instrumentation", {}) if isinstance(d.get("instrumentation"), dict) else {}

# Coverage tracking warning
cov_tracking = hbi.get("coverage_tracking_enabled")
# Try multiple locations
if cov_tracking is None:
    try:
        hb = json.load(open("$STATE_DIR/harness-built.json"))
        cov_tracking = hb.get("coverage_tracking", False)
    except:
        cov_tracking = False

state_age = now - d.get("now", now)

print(f"tick #{d.get('tick_number', 0)} | engine={fuzzer.get('engine','?')} | running={fuzzer.get('running', False)} | state_age={state_age}s")

# Coverage line - flag disabled tracking
if not cov_tracking:
    print(f"\033[33mCoverage tracking: DISABLED -- recommendations based on libFuzzer cov counter only, not real line coverage\033[0m")
    print(f"  -> rebuild with 'cc-fuzzer:campaign --reset' or pass '--no-coverage' to opt out explicitly")
elif cov.get("lines_total", 0) == 0:
    print(f"\033[31mCoverage: BROKEN -- tracking enabled but lines_total=0. Check fuzz/state/preflight.json\033[0m")
else:
    pct = cov.get("line_pct", 0)
    secs_since = cov.get("seconds_since_progress", 0)
    plateau = "PLATEAU" if cov.get("plateau") else "climbing"
    print(f"Coverage:  {cov.get('lines_covered', 0)} / {cov.get('lines_total', 0)} lines ({pct}%) -- {plateau}, last progress {secs_since}s ago")

print(f"Fuzzer:    {fs.get('execs', 0):,} execs ({fs.get('execs_per_sec', 0)}/s) | {fs.get('paths', 0)} paths | {fs.get('crashes_total', 0)} crashes ({fs.get('new_crashes_since_previous', 0)} new)")
print(f"Findings:  {fnd.get('unique_count', 0)} unique")
print(f"Gaps:      {gaps.get('total_pending', 0)} pending ({gaps.get('for_concolic',0)}/concolic + {gaps.get('for_seedgen',0)}/seedgen + {gaps.get('for_harness',0)}/harness)")
print(f"Decision:  {rec.get('branch', '?')} -- {rec.get('reason', '')}")
PY

# Engine line from fuzzer.log
if [ -f "$LOG" ]; then
  LAST=$(grep -E '^#[0-9]+' "$LOG" 2>/dev/null | tail -1)
  if [ -n "$LAST" ]; then
    echo "Engine:    $LAST"
  fi
fi

# Coverage trend (last 5 snapshots)
SNAPSHOTS=$(ls -t "$STATE_DIR"/snapshots/coverage-*.json 2>/dev/null | head -5)
if [ -n "$SNAPSHOTS" ]; then
  echo ""
  echo "Recent snapshots:"
  python3 -c "
import json
import sys
for f in sys.argv[1:][::-1]:
    try:
        d = json.load(open(f))
        ts = d.get('timestamp', 0)
        c = d.get('coverage', {})
        s = d.get('fuzzer_stats', {})
        print(f'  {ts}  lines={c.get(\"lines_covered\", 0):4d} ({c.get(\"line_pct\", 0):5.2f}%)  execs={s.get(\"execs\", 0):8d}  crashes={s.get(\"crashes\", 0)}')
    except: pass
" $SNAPSHOTS
fi
