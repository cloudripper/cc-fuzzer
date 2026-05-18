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
. "$SCRIPT_DIR/_lib/harness-path.sh"
STATE_DIR="${FUZZ_STATE_DIR:-fuzz/state}"
SNAPSHOTS_DIR="$STATE_DIR/snapshots"
mkdir -p "$STATE_DIR" "$SNAPSHOTS_DIR"

OUT="$STATE_DIR/current.json"
TMP="$STATE_DIR/.current.json.tmp"

#==============================================================================
# Multi-harness early exit (schema v9)
#
# In multi mode the per-harness state collection is too tangled with the
# singular path's global variables to refactor cleanly in a single pass, so
# this block runs entirely in python: walks declared harnesses, computes
# per-harness coverage / fuzzer_stats / gaps / recommendation, picks
# active_harness from a fixed priority table, writes current/v2 with
# back-compat shims, and exits. The singular path below is unchanged from v8.
#==============================================================================
if is_multi; then
  NOW=$(date +%s)
  DECLARED="$(declared_harnesses)"
  export STATE_DIR SNAPSHOTS_DIR DECLARED NOW TMP OUT

  python3 - <<'PY'
import json, os, sys, glob, re

state_dir  = os.environ['STATE_DIR']
snaps_dir  = os.environ['SNAPSHOTS_DIR']
declared   = [n for n in os.environ['DECLARED'].splitlines() if n.strip()]
now        = int(os.environ['NOW'])
tmp_path   = os.environ['TMP']
out_path   = os.environ['OUT']

# Priority table (highest first). Determines which harness becomes
# active_harness when multiple have actionable recommendations.
PRIORITY = ['triage','restart_fuzzer','fix_instrumentation','analyze_gaps',
            'reanalyze_gaps','concolic','generate_seeds','mutator','stop','sleep']
PRI = {b: i for i, b in enumerate(PRIORITY)}

def safe_read_json(p, default=None):
    try:
        with open(p) as f:
            return json.load(f)
    except Exception:
        return default

# 1. Slot manifest (live)
manifest = safe_read_json(os.path.join(state_dir, 'fuzzers.json'), {})
slots = manifest.get('slots', [])

def slot_alive(s):
    pid = s.get('pid','')
    try:
        if pid and int(pid) > 0:
            os.kill(int(pid), 0)
            return True
    except (ValueError, OSError, ProcessLookupError):
        pass
    return False

def slots_for_harness(h):
    return [s for s in slots if s.get('harness') == h]

# 2. Harness binaries / symcc availability (from harnesses.json)
hset = safe_read_json(os.path.join(state_dir, 'harnesses.json'), {})
records = {h.get('name'): h for h in hset.get('harnesses', []) if isinstance(h, dict)}

# 3. Findings counts by harness
by_harness = {h: 0 for h in declared}
total_findings = 0
findings_path = os.path.join(state_dir, 'findings.jsonl')
if os.path.isfile(findings_path):
    with open(findings_path) as f:
        for line in f:
            line = line.strip()
            if not line: continue
            try:
                d = json.loads(line)
            except Exception:
                continue
            total_findings += 1
            for h in d.get('harnesses') or []:
                if h in by_harness:
                    by_harness[h] += 1

# 4. Per-harness state collection
def collect(harness):
    # Coverage snapshot — pick the one with the highest timestamp field
    cov_files = glob.glob(os.path.join(snaps_dir, f'coverage-{harness}-*.json'))
    best_cov = None; best_ts = -1
    for f in cov_files:
        d = safe_read_json(f, {})
        ts = d.get('timestamp', 0)
        if ts > best_ts:
            best_ts = ts; best_cov = (f, d)
    cov_file = best_cov[0] if best_cov else ''
    cov_doc  = best_cov[1] if best_cov else {}
    cov_ts   = cov_doc.get('timestamp', 0)
    c = cov_doc.get('coverage', {})
    lines_cov   = c.get('lines_covered', 0)
    lines_total = c.get('lines_total', 0)
    line_pct    = c.get('line_pct', 0)

    # Plateau: 3 most recent snapshots, <1% growth = plateau
    cov_sorted = sorted(
        ((d.get('timestamp', 0), d) for d in (safe_read_json(f, {}) for f in cov_files)),
        reverse=True
    )
    plateau = False
    last_progress_ts = cov_ts
    if len(cov_sorted) >= 3:
        recent = cov_sorted[0][1].get('coverage', {}).get('lines_covered', 0)
        oldest = cov_sorted[2][1].get('coverage', {}).get('lines_covered', 0)
        delta_pct = ((recent - oldest) / max(oldest, 1)) * 100 if oldest else 0
        plateau = abs(delta_pct) < 1.0
        last_progress_ts = cov_sorted[0][0] if recent > oldest else cov_sorted[2][0]
    secs_since = max(0, now - int(last_progress_ts)) if last_progress_ts else 0

    # Instrumentation status
    inst = cov_doc.get('instrumentation', {})
    inst_ok = bool(inst.get('ok', True))
    inst_tracking = bool(inst.get('tracking_enabled', False))

    # Aggregated fuzzer stats across this harness's slots — simplest model:
    # take the snapshot's recorded stats (already aggregated when snapshot ran).
    fs = cov_doc.get('fuzzer_stats', {})
    execs = fs.get('execs', 0)
    execs_per_sec = fs.get('execs_per_sec', 0)
    paths = fs.get('paths', 0)
    crashes = fs.get('crashes', 0)
    new_crashes = len(cov_doc.get('new_crashes_since_previous', []))

    # Latest gap report
    gap_files = sorted(glob.glob(os.path.join(snaps_dir, f'gaps-{harness}-*.json')))
    gap_file = gap_files[-1] if gap_files else ''
    gap_doc = safe_read_json(gap_file, {}) if gap_file else {}
    gaps = gap_doc.get('gaps', []) if gap_file else []
    gap_total = len(gaps)
    gap_direct = sum(1 for g in gaps if g.get('reason') == 'direct_compare')
    gap_concolic = sum(1 for g in gaps if g.get('reason') in ('checksum_barrier','deep_path_condition'))
    gap_seedgen = sum(1 for g in gaps if g.get('reason') in ('format_barrier','value_constraint'))
    gap_harness = sum(1 for g in gaps if g.get('reason') in ('harness_gap','state_precondition'))
    gap_mutator = sum(1 for g in gaps if g.get('recommended_agent') == 'mutator')

    # Per-harness liveness across its slots
    my_slots = slots_for_harness(harness)
    any_alive = any(slot_alive(s) for s in my_slots)

    # SymCC availability — read per-harness record
    rec = records.get(harness, {})
    symcc_bin = rec.get('symcc_binary') or ''
    symcc_avail = bool(symcc_bin) and os.path.isfile(symcc_bin) and os.access(symcc_bin, os.X_OK)

    # Per-harness recommendation (same logic as singular)
    if my_slots and not any_alive:
        branch, reason = 'restart_fuzzer', f'no live slot for harness {harness}'
    elif inst_tracking and not inst_ok:
        branch, reason = 'fix_instrumentation', 'coverage tracking enabled but instrumentation broken'
    elif new_crashes > 0:
        branch, reason = 'triage', f'{new_crashes} new crash files for {harness} since last snapshot'
    elif plateau and gap_concolic > 0 and symcc_avail:
        branch, reason = 'concolic', f'plateau on {harness}, {gap_concolic} concolic-eligible gaps, SymCC available'
    elif plateau and not gap_file:
        branch, reason = 'analyze_gaps', f'plateau on {harness}, no gap report yet'
    elif plateau and gap_seedgen > 0:
        branch, reason = 'generate_seeds', f'plateau on {harness}, {gap_seedgen} seedgen-eligible gaps pending'
    elif plateau and secs_since > 1800:
        branch, reason = 'reanalyze_gaps', f'plateau on {harness} >30min, refresh'
    else:
        branch, reason = 'sleep', f'{harness}: coverage climbing or recent progress'

    return {
        'name': harness,
        'harness': {
            'binary': rec.get('harness_binary',''),
            'symcc_binary': symcc_bin,
            'symcc_available': symcc_avail,
        },
        'coverage': {
            'snapshot_file': cov_file,
            'snapshot_ts': int(cov_ts),
            'lines_covered': lines_cov,
            'lines_total': lines_total,
            'line_pct': line_pct,
            'plateau': plateau,
            'seconds_since_progress': secs_since,
        },
        'fuzzer_stats': {
            'execs': execs,
            'execs_per_sec': execs_per_sec,
            'paths': paths,
            'crashes_total': crashes,
            'new_crashes_since_previous': new_crashes,
        },
        'gaps': {
            'latest_report': gap_file,
            'total_pending': gap_total,
            'for_concolic': gap_concolic,
            'for_seedgen': gap_seedgen,
            'for_harness': gap_harness,
            'for_mutator': gap_mutator,
            'direct_compare': gap_direct,
        },
        'recommendation': {'branch': branch, 'reason': reason},
        '_priority': PRI.get(branch, 99),
    }

harness_entries = [collect(h) for h in declared]

# Pick active harness via priority table; ties broken by declaration order.
active_entry = min(
    harness_entries, key=lambda e: (e['_priority'], declared.index(e['name']))
) if harness_entries else None
active_name = active_entry['name'] if active_entry else (declared[0] if declared else '')

# Strip the internal _priority key before emitting
for e in harness_entries:
    e.pop('_priority', None)

# Build the per-slot summary array
slot_summaries = []
for s in slots:
    slot_summaries.append({
        'slot':          s.get('slot',''),
        'harness':       s.get('harness',''),
        'engine':        s.get('engine','unknown'),
        'pid':           s.get('pid',''),
        'running':       slot_alive(s),
        'started_at':    s.get('started_at') or None,
        'restart_count': int(s.get('restart_count', 0) or 0),
    })

# Tick number
tick_n = 0
events_path = os.path.join(state_dir, 'events.jsonl')
if os.path.isfile(events_path):
    with open(events_path) as f:
        for line in f:
            line = line.strip()
            if not line: continue
            try:
                if json.loads(line).get('event') == 'tick':
                    tick_n += 1
            except Exception:
                pass

# Active-harness mirrors for back-compat shims
ae = active_entry or {
    'harness': {'binary':'','symcc_binary':'','symcc_available':False},
    'coverage': {'snapshot_file':'','snapshot_ts':0,'lines_covered':0,'lines_total':0,
                 'line_pct':0,'plateau':False,'seconds_since_progress':0},
    'fuzzer_stats': {'execs':0,'execs_per_sec':0,'paths':0,'crashes_total':0,'new_crashes_since_previous':0},
    'gaps': {'latest_report':'','total_pending':0,'for_concolic':0,'for_seedgen':0,
             'for_harness':0,'for_mutator':0,'direct_compare':0},
    'recommendation': {'branch':'sleep','reason':''},
}

# Single-slot mirror for legacy `fuzzer` field
first_slot = slot_summaries[0] if slot_summaries else {
    'pid':'','running':False,'engine':'unknown'
}

doc = {
    'schema': 'cc-fuzzer-current/v2',
    'now': now,
    'tick_number': tick_n,
    'active_harness': active_name,
    'harnesses': harness_entries,
    'fuzzers': slot_summaries,
    'findings': {
        'unique_count': total_findings,
        'file': os.path.join(state_dir, 'findings.jsonl'),
        'by_harness': by_harness,
    },
    'recommendation': {
        'branch':  ae['recommendation']['branch'],
        'reason':  ae['recommendation']['reason'],
        'harness': active_name,
    },
    # Back-compat shims (mirror of harnesses[active]); removed in schema v10.
    'harness': {
        'binary':          ae['harness']['binary'],
        'symcc_binary':    ae['harness']['symcc_binary'],
        'symcc_available': ae['harness']['symcc_available'],
    },
    'coverage':     ae['coverage'],
    'fuzzer_stats': ae['fuzzer_stats'],
    'gaps':         ae['gaps'],
    'fuzzer': {
        'pid':     first_slot.get('pid',''),
        'running': bool(first_slot.get('running', False)),
        'engine':  first_slot.get('engine','unknown') or 'unknown',
    },
    'multi_fuzzer': True,
}

with open(tmp_path, 'w') as f:
    json.dump(doc, f, indent=2)
os.replace(tmp_path, out_path)
print(out_path)
PY

  exit $?
fi
#==============================================================================
# End multi-harness block — everything below is the singular v8 path.
#==============================================================================


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

# 1. Fuzzer state — multi-slot aware (v0.17+).
# Walk fuzzer-*.pid files. The first slot found is exposed as the legacy
# singular `fuzzer` field for backward compat; all slots are emitted as the
# `fuzzers` array further down. Falls back to legacy fuzzer.pid for
# pre-v0.17 campaigns.
SLOTS_JSON="[]"
TYPED_PIDS=0
for pidf in "$STATE_DIR"/fuzzer-*.pid; do
  [ -f "$pidf" ] || continue
  TYPED_PIDS=1
  break
done
if [ "$TYPED_PIDS" -eq 1 ]; then
  SLOTS_JSON=$(python3 - <<PY
import json, os, glob, re, subprocess
state_dir = '$STATE_DIR'
out = []
# Order: read fuzzers.json if present for declared slot order, otherwise
# walk fuzzer-*.pid files in alpha order.
manifest = {}
mf = os.path.join(state_dir, 'fuzzers.json')
if os.path.isfile(mf):
    try:
        d = json.load(open(mf))
        for s in d.get('slots', []):
            manifest[s['slot']] = s
    except: pass
seen = set()
order = []
# Manifest order first
for name in manifest.keys():
    order.append(name)
    seen.add(name)
# Then any orphan pid files not in manifest
for pidf in sorted(glob.glob(os.path.join(state_dir, 'fuzzer-*.pid'))):
    base = os.path.basename(pidf)
    m = re.match(r'fuzzer-(.+)\.pid$', base)
    if not m: continue
    n = m.group(1)
    if n not in seen:
        order.append(n)
        seen.add(n)

for name in order:
    pid_path = os.path.join(state_dir, f'fuzzer-{name}.pid')
    eng_path = os.path.join(state_dir, f'fuzzer-{name}.engine')
    pid = ''
    if os.path.isfile(pid_path):
        try: pid = open(pid_path).read().strip()
        except: pass
    engine = 'unknown'
    if os.path.isfile(eng_path):
        try: engine = open(eng_path).read().strip()
        except: pass
    if not engine: engine = 'unknown'
    running = False
    if pid:
        try:
            os.kill(int(pid), 0)
            running = True
        except: pass
    m = manifest.get(name, {})
    out.append({
        'slot': name,
        'engine': engine,
        'pid': pid,
        'running': running,
        'started_at': m.get('started_at') or None,
        'restart_count': int(m.get('restart_count', 0) or 0),
    })
print(json.dumps(out))
PY
)
  # Populate legacy fuzzer / engine fields from first slot for back-compat
  read FUZZER_PID FUZZER_RUNNING ENGINE < <(python3 -c "
import json
slots = json.loads('''$SLOTS_JSON''')
if slots:
    s = slots[0]
    print(s.get('pid','') or '""""""'.replace('\"','""'), str(s.get('running', False)).lower(), s.get('engine','unknown'))
else:
    print('','false','unknown')
" 2>/dev/null)
elif [ -f "$STATE_DIR/fuzzer.pid" ]; then
  # Legacy pre-v0.17 single-slot layout
  FUZZER_PID=$(cat "$STATE_DIR/fuzzer.pid")
  if kill -0 "$FUZZER_PID" 2>/dev/null; then
    FUZZER_RUNNING=true
  fi
  [ -f "$STATE_DIR/fuzzer.engine" ] && ENGINE=$(cat "$STATE_DIR/fuzzer.engine")
  SLOTS_JSON=$(python3 -c "
import json
print(json.dumps([{
    'slot': 'main',
    'engine': '$ENGINE' or 'unknown',
    'pid': '$FUZZER_PID',
    'running': $FUZZER_RUNNING,
    'started_at': None,
    'restart_count': 0,
}]))
" 2>/dev/null)
fi

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

# 7b. Determine ANY_RUNNING from SLOTS_JSON (multi-fuzzer aware).
# restart_fuzzer fires only when *all* slots are dead. Per-slot restarts
# happen invisibly via check-slot-liveness.sh.
ANY_RUNNING=$(python3 -c "
import json
try:
    slots = json.loads('''$SLOTS_JSON''')
    print('true' if any(s.get('running') for s in slots) else 'false')
except:
    print('$FUZZER_RUNNING')
")

# 8. Recommended decision branch
if [ "$ANY_RUNNING" != "true" ]; then
  RECOMMENDED_BRANCH="restart_fuzzer"
  RECOMMENDED_REASON="no fuzzer slot is running"
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

# 9. Write atomically — assemble JSON via python3 to keep the slot array clean
export NOW TICK_NUMBER FUZZER_PID FUZZER_RUNNING ENGINE HARNESS_BIN SYMCC_BIN SYMCC_AVAILABLE
export LATEST_COV_FILE LATEST_COV_TS LINES_COV LINES_TOTAL LINE_PCT PLATEAU SECONDS_SINCE_PROGRESS
export EXECS EXECS_PER_SEC PATHS CRASHES_TOTAL NEW_CRASHES_COUNT UNIQUE_FINDINGS
export STATE_DIR LATEST_GAP_FILE GAPS_PENDING GAPS_FOR_CONCOLIC GAPS_FOR_SEEDGEN
export GAPS_FOR_HARNESS GAPS_FOR_MUTATOR GAPS_DIRECT_COMPARE
export RECOMMENDED_BRANCH RECOMMENDED_REASON
export SLOTS_JSON

python3 - "$TMP" <<'PY'
import json, os, sys
def tri(s): return s == 'true'
def num(s):
    s = (s or '0').strip()
    try: return int(s)
    except:
        try: return float(s)
        except: return 0

slots = []
try:
    slots = json.loads(os.environ.get('SLOTS_JSON','[]') or '[]')
except: slots = []

doc = {
    "schema": "cc-fuzzer-current/v1",
    "now": num(os.environ.get('NOW','0')),
    "tick_number": num(os.environ.get('TICK_NUMBER','0')),
    "fuzzer": {
        "pid": os.environ.get('FUZZER_PID',''),
        "running": tri(os.environ.get('FUZZER_RUNNING','false')),
        "engine": os.environ.get('ENGINE','unknown') or 'unknown',
    },
    "fuzzers": slots,
    "harness": {
        "binary": os.environ.get('HARNESS_BIN',''),
        "symcc_binary": os.environ.get('SYMCC_BIN','') or '',
        "symcc_available": tri(os.environ.get('SYMCC_AVAILABLE','false')),
    },
    "coverage": {
        "snapshot_file": os.environ.get('LATEST_COV_FILE',''),
        "snapshot_ts": num(os.environ.get('LATEST_COV_TS','0')),
        "lines_covered": num(os.environ.get('LINES_COV','0')),
        "lines_total": num(os.environ.get('LINES_TOTAL','0')),
        "line_pct": num(os.environ.get('LINE_PCT','0')),
        "plateau": tri(os.environ.get('PLATEAU','false')),
        "seconds_since_progress": num(os.environ.get('SECONDS_SINCE_PROGRESS','0')),
    },
    "fuzzer_stats": {
        "execs": num(os.environ.get('EXECS','0')),
        "execs_per_sec": num(os.environ.get('EXECS_PER_SEC','0')),
        "paths": num(os.environ.get('PATHS','0')),
        "crashes_total": num(os.environ.get('CRASHES_TOTAL','0')),
        "new_crashes_since_previous": num(os.environ.get('NEW_CRASHES_COUNT','0')),
    },
    "findings": {
        "unique_count": num(os.environ.get('UNIQUE_FINDINGS','0')),
        "file": os.environ.get('STATE_DIR','fuzz/state') + '/findings.jsonl',
    },
    "gaps": {
        "latest_report": os.environ.get('LATEST_GAP_FILE',''),
        "total_pending": num(os.environ.get('GAPS_PENDING','0')),
        "for_concolic": num(os.environ.get('GAPS_FOR_CONCOLIC','0')),
        "for_seedgen": num(os.environ.get('GAPS_FOR_SEEDGEN','0')),
        "for_harness": num(os.environ.get('GAPS_FOR_HARNESS','0')),
        "for_mutator": num(os.environ.get('GAPS_FOR_MUTATOR','0')),
        "direct_compare": num(os.environ.get('GAPS_DIRECT_COMPARE','0')),
    },
    "recommendation": {
        "branch": os.environ.get('RECOMMENDED_BRANCH','sleep'),
        "reason": os.environ.get('RECOMMENDED_REASON',''),
    },
}

# Add a top-level convenience flag so the orchestrator can spot multi-slot
# campaigns at a glance without re-counting.
doc['multi_fuzzer'] = len(slots) > 1

with open(sys.argv[1], 'w') as f:
    json.dump(doc, f, indent=2)
PY

mv "$TMP" "$OUT"
echo "$OUT"
