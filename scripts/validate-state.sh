#!/usr/bin/env bash
# validate-state.sh
#
# Strict validator for cc-fuzzer state per STATE_SCHEMA.md.
# Returns exit 0 if state is valid, exit 1 with a report if not.
#
# Called by:
#   - fuzz-orchestrator at session start
#   - /cc-fuzzer:campaign before any action
#   - manually by the user via /cc-fuzzer:validate
#
# Strictness rules (per Q2 answer):
#   - Every JSON file must have a `schema` field matching a known schema/version
#   - Every required field must be present
#   - Unrecognized fields are an ERROR
#   - File locations must match STATE_SCHEMA.md exactly

set -u

# Path anchor - refuses cwd inside fuzz/, refuses recursive fuzz/fuzz/
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
. "$SCRIPT_DIR/_lib/path-anchor.sh"

FUZZ_ROOT="${FUZZ_ROOT:-fuzz}"
STATE_DIR="$FUZZ_ROOT/state"
SNAPSHOTS_DIR="$STATE_DIR/snapshots"
HARNESS_DIR="$FUZZ_ROOT/harness"
CRASHES_DIR="$FUZZ_ROOT/crashes"
CORPUS_DIR="$FUZZ_ROOT/corpus"

EXPECTED_SCHEMA_VERSION="v7"

ERRORS=()
WARNINGS=()

err() { ERRORS+=("$1"); }
warn() { WARNINGS+=("$1"); }

#------------------------------------------------------------------------------
# Step 1: Filesystem layout
#------------------------------------------------------------------------------

if [ ! -d "$FUZZ_ROOT" ]; then
  echo "no campaign: $FUZZ_ROOT does not exist"
  echo "ok"
  exit 0  # Not an error - just no campaign yet
fi

# Required directories - if any are missing AND state/ exists, that's a problem
if [ -d "$STATE_DIR" ]; then
  for d in "$STATE_DIR" "$SNAPSHOTS_DIR" "$HARNESS_DIR" "$CRASHES_DIR" "$CRASHES_DIR/new" "$CRASHES_DIR/known" "$CRASHES_DIR/flaky" "$CORPUS_DIR"; do
    [ -d "$d" ] || warn "missing required directory: $d (will be created)"
  done
fi

# Forbidden legacy paths (these are bug-magnets - the triager has been known
# to write to fuzz/state/crashes/ instead of fuzz/crashes/new/)
for legacy in \
  "$FUZZ_ROOT/known-crashes" \
  "$FUZZ_ROOT/known_crashes" \
  "$STATE_DIR/crashes" \
  "out/default/crashes"; do
  if [ -d "$legacy" ]; then
    err "legacy path exists: $legacy (must be migrated to $CRASHES_DIR/new/ or known/)"
  fi
done

# Timestamped files must be in snapshots/, not state/ root
if [ -d "$STATE_DIR" ]; then
  for stray in "$STATE_DIR"/coverage-*.json "$STATE_DIR"/gaps-*.json "$STATE_DIR"/concolic-*.json; do
    [ -f "$stray" ] && err "timestamped file in wrong location: $stray (must be in $SNAPSHOTS_DIR/)"
  done
fi

# FINDINGS-REPORT.md is REWRITABLE; warn if absent (not an error)
if [ -d "$STATE_DIR" ] && [ ! -f "$STATE_DIR/FINDINGS-REPORT.md" ]; then
  warn "missing $STATE_DIR/FINDINGS-REPORT.md (run /cc-fuzzer:report or migrate-state.sh to create)"
fi

# Crash directory naming - must be f\d{3,} per spec
if [ -d "$CRASHES_DIR/known" ]; then
  for d in "$CRASHES_DIR/known"/*/; do
    [ -d "$d" ] || continue
    base=$(basename "$d")
    if ! [[ "$base" =~ ^f[0-9]{3,}$ ]]; then
      err "non-conforming crash directory name: $CRASHES_DIR/known/$base (must match ^f\\d{3,}\$)"
    fi
  done
fi

#------------------------------------------------------------------------------
# Step 2: schema-version file
#------------------------------------------------------------------------------

if [ -d "$STATE_DIR" ] && [ ! -f "$STATE_DIR/schema-version" ]; then
  warn "missing $STATE_DIR/schema-version (run migrate-state.sh to create)"
elif [ -f "$STATE_DIR/schema-version" ]; then
  ACTUAL_VERSION=$(head -1 "$STATE_DIR/schema-version" | tr -d ' \n')
  if [ "$ACTUAL_VERSION" != "$EXPECTED_SCHEMA_VERSION" ]; then
    err "schema version mismatch: state has '$ACTUAL_VERSION', plugin expects '$EXPECTED_SCHEMA_VERSION'"
  fi
fi

#------------------------------------------------------------------------------
# Step 3: JSON schema validation - one validator per schema type
#------------------------------------------------------------------------------

# Helper: validate a JSON file against a schema. Args:
#   $1 = file path
#   $2 = expected schema string (e.g. "harness-built/v1")
#   $3 = comma-separated required fields
#   $4 = comma-separated allowed (required+optional) fields
validate_json() {
  local file="$1"
  local expected_schema="$2"
  local required="$3"
  local allowed="$4"

  [ -f "$file" ] || { err "missing required file: $file"; return; }

  # Validate with python (single dependency, present everywhere)
  local result
  result=$(python3 - <<PY 2>&1
import json, sys
try:
    with open("$file") as f:
        d = json.load(f)
except json.JSONDecodeError as e:
    print(f"PARSE_ERROR: {e}")
    sys.exit(1)
except Exception as e:
    print(f"READ_ERROR: {e}")
    sys.exit(1)

if not isinstance(d, dict):
    print(f"NOT_OBJECT: top-level must be a JSON object, got {type(d).__name__}")
    sys.exit(1)

schema = d.get("schema")
if schema != "$expected_schema":
    print(f"WRONG_SCHEMA: expected '$expected_schema', got '{schema}'")
    sys.exit(1)

required = set("$required".split(",")) if "$required" else set()
allowed = set("$allowed".split(",")) if "$allowed" else set()
allowed.add("schema")

actual = set(d.keys())
missing = required - actual
unrecognized = actual - allowed

if missing:
    print(f"MISSING_FIELDS: {sorted(missing)}")
    sys.exit(1)
if unrecognized:
    print(f"UNRECOGNIZED_FIELDS: {sorted(unrecognized)}")
    sys.exit(1)

print("OK")
PY
)

  if [ "$result" != "OK" ]; then
    err "$file: $result"
  fi
}

# 3a. harness-built.json (v5)
if [ -f "$STATE_DIR/harness-built.json" ]; then
  validate_json "$STATE_DIR/harness-built.json" \
    "harness-built/v5" \
    "harness_source,harness_binary,build_script,entry_function,target_source,target_source_hash,build_command_hash,built_at,coverage_tracking,cmplog_enabled,fuzzing_mode" \
    "harness_source,harness_binary,coverage_binary,verify_binary,coverage_tracking,coverage_disabled_reason,cmplog_binary,cmplog_enabled,cmplog_disabled_reason,symcc_binary,mutator_source,build_script,dict_files,entry_function,input_encoding,sanitizers,fuzzing_mode,target_source,target_source_hash,build_command_hash,harness_attempts,built_at,build_command"

  # Cross-check: if coverage_tracking=true, coverage_binary must exist and be executable
  TRACK=$(python3 -c "
import json
try: print(json.load(open('$STATE_DIR/harness-built.json')).get('coverage_tracking', False))
except: pass" 2>/dev/null)
  COV_BIN=$(python3 -c "
import json
try: print(json.load(open('$STATE_DIR/harness-built.json')).get('coverage_binary') or '')
except: pass" 2>/dev/null)
  if [ "$TRACK" = "True" ]; then
    if [ -z "$COV_BIN" ]; then
      err "harness-built.json: coverage_tracking=true but coverage_binary is null/missing"
    elif [ ! -x "$COV_BIN" ]; then
      err "harness-built.json: coverage_binary not executable: $COV_BIN"
    fi
  else
    # coverage_tracking=false requires a reason field per spec v3+
    REASON=$(python3 -c "
import json
try: print(json.load(open('$STATE_DIR/harness-built.json')).get('coverage_disabled_reason') or '')
except: pass" 2>/dev/null)
    if [ -z "$REASON" ]; then
      warn "harness-built.json: coverage_tracking=false but no coverage_disabled_reason set. Run migrate-state.sh to backfill, or rebuild with /cc-fuzzer:campaign --reset to enable coverage."
    fi
  fi

  # v0.13: same pattern for cmplog. cmplog_enabled=true requires an executable binary.
  # cmplog_enabled=false requires a reason.
  CMPLOG_TRACK=$(python3 -c "
import json
try: print(json.load(open('$STATE_DIR/harness-built.json')).get('cmplog_enabled', False))
except: pass" 2>/dev/null)
  CMPLOG_BIN=$(python3 -c "
import json
try: print(json.load(open('$STATE_DIR/harness-built.json')).get('cmplog_binary') or '')
except: pass" 2>/dev/null)
  if [ "$CMPLOG_TRACK" = "True" ]; then
    if [ -z "$CMPLOG_BIN" ]; then
      err "harness-built.json: cmplog_enabled=true but cmplog_binary is null/missing"
    elif [ ! -x "$CMPLOG_BIN" ]; then
      warn "harness-built.json: cmplog_binary not executable: $CMPLOG_BIN (run-fuzzer.sh will continue without -c)"
    fi
  else
    CMPLOG_REASON=$(python3 -c "
import json
try: print(json.load(open('$STATE_DIR/harness-built.json')).get('cmplog_disabled_reason') or '')
except: pass" 2>/dev/null)
    if [ -z "$CMPLOG_REASON" ]; then
      warn "harness-built.json: cmplog_enabled=false but no cmplog_disabled_reason set. Run migrate-state.sh to backfill."
    fi
  fi

  # v7: fuzzing_mode must be in_process or process_based
  FMODE=$(python3 -c "
import json
try: print(json.load(open('$STATE_DIR/harness-built.json')).get('fuzzing_mode',''))
except: pass" 2>/dev/null)
  case "$FMODE" in
    in_process|process_based) ;;
    "") err "harness-built.json: fuzzing_mode missing (run migrate-state.sh to backfill)" ;;
    *) err "harness-built.json: invalid fuzzing_mode '$FMODE' (expected in_process or process_based)" ;;
  esac
fi

# 3b. current.json
if [ -f "$STATE_DIR/current.json" ]; then
  validate_json "$STATE_DIR/current.json" \
    "cc-fuzzer-current/v1" \
    "now,tick_number,fuzzer,harness,coverage,fuzzer_stats,findings,gaps,recommendation" \
    "now,tick_number,fuzzer,harness,coverage,fuzzer_stats,findings,gaps,recommendation,last_report_at"

  # Additionally check recommendation.branch is in the allowed set
  if [ -f "$STATE_DIR/current.json" ]; then
    BRANCH=$(python3 -c "
import json
try: print(json.load(open('$STATE_DIR/current.json')).get('recommendation', {}).get('branch', ''))
except: pass" 2>/dev/null)
    case "$BRANCH" in
      sleep|restart_fuzzer|fix_instrumentation|triage|analyze_gaps|reanalyze_gaps|generate_seeds|concolic|mutator|stop) ;;
      "") ;; # empty is fine, will be set on next update
      *) err "current.json: invalid recommendation.branch '$BRANCH'" ;;
    esac
  fi
fi

# 3c. budget.json
if [ -f "$STATE_DIR/budget.json" ]; then
  validate_json "$STATE_DIR/budget.json" \
    "budget/v1" \
    "campaign_started,limit_usd,spent_usd,last_updated" \
    "campaign_started,limit_usd,spent_usd,spent_per_model,tokens_in,tokens_out,last_updated"
fi

# 3d. findings.jsonl - validate each line, with strict id/category/exploitability
if [ -f "$STATE_DIR/findings.jsonl" ]; then
  # Run the python validator and capture output. Then iterate in the main shell
  # so err() actually mutates the ERRORS array. (Piping into `while read` would
  # run the loop in a subshell and lose the appends.)
  PY_OUT=$(python3 - <<PY 2>&1
import json, re, os
required = {"schema","id","stack_hash","category","location","exploitability","root_cause","reproducer","first_seen","last_seen","dedup_count"}
allowed = required | {"subcategory","sanitizer_report_excerpt","verified_against_build","status","stale_against_build"}
allowed_categories = {"heap-buffer-overflow","heap-use-after-free","stack-buffer-overflow","global-buffer-overflow","stack-overflow","null-deref","assertion-failure","oom","timeout","flaky","harness-artifact"}
allowed_exploitability = {"likely","medium","unlikely","harness-artifact"}
ID_RE = re.compile(r"^f[0-9]{3,}$")

# Track stack_hash uniqueness - one stack_hash per finding id
seen_hashes = {}
seen_ids = set()

with open("$STATE_DIR/findings.jsonl") as f:
    for ln, line in enumerate(f, 1):
        line = line.strip()
        if not line: continue
        try:
            d = json.loads(line)
        except Exception as e:
            print(f"findings.jsonl line {ln}: parse error: {e}")
            continue
        if d.get("schema") != "finding/v1":
            print(f"findings.jsonl line {ln}: wrong schema '{d.get('schema')}'")
            continue
        keys = set(d.keys())
        missing = required - keys
        unrec = keys - allowed
        if missing: print(f"findings.jsonl line {ln}: missing fields {sorted(missing)}")
        if unrec: print(f"findings.jsonl line {ln}: unrecognized fields {sorted(unrec)}")

        # ID format check - this is the FIND-001 / FIND-NOCRASH-1 / etc bug
        fid = d.get("id", "")
        if fid and not ID_RE.match(fid):
            print(f"findings.jsonl line {ln}: invalid id format '{fid}' (must match ^f[0-9]{{3,}}\$)")
        if fid in seen_ids:
            print(f"findings.jsonl line {ln}: duplicate id '{fid}'")
        seen_ids.add(fid)

        # Category enum check - this catches the f001-with-FIND-001-v6-as-category bug
        cat = d.get("category", "")
        if cat and cat not in allowed_categories and not cat.startswith("ubsan-"):
            print(f"findings.jsonl line {ln}: invalid category '{cat}'")

        # Exploitability enum check
        expl = d.get("exploitability", "")
        if expl and expl not in allowed_exploitability:
            print(f"findings.jsonl line {ln}: invalid exploitability '{expl}'")

        # stack_hash uniqueness (modulo dedup_count)
        sh = d.get("stack_hash", "")
        if sh:
            if sh in seen_hashes and seen_hashes[sh] != fid:
                print(f"findings.jsonl line {ln}: stack_hash '{sh}' already used by {seen_hashes[sh]} (use findings.sh dedup)")
            seen_hashes[sh] = fid

        # Reproducer path must point at crashes/{known,stale}/<id>/repro.bin
        rep = d.get("reproducer", "")
        status = d.get("status", "")
        if rep and fid:
            if status == "stale":
                expected = f"fuzz/crashes/stale/{fid}/repro.bin"
            else:
                expected = f"fuzz/crashes/known/{fid}/repro.bin"
            if rep != expected:
                print(f"findings.jsonl line {ln}: reproducer '{rep}' should be '{expected}'")

        # Reproducer file must exist
        if rep and not os.path.isfile(rep):
            print(f"findings.jsonl line {ln}: reproducer file does not exist: {rep}")
PY
)
  if [ -n "$PY_OUT" ]; then
    while IFS= read -r line; do
      [ -n "$line" ] && err "$line"
    done <<< "$PY_OUT"
  fi
fi

# 3e. events.jsonl - lightweight check
if [ -f "$STATE_DIR/events.jsonl" ]; then
  PY_OUT=$(python3 - <<PY 2>&1
import json
required_base = {"schema","ts","tick","event"}
with open("$STATE_DIR/events.jsonl") as f:
    for ln, line in enumerate(f, 1):
        line = line.strip()
        if not line: continue
        try:
            d = json.loads(line)
        except Exception as e:
            print(f"events.jsonl line {ln}: parse error: {e}")
            continue
        if d.get("schema") != "event/v1":
            print(f"events.jsonl line {ln}: wrong schema")
            continue
        missing = required_base - set(d.keys())
        if missing:
            print(f"events.jsonl line {ln}: missing {sorted(missing)}")
PY
)
  if [ -n "$PY_OUT" ]; then
    while IFS= read -r line; do
      [ -n "$line" ] && err "$line"
    done <<< "$PY_OUT"
  fi
fi

# 3f. snapshot files
if [ -d "$SNAPSHOTS_DIR" ]; then
  for f in "$SNAPSHOTS_DIR"/coverage-*.json; do
    [ -f "$f" ] || continue
    validate_json "$f" \
      "coverage-snapshot/v2" \
      "timestamp,engine,fuzzer_stats,coverage,instrumentation" \
      "timestamp,engine,fuzzer_stats,coverage,instrumentation,previous_snapshot_ts,new_crashes_since_previous,top_unreached_functions"
  done
  for f in "$SNAPSHOTS_DIR"/gaps-*.json; do
    [ -f "$f" ] || continue
    validate_json "$f" \
      "gaps-report/v1" \
      "timestamp,snapshot_file,gaps" \
      "timestamp,snapshot_file,gaps"
  done
  for f in "$SNAPSHOTS_DIR"/concolic-*.json; do
    [ -f "$f" ] || continue
    validate_json "$f" \
      "concolic-result/v1" \
      "timestamp,gaps_targeted,seeds_used,inputs_generated,inputs_validated,inputs_promoted_to_corpus" \
      "timestamp,gaps_targeted,seeds_used,inputs_generated,inputs_validated,inputs_promoted_to_corpus,symcc_timeouts,symcc_errors"
  done
fi

#------------------------------------------------------------------------------
# Step 4: Cross-reference checks
#------------------------------------------------------------------------------

# If harness-built.json exists, the harness binary should exist
if [ -f "$STATE_DIR/harness-built.json" ]; then
  HBIN=$(python3 -c "
import json
try: print(json.load(open('$STATE_DIR/harness-built.json')).get('harness_binary', ''))
except: pass" 2>/dev/null)
  if [ -n "$HBIN" ] && [ ! -x "$HBIN" ]; then
    warn "harness binary referenced but not executable: $HBIN"
  fi
fi

# crashes/known/<id>/ subdirs should each have a repro.bin
if [ -d "$CRASHES_DIR/known" ]; then
  for d in "$CRASHES_DIR/known"/*/; do
    [ -d "$d" ] || continue
    if [ ! -f "$d/repro.bin" ]; then
      err "missing canonical reproducer: $d/repro.bin"
    fi
  done
fi

#------------------------------------------------------------------------------
# Output
#------------------------------------------------------------------------------

if [ "${#WARNINGS[@]}" -gt 0 ]; then
  echo "WARNINGS (${#WARNINGS[@]}):"
  for w in "${WARNINGS[@]}"; do echo "  $w"; done
fi

if [ "${#ERRORS[@]}" -gt 0 ]; then
  echo ""
  echo "ERRORS (${#ERRORS[@]}):"
  for e in "${ERRORS[@]}"; do echo "  $e"; done
  echo ""
  echo "FAIL: state validation failed. See errors above."
  echo "  - Run 'scripts/migrate-state.sh' if this is a schema version mismatch"
  echo "  - Run '/cc-fuzzer:reset' to wipe state and start over"
  echo "  - Or fix individual issues manually"
  exit 1
fi

echo "ok"
exit 0
