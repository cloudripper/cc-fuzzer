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
# Strictness rules:
#   - Every JSON file must have a `schema` field matching a known schema/version
#   - Every required field must be present
#   - Unrecognized fields are an ERROR
#   - File locations must match STATE_SCHEMA.md exactly
#
# Multi-harness mode (schema v9):
#   Mode is detected from fuzz-config.json:harnesses[] (non-empty list = multi).
#   In multi mode, validates the v9 shapes (harness-set/v1, harness-built/v6,
#   current/v2, fuzz-config/v3, fuzzers/v2, finding/v2) and per-harness
#   filesystem layout under fuzz/harnesses/<name>/. In singular mode, validates
#   the v8 shapes unchanged (only the schema-version bumps to v9).

set -u

# Path anchor - refuses cwd inside fuzz/, refuses recursive fuzz/fuzz/
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
. "$SCRIPT_DIR/_lib/path-anchor.sh"

FUZZ_ROOT="${FUZZ_ROOT:-fuzz}"
STATE_DIR="$FUZZ_ROOT/state"
SNAPSHOTS_DIR="$STATE_DIR/snapshots"
HARNESS_DIR="$FUZZ_ROOT/harness"            # singular only
HARNESSES_DIR="$FUZZ_ROOT/harnesses"        # multi only
CRASHES_DIR="$FUZZ_ROOT/crashes"
CORPUS_DIR="$FUZZ_ROOT/corpus"              # singular only

EXPECTED_SCHEMA_VERSION="v9"

ERRORS=()
WARNINGS=()

err()  { ERRORS+=("$1"); }
warn() { WARNINGS+=("$1"); }

#------------------------------------------------------------------------------
# Multi-harness mode detection (schema v9)
#
# Multi mode is active iff fuzz-config.json contains a non-empty harnesses[]
# array of objects with a `name` field. All schema versions and filesystem
# checks below dispatch on this single signal.
#------------------------------------------------------------------------------
MODE="singular"
DECLARED_HARNESSES=()
if [ -f "$STATE_DIR/fuzz-config.json" ]; then
  NAMES=$(CFG="$STATE_DIR/fuzz-config.json" python3 - <<'PY' 2>/dev/null
import json, os
try:
    d = json.load(open(os.environ['CFG']))
    hs = d.get('harnesses') or []
    if isinstance(hs, list):
        for h in hs:
            if isinstance(h, dict) and h.get('name'):
                print(h['name'])
except Exception:
    pass
PY
)
  if [ -n "$NAMES" ]; then
    MODE="multi"
    while IFS= read -r n; do
      [ -n "$n" ] && DECLARED_HARNESSES+=("$n")
    done <<< "$NAMES"
  fi
fi

is_known_harness() {
  local name="$1"
  local n
  for n in "${DECLARED_HARNESSES[@]:-}"; do
    [ "$n" = "$name" ] && return 0
  done
  return 1
}

# Joined list of declared harnesses, one per line, for passing to python via env.
declared_env() { printf '%s\n' "${DECLARED_HARNESSES[@]:-}"; }

#------------------------------------------------------------------------------
# Step 1: Filesystem layout
#------------------------------------------------------------------------------

if [ ! -d "$FUZZ_ROOT" ]; then
  echo "no campaign: $FUZZ_ROOT does not exist"
  echo "ok"
  exit 0  # Not an error - just no campaign yet
fi

# Required directories (campaign-level, both modes)
if [ -d "$STATE_DIR" ]; then
  for d in "$STATE_DIR" "$SNAPSHOTS_DIR" "$CRASHES_DIR" "$CRASHES_DIR/new" "$CRASHES_DIR/known" "$CRASHES_DIR/flaky"; do
    [ -d "$d" ] || warn "missing required directory: $d (will be created)"
  done
fi

# Mode-specific filesystem layout
if [ "$MODE" = "singular" ]; then
  if [ -d "$STATE_DIR" ]; then
    [ -d "$HARNESS_DIR" ] || warn "missing required directory: $HARNESS_DIR (will be created)"
    [ -d "$CORPUS_DIR" ]  || warn "missing required directory: $CORPUS_DIR (will be created)"
  fi
  # Multi-mode layout must NOT exist in singular mode
  if [ -d "$HARNESSES_DIR" ]; then
    err "singular mode but $HARNESSES_DIR/ exists (multi-mode layout). Either remove it or activate multi-mode by declaring harnesses[] in fuzz-config.json."
  fi
else
  # Multi: fuzz/harnesses/<name>/{harness,corpus,coverage}/ per declared harness
  if [ ! -d "$HARNESSES_DIR" ]; then
    err "multi mode (harnesses[] declared in fuzz-config.json) but $HARNESSES_DIR/ does not exist"
  else
    for name in "${DECLARED_HARNESSES[@]}"; do
      bundle="$HARNESSES_DIR/$name"
      [ -d "$bundle" ]          || warn "declared harness '$name' has no bundle at $bundle (run /cc-fuzzer:campaign or harness-writer to build)"
      [ -d "$bundle/harness" ]  || warn "missing $bundle/harness/"
      [ -d "$bundle/corpus" ]   || warn "missing $bundle/corpus/"
      [ -d "$bundle/coverage" ] || warn "missing $bundle/coverage/"
    done
  fi
  # Singular-mode top-level paths must NOT exist as regular directories in multi mode
  for legacy in "$HARNESS_DIR" "$CORPUS_DIR"; do
    if [ -d "$legacy" ] && [ ! -L "$legacy" ]; then
      err "multi mode but singular path $legacy/ still exists (the singular->multi upgrade should have moved it to $HARNESSES_DIR/<original>/). Either complete the upgrade or remove the stray directory."
    fi
  done
fi

# Forbidden legacy paths (these are bug-magnets - the triager has been known
# to write to fuzz/state/crashes/ instead of fuzz/crashes/new/)
for legacy in \
  "$FUZZ_ROOT/known-crashes" \
  "$FUZZ_ROOT/known_crashes" \
  "$STATE_DIR/crashes" \
  "$STATE_DIR/harnesses" \
  "out/default/crashes"; do
  if [ -d "$legacy" ]; then
    err "legacy/forbidden path exists: $legacy"
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
#   $5 = (optional) "lenient" → unrecognized fields produce a WARN, not an ERR.
#        Used for immutable historical snapshot files (coverage/gaps/concolic)
#        where the schema has expanded over time and older agent versions wrote
#        files with fields not present in the current allowed-list. Required
#        fields and wrong-schema checks remain hard errors regardless.
validate_json() {
  local file="$1"
  local expected_schema="$2"
  local required="$3"
  local allowed="$4"
  local mode="${5:-strict}"

  [ -f "$file" ] || { err "missing required file: $file"; return; }

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
lenient = "$mode" == "lenient"

actual = set(d.keys())
missing = required - actual
unrecognized = actual - allowed

if missing:
    print(f"MISSING_FIELDS: {sorted(missing)}")
    sys.exit(1)
if unrecognized:
    # In lenient mode the validator still surfaces the extra fields, but as
    # a warning so old snapshots don't block the campaign. The "WARN:" prefix
    # is interpreted by the caller below.
    prefix = "WARN: " if lenient else ""
    print(f"{prefix}UNRECOGNIZED_FIELDS: {sorted(unrecognized)}")
    sys.exit(0 if lenient else 1)

print("OK")
PY
)

  case "$result" in
    OK) ;;
    WARN:*) warn "$file: ${result#WARN: }" ;;
    *) err "$file: $result" ;;
  esac
}

# Field sets shared by singular v5 and multi v6 (v6 adds `name`)
HARNESS_BUILT_REQUIRED_V5="harness_source,harness_binary,build_script,entry_function,target_source,target_source_hash,build_command_hash,built_at,coverage_tracking,cmplog_enabled,fuzzing_mode"
HARNESS_BUILT_ALLOWED_V5="harness_source,harness_binary,coverage_binary,verify_binary,coverage_tracking,coverage_disabled_reason,cmplog_binary,cmplog_enabled,cmplog_disabled_reason,symcc_binary,mutator_source,build_script,dict_files,entry_function,input_encoding,sanitizers,fuzzing_mode,target_source,target_source_hash,build_command_hash,harness_attempts,built_at,build_command"
HARNESS_BUILT_REQUIRED_V6="name,${HARNESS_BUILT_REQUIRED_V5}"
HARNESS_BUILT_ALLOWED_V6="name,${HARNESS_BUILT_ALLOWED_V5}"

# 3a. harness-built.json
# Singular mode: this is the canonical record (harness-built/v5).
# Multi mode:    this is a read-only mirror of harnesses.json[0] (harness-built/v6).
if [ -f "$STATE_DIR/harness-built.json" ]; then
  if [ "$MODE" = "singular" ]; then
    validate_json "$STATE_DIR/harness-built.json" "harness-built/v5" \
      "$HARNESS_BUILT_REQUIRED_V5" "$HARNESS_BUILT_ALLOWED_V5"
  else
    validate_json "$STATE_DIR/harness-built.json" "harness-built/v6" \
      "$HARNESS_BUILT_REQUIRED_V6" "$HARNESS_BUILT_ALLOWED_V6"
  fi

  # Coverage/cmplog/fuzzing_mode cross-checks apply identically to both schemas.
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
    REASON=$(python3 -c "
import json
try: print(json.load(open('$STATE_DIR/harness-built.json')).get('coverage_disabled_reason') or '')
except: pass" 2>/dev/null)
    if [ -z "$REASON" ]; then
      warn "harness-built.json: coverage_tracking=false but no coverage_disabled_reason set. Run migrate-state.sh to backfill, or rebuild with /cc-fuzzer:campaign --reset to enable coverage."
    fi
  fi

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

  FMODE=$(python3 -c "
import json
try: print(json.load(open('$STATE_DIR/harness-built.json')).get('fuzzing_mode',''))
except: pass" 2>/dev/null)
  case "$FMODE" in
    in_process|process_based) ;;
    "") err "harness-built.json: fuzzing_mode missing (run migrate-state.sh to backfill)" ;;
    *) err "harness-built.json: invalid fuzzing_mode '$FMODE' (expected in_process or process_based)" ;;
  esac

  HASH_CHECK=$(python3 -c "
import json, re
try:
    d = json.load(open('$STATE_DIR/harness-built.json'))
    for k in ('target_source_hash','build_command_hash'):
        v = d.get(k, '')
        if not re.match(r'^[0-9a-f]{16}\$', v or ''):
            print(f'{k}={v}')
except Exception as e:
    print(f'parse_error={e}')
" 2>/dev/null)
  if [ -n "$HASH_CHECK" ]; then
    while IFS= read -r line; do
      [ -z "$line" ] && continue
      err "harness-built.json: $line is not 16-char lowercase hex (placeholder stub?). Rebuild via /cc-fuzzer:campaign --reset, or run scripts/write-harness-built.sh to repair."
    done <<< "$HASH_CHECK"
  fi
fi

# 3a-multi. harnesses.json (multi mode only) + mirror-drift check
if [ "$MODE" = "multi" ]; then
  if [ ! -f "$STATE_DIR/harnesses.json" ]; then
    err "multi mode (harnesses[] declared) but $STATE_DIR/harnesses.json is missing"
  else
    validate_json "$STATE_DIR/harnesses.json" "harness-set/v1" \
      "harnesses" "harnesses"

    HS_ERRS=$(HARNESSES_PATH="$STATE_DIR/harnesses.json" \
              MIRROR_PATH="$STATE_DIR/harness-built.json" \
              DECLARED="$(declared_env)" \
              REQUIRED_V6="$HARNESS_BUILT_REQUIRED_V6" \
              ALLOWED_V6="$HARNESS_BUILT_ALLOWED_V6" \
              python3 - <<'PY' 2>&1
import json, os, re
SLUG = re.compile(r'^[a-z0-9][a-z0-9_-]{0,31}$')
required = set(os.environ['REQUIRED_V6'].split(',')) | {'schema'}
allowed  = set(os.environ['ALLOWED_V6'].split(',')) | {'schema'}
declared = [n for n in os.environ['DECLARED'].splitlines() if n.strip()]

try:
    doc = json.load(open(os.environ['HARNESSES_PATH']))
except Exception as e:
    print(f'harnesses.json: parse error: {e}'); raise SystemExit(0)

hs = doc.get('harnesses') or []
if not hs:
    print('harnesses.json: harnesses[] is empty (multi mode requires at least one entry)')
    raise SystemExit(0)

seen = set()
for i, h in enumerate(hs):
    if not isinstance(h, dict):
        print(f'harnesses.json: harnesses[{i}] is not an object'); continue
    if h.get('schema') != 'harness-built/v6':
        print(f"harnesses.json: harnesses[{i}].schema is '{h.get('schema')}' (expected harness-built/v6)")
    name = h.get('name','')
    if not SLUG.match(name or ''):
        print(f"harnesses.json: harnesses[{i}].name '{name}' invalid (regex ^[a-z0-9][a-z0-9_-]{{0,31}}$)")
    if name in seen:
        print(f"harnesses.json: duplicate harness name '{name}'")
    seen.add(name)
    keys = set(h.keys())
    missing = required - keys
    unrec  = keys - allowed
    if missing:
        print(f'harnesses.json: harnesses[{i}] ({name!r}) missing fields {sorted(missing)}')
    if unrec:
        print(f'harnesses.json: harnesses[{i}] ({name!r}) unrecognized fields {sorted(unrec)}')

# Cross-ref: harnesses.json names must equal the fuzz-config.json:harnesses[] name set
config_names = set(declared)
hs_names = {h.get('name') for h in hs if isinstance(h, dict)}
extra_in_hs = hs_names - config_names
missing_in_hs = config_names - hs_names
if extra_in_hs:
    print(f"harnesses.json declares {sorted(extra_in_hs)} not in fuzz-config.json:harnesses[]")
if missing_in_hs:
    print(f"fuzz-config.json:harnesses[] declares {sorted(missing_in_hs)} not in harnesses.json")

# Mirror invariant: state/harness-built.json must equal harnesses[0] field-by-field
mirror_path = os.environ['MIRROR_PATH']
if os.path.isfile(mirror_path) and hs:
    try:
        mirror = json.load(open(mirror_path))
    except Exception as e:
        print(f'harness-built.json: parse error reading mirror: {e}')
    else:
        head = hs[0]
        all_keys = set(mirror.keys()) | set(head.keys())
        drift = []
        for k in all_keys:
            if mirror.get(k) != head.get(k):
                drift.append(k)
        if drift:
            print(f"harness-built.json: MIRROR DRIFT vs harnesses.json[0] on fields {sorted(drift)} (mirror file is read-only; writes must go to harnesses.json)")
PY
)
    if [ -n "$HS_ERRS" ]; then
      while IFS= read -r line; do
        [ -z "$line" ] && continue
        err "$line"
      done <<< "$HS_ERRS"
    fi
  fi
fi

# 3b. current.json
if [ -f "$STATE_DIR/current.json" ]; then
  if [ "$MODE" = "singular" ]; then
    validate_json "$STATE_DIR/current.json" "cc-fuzzer-current/v1" \
      "now,tick_number,fuzzer,fuzzers,harness,coverage,fuzzer_stats,findings,gaps,recommendation" \
      "now,tick_number,fuzzer,fuzzers,harness,coverage,fuzzer_stats,findings,gaps,recommendation,last_report_at,multi_fuzzer"
  else
    validate_json "$STATE_DIR/current.json" "cc-fuzzer-current/v2" \
      "now,tick_number,active_harness,harnesses,fuzzers,findings,recommendation" \
      "now,tick_number,active_harness,harnesses,fuzzers,findings,recommendation,last_report_at,multi_fuzzer,coverage,fuzzer_stats,gaps,fuzzer,harness"

    # active_harness + recommendation.harness must reference declared harnesses
    ACTIVE=$(python3 -c "
import json
try: print(json.load(open('$STATE_DIR/current.json')).get('active_harness',''))
except: pass" 2>/dev/null)
    if [ -n "$ACTIVE" ] && ! is_known_harness "$ACTIVE"; then
      err "current.json: active_harness '$ACTIVE' is not a declared harness"
    fi
    REC_H=$(python3 -c "
import json
try: print(json.load(open('$STATE_DIR/current.json')).get('recommendation', {}).get('harness',''))
except: pass" 2>/dev/null)
    if [ -n "$REC_H" ] && ! is_known_harness "$REC_H"; then
      err "current.json: recommendation.harness '$REC_H' is not a declared harness"
    fi
  fi

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

# 3c. budget.json (campaign-level, unchanged across modes)
if [ -f "$STATE_DIR/budget.json" ]; then
  validate_json "$STATE_DIR/budget.json" \
    "budget/v1" \
    "campaign_started,limit_usd,spent_usd,last_updated" \
    "campaign_started,limit_usd,spent_usd,spent_per_model,tokens_in,tokens_out,last_updated"
fi

# 3c2. fuzz-config.json
if [ -f "$STATE_DIR/fuzz-config.json" ]; then
  if [ "$MODE" = "singular" ]; then
    validate_json "$STATE_DIR/fuzz-config.json" "fuzz-config/v2" \
      "fuzz_forks" "fuzz_forks,fuzzer_slots"
  else
    validate_json "$STATE_DIR/fuzz-config.json" "fuzz-config/v3" \
      "fuzz_forks,harnesses,fuzzer_slots" "fuzz_forks,harnesses,fuzzer_slots"
  fi

  SLOT_ERRS=$(MODE="$MODE" \
              DECLARED="$(declared_env)" \
              CFG="$STATE_DIR/fuzz-config.json" \
              python3 - <<'PY' 2>&1
import json, re, os
mode = os.environ.get('MODE','singular')
declared = {n for n in os.environ.get('DECLARED','').splitlines() if n.strip()}
try:
    d = json.load(open(os.environ['CFG']))
except Exception:
    raise SystemExit(0)
slots = d.get('fuzzer_slots') or []
if not isinstance(slots, list):
    print('fuzz-config.json: fuzzer_slots must be a list'); raise SystemExit(0)
slot_re = re.compile(r'^[a-z0-9-]{1,32}$')
seen = set()
for i, s in enumerate(slots):
    if not isinstance(s, dict):
        print(f'fuzz-config.json: fuzzer_slots[{i}] is not an object'); continue
    name = s.get('slot','')
    if not slot_re.match(name):
        print(f'fuzz-config.json: fuzzer_slots[{i}].slot "{name}" invalid (regex ^[a-z0-9-]{{1,32}}$)')
    if name in seen:
        print(f'fuzz-config.json: duplicate slot name "{name}"')
    seen.add(name)
    engine = s.get('engine','')
    if engine not in ('libfuzzer','aflpp'):
        print(f'fuzz-config.json: fuzzer_slots[{i}].engine "{engine}" must be libfuzzer or aflpp')
    role = s.get('role')
    if role is not None and role not in ('master','secondary'):
        print(f'fuzz-config.json: fuzzer_slots[{i}].role "{role}" must be master, secondary, or null')
    sched = s.get('afl_power_schedule')
    if sched is not None and sched not in ('explore','exploit','fast','coe','quad','lin','seek','rare'):
        print(f'fuzz-config.json: fuzzer_slots[{i}].afl_power_schedule "{sched}" not a valid AFL++ schedule')
    if mode == 'multi':
        h = s.get('harness','')
        if not h:
            print(f'fuzz-config.json: fuzzer_slots[{i}] ({name!r}) missing required field harness (multi mode)')
        elif h not in declared:
            print(f'fuzz-config.json: fuzzer_slots[{i}] ({name!r}) references undeclared harness "{h}"')

if mode == 'multi':
    hs = d.get('harnesses') or []
    if not isinstance(hs, list) or not hs:
        print('fuzz-config.json: multi mode requires non-empty harnesses[]')
    else:
        slug = re.compile(r'^[a-z0-9][a-z0-9_-]{0,31}$')
        names = set()
        for i, h in enumerate(hs):
            if not isinstance(h, dict):
                print(f'fuzz-config.json: harnesses[{i}] is not an object'); continue
            n = h.get('name','')
            if not slug.match(n or ''):
                print(f'fuzz-config.json: harnesses[{i}].name "{n}" invalid (regex ^[a-z0-9][a-z0-9_-]{{0,31}}$)')
            if n in names:
                print(f'fuzz-config.json: duplicate harness name "{n}"')
            names.add(n)
            if not h.get('entry_function'):
                print(f'fuzz-config.json: harnesses[{i}] ({n!r}) missing entry_function')
PY
)
  if [ -n "$SLOT_ERRS" ]; then
    while IFS= read -r line; do
      [ -z "$line" ] && continue
      err "$line"
    done <<< "$SLOT_ERRS"
  fi
fi

# 3c3. fuzzers.json (live manifest)
if [ -f "$STATE_DIR/fuzzers.json" ]; then
  if [ "$MODE" = "singular" ]; then
    validate_json "$STATE_DIR/fuzzers.json" "fuzzers/v1" "slots" "slots"
  else
    validate_json "$STATE_DIR/fuzzers.json" "fuzzers/v2" "slots" "slots"
  fi
  MAN_ERRS=$(MODE="$MODE" \
             DECLARED="$(declared_env)" \
             MANIFEST_PATH="$STATE_DIR/fuzzers.json" \
             python3 - <<'PY' 2>&1
import json, os
mode = os.environ.get('MODE','singular')
declared = {n for n in os.environ.get('DECLARED','').splitlines() if n.strip()}
required_base = {"slot","engine","binary","pid","pgid","started_at","log_file","pid_file","engine_file","restart_count"}
required = required_base | ({"harness"} if mode == 'multi' else set())
try:
    d = json.load(open(os.environ['MANIFEST_PATH']))
except Exception:
    raise SystemExit(0)
slots = d.get('slots') or []
for i, s in enumerate(slots):
    if not isinstance(s, dict):
        print(f'fuzzers.json: slots[{i}] is not an object'); continue
    missing = required - set(s.keys())
    if missing:
        slot_name = s.get('slot','?')
        print(f'fuzzers.json: slots[{i}] ({slot_name!r}) missing fields {sorted(missing)}')
    if mode == 'multi':
        h = s.get('harness','')
        if h and h not in declared:
            slot_name = s.get('slot','?')
            print(f'fuzzers.json: slots[{i}] ({slot_name!r}) harness "{h}" not declared in fuzz-config.json')
PY
)
  if [ -n "$MAN_ERRS" ]; then
    while IFS= read -r line; do
      [ -z "$line" ] && continue
      err "$line"
    done <<< "$MAN_ERRS"
  fi
fi

# 3d. findings.jsonl - per-line validation, strict id/category/exploitability;
#                     multi mode additionally requires non-empty harnesses[]
if [ -f "$STATE_DIR/findings.jsonl" ]; then
  PY_OUT=$(MODE="$MODE" \
           DECLARED="$(declared_env)" \
           FINDINGS="$STATE_DIR/findings.jsonl" \
           python3 - <<'PY' 2>&1
import json, re, os
mode = os.environ.get('MODE','singular')
declared = {n for n in os.environ.get('DECLARED','').splitlines() if n.strip()}

if mode == 'singular':
    expected_schema = 'finding/v1'
    required = {"schema","id","stack_hash","category","location","exploitability","root_cause","reproducer","first_seen","last_seen","dedup_count"}
    allowed  = required | {"subcategory","sanitizer_report_excerpt","verified_against_build","status","stale_against_build"}
else:
    expected_schema = 'finding/v2'
    required = {"schema","id","stack_hash","category","location","exploitability","root_cause","reproducer","first_seen","last_seen","dedup_count","harnesses"}
    allowed  = required | {"subcategory","sanitizer_report_excerpt","verified_against_build","status","stale_against_build"}

allowed_categories = {"heap-buffer-overflow","heap-use-after-free","stack-buffer-overflow","global-buffer-overflow","stack-overflow","null-deref","assertion-failure","oom","timeout","flaky","harness-artifact"}
allowed_exploitability = {"likely","medium","unlikely","harness-artifact"}
ID_RE = re.compile(r"^f[0-9]{3,}$")

seen_hashes = {}
seen_ids = set()

with open(os.environ['FINDINGS']) as f:
    for ln, line in enumerate(f, 1):
        line = line.strip()
        if not line: continue
        try:
            d = json.loads(line)
        except Exception as e:
            print(f"findings.jsonl line {ln}: parse error: {e}")
            continue
        if d.get("schema") != expected_schema:
            print(f"findings.jsonl line {ln}: wrong schema '{d.get('schema')}' (expected {expected_schema})")
            continue
        keys = set(d.keys())
        missing = required - keys
        unrec = keys - allowed
        if missing: print(f"findings.jsonl line {ln}: missing fields {sorted(missing)}")
        if unrec:   print(f"findings.jsonl line {ln}: unrecognized fields {sorted(unrec)}")

        fid = d.get("id", "")
        if fid and not ID_RE.match(fid):
            print(f"findings.jsonl line {ln}: invalid id format '{fid}' (must match ^f[0-9]{{3,}}$)")
        if fid in seen_ids:
            print(f"findings.jsonl line {ln}: duplicate id '{fid}'")
        seen_ids.add(fid)

        cat = d.get("category", "")
        if cat and cat not in allowed_categories and not cat.startswith("ubsan-"):
            print(f"findings.jsonl line {ln}: invalid category '{cat}'")

        expl = d.get("exploitability", "")
        if expl and expl not in allowed_exploitability:
            print(f"findings.jsonl line {ln}: invalid exploitability '{expl}'")

        sh = d.get("stack_hash", "")
        if sh:
            if sh in seen_hashes and seen_hashes[sh] != fid:
                print(f"findings.jsonl line {ln}: stack_hash '{sh}' already used by {seen_hashes[sh]} (use findings.sh dedup)")
            seen_hashes[sh] = fid

        rep = d.get("reproducer", "")
        status = d.get("status", "")
        if rep and fid:
            if status == "stale":
                expected = f"fuzz/crashes/stale/{fid}/repro.bin"
            else:
                expected = f"fuzz/crashes/known/{fid}/repro.bin"
            if rep != expected:
                print(f"findings.jsonl line {ln}: reproducer '{rep}' should be '{expected}'")
        if rep and not os.path.isfile(rep):
            print(f"findings.jsonl line {ln}: reproducer file does not exist: {rep}")

        if mode == 'multi':
            hs = d.get('harnesses')
            if not isinstance(hs, list) or not hs:
                print(f"findings.jsonl line {ln}: harnesses[] is empty (multi mode requires >=1 source harness)")
            else:
                for h in hs:
                    if h not in declared:
                        print(f"findings.jsonl line {ln}: harnesses[] contains undeclared harness '{h}'")
PY
)
  if [ -n "$PY_OUT" ]; then
    while IFS= read -r line; do
      [ -n "$line" ] && err "$line"
    done <<< "$PY_OUT"
  fi
fi

# 3e. events.jsonl - lightweight check (unchanged across modes)
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
# Schemas are the same across modes (coverage-snapshot/v2, gaps-report/v1,
# concolic-result/v1). Multi mode additionally:
#   - allows an optional top-level `harness` field
#   - requires filename prefix <harness>- before <ts>
#   - requires the `harness` field to match the prefix
if [ -d "$SNAPSHOTS_DIR" ]; then
  # Snapshot files are immutable historical artifacts written by varying
  # agent versions. The schema has expanded over time (e.g. coverage-analyst
  # has added 'notes', 'per_file', 'summary' to gaps-report at various points).
  # Validate them in lenient mode: required fields and wrong-schema are still
  # hard errors, but unknown fields are downgraded to warnings so a single
  # stale snapshot can't wedge the campaign into a `corrupted` state.
  for f in "$SNAPSHOTS_DIR"/coverage-*.json; do
    [ -f "$f" ] || continue
    validate_json "$f" \
      "coverage-snapshot/v2" \
      "timestamp,engine,fuzzer_stats,coverage,instrumentation" \
      "timestamp,engine,fuzzer_stats,coverage,instrumentation,previous_snapshot_ts,new_crashes_since_previous,top_unreached_functions,harness" \
      lenient
  done
  for f in "$SNAPSHOTS_DIR"/gaps-*.json; do
    [ -f "$f" ] || continue
    validate_json "$f" \
      "gaps-report/v1" \
      "timestamp,snapshot_file,gaps" \
      "timestamp,snapshot_file,gaps,harness" \
      lenient
  done
  for f in "$SNAPSHOTS_DIR"/concolic-*.json; do
    [ -f "$f" ] || continue
    validate_json "$f" \
      "concolic-result/v1" \
      "timestamp,gaps_targeted,seeds_used,inputs_generated,inputs_validated,inputs_promoted_to_corpus" \
      "timestamp,gaps_targeted,seeds_used,inputs_generated,inputs_validated,inputs_promoted_to_corpus,symcc_timeouts,symcc_errors,harness" \
      lenient
  done

  if [ "$MODE" = "multi" ]; then
    SNAP_ERRS=$(SNAPS_DIR="$SNAPSHOTS_DIR" \
                DECLARED="$(declared_env)" \
                python3 - <<'PY' 2>&1
import json, os, re, glob
declared = {n for n in os.environ['DECLARED'].splitlines() if n.strip()}
patterns = [
    ('coverage', re.compile(r'^coverage-([a-z0-9][a-z0-9_-]{0,31})-(\d+)\.json$')),
    ('gaps',     re.compile(r'^gaps-([a-z0-9][a-z0-9_-]{0,31})-(\d+)\.json$')),
    ('concolic', re.compile(r'^concolic-([a-z0-9][a-z0-9_-]{0,31})-(\d+)\.json$')),
]
singular_re = re.compile(r'^(coverage|gaps|concolic)-\d+\.json$')
for path in sorted(glob.glob(os.path.join(os.environ['SNAPS_DIR'], '*.json'))):
    base = os.path.basename(path)
    if base.startswith('plan-') or base.startswith('delta-'):
        continue
    matched = False
    for kind, pat in patterns:
        m = pat.match(base)
        if not m: continue
        matched = True
        harness = m.group(1)
        if harness not in declared:
            print(f'snapshots/{base}: filename prefix references undeclared harness "{harness}"')
            break
        try:
            d = json.load(open(path))
        except Exception:
            break
        h_field = d.get('harness')
        if h_field is None:
            print(f'snapshots/{base}: multi-mode snapshot must carry top-level "harness" field')
        elif h_field != harness:
            print(f'snapshots/{base}: harness field "{h_field}" disagrees with filename prefix "{harness}"')
        break
    if not matched and singular_re.match(base):
        print(f'snapshots/{base}: singular-mode filename in multi mode (the upgrade should have renamed it to include a harness prefix)')
PY
)
    if [ -n "$SNAP_ERRS" ]; then
      while IFS= read -r line; do
        [ -z "$line" ] && continue
        err "$line"
      done <<< "$SNAP_ERRS"
    fi
  fi
fi

#------------------------------------------------------------------------------
# Step 4: Cross-reference checks
#------------------------------------------------------------------------------

# Harness binary executable
if [ "$MODE" = "singular" ] && [ -f "$STATE_DIR/harness-built.json" ]; then
  HBIN=$(python3 -c "
import json
try: print(json.load(open('$STATE_DIR/harness-built.json')).get('harness_binary', ''))
except: pass" 2>/dev/null)
  if [ -n "$HBIN" ] && [ ! -x "$HBIN" ]; then
    warn "harness binary referenced but not executable: $HBIN"
  fi
fi

if [ "$MODE" = "multi" ] && [ -f "$STATE_DIR/harnesses.json" ]; then
  BIN_REPORT=$(HS_PATH="$STATE_DIR/harnesses.json" python3 - <<'PY' 2>&1
import json, os
try:
    doc = json.load(open(os.environ['HS_PATH']))
except Exception:
    raise SystemExit(0)
for h in doc.get('harnesses', []):
    name = h.get('name','?')
    b = h.get('harness_binary','')
    if b and not (os.path.isfile(b) and os.access(b, os.X_OK)):
        print(f'harness "{name}" binary not executable: {b}')
PY
)
  if [ -n "$BIN_REPORT" ]; then
    while IFS= read -r line; do
      [ -z "$line" ] && continue
      warn "$line"
    done <<< "$BIN_REPORT"
  fi
fi

# crashes/known/<id>/ subdirs should each have a repro.bin (and harnesses.txt in multi mode)
if [ -d "$CRASHES_DIR/known" ]; then
  for d in "$CRASHES_DIR/known"/*/; do
    [ -d "$d" ] || continue
    if [ ! -f "$d/repro.bin" ]; then
      err "missing canonical reproducer: $d/repro.bin"
    fi
    if [ "$MODE" = "multi" ] && [ ! -f "${d%/}/harnesses.txt" ]; then
      err "multi mode: missing ${d%/}/harnesses.txt (one harness name per line, must mirror finding.harnesses[])"
    fi
  done
fi

# Multi mode: crashes/new/* filenames must be <harness>__<sha256>.bin with a known harness prefix
if [ "$MODE" = "multi" ] && [ -d "$CRASHES_DIR/new" ]; then
  for f in "$CRASHES_DIR/new"/*; do
    [ -f "$f" ] || continue
    base=$(basename "$f")
    if [[ ! "$base" =~ ^([a-z0-9][a-z0-9_-]{0,31})__[0-9a-f]{16,64}\.bin$ ]]; then
      err "crashes/new/$base: multi-mode filename must match <harness>__<hash>.bin"
    else
      h="${BASH_REMATCH[1]}"
      if ! is_known_harness "$h"; then
        err "crashes/new/$base: prefix references undeclared harness '$h'"
      fi
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
