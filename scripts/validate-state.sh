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

EXPECTED_SCHEMA_VERSION="v10"

ERRORS=()
WARNINGS=()

err()  { ERRORS+=("$1"); }
warn() { WARNINGS+=("$1"); }

#------------------------------------------------------------------------------
# Multi-harness mode detection (schema v10)
#
# Multi mode is active iff fuzz-config.json contains a non-empty harnesses[]
# array of objects with a `name` field. All schema versions and filesystem
# checks below dispatch on this single signal.
#------------------------------------------------------------------------------
MODE="singular"
DECLARED_HARNESSES=()
CHECKS="$SCRIPT_DIR/_lib/state_checks.py"
if [ -f "$STATE_DIR/fuzz-config.json" ]; then
  NAMES=$(CFG="$STATE_DIR/fuzz-config.json" python3 "$CHECKS" config-harness-names 2>/dev/null)
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

# FINDINGS-REPORT-<target>.md is REWRITABLE; warn if none exists (not an error)
if [ -d "$STATE_DIR" ] && ! ls "$STATE_DIR"/FINDINGS-REPORT-*.md >/dev/null 2>&1; then
  warn "no FINDINGS-REPORT-*.md in $STATE_DIR (run /cc-fuzzer:report to generate)"
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
  result=$(FILE="$file" SCHEMA="$expected_schema" REQUIRED="$required" \
           ALLOWED="$allowed" LENIENT="$mode" \
           python3 "$CHECKS" validate-json 2>&1)

  case "$result" in
    OK) ;;
    WARN:*) warn "$file: ${result#WARN: }" ;;
    *) err "$file: $result" ;;
  esac
}

# Field sets shared by singular v5 and multi v6/v7 (v6 adds `name`, v7 adds nix backend fields)
HARNESS_BUILT_REQUIRED_V5="harness_source,harness_binary,build_script,entry_function,target_source,target_source_hash,build_command_hash,built_at,coverage_tracking,cmplog_enabled,fuzzing_mode"
HARNESS_BUILT_ALLOWED_V5="harness_source,harness_binary,coverage_binary,coverage_dso,verify_binary,coverage_tracking,coverage_disabled_reason,cmplog_binary,cmplog_enabled,cmplog_disabled_reason,symcc_binary,mutator_source,build_script,dict_files,entry_function,input_encoding,sanitizers,fuzzing_mode,target_source,target_source_hash,build_command_hash,harness_attempts,built_at,build_command,oracle"
HARNESS_BUILT_REQUIRED_V6="name,${HARNESS_BUILT_REQUIRED_V5}"
HARNESS_BUILT_ALLOWED_V6="name,${HARNESS_BUILT_ALLOWED_V5}"
HARNESS_BUILT_REQUIRED_V7="name,build_backend,${HARNESS_BUILT_REQUIRED_V5}"
HARNESS_BUILT_ALLOWED_V7="build_backend,build_backend_decided_at,build_backend_decided_by,nix,${HARNESS_BUILT_ALLOWED_V6}"

# 3a. harness-built.json
# Singular mode: this is the canonical record (harness-built/v5).
# Multi mode:    this is a read-only mirror of harnesses.json[0] (harness-built/v7).
if [ -f "$STATE_DIR/harness-built.json" ]; then
  if [ "$MODE" = "singular" ]; then
    validate_json "$STATE_DIR/harness-built.json" "harness-built/v5" \
      "$HARNESS_BUILT_REQUIRED_V5" "$HARNESS_BUILT_ALLOWED_V5"
  else
    validate_json "$STATE_DIR/harness-built.json" "harness-built/v7" \
      "$HARNESS_BUILT_REQUIRED_V7" "$HARNESS_BUILT_ALLOWED_V7"
  fi

  # Coverage/cmplog/fuzzing_mode cross-checks apply identically to both schemas.
  HB="$STATE_DIR/harness-built.json"
  TRACK=$(python3 "$CHECKS" field "$HB" coverage_tracking False 2>/dev/null)
  COV_BIN=$(python3 "$CHECKS" field "$HB" coverage_binary 2>/dev/null)
  if [ "$TRACK" = "True" ]; then
    if [ -z "$COV_BIN" ]; then
      err "harness-built.json: coverage_tracking=true but coverage_binary is null/missing"
    elif [ ! -x "$COV_BIN" ]; then
      err "harness-built.json: coverage_binary not executable: $COV_BIN"
    fi
  else
    REASON=$(python3 "$CHECKS" field "$HB" coverage_disabled_reason 2>/dev/null)
    if [ -z "$REASON" ]; then
      warn "harness-built.json: coverage_tracking=false but no coverage_disabled_reason set. Run migrate-state.sh to backfill, or rebuild with /cc-fuzzer:campaign --reset to enable coverage."
    fi
  fi

  CMPLOG_TRACK=$(python3 "$CHECKS" field "$HB" cmplog_enabled False 2>/dev/null)
  CMPLOG_BIN=$(python3 "$CHECKS" field "$HB" cmplog_binary 2>/dev/null)
  if [ "$CMPLOG_TRACK" = "True" ]; then
    if [ -z "$CMPLOG_BIN" ]; then
      err "harness-built.json: cmplog_enabled=true but cmplog_binary is null/missing"
    elif [ ! -x "$CMPLOG_BIN" ]; then
      warn "harness-built.json: cmplog_binary not executable: $CMPLOG_BIN (run-fuzzer.sh will continue without -c)"
    fi
  else
    CMPLOG_REASON=$(python3 "$CHECKS" field "$HB" cmplog_disabled_reason 2>/dev/null)
    if [ -z "$CMPLOG_REASON" ]; then
      warn "harness-built.json: cmplog_enabled=false but no cmplog_disabled_reason set. Run migrate-state.sh to backfill."
    fi
  fi

  FMODE=$(python3 "$CHECKS" field "$HB" fuzzing_mode 2>/dev/null)
  case "$FMODE" in
    in_process|process_based) ;;
    "") err "harness-built.json: fuzzing_mode missing (run migrate-state.sh to backfill)" ;;
    *) err "harness-built.json: invalid fuzzing_mode '$FMODE' (expected in_process or process_based)" ;;
  esac

  HASH_CHECK=$(python3 "$CHECKS" hash-check "$HB" 2>/dev/null)
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
              REQUIRED_V6="$HARNESS_BUILT_REQUIRED_V7" \
              ALLOWED_V6="$HARNESS_BUILT_ALLOWED_V7" \
              EXPECTED_HARNESS_SCHEMA="harness-built/v7" \
              python3 "$CHECKS" harnesses-mirror 2>&1)
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
      "now,tick_number,fuzzer,fuzzers,harness,coverage,fuzzer_stats,findings,gaps,recommendation,last_report_at,multi_fuzzer,tick_coverage,consult_state,yolo_state"
  else
    validate_json "$STATE_DIR/current.json" "cc-fuzzer-current/v2" \
      "now,tick_number,active_harness,harnesses,fuzzers,findings,recommendation" \
      "now,tick_number,active_harness,harnesses,fuzzers,findings,recommendation,last_report_at,multi_fuzzer,coverage,fuzzer_stats,gaps,fuzzer,harness,tick_coverage,consult_state,yolo_state"

    # active_harness + recommendation.harness must reference declared harnesses
    CUR="$STATE_DIR/current.json"
    ACTIVE=$(python3 "$CHECKS" field "$CUR" active_harness 2>/dev/null)
    if [ -n "$ACTIVE" ] && ! is_known_harness "$ACTIVE"; then
      err "current.json: active_harness '$ACTIVE' is not a declared harness"
    fi
    REC_H=$(python3 "$CHECKS" field "$CUR" recommendation.harness 2>/dev/null)
    if [ -n "$REC_H" ] && ! is_known_harness "$REC_H"; then
      err "current.json: recommendation.harness '$REC_H' is not a declared harness"
    fi
  fi

  BRANCH=$(python3 "$CHECKS" field "$STATE_DIR/current.json" recommendation.branch 2>/dev/null)
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
      "fuzz_forks" "fuzz_forks,fuzzer_slots,tick,cve,yolo,code_review"
  else
    validate_json "$STATE_DIR/fuzz-config.json" "fuzz-config/v3" \
      "fuzz_forks,harnesses,fuzzer_slots" "fuzz_forks,harnesses,fuzzer_slots,tick,cve,yolo,code_review"
  fi

  SLOT_ERRS=$(MODE="$MODE" \
              DECLARED="$(declared_env)" \
              CFG="$STATE_DIR/fuzz-config.json" \
              python3 "$CHECKS" slots 2>&1)
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
             python3 "$CHECKS" fuzzers-manifest 2>&1)
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
           python3 "$CHECKS" findings 2>&1)
  if [ -n "$PY_OUT" ]; then
    while IFS= read -r line; do
      [ -n "$line" ] && err "$line"
    done <<< "$PY_OUT"
  fi
fi

# 3d3. harness-corrections.jsonl - v0.18 triager → harness-writer feedback.
# Lightweight per-line schema check.
if [ -f "$STATE_DIR/harness-corrections.jsonl" ]; then
  HC_OUT=$(HCS="$STATE_DIR/harness-corrections.jsonl" python3 "$CHECKS" jsonl-corrections 2>&1)
  if [ -n "$HC_OUT" ]; then
    while IFS= read -r line; do
      [ -n "$line" ] && err "$line"
    done <<< "$HC_OUT"
  fi
fi

# 3d2. dropped_crashes.jsonl - v0.18 transparency log. Lightweight: every line
# must be a dropped-crash/v1 record with required fields and a valid stage.
if [ -f "$STATE_DIR/dropped_crashes.jsonl" ]; then
  DROP_OUT=$(DROPS="$STATE_DIR/dropped_crashes.jsonl" python3 "$CHECKS" jsonl-dropped 2>&1)
  if [ -n "$DROP_OUT" ]; then
    while IFS= read -r line; do
      [ -n "$line" ] && err "$line"
    done <<< "$DROP_OUT"
  fi
fi

# 3e. events.jsonl - lightweight check (unchanged across modes)
if [ -f "$STATE_DIR/events.jsonl" ]; then
  PY_OUT=$(EVENTS="$STATE_DIR/events.jsonl" python3 "$CHECKS" jsonl-events 2>&1)
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
  # tick-coverage roundup (v0.18): one aggregate per tick across all harnesses.
  # Lenient for the same reason — the schema may grow before downstream code
  # catches up.
  for f in "$SNAPSHOTS_DIR"/tick-coverage-*.json; do
    [ -f "$f" ] || continue
    validate_json "$f" \
      "tick-coverage/v1" \
      "timestamp,mode,harnesses,overall" \
      "timestamp,mode,harnesses,overall,stale_harnesses,stale_threshold_seconds" \
      lenient
  done
  # Planner-consult artifacts (v0.18): the briefing the orchestrator hands to
  # campaign-planner consult mode, and the verdict the planner returns.
  for f in "$SNAPSHOTS_DIR"/tick-briefing-*.json; do
    [ -f "$f" ] || continue
    validate_json "$f" \
      "tick-briefing/v1" \
      "ts,tick_number,trigger,coverage,active_gaps,sonnet_recommendation" \
      "ts,tick_number,trigger,last_consult_ts,last_consult_tick,ticks_since_last_consult,coverage,active_gaps,dispatched_since_last_consult,findings_since_last_consult,sonnet_recommendation,toolbox,ceiling" \
      lenient
  done
  # Ceiling-probe artifacts (self_loop plateau/structural-ceiling verdict). The
  # runtime copy lives in current.json.yolo_state.evaluation.ceiling_probe; this
  # snapshot is written by ceiling-probe.sh for audit + the pre-halt consult.
  for f in "$SNAPSHOTS_DIR"/ceiling-probe-*.json; do
    [ -f "$f" ] || continue
    validate_json "$f" \
      "ceiling-probe/v1" \
      "ladder_stage,is_real_ceiling,structural_candidates,engine_fit,summary" \
      "timestamp,harness,plateau_active,ladder_stage,is_real_ceiling,ticks_since_gain,plateau_escalate_ticks,structural_candidates,untried_candidates,recommended_structural,attempted_since_plateau,harness_writer_dispatches_since_plateau,consult_since_plateau,engine_fit,dead_count,summary" \
      lenient
  done
  for f in "$SNAPSHOTS_DIR"/planner-consult-*.json; do
    [ -f "$f" ] || continue
    validate_json "$f" \
      "planner-consult/v1" \
      "ts,verdict,reason" \
      "ts,tick_number,briefing_file,verdict,reason,tactic,rationale" \
      lenient
  done
  # CVE intelligence artifacts (v0.18 WS-E). One context file per refresh of
  # the cache; agents read the latest. Lenient on extra fields.
  for f in "$SNAPSHOTS_DIR"/cve-context-*.json; do
    [ -f "$f" ] || continue
    validate_json "$f" \
      "cve-context/v1" \
      "ts,target,nvd_query,fetch_stats,hotspots,pattern_frequency,cves" \
      "ts,target,nvd_query,fetch_stats,hotspots,pattern_frequency,patch_idioms,time_since_last_high_cve_days,cves" \
      lenient
  done
  # Code-review artifacts (v0.18 WS-H). Prescan is Tier-1 (deterministic);
  # the full review is the Sonnet+optional-Opus output. Both lenient.
  for f in "$SNAPSHOTS_DIR"/code-review-prescan-*.json; do
    [ -f "$f" ] || continue
    validate_json "$f" \
      "code-review-prescan/v1" \
      "ts,target_root,scope,top_candidates" \
      "ts,target_root,scope,top_candidates,full_inventory_summary" \
      lenient
  done
  for f in "$SNAPSHOTS_DIR"/code-review-*.json; do
    case "$(basename "$f")" in code-review-prescan-*.json) continue ;; esac
    [ -f "$f" ] || continue
    validate_json "$f" \
      "code-review/v1" \
      "ts,target,scope,tiers_run,findings,focus_areas" \
      "ts,target,scope,tiers_run,findings,focus_areas,model_costs" \
      lenient
  done

  if [ "$MODE" = "multi" ]; then
    SNAP_ERRS=$(SNAPS_DIR="$SNAPSHOTS_DIR" \
                DECLARED="$(declared_env)" \
                python3 "$CHECKS" snapshot-multi 2>&1)
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
  HBIN=$(python3 "$CHECKS" field "$STATE_DIR/harness-built.json" harness_binary 2>/dev/null)
  if [ -n "$HBIN" ] && [ ! -x "$HBIN" ]; then
    warn "harness binary referenced but not executable: $HBIN"
  fi
fi

if [ "$MODE" = "multi" ] && [ -f "$STATE_DIR/harnesses.json" ]; then
  BIN_REPORT=$(HS_PATH="$STATE_DIR/harnesses.json" python3 "$CHECKS" harness-bins 2>&1)
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
# Nix environment issues (schema v10)
# nix-environment-issues.json is written by nix-env-reconcile.sh at session
# start. severity=error issues on nix-committed harnesses are hard errors here
# so the orchestrator's preflight gate also catches them during validate.
#------------------------------------------------------------------------------
NIX_ENV_ISSUES="$STATE_DIR/nix-environment-issues.json"
if [ -f "$NIX_ENV_ISSUES" ]; then
  while IFS= read -r line; do
    [ -z "$line" ] && continue
    case "$line" in
      ERR:*)  err  "${line#ERR: }" ;;
      WARN:*) warn "${line#WARN: }" ;;
    esac
  done < <(NIX_ENV_ISSUES="$NIX_ENV_ISSUES" python3 - <<'PY'
import json, os, sys

path = os.environ["NIX_ENV_ISSUES"]
try:
    doc = json.load(open(path))
except Exception:
    sys.exit(0)
issues = doc.get("issues") or []
for iss in issues:
    if not isinstance(iss, dict):
        continue
    sev = iss.get("severity", "warning")
    code = iss.get("code", "?")
    summary = iss.get("summary", "")
    hint = (iss.get("remediation") or {}).get("human_message", "")
    msg = f"nix-environment ({code}): {summary}"
    if hint:
        msg += f" — {hint}"
    print(f"ERR: {msg}" if sev == "error" else f"WARN: {msg}")
PY
)
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
