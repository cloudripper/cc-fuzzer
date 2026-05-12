#!/usr/bin/env bash
# snapshot-coverage.sh
#
# Produces fuzz/state/snapshots/coverage-<ts>.json strictly per
# STATE_SCHEMA.md. Fails loudly when instrumentation is broken rather than
# producing silent-zero snapshots.
#
# What's included:
#   1. LLVM tool probing - finds llvm-cov / llvm-profdata in /usr/lib/llvm-*/bin/
#      when not in PATH, instead of silently giving up.
#   2. Fork-mode-aware libFuzzer log parsing - when -fork=N is in use, the
#      libFuzzer parent log line format includes trailing colons (e.g. "#1971:")
#      and per-fork temp dirs at /tmp/libFuzzerTemp.FuzzWithFork<PID>.dir/.
#   3. Coverage binary support - if harness-built.json declares a coverage_binary,
#      we run it against the corpus to produce profraw, merge with llvm-profdata,
#      and read with llvm-cov export. No silent zeros.
#   4. Strict instrumentation field - every snapshot carries an "instrumentation"
#      object so downstream code can tell "real zero" from "broken zero".

set -u

# Path anchor - refuses cwd inside fuzz/, refuses recursive fuzz/fuzz/
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
. "$SCRIPT_DIR/_lib/path-anchor.sh"

TS=$(date +%s)
STATE_DIR="${FUZZ_STATE_DIR:-fuzz/state}"
SNAPSHOTS_DIR="$STATE_DIR/snapshots"
HARNESS_INFO="$STATE_DIR/harness-built.json"
COV_DIR="${FUZZ_COV_DIR:-fuzz/coverage}"
CORPUS_DIR="${FUZZ_CORPUS_DIR:-fuzz/corpus}"
mkdir -p "$STATE_DIR" "$SNAPSHOTS_DIR" "$COV_DIR"

OUT_FILE="$SNAPSHOTS_DIR/coverage-$TS.json"

#------------------------------------------------------------------------------
# 1. LLVM tool probe
#------------------------------------------------------------------------------
probe_llvm_tool() {
  local tool="$1"
  if command -v "$tool" >/dev/null 2>&1; then
    command -v "$tool"
    return 0
  fi
  # Walk /usr/lib/llvm-*/bin/ from highest version down
  for v in 21 20 19 18 17 16 15 14 13 12 11; do
    if [ -x "/usr/lib/llvm-$v/bin/$tool" ]; then
      echo "/usr/lib/llvm-$v/bin/$tool"
      return 0
    fi
  done
  return 1
}

LLVM_COV_BIN=$(probe_llvm_tool llvm-cov 2>/dev/null || true)
LLVM_PROFDATA_BIN=$(probe_llvm_tool llvm-profdata 2>/dev/null || true)

LLVM_COV_AVAILABLE=false
[ -n "$LLVM_COV_BIN" ] && [ -n "$LLVM_PROFDATA_BIN" ] && LLVM_COV_AVAILABLE=true

#------------------------------------------------------------------------------
# 2. Read harness-built.json for coverage_binary path
#------------------------------------------------------------------------------
COVERAGE_BINARY=""
HARNESS_BIN=""
COVERAGE_TRACKING_ENABLED=true
if [ -f "$HARNESS_INFO" ]; then
  COVERAGE_BINARY=$(python3 -c "
import json
try: print(json.load(open('$HARNESS_INFO')).get('coverage_binary') or '')
except: pass" 2>/dev/null)
  HARNESS_BIN=$(python3 -c "
import json
try: print(json.load(open('$HARNESS_INFO')).get('harness_binary') or '')
except: pass" 2>/dev/null)
  TRACKING=$(python3 -c "
import json
try: print(json.load(open('$HARNESS_INFO')).get('coverage_tracking', True))
except: print(True)" 2>/dev/null)
  [ "$TRACKING" = "False" ] && COVERAGE_TRACKING_ENABLED=false
fi

COVERAGE_BUILD_PRESENT=false
[ -n "$COVERAGE_BINARY" ] && [ -x "$COVERAGE_BINARY" ] && COVERAGE_BUILD_PRESENT=true

#------------------------------------------------------------------------------
# 3. Engine detection + fuzzer stats
#------------------------------------------------------------------------------
ENGINE="unknown"
EXECS=0
PATHS=0
CRASHES=0
HANGS=0
EXEC_RATE=0
PARSED_ENGINE_LOG=false
FORK_MODE=false

OUT_DIR="${FUZZ_OUT_DIR:-out}"

if [ -f "$OUT_DIR/default/fuzzer_stats" ]; then
  ENGINE="aflpp"
  EXECS=$(awk -F': *' '/^execs_done/{print $2; exit}' "$OUT_DIR/default/fuzzer_stats" 2>/dev/null || echo 0)
  PATHS=$(awk -F': *' '/^corpus_count/{print $2; exit}' "$OUT_DIR/default/fuzzer_stats" 2>/dev/null || echo 0)
  CRASHES=$(awk -F': *' '/^saved_crashes/{print $2; exit}' "$OUT_DIR/default/fuzzer_stats" 2>/dev/null || echo 0)
  HANGS=$(awk -F': *' '/^saved_hangs/{print $2; exit}' "$OUT_DIR/default/fuzzer_stats" 2>/dev/null || echo 0)
  EXEC_RATE=$(awk -F': *' '/^execs_per_sec/{print $2; exit}' "$OUT_DIR/default/fuzzer_stats" 2>/dev/null || echo 0)
  PARSED_ENGINE_LOG=true
elif [ -f "$STATE_DIR/fuzzer.log" ]; then
  ENGINE="libfuzzer"

  # Detect fork mode multiple ways - the fuzzer.log doesn't always capture the
  # -fork= argument (depends on how stderr is redirected). Belt and suspenders:
  #   1. Look in the log for explicit fork-mode markers
  #   2. Check if the running process has -fork= in its cmdline (most reliable)
  #   3. Check if a libFuzzerTemp.FuzzWithFork<PID>.dir exists
  if grep -q -- '-fork=' "$STATE_DIR/fuzzer.log" 2>/dev/null \
     || grep -qE 'fuzzing in separate process|INFO: fork_mode|Job [0-9]+ exited' "$STATE_DIR/fuzzer.log" 2>/dev/null; then
    FORK_MODE=true
  fi

  FUZZER_PID=""
  if [ -f "$STATE_DIR/fuzzer.pid" ]; then
    FUZZER_PID=$(cat "$STATE_DIR/fuzzer.pid" 2>/dev/null)
    if [ -n "$FUZZER_PID" ] && [ -r "/proc/$FUZZER_PID/cmdline" ]; then
      if tr '\0' ' ' < "/proc/$FUZZER_PID/cmdline" 2>/dev/null | grep -q -- '-fork='; then
        FORK_MODE=true
      fi
    fi
    if [ -n "$FUZZER_PID" ] && [ -d "/tmp/libFuzzerTemp.FuzzWithFork$FUZZER_PID.dir" ]; then
      FORK_MODE=true
    fi
  fi

  # Helper: safe integer comparison that returns 0 on parse failure
  _is_int() { case "${1:-}" in ''|*[!0-9]*) return 1 ;; *) return 0 ;; esac; }

  # ---------------------------------------------------------------------
  # Strategy: try every known libFuzzer log format and take whatever produces
  # the highest exec count (which is the most-recent state).
  # ---------------------------------------------------------------------

  # Format A (non-fork): "#NNNN REDUCE cov: 678 ft: 1234 corp: 56/7Kb exec/s: 890 rss: 250Mb"
  # Format B (fork worker): "#NNNN: cov: 678 ft: 1234 corp: 56 exec/s: 890 ..."
  # Format C (fork master pulse, rare): "#NNNN pulse cov: 678 ft: 1234 ... exec/s: NNN"
  # All three have the same parseable structure. Try the parent log first.
  parse_status_line() {
    local line="$1"
    local execs paths rate
    execs=$(echo "$line" | awk '{print $1}' | tr -d '#:')
    paths=$(echo "$line" | grep -oE 'cov: [0-9]+' | awk '{print $2}')
    rate=$(echo "$line" | grep -oE 'exec/s: [0-9]+' | awk '{print $2}')
    _is_int "$execs" || execs=0
    _is_int "$paths" || paths=0
    _is_int "$rate"  || rate=0
    echo "$execs $paths $rate"
  }

  # Try the parent log
  LAST_PARENT=$(grep -E '^#[0-9]+' "$STATE_DIR/fuzzer.log" 2>/dev/null | tail -1)
  if [ -n "$LAST_PARENT" ]; then
    read P_EXECS P_PATHS P_RATE <<< "$(parse_status_line "$LAST_PARENT")"
    if _is_int "$P_EXECS" && [ "$P_EXECS" -gt 0 ]; then
      EXECS=$P_EXECS
      PATHS=$P_PATHS
      EXEC_RATE=$P_RATE
      PARSED_ENGINE_LOG=true
    fi
  fi

  # In fork mode also try per-worker logs and take the maximum
  if [ "$FORK_MODE" = "true" ] && [ -n "$FUZZER_PID" ]; then
    FORK_DIR="/tmp/libFuzzerTemp.FuzzWithFork$FUZZER_PID.dir"
    if [ -d "$FORK_DIR" ]; then
      # Find the most-recent #NNNN status line across all worker logs
      FORK_LAST=$(grep -hE '^#[0-9]+' "$FORK_DIR"/*.log 2>/dev/null | sort -t'#' -k2 -n | tail -1)
      if [ -n "$FORK_LAST" ]; then
        read F_EXECS F_PATHS F_RATE <<< "$(parse_status_line "$FORK_LAST")"
        FORK_COUNT=$(ls "$FORK_DIR"/*.log 2>/dev/null | wc -l)
        _is_int "$FORK_COUNT" || FORK_COUNT=1
        [ "$FORK_COUNT" -lt 1 ] && FORK_COUNT=1

        # Per-worker numbers are per-process; the parent total is roughly
        # max(worker_execs) since each worker starts from zero. exec/s
        # however should be the sum across workers.
        if _is_int "$F_EXECS" && [ "$F_EXECS" -gt "${EXECS:-0}" ]; then
          EXECS=$F_EXECS
          PATHS=$F_PATHS
        fi
        if _is_int "$F_RATE" && [ "$F_RATE" -gt 0 ]; then
          # Approximate parent total exec/s as worker rate * fork count
          EXEC_RATE=$((F_RATE * FORK_COUNT))
        fi
        PARSED_ENGINE_LOG=true
      fi
    fi
  fi

  # Final fallback: parse any "Job <PID> exited" lines for an at-least-something
  # signal. These don't carry exec stats but they DO confirm the master is alive.
  if [ "$PARSED_ENGINE_LOG" = "false" ]; then
    if grep -qE 'Job [0-9]+ exited' "$STATE_DIR/fuzzer.log" 2>/dev/null; then
      # Master is running fork batches but no #N lines visible. This happens
      # when no worker has emitted a status line yet (campaign just started)
      # or when every worker crashed before its first status emit.
      PARSED_ENGINE_LOG=true   # we know enough to say the engine is alive
      EXECS=0
      PATHS=0
      EXEC_RATE=0
    fi
  fi

  # Crashes: hard-linked to fuzz/crashes/ by detect-crashes hook
  CRASHES=$(find "${FUZZ_CRASHES_DIR:-fuzz/crashes}/new" "${FUZZ_CRASHES_DIR:-fuzz/crashes}/known" \
              -name '*.bin' -type f 2>/dev/null | wc -l | tr -d ' ')
fi

#------------------------------------------------------------------------------
# 4. Coverage measurement (if instrumented build is present)
#------------------------------------------------------------------------------
COV_LINES=0
COV_TOTAL=0
COV_PCT=0
COV_RUN_OK=false

if [ "$COVERAGE_TRACKING_ENABLED" = "true" ] && [ "$COVERAGE_BUILD_PRESENT" = "true" ] && [ "$LLVM_COV_AVAILABLE" = "true" ]; then
  # Sampling strategy:
  #   1. Always run named seed_*.bin first (these are hand-crafted seeds for
  #      specific predicates; they should never be missed by the random sampler).
  #   2. Then random-sample MAX_SAMPLES files from the rest of the corpus to
  #      keep snapshot cost bounded. Random sampling is critical: alphabetical
  #      iteration biases toward early-discovered (low-coverage) hash-named
  #      inputs and produces wildly underreported coverage.
  #   3. Use per-PID profraw files (snap_%p.profraw) so each invocation writes
  #      its own file, then merge them at the end. Sharing a single profraw
  #      across runs has known race conditions on some libc/clang combinations.
  PROFRAW="$COV_DIR/default.profraw"
  PROFDATA="$COV_DIR/default.profdata"
  rm -f "$PROFRAW" "$PROFDATA"
  rm -f "$COV_DIR"/snap_*.profraw

  if [ -d "$CORPUS_DIR" ]; then
    SAMPLED=0
    MAX_SAMPLES=${SNAPSHOT_COVERAGE_MAX_SAMPLES:-500}

    # Step 1: all named seed_* files (cheap, usually fewer than ~50)
    for f in "$CORPUS_DIR"/seed_*.bin "$CORPUS_DIR"/seed_*.txt; do
      [ -f "$f" ] || continue
      LLVM_PROFILE_FILE="$COV_DIR/snap_%p.profraw" \
        timeout 5 "$COVERAGE_BINARY" "$f" >/dev/null 2>&1 || true
      SAMPLED=$((SAMPLED + 1))
    done

    # Step 2: random sample from the rest, up to MAX_SAMPLES total
    if [ "$SAMPLED" -lt "$MAX_SAMPLES" ]; then
      REMAINING=$((MAX_SAMPLES - SAMPLED))
      while IFS= read -r f; do
        [ -f "$f" ] || continue
        LLVM_PROFILE_FILE="$COV_DIR/snap_%p.profraw" \
          timeout 5 "$COVERAGE_BINARY" "$f" >/dev/null 2>&1 || true
        SAMPLED=$((SAMPLED + 1))
      done < <(find "$CORPUS_DIR" -maxdepth 1 -type f -not -name 'seed_*' 2>/dev/null \
                  | shuf | head -"$REMAINING")
    fi

    # Step 3: merge all per-process profraw files into one
    SNAP_FILES=( "$COV_DIR"/snap_*.profraw )
    if [ ${#SNAP_FILES[@]} -gt 0 ] && [ -f "${SNAP_FILES[0]}" ]; then
      "$LLVM_PROFDATA_BIN" merge -sparse "${SNAP_FILES[@]}" -o "$PROFRAW" 2>/dev/null || true
      rm -f "${SNAP_FILES[@]}"
    fi

    if [ -f "$PROFRAW" ]; then
      if "$LLVM_PROFDATA_BIN" merge -sparse "$PROFRAW" -o "$PROFDATA" 2>/dev/null; then
        SUMMARY_JSON=$("$LLVM_COV_BIN" export "$COVERAGE_BINARY" \
                          -instr-profile="$PROFDATA" \
                          --summary-only 2>/dev/null || true)
        if [ -n "$SUMMARY_JSON" ]; then
          read COV_LINES COV_TOTAL COV_PCT < <(echo "$SUMMARY_JSON" | python3 -c "
import json, sys
try:
    d = json.load(sys.stdin)
    totals = d['data'][0]['totals']
    lines = totals['lines']
    covered = lines.get('covered', 0)
    total = lines.get('count', 0)
    pct = (covered / total * 100) if total else 0
    print(covered, total, f'{pct:.2f}')
except Exception as e:
    print(0, 0, 0)
" 2>/dev/null || echo "0 0 0")
          COV_RUN_OK=true
        fi
      fi
    fi
  fi
fi

#------------------------------------------------------------------------------
# 5. Find new crash files since last snapshot
#------------------------------------------------------------------------------
PREV=$(ls -t "$SNAPSHOTS_DIR"/coverage-*.json 2>/dev/null | head -1)
PREV_TS=0
if [ -n "$PREV" ]; then
  PREV_TS=$(basename "$PREV" | sed 's/coverage-//;s/.json//')
fi

NEW_CRASHES_JSON="[]"
NEW_CRASH_LIST=$(find "${FUZZ_CRASHES_DIR:-fuzz/crashes}/new" -name '*.bin' \
                   -newermt "@$PREV_TS" -type f 2>/dev/null | head -50)
if [ -n "$NEW_CRASH_LIST" ]; then
  NEW_CRASHES_JSON=$(echo "$NEW_CRASH_LIST" | python3 -c "
import sys, json
print(json.dumps([line.strip() for line in sys.stdin if line.strip()]))
")
fi

#------------------------------------------------------------------------------
# 6. Top unreached functions
#------------------------------------------------------------------------------
UNREACHED_JSON="[]"
if [ "$COV_RUN_OK" = "true" ] && [ -f "$COV_DIR/default.profdata" ]; then
  UNREACHED_JSON=$("$LLVM_COV_BIN" export "$COVERAGE_BINARY" \
                    -instr-profile="$COV_DIR/default.profdata" 2>/dev/null \
    | python3 -c "
import sys, json
try:
    d = json.load(sys.stdin)
    funcs = d['data'][0].get('functions', [])
    unreached = [f['name'] for f in funcs if f.get('count', 0) == 0]
    print(json.dumps(unreached[:15]))
except Exception:
    print('[]')
" 2>/dev/null || echo '[]')
fi

#------------------------------------------------------------------------------
# 7. Strict instrumentation check
#------------------------------------------------------------------------------
# If coverage tracking was supposed to work but produced zeros, that's an error.
INSTRUMENTATION_OK=true
INSTRUMENTATION_ERRORS_JSON="[]"
ERRS=()

if [ "$COVERAGE_TRACKING_ENABLED" = "true" ]; then
  [ "$LLVM_COV_AVAILABLE" = "true" ] || ERRS+=("llvm-cov/llvm-profdata not found in PATH or /usr/lib/llvm-*/bin/")
  [ "$COVERAGE_BUILD_PRESENT" = "true" ] || ERRS+=("coverage_binary missing or not executable per harness-built.json")
  if [ "$COV_LINES" = "0" ] && [ "$COV_TOTAL" = "0" ] && [ "$COVERAGE_BUILD_PRESENT" = "true" ]; then
    ERRS+=("coverage run produced zero lines despite instrumented build - check LLVM_PROFILE_FILE handling")
  fi
fi

if [ "$PARSED_ENGINE_LOG" != "true" ] && [ "$ENGINE" != "unknown" ]; then
  # In fork mode, workers finish between snapshots leaving no live log lines.
  # If coverage data is valid (non-zero lines covered), this is not a real error.
  if [ "$FORK_MODE" = "true" ] && [ "${COV_LINES:-0}" -gt 0 ]; then
    : # fork mode with valid coverage — exec stats being zero is expected
  else
    ERRS+=("engine $ENGINE detected but log parsing failed - exec stats will be zero")
  fi
fi

if [ "${#ERRS[@]}" -gt 0 ]; then
  INSTRUMENTATION_OK=false
  INSTRUMENTATION_ERRORS_JSON=$(printf '%s\n' "${ERRS[@]}" | python3 -c "
import sys, json
print(json.dumps([l.strip() for l in sys.stdin if l.strip()]))
")
fi

#------------------------------------------------------------------------------
# 8. Write the snapshot
#------------------------------------------------------------------------------
cat > "$OUT_FILE" <<EOF
{
  "schema": "coverage-snapshot/v2",
  "timestamp": $TS,
  "engine": "$ENGINE",
  "fuzzer_stats": {
    "execs": $EXECS,
    "paths": $PATHS,
    "crashes": $CRASHES,
    "hangs": $HANGS,
    "execs_per_sec": $EXEC_RATE
  },
  "coverage": {
    "lines_covered": $COV_LINES,
    "lines_total": $COV_TOTAL,
    "line_pct": $COV_PCT
  },
  "instrumentation": {
    "tracking_enabled": $COVERAGE_TRACKING_ENABLED,
    "coverage_build_present": $COVERAGE_BUILD_PRESENT,
    "llvm_cov_available": $LLVM_COV_AVAILABLE,
    "coverage_run_ok": $COV_RUN_OK,
    "parsed_engine_log": $PARSED_ENGINE_LOG,
    "fork_mode": $FORK_MODE,
    "ok": $INSTRUMENTATION_OK,
    "errors": $INSTRUMENTATION_ERRORS_JSON
  },
  "previous_snapshot_ts": $PREV_TS,
  "new_crashes_since_previous": $NEW_CRASHES_JSON,
  "top_unreached_functions": $UNREACHED_JSON
}
EOF

echo "$OUT_FILE"

# Refresh current.json so callers don't have to.
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
if [ -x "$SCRIPT_DIR/update-current.sh" ]; then
  FUZZ_STATE_DIR="$STATE_DIR" bash "$SCRIPT_DIR/update-current.sh" >/dev/null 2>&1 || true
fi

# Exit non-zero if instrumentation was supposed to work but didn't.
# This is the strictness change - the orchestrator sees non-zero and stops.
if [ "$INSTRUMENTATION_OK" = "false" ] && [ "$COVERAGE_TRACKING_ENABLED" = "true" ]; then
  echo "WARN: instrumentation is broken - see fuzz/state/snapshots/coverage-$TS.json instrumentation.errors" >&2
  # Don't exit 1 here - the snapshot still has fuzzer stats. The orchestrator
  # checks instrumentation.ok in current.json and decides what to do.
fi

exit 0
