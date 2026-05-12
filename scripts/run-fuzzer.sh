#!/usr/bin/env bash
# run-fuzzer.sh
#
# Launches a fuzzer in the background, records the PID, and tees stdout/stderr
# into fuzz/state/fuzzer.log. The orchestrator never blocks on this.
#
# Usage:
#   run-fuzzer.sh <harness-binary> [corpus-dir]
#
# Engine detection:
#   - If the binary itself is a libFuzzer runner (has LLVMFuzzerTestOneInput),
#     run it directly with libFuzzer flags.
#   - Else if afl-fuzz is available, use AFL++.
#
# Forbidden flags (refused at startup):
#   -ignore_crashes=1     suppresses crash recording, defeats the whole point
#   -detect_leaks=0       disables ASan leak detection
#   -detect_odr_violation=0
#   ASAN_OPTIONS containing abort_on_error=0 or detect_leaks=0
#
# These flags have been added by past agents "to keep the fuzzer running" and
# each time they caused real damage (silent crash loss in the findutils campaign).
# The whitelist is intentional and not user-configurable from this script.

set -u

# Path anchor - refuses cwd inside fuzz/, refuses recursive fuzz/fuzz/
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
. "$SCRIPT_DIR/_lib/path-anchor.sh"

BIN="${1:-}"
CORPUS="${2:-fuzz/corpus}"
STATE_DIR="${FUZZ_STATE_DIR:-$FUZZ_ROOT/state}"
OUT_DIR="${FUZZ_OUT_DIR:-$PROJECT_ROOT/out}"
mkdir -p "$STATE_DIR" "$OUT_DIR" "$CORPUS"

# Refuse forbidden flags if anyone tries to inject them via env
for env_var in ASAN_OPTIONS UBSAN_OPTIONS; do
  val="${!env_var:-}"
  case "$val" in
    *abort_on_error=0*|*detect_leaks=0*|*halt_on_error=0*)
      echo "ERROR: $env_var contains a safety-defeating option: $val" >&2
      echo "       refusing to launch. Unset or fix $env_var and retry." >&2
      exit 2
      ;;
  esac
done

if [ -z "$BIN" ] || [ ! -x "$BIN" ]; then
  echo "ERROR: harness binary missing or not executable: '$BIN'" >&2
  echo "       run /fuzz:harness first" >&2
  exit 1
fi

# Stop any existing fuzzer first — use kill-harness-processes.sh to also
# catch bash-forked child processes that a simple PID kill would miss.
if [ -f "$STATE_DIR/fuzzer.pid" ] || [ -f "$STATE_DIR/harness-built.json" ]; then
  bash "$SCRIPT_DIR/kill-harness-processes.sh" --quiet >/dev/null 2>&1 || true
fi

ENGINE=""
if nm "$BIN" 2>/dev/null | grep -q LLVMFuzzerTestOneInput; then
  ENGINE="libfuzzer"
fi

# Read fuzzing_mode from harness-built.json (default: in_process)
FUZZING_MODE="in_process"
if [ -f "$STATE_DIR/harness-built.json" ]; then
  FUZZING_MODE=$(python3 -c "
import json
try: print(json.load(open('$STATE_DIR/harness-built.json')).get('fuzzing_mode','in_process'))
except: print('in_process')" 2>/dev/null)
fi
echo "fuzzing_mode=$FUZZING_MODE" >&2

# Read dict_files from harness-built.json. Both libFuzzer and AFL++ accept
# multiple dictionaries; libFuzzer takes one -dict= per entry; AFL++ takes
# repeated -x. We build the appropriate flag list.
DICT_FLAGS=()
if [ -f "$STATE_DIR/harness-built.json" ]; then
  DICT_FILES=$(python3 -c "
import json
try:
    d = json.load(open('$STATE_DIR/harness-built.json'))
    files = d.get('dict_files') or ([d['dict_file']] if d.get('dict_file') else [])
    for f in files:
        if f: print(f)
except Exception:
    pass
" 2>/dev/null)
  if [ -n "$DICT_FILES" ]; then
    while IFS= read -r df; do
      [ -f "$df" ] || continue
      if [ "$ENGINE" = "libfuzzer" ]; then
        DICT_FLAGS+=("-dict=$df")
      else
        # For AFL++, we'll concatenate later
        DICT_FLAGS+=("$df")
      fi
    done <<< "$DICT_FILES"
  fi
fi

if [ "$ENGINE" = "libfuzzer" ]; then
  # Resolve fork count from config (env > override > project file > default 2)
  . "$SCRIPT_DIR/_lib/fuzz-config.sh"
  FORKS=$(resolve_fuzz_forks)

  # libFuzzer with -fork=N: master coordinates N worker processes. Each worker
  # dies on crash and is respawned by master. The master saves crash artifacts
  # to the corpus directory's parent. Crash recording is ON (no -ignore_crashes;
  # that flag is forbidden, see header).
  # fuzz_forks=0 means single-process mode (no -fork flag); fork workers can
  # deadlock on popen/read blocking calls that survive SIGALRM via pclose retry.
  FORK_FLAGS=()
  if [ "$FORKS" -gt 0 ] 2>/dev/null; then
    echo "launching libFuzzer with -fork=$FORKS (mode=$FUZZING_MODE)" >&2
    FORK_FLAGS=("-fork=$FORKS")
  else
    echo "launching libFuzzer single-process (fuzz_forks=0, mode=$FUZZING_MODE)" >&2
  fi

  # Extra flags for process_based mode:
  #   -close_fd_mask=3  — suppress child process stdio noise
  #   higher rss limit  — allow headroom for exec'd child processes
  LF_RSZ_MB=2048
  EXTRA_LF_FLAGS=()
  if [ "$FUZZING_MODE" = "process_based" ]; then
    EXTRA_LF_FLAGS+=("-close_fd_mask=3")
    LF_RSZ_MB=4096
    echo "  process_based: -close_fd_mask=3, rss_limit_mb=4096" >&2
  fi

  nohup "$BIN" "$CORPUS" \
    "${DICT_FLAGS[@]}" \
    "${FORK_FLAGS[@]}" \
    "${EXTRA_LF_FLAGS[@]}" \
    -print_final_stats=1 \
    -timeout=10 \
    -rss_limit_mb="$LF_RSZ_MB" \
    -print_pcs=0 \
    > "$STATE_DIR/fuzzer.log" 2>&1 &
  PID=$!
elif command -v afl-fuzz >/dev/null 2>&1; then
  ENGINE="aflpp"
  # AFL++ takes a single dict file; concatenate ours into one.
  AFL_DICT_FLAG=()
  if [ "${#DICT_FLAGS[@]}" -gt 0 ]; then
    MERGED="$STATE_DIR/merged-dict.dict"
    : > "$MERGED"
    for df in "${DICT_FLAGS[@]}"; do
      echo "# === $df ===" >> "$MERGED"
      cat "$df" >> "$MERGED"
      echo "" >> "$MERGED"
    done
    AFL_DICT_FLAG=("-x" "$MERGED")
  fi

  # If a cmplog binary was built (harness-writer wrote it to harness-built.json
  # under cmplog_binary, with cmplog_enabled=true), pass it via -c so AFL++
  # uses Redqueen-style input-to-state on top of regular coverage feedback.
  # This is the runtime side of v0.13's I2S integration; the dictionary
  # extraction (extract-cmplog-dict.sh) is the offline side that surfaces
  # cmplog observations to the LLM agents.
  CMPLOG_FLAG=()
  if [ -f "$STATE_DIR/harness-built.json" ]; then
    CMPLOG_INFO=$(python3 -c "
import json
try:
    d = json.load(open('$STATE_DIR/harness-built.json'))
    enabled = d.get('cmplog_enabled', False)
    binp = d.get('cmplog_binary', '') or ''
    print(f'{enabled}|{binp}')
except Exception:
    print('False|')
" 2>/dev/null)
    CMPLOG_ENABLED="${CMPLOG_INFO%%|*}"
    CMPLOG_BIN="${CMPLOG_INFO#*|}"
    if [ "$CMPLOG_ENABLED" = "True" ] && [ -n "$CMPLOG_BIN" ] && [ -x "$CMPLOG_BIN" ]; then
      CMPLOG_FLAG=("-c" "$CMPLOG_BIN")
      echo "cmplog: enabled, using $CMPLOG_BIN" >&2
    elif [ "$CMPLOG_ENABLED" = "True" ] && [ -n "$CMPLOG_BIN" ]; then
      echo "WARN: cmplog_enabled=true but binary not executable: $CMPLOG_BIN" >&2
      echo "      continuing without cmplog" >&2
    fi
  fi

  # For process_based: AFL++ passes the input file path via @@
  # For in_process: AFL++ uses persistent mode (__AFL_LOOP) reading from AFL's buffer
  if [ "$FUZZING_MODE" = "process_based" ]; then
    AFL_TARGET_ARGS=("@@")
    echo "  AFL++ process_based mode: target invoked as '$BIN @@'" >&2
  else
    AFL_TARGET_ARGS=()
    echo "  AFL++ in_process mode: persistent harness reads AFL buffer" >&2
  fi

  nohup afl-fuzz "${AFL_DICT_FLAG[@]}" "${CMPLOG_FLAG[@]}" -i "$CORPUS" -o "$OUT_DIR" -- "$BIN" "${AFL_TARGET_ARGS[@]}" \
    > "$STATE_DIR/fuzzer.log" 2>&1 &
  PID=$!
else
  echo "ERROR: no usable fuzzing engine found." >&2
  echo "       binary is not a libFuzzer runner and afl-fuzz is not in PATH" >&2
  exit 1
fi

echo "$PID" > "$STATE_DIR/fuzzer.pid"
echo "$ENGINE" > "$STATE_DIR/fuzzer.engine"
echo "Fuzzer started: engine=$ENGINE PID=$PID"
echo "Logs:           $STATE_DIR/fuzzer.log"
echo "Stop with:      kill \$(cat $STATE_DIR/fuzzer.pid)"

# Refresh current.json so the orchestrator sees the new state on its next tick
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
if [ -x "$SCRIPT_DIR/update-current.sh" ]; then
  FUZZ_STATE_DIR="$STATE_DIR" bash "$SCRIPT_DIR/update-current.sh" >/dev/null 2>&1 || true
fi
