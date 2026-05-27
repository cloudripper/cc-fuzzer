#!/usr/bin/env bash
# launch-fuzzer-slot.sh
#
# Launches a single fuzzer slot in the background. A "slot" is one fuzzer
# process within a (possibly multi-fuzzer) campaign. In v0.17 a slot has its
# own pid/log/engine files and engine-specific flags; in schema v9 a slot
# additionally binds to a specific harness (`--harness <name>`), and its
# binary/corpus/output paths are resolved per-harness via _lib/harness-path.sh.
#
# Single-fuzzer singular-mode campaigns use exactly one slot named "main"
# with no harness binding (the implicit campaign harness). Multi-fuzzer or
# multi-harness campaigns declare additional slots in
# fuzz/state/fuzz-config.json under `fuzzer_slots`.
#
# Usage:
#   launch-fuzzer-slot.sh \
#     --slot <name>                       (default: main)
#     --engine libfuzzer|aflpp            (required; auto-detect if "auto")
#     [--harness <name>]                  (multi mode: required; singular: ignored)
#     [--binary <harness-binary>]         (defaults to per-harness harness_binary)
#     [--corpus <dir>]                    (defaults to per-harness corpus dir)
#     [--role master|secondary]           (AFL++ only)
#     [--power-schedule <name>]           (AFL++ only)
#     [--libfuzzer-forks <N>]             (libFuzzer only; overrides fuzz-config)
#     [--restart-of <slot>]               (internal use by check-slot-liveness.sh)
#
# Side effects:
#   - Launches the fuzzer with nohup; PID written to fuzz/state/fuzzer-<slot>.pid
#   - Engine written to fuzz/state/fuzzer-<slot>.engine
#   - Stdout/stderr tee'd into fuzz/state/fuzzer-<slot>.log
#   - Slot entry created/updated in fuzz/state/fuzzers.json
#       (schema fuzzers/v1 in singular mode, fuzzers/v2 in multi mode w/ harness)
#   - Multi mode: each slot runs in its own cwd (libFuzzer) or out-dir (AFL++)
#       under fuzz/harnesses/<harness>/ so crash files attribute to the harness.
#   - When --slot=main and singular mode, also writes legacy fuzzer.pid/.engine/.log
#     symlinks so pre-v0.17 readers keep working.
#
# Refuses to launch if:
#   - The slot is already running (existing PID is alive)
#   - The binary doesn't exist or isn't executable
#   - The engine value is bogus
#   - Multi mode but --harness is missing or references an undeclared harness
#   - Forbidden ASAN_OPTIONS / UBSAN_OPTIONS env vars are set

set -u

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
. "$SCRIPT_DIR/_lib/path-anchor.sh"
. "$SCRIPT_DIR/_lib/fuzz-config.sh"
. "$SCRIPT_DIR/_lib/harness-path.sh"
STATE_DIR="${FUZZ_STATE_DIR:-$FUZZ_ROOT/state}"
OUT_DIR="${FUZZ_OUT_DIR:-$PROJECT_ROOT/out}"

SLOT="main"
ENGINE="auto"
HARNESS=""
BIN=""
CORPUS=""
ROLE=""
POWER_SCHEDULE=""
LF_FORKS_OVERRIDE=""
RESTART_OF=""
TIMEOUT_MS=""

while [ $# -gt 0 ]; do
  case "$1" in
    --slot)              SLOT="${2:-}"; shift 2 ;;
    --engine)            ENGINE="${2:-}"; shift 2 ;;
    --harness)           HARNESS="${2:-}"; shift 2 ;;
    --binary)            BIN="${2:-}"; shift 2 ;;
    --corpus)            CORPUS="${2:-}"; shift 2 ;;
    --role)              ROLE="${2:-}"; shift 2 ;;
    --power-schedule)    POWER_SCHEDULE="${2:-}"; shift 2 ;;
    --libfuzzer-forks)   LF_FORKS_OVERRIDE="${2:-}"; shift 2 ;;
    --timeout-ms)        TIMEOUT_MS="${2:-}"; shift 2 ;;
    --restart-of)        RESTART_OF="${2:-}"; shift 2 ;;
    -h|--help)
      sed -n '2,/^$/p' "$0" | sed 's/^# \?//'
      exit 0
      ;;
    *) echo "ERROR: unknown arg '$1'" >&2; exit 2 ;;
  esac
done

# Resolve harness binding. In multi mode --harness is required and must match
# a declared harness; in singular mode the implicit harness is the only one.
if is_multi; then
  if [ -z "$HARNESS" ]; then
    echo "ERROR: multi-harness mode active but --harness <name> was not provided" >&2
    exit 2
  fi
  if ! is_known_harness "$HARNESS"; then
    echo "ERROR: harness '$HARNESS' is not declared in fuzz-config.json:harnesses[]" >&2
    exit 2
  fi
else
  # Singular: ignore --harness, fall back to the implicit harness name (for
  # uniform downstream code). default_harness reads harness-built.json:entry_function.
  if [ -z "$HARNESS" ]; then
    HARNESS=$(default_harness)
  fi
fi

# Resolve binary and corpus defaults from the per-harness record if not given.
if [ -z "$BIN" ] && [ -n "$HARNESS" ]; then
  BIN=$(harness_binary "$HARNESS")
fi
if is_multi && [ -n "$HARNESS" ]; then
  # In multi mode the per-harness corpus is authoritative. Resolve it when no
  # --corpus was given, AND override (with a warning) when the caller passed the
  # legacy singular fuzz/corpus — that is almost always a relaunch-path
  # regression (run-fuzzer.sh used to force it), and using it would bypass the
  # harness's evolved corpus and trip validate-state. An explicit DIFFERENT
  # --corpus path is still honored.
  ph=$(corpus_dir "$HARNESS")
  case "$CORPUS" in
    "")                CORPUS="$ph" ;;
    fuzz/corpus|*/fuzz/corpus)
      echo "WARN: --corpus pointed at the legacy singular '$CORPUS' in multi mode; using per-harness $ph" >&2
      CORPUS="$ph" ;;
  esac
elif [ -z "$CORPUS" ]; then
  if [ -n "$HARNESS" ]; then
    CORPUS=$(corpus_dir "$HARNESS")
  else
    CORPUS="fuzz/corpus"
  fi
fi

# Slot-name validation
case "$SLOT" in
  ''|*[!a-z0-9-]*) echo "ERROR: invalid --slot '$SLOT' (must match ^[a-z0-9-]+\$)" >&2; exit 2 ;;
esac
[ "${#SLOT}" -le 32 ] || { echo "ERROR: --slot too long (max 32 chars)" >&2; exit 2; }

[ -n "$BIN" ] || { echo "ERROR: --binary is required" >&2; exit 2; }
[ -x "$BIN" ] || { echo "ERROR: binary not executable: $BIN" >&2; exit 2; }

mkdir -p "$STATE_DIR" "$OUT_DIR" "$CORPUS"

# Refuse forbidden env safety flags
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

# Per-slot file paths
PID_FILE="$STATE_DIR/fuzzer-$SLOT.pid"
ENGINE_FILE="$STATE_DIR/fuzzer-$SLOT.engine"
LOG_FILE="$STATE_DIR/fuzzer-$SLOT.log"

# Refuse if slot is already running
if [ -f "$PID_FILE" ]; then
  existing=$(cat "$PID_FILE" 2>/dev/null | tr -d ' \n')
  if [ -n "$existing" ] && kill -0 "$existing" 2>/dev/null; then
    echo "ERROR: slot '$SLOT' already running (PID $existing)" >&2
    echo "       stop-fuzzer.sh --slot $SLOT first if you want to restart it." >&2
    exit 3
  fi
fi

# Auto-detect engine if requested
if [ "$ENGINE" = "auto" ]; then
  if nm "$BIN" 2>/dev/null | grep -q LLVMFuzzerTestOneInput; then
    ENGINE="libfuzzer"
  elif command -v afl-fuzz >/dev/null 2>&1; then
    ENGINE="aflpp"
  else
    echo "ERROR: cannot auto-detect engine for $BIN (no LLVMFuzzerTestOneInput symbol and afl-fuzz not in PATH)" >&2
    exit 1
  fi
fi

case "$ENGINE" in
  libfuzzer|aflpp) ;;
  *) echo "ERROR: invalid --engine '$ENGINE' (expected libfuzzer or aflpp)" >&2; exit 2 ;;
esac

# Read fuzzing_mode, cmplog, and dict files via the per-harness helper. In
# singular mode this reads from harness-built.json; in multi mode it reads
# from harnesses.json[<harness>].
FUZZING_MODE=$(harness_field "$HARNESS" fuzzing_mode)
[ -z "$FUZZING_MODE" ] && FUZZING_MODE="in_process"

# --timeout-ms default. Per-input timeout passed to the engine. The interesting
# case is AFL++ + process_based: AFL's default 1000 ms calibration timeout
# kills any seed whose startup (fork+exec+init) exceeds it, which for daemon-
# or CLI-style targets is essentially every seed. Auto-bump for that combo.
#
# Order of precedence:
#   1. Explicit --timeout-ms argument (from fuzz-config.json:fuzzer_slots[].timeout_ms)
#   2. Auto-default by (engine, fuzzing_mode)
if [ -z "$TIMEOUT_MS" ]; then
  if [ "$ENGINE" = "aflpp" ] && [ "$FUZZING_MODE" = "process_based" ]; then
    TIMEOUT_MS=5000
  else
    TIMEOUT_MS=1000
  fi
fi
case "$TIMEOUT_MS" in
  ''|*[!0-9]*) echo "ERROR: --timeout-ms must be a positive integer (got '$TIMEOUT_MS')" >&2; exit 2 ;;
esac
[ "$TIMEOUT_MS" -ge 100 ] 2>/dev/null || { echo "ERROR: --timeout-ms below 100ms floor" >&2; exit 2; }

CMPLOG_ENABLED=$(harness_field "$HARNESS" cmplog_enabled)
[ "$CMPLOG_ENABLED" = "True" ] && CMPLOG_ENABLED="true"
[ "$CMPLOG_ENABLED" = "False" ] || [ -z "$CMPLOG_ENABLED" ] && CMPLOG_ENABLED="false"

CMPLOG_BIN=$(harness_field "$HARNESS" cmplog_binary)
[ "$CMPLOG_BIN" = "None" ] && CMPLOG_BIN=""

DICT_FILES=()
DICT_JSON=$(harness_field "$HARNESS" dict_files)
if [ -n "$DICT_JSON" ] && [ "$DICT_JSON" != "None" ]; then
  while IFS= read -r df; do
    [ -n "$df" ] && DICT_FILES+=("$df")
  done < <(DJ="$DICT_JSON" python3 "$SCRIPT_DIR/_lib/launch_slot.py" parse-dict-json 2>/dev/null)
fi

# Resolve per-harness output paths so crash files attribute back to a harness.
# Multi mode:
#   - libFuzzer cwd = fuzz/harnesses/<harness>/.libfuzzer-cwd/   (per-harness)
#   - AFL++ -o      = fuzz/harnesses/<harness>/aflpp-out/        (per-harness)
# Singular mode: keep existing behavior (cwd=$PROJECT_ROOT; OUT_DIR as set above).
SLOT_CWD="$PROJECT_ROOT"
if is_multi; then
  SLOT_CWD="$FUZZ_ROOT/harnesses/$HARNESS/.libfuzzer-cwd"
  OUT_DIR="$FUZZ_ROOT/harnesses/$HARNESS/aflpp-out"
  mkdir -p "$SLOT_CWD" "$OUT_DIR"
fi

# Absolutize paths that get passed to a process running in SLOT_CWD. Realpath
# is preferred but may fail on non-existent dict files; fall back to PROJECT_ROOT
# anchoring so relative paths still resolve.
_abs() {
  local p="$1"
  case "$p" in
    /*) echo "$p" ;;
    *)  if [ -e "$p" ]; then realpath "$p" 2>/dev/null || echo "$PROJECT_ROOT/$p"
        else echo "$PROJECT_ROOT/$p"; fi ;;
  esac
}
BIN_ABS=$(_abs "$BIN")
CORPUS_ABS=$(_abs "$CORPUS")

# Build engine-specific launch
PID=""
if [ "$ENGINE" = "libfuzzer" ]; then
  FORKS=""
  if [ -n "$LF_FORKS_OVERRIDE" ]; then
    FORKS="$LF_FORKS_OVERRIDE"
  else
    FORKS=$(resolve_fuzz_forks)
  fi

  DICT_FLAGS=()
  for df in "${DICT_FILES[@]}"; do
    [ -f "$df" ] || continue
    DICT_FLAGS+=("-dict=$(_abs "$df")")
  done

  FORK_FLAGS=()
  if [ "$FORKS" -gt 0 ] 2>/dev/null; then
    FORK_FLAGS=("-fork=$FORKS")
    echo "slot=$SLOT: launching libFuzzer with -fork=$FORKS (mode=$FUZZING_MODE${HARNESS:+, harness=$HARNESS})" >&2
  else
    echo "slot=$SLOT: launching libFuzzer single-process (fuzz_forks=0, mode=$FUZZING_MODE${HARNESS:+, harness=$HARNESS})" >&2
  fi

  LF_RSZ_MB=2048
  EXTRA_LF_FLAGS=()
  if [ "$FUZZING_MODE" = "process_based" ]; then
    EXTRA_LF_FLAGS+=("-close_fd_mask=3")
    LF_RSZ_MB=4096
  fi
  # libFuzzer -timeout is in SECONDS (AFL is ms). Round up.
  LF_TIMEOUT_SEC=$(( (TIMEOUT_MS + 999) / 1000 ))
  [ "$LF_TIMEOUT_SEC" -lt 1 ] && LF_TIMEOUT_SEC=1

  # Launch from SLOT_CWD so libFuzzer's ./crash-* writes there. Use a subshell
  # for cwd isolation, then capture the backgrounded PID. The trick: bash's $!
  # works inside the subshell because nohup &'s job is the subshell's child,
  # but the parent needs that PID — write it to a temp file before the
  # subshell exits.
  PID_TMP=$(mktemp)
  (
    cd "$SLOT_CWD"
    nohup "$BIN_ABS" "$CORPUS_ABS" \
      "${DICT_FLAGS[@]}" \
      "${FORK_FLAGS[@]}" \
      "${EXTRA_LF_FLAGS[@]}" \
      -print_final_stats=1 \
      -timeout="$LF_TIMEOUT_SEC" \
      -rss_limit_mb="$LF_RSZ_MB" \
      -print_pcs=0 \
      > "$LOG_FILE" 2>&1 &
    echo "$!" > "$PID_TMP"
    disown
  )
  PID=$(cat "$PID_TMP" 2>/dev/null || echo "")
  rm -f "$PID_TMP"
else
  # aflpp
  if ! command -v afl-fuzz >/dev/null 2>&1; then
    echo "ERROR: --engine aflpp but afl-fuzz not in PATH" >&2
    exit 1
  fi

  AFL_DICT_FLAG=()
  if [ "${#DICT_FILES[@]}" -gt 0 ]; then
    # Per-harness merged dict so different harnesses don't stomp on each other.
    if is_multi; then
      MERGED="$STATE_DIR/merged-dict-${HARNESS}.dict"
    else
      MERGED="$STATE_DIR/merged-dict.dict"
    fi
    : > "$MERGED"
    for df in "${DICT_FILES[@]}"; do
      [ -f "$df" ] || continue
      echo "# === $df ===" >> "$MERGED"
      cat "$df" >> "$MERGED"
      echo "" >> "$MERGED"
    done
    AFL_DICT_FLAG=("-x" "$MERGED")
  fi

  CMPLOG_FLAG=()
  if [ "$CMPLOG_ENABLED" = "true" ] && [ -n "$CMPLOG_BIN" ] && [ -x "$CMPLOG_BIN" ]; then
    CMPLOG_FLAG=("-c" "$CMPLOG_BIN")
    echo "slot=$SLOT: cmplog enabled ($CMPLOG_BIN)" >&2
  fi

  # AFL++ M/S role: -M <name> for master, -S <name> for secondary.
  # When neither is set, AFL++ runs standalone (single-instance).
  ROLE_FLAG=()
  case "$ROLE" in
    master)     ROLE_FLAG=("-M" "$SLOT") ;;
    secondary)  ROLE_FLAG=("-S" "$SLOT") ;;
    "")         ;;
    *) echo "ERROR: invalid --role '$ROLE' (expected master or secondary)" >&2; exit 2 ;;
  esac

  POWER_FLAG=()
  if [ -n "$POWER_SCHEDULE" ]; then
    case "$POWER_SCHEDULE" in
      explore|exploit|fast|coe|quad|lin|seek|rare)
        POWER_FLAG=("-p" "$POWER_SCHEDULE") ;;
      *) echo "ERROR: invalid --power-schedule '$POWER_SCHEDULE'" >&2; exit 2 ;;
    esac
  fi

  if [ "$FUZZING_MODE" = "process_based" ]; then
    AFL_TARGET_ARGS=("@@")
  else
    AFL_TARGET_ARGS=()
  fi

  # -t <ms>+   per-input timeout. The trailing `+` means skip-on-timeout
  #             rather than abort during dry-run. Without it, AFL refuses
  #             to start when ANY seed in the initial corpus exceeds the
  #             timeout — which is essentially every seed for slow-start
  #             process_based targets.
  AFL_TIMEOUT_FLAG=("-t" "${TIMEOUT_MS}+")

  echo "slot=$SLOT: launching AFL++ (role=${ROLE:-standalone}, schedule=${POWER_SCHEDULE:-default}, mode=$FUZZING_MODE, timeout=${TIMEOUT_MS}ms${HARNESS:+, harness=$HARNESS})" >&2

  nohup afl-fuzz \
    "${AFL_TIMEOUT_FLAG[@]}" \
    "${AFL_DICT_FLAG[@]}" \
    "${CMPLOG_FLAG[@]}" \
    "${ROLE_FLAG[@]}" \
    "${POWER_FLAG[@]}" \
    -i "$CORPUS" -o "$OUT_DIR" \
    -- "$BIN" "${AFL_TARGET_ARGS[@]}" \
    > "$LOG_FILE" 2>&1 &
  PID=$!
fi

# Record per-slot files
echo "$PID" > "$PID_FILE"
echo "$ENGINE" > "$ENGINE_FILE"

# Find PGID for kill-by-group teardown. ps may return empty for a
# very-short-lived process (e.g. immediate exec failure); fall back to PID.
PGID=$(ps -o pgid= -p "$PID" 2>/dev/null | tr -d ' ')
[ -z "$PGID" ] && PGID="$PID"

STARTED_AT=$(date -u +"%Y-%m-%dT%H:%M:%SZ")

# Update fuzz/state/fuzzers.json — atomic read-modify-write
MANIFEST="$STATE_DIR/fuzzers.json"
MANIFEST_TMP="$MANIFEST.tmp"

IS_MULTI=0
if is_multi; then IS_MULTI=1; fi
export SLOT ENGINE BIN PID PGID STARTED_AT LOG_FILE PID_FILE ENGINE_FILE ROLE POWER_SCHEDULE MANIFEST RESTART_OF HARNESS IS_MULTI
python3 "$SCRIPT_DIR/_lib/launch_slot.py" update-manifest

# Backward-compat: when slot is "main" and we're in singular mode, maintain the
# legacy single-slot files so pre-v0.17 readers (anything still doing
# `cat fuzz/state/fuzzer.pid`) keep working. In multi mode the singular
# fuzzer.pid is meaningless — there is no single "the fuzzer" — so skip.
if [ "$SLOT" = "main" ] && ! is_multi; then
  ln -sf "fuzzer-main.pid"    "$STATE_DIR/fuzzer.pid"
  ln -sf "fuzzer-main.engine" "$STATE_DIR/fuzzer.engine"
  ln -sf "fuzzer-main.log"    "$STATE_DIR/fuzzer.log"
fi

echo "slot=$SLOT engine=$ENGINE pid=$PID pgid=$PGID log=$LOG_FILE"
