#!/usr/bin/env bash
# write-harness-built.sh
#
# Writes fuzz/state/harness-built.json with computed SHA-256 hashes for
# target_source and build_command. The harness-writer agent calls this
# after a successful build instead of hand-writing the JSON — which has
# historically resulted in placeholder stub hashes ("00000000<...>")
# making every subsequent check-campaign-state.sh return "stale".
#
# Usage (long options only — order doesn't matter):
#   write-harness-built.sh \
#     --target-source PATH         (required)
#     --build-script PATH          (required; path to fuzz/harness/build.sh)
#     --harness-source PATH        (required)
#     --harness-binary PATH        (required; must be executable)
#     --entry-function NAME        (required)
#     --fuzzing-mode MODE          (required; in_process | process_based)
#
#     --coverage-binary PATH       (one of these required)
#     --no-coverage [--coverage-disabled-reason REASON]
#
#     --verify-binary PATH         (one of these required)
#     --no-verify
#
#     --cmplog-binary PATH         (one of these required)
#     --no-cmplog [--cmplog-disabled-reason REASON]
#
#     [--symcc-binary PATH]
#     [--sanitizers a,b,c]         (default: address,undefined,fuzzer)
#     [--input-encoding ENC]       (default: passthrough)
#     [--dict-file PATH]           (repeatable)
#     [--attempts N]               (default: 1)
#     [--build-command CMD]        (optional; recorded verbatim)
#
# Exits non-zero on any validation failure (missing required arg, bad path,
# unexecutable binary, conflicting flags). No partial writes — the file is
# only renamed into place after every check passes.

set -u

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
. "$SCRIPT_DIR/_lib/path-anchor.sh"
. "$SCRIPT_DIR/_lib/harness-path.sh"
STATE_DIR="${FUZZ_STATE_DIR:-$FUZZ_ROOT/state}"

# Defaults
TARGET_SOURCE=""
BUILD_SCRIPT=""
HARNESS_SOURCE=""
HARNESS_BINARY=""
ENTRY_FUNCTION=""
FUZZING_MODE=""
COVERAGE_BINARY=""
NO_COVERAGE=0
COVERAGE_REASON=""
COVERAGE_DSO=()   # instrumented .so paths to feed llvm-cov as extra -object args
VERIFY_BINARY=""
NO_VERIFY=0
CMPLOG_BINARY=""
NO_CMPLOG=0
CMPLOG_REASON=""
SYMCC_BINARY=""
SANITIZERS="address,undefined,fuzzer"
INPUT_ENCODING="passthrough"
DICT_FILES=()
ATTEMPTS=1
BUILD_COMMAND=""
HARNESS_NAME=""   # multi-mode only: identifies which harness record to update
BUILD_BACKEND="legacy"  # nix | legacy
ORACLE_JSON=""    # oracle-driven fuzzing: JSON oracle config, "" ⇒ crash oracle

usage_err() {
  echo "ERROR: $*" >&2
  echo "       run with no args for usage" >&2
  exit 2
}

while [ $# -gt 0 ]; do
  case "$1" in
    --target-source)              TARGET_SOURCE="${2:-}"; shift 2 ;;
    --build-script)               BUILD_SCRIPT="${2:-}"; shift 2 ;;
    --harness-source)             HARNESS_SOURCE="${2:-}"; shift 2 ;;
    --harness-binary)             HARNESS_BINARY="${2:-}"; shift 2 ;;
    --entry-function)             ENTRY_FUNCTION="${2:-}"; shift 2 ;;
    --fuzzing-mode)               FUZZING_MODE="${2:-}"; shift 2 ;;
    --coverage-binary)            COVERAGE_BINARY="${2:-}"; shift 2 ;;
    --no-coverage)                NO_COVERAGE=1; shift ;;
    --coverage-disabled-reason)   COVERAGE_REASON="${2:-}"; shift 2 ;;
    --coverage-dso)               COVERAGE_DSO+=("${2:-}"); shift 2 ;;
    --verify-binary)              VERIFY_BINARY="${2:-}"; shift 2 ;;
    --no-verify)                  NO_VERIFY=1; shift ;;
    --cmplog-binary)              CMPLOG_BINARY="${2:-}"; shift 2 ;;
    --no-cmplog)                  NO_CMPLOG=1; shift ;;
    --cmplog-disabled-reason)     CMPLOG_REASON="${2:-}"; shift 2 ;;
    --symcc-binary)               SYMCC_BINARY="${2:-}"; shift 2 ;;
    --sanitizers)                 SANITIZERS="${2:-}"; shift 2 ;;
    --input-encoding)             INPUT_ENCODING="${2:-}"; shift 2 ;;
    --dict-file)                  DICT_FILES+=("${2:-}"); shift 2 ;;
    --attempts)                   ATTEMPTS="${2:-1}"; shift 2 ;;
    --build-command)              BUILD_COMMAND="${2:-}"; shift 2 ;;
    --harness)                    HARNESS_NAME="${2:-}"; shift 2 ;;
    --build-backend)              BUILD_BACKEND="${2:-legacy}"; shift 2 ;;
    --oracle-config)              ORACLE_JSON="${2:-}"; shift 2 ;;
    -h|--help|"")
      sed -n '2,/^$/p' "$0" | sed 's/^# \?//'
      exit 0
      ;;
    *) usage_err "unknown arg '$1'" ;;
  esac
done

# --- Required-arg checks ---
[ -n "$TARGET_SOURCE" ]   || usage_err "--target-source is required"
[ -n "$BUILD_SCRIPT" ]    || usage_err "--build-script is required"
[ -n "$HARNESS_SOURCE" ]  || usage_err "--harness-source is required"
[ -n "$HARNESS_BINARY" ]  || usage_err "--harness-binary is required"
[ -n "$ENTRY_FUNCTION" ]  || usage_err "--entry-function is required"
[ -n "$FUZZING_MODE" ]    || usage_err "--fuzzing-mode is required"

# --- File-existence checks ---
[ -f "$TARGET_SOURCE" ]   || usage_err "target source not found: $TARGET_SOURCE"
[ -f "$BUILD_SCRIPT" ]    || usage_err "build script not found: $BUILD_SCRIPT"
[ -f "$HARNESS_SOURCE" ]  || usage_err "harness source not found: $HARNESS_SOURCE"
[ -x "$HARNESS_BINARY" ]  || usage_err "harness binary not executable: $HARNESS_BINARY"

case "$FUZZING_MODE" in
  in_process|process_based) ;;
  *) usage_err "--fuzzing-mode must be in_process or process_based, got '$FUZZING_MODE'" ;;
esac

# --- Coverage section ---
if [ "$NO_COVERAGE" -eq 1 ] && [ -n "$COVERAGE_BINARY" ]; then
  usage_err "--no-coverage and --coverage-binary are mutually exclusive"
fi
COVERAGE_TRACKING=true
COVERAGE_BIN_JSON=""
COVERAGE_REASON_JSON=""
if [ "$NO_COVERAGE" -eq 1 ]; then
  COVERAGE_TRACKING=false
  [ -n "$COVERAGE_REASON" ] || usage_err "--no-coverage requires --coverage-disabled-reason"
  COVERAGE_REASON_JSON="$COVERAGE_REASON"
elif [ -n "$COVERAGE_BINARY" ]; then
  [ -x "$COVERAGE_BINARY" ] || usage_err "coverage binary not executable: $COVERAGE_BINARY"
  COVERAGE_BIN_JSON="$COVERAGE_BINARY"
else
  usage_err "must pass exactly one of --coverage-binary or --no-coverage"
fi

# --- Verify section ---
if [ "$NO_VERIFY" -eq 1 ] && [ -n "$VERIFY_BINARY" ]; then
  usage_err "--no-verify and --verify-binary are mutually exclusive"
fi
VERIFY_BIN_JSON=""
if [ "$NO_VERIFY" -eq 1 ]; then
  VERIFY_BIN_JSON=""
elif [ -n "$VERIFY_BINARY" ]; then
  [ -x "$VERIFY_BINARY" ] || usage_err "verify binary not executable: $VERIFY_BINARY"
  VERIFY_BIN_JSON="$VERIFY_BINARY"
else
  usage_err "must pass exactly one of --verify-binary or --no-verify"
fi

# --- Cmplog section ---
if [ "$NO_CMPLOG" -eq 1 ] && [ -n "$CMPLOG_BINARY" ]; then
  usage_err "--no-cmplog and --cmplog-binary are mutually exclusive"
fi
CMPLOG_ENABLED=true
CMPLOG_BIN_JSON=""
CMPLOG_REASON_JSON=""
if [ "$NO_CMPLOG" -eq 1 ]; then
  CMPLOG_ENABLED=false
  [ -n "$CMPLOG_REASON" ] || usage_err "--no-cmplog requires --cmplog-disabled-reason"
  CMPLOG_REASON_JSON="$CMPLOG_REASON"
elif [ -n "$CMPLOG_BINARY" ]; then
  [ -x "$CMPLOG_BINARY" ] || usage_err "cmplog binary not executable: $CMPLOG_BINARY"
  CMPLOG_BIN_JSON="$CMPLOG_BINARY"
else
  usage_err "must pass exactly one of --cmplog-binary or --no-cmplog"
fi

# --- Symcc (optional) ---
if [ -n "$SYMCC_BINARY" ] && [ ! -x "$SYMCC_BINARY" ]; then
  usage_err "symcc binary not executable: $SYMCC_BINARY"
fi

# --- Dict files ---
for df in "${DICT_FILES[@]}"; do
  [ -z "$df" ] && continue
  [ -f "$df" ] || usage_err "dict file not found: $df"
done

# --- Compute hashes ---
TARGET_HASH=$(sha256sum -- "$TARGET_SOURCE" | cut -c1-16)
BUILD_HASH=$(sha256sum -- "$BUILD_SCRIPT" | cut -c1-16)

if ! echo "$TARGET_HASH" | grep -qE '^[0-9a-f]{16}$'; then
  echo "ERROR: target_source_hash is not 16 hex chars: '$TARGET_HASH'" >&2
  exit 3
fi
if ! echo "$BUILD_HASH" | grep -qE '^[0-9a-f]{16}$'; then
  echo "ERROR: build_command_hash is not 16 hex chars: '$BUILD_HASH'" >&2
  exit 3
fi

BUILT_AT=$(date -u +"%Y-%m-%dT%H:%M:%SZ")

# --- Emit JSON via python3 for safe quoting ---
mkdir -p "$STATE_DIR"
OUT="$STATE_DIR/harness-built.json"
TMP="$OUT.tmp"

DICT_FILES_PY=""
if [ "${#DICT_FILES[@]}" -gt 0 ]; then
  DICT_FILES_PY=$(printf '%s\n' "${DICT_FILES[@]}")
fi
COVERAGE_DSO_PY=""
if [ "${#COVERAGE_DSO[@]}" -gt 0 ]; then
  COVERAGE_DSO_PY=$(printf '%s\n' "${COVERAGE_DSO[@]}")
fi
SANITIZERS_PY="$SANITIZERS"

# Multi-mode dispatch: when invoked with --harness and the campaign is in
# multi mode, the authoritative record lives in harnesses.json[<name>] using
# schema harness-built/v6 (adds `name`). The singular harness-built.json is
# then rewritten as a read-only mirror of harnesses[0].
IS_MULTI_WRITE=0
if [ -n "$HARNESS_NAME" ] && is_multi; then
  IS_MULTI_WRITE=1
fi

export TARGET_SOURCE BUILD_SCRIPT HARNESS_SOURCE HARNESS_BINARY ENTRY_FUNCTION FUZZING_MODE
export COVERAGE_TRACKING COVERAGE_BIN_JSON COVERAGE_REASON_JSON COVERAGE_DSO_PY
export VERIFY_BIN_JSON
export CMPLOG_ENABLED CMPLOG_BIN_JSON CMPLOG_REASON_JSON
export SYMCC_BINARY SANITIZERS_PY INPUT_ENCODING DICT_FILES_PY
export TARGET_HASH BUILD_HASH BUILT_AT ATTEMPTS BUILD_COMMAND
export HARNESS_NAME IS_MULTI_WRITE STATE_DIR BUILD_BACKEND ORACLE_JSON

python3 "$SCRIPT_DIR/_lib/write_harness_built.py" "$TMP"

# --- Atomic rename for the mirror / singular file ---
mv -- "$TMP" "$OUT"

if [ "$IS_MULTI_WRITE" -eq 1 ]; then
  echo "Wrote $STATE_DIR/harnesses.json (entry: $HARNESS_NAME)"
  echo "Updated mirror $OUT (mirrors harnesses[0])"
else
  echo "Wrote $OUT"
fi
echo "  target_source_hash : $TARGET_HASH  ($TARGET_SOURCE)"
echo "  build_command_hash : $BUILD_HASH  ($BUILD_SCRIPT)"
echo "  built_at           : $BUILT_AT"
