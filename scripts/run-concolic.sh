#!/usr/bin/env bash
# run-concolic.sh
#
# Runs SymCC against a single seed input and writes any new path-exploring
# inputs into the output directory. Bounded by --timeout to prevent path
# explosion from starving the main fuzzer.
#
# Usage:
#   run-concolic.sh --binary <symcc-binary> --seed <seed-file> \
#                   --output <out-dir> [--target-line <file:line>] \
#                   [--timeout <seconds>]
#
# This is invoked once per (seed, gap) pair by concolic-executor.

set -u

# SymCC PATH fallback: if symcc not in PATH, search /nix/store.
# This is needed when SymCC is installed via Nix but the shell profile
# hasn't been sourced (e.g. when invoked from a subprocess).
if ! command -v symcc >/dev/null 2>&1; then
  _NIX_SYMCC=$(find /nix/store -maxdepth 4 -type f -executable -name "symcc" 2>/dev/null | head -1)
  if [ -n "$_NIX_SYMCC" ]; then
    export PATH="$(dirname "$_NIX_SYMCC"):$PATH"
    echo "[concolic] symcc not in PATH — using nix-store fallback: $_NIX_SYMCC" >&2
  fi
fi

# Parse args
BIN=""
SEED=""
OUT=""
TARGET_LINE=""
TIMEOUT=60

while [[ $# -gt 0 ]]; do
  case "$1" in
    --binary) BIN="$2"; shift 2;;
    --seed) SEED="$2"; shift 2;;
    --output) OUT="$2"; shift 2;;
    --target-line) TARGET_LINE="$2"; shift 2;;
    --timeout) TIMEOUT="$2"; shift 2;;
    *) echo "ERROR: unknown arg: $1" >&2; exit 2;;
  esac
done

if [ -z "$BIN" ] || [ -z "$SEED" ] || [ -z "$OUT" ]; then
  echo "Usage: $0 --binary <symcc-binary> --seed <seed> --output <out-dir>" >&2
  exit 2
fi

if [ ! -x "$BIN" ]; then
  echo "ERROR: SymCC binary not executable: $BIN" >&2
  exit 1
fi

if [ ! -f "$SEED" ]; then
  echo "ERROR: seed file not found: $SEED" >&2
  exit 1
fi

mkdir -p "$OUT"

# SymCC environment:
#   SYMCC_INPUT_FILE  - the concrete seed to start from (read by SymCC runtime)
#   SYMCC_OUTPUT_DIR  - where to write new inputs
#   SYMCC_NO_SYMBOLIC_INPUT - 0 means treat stdin as symbolic
#   SYMCC_AFL_COVERAGE_MAP - optional AFL bitmap for coverage feedback
#   SYMCC_TIMEOUT - per-Z3-query timeout in milliseconds (default 30000)
SEED_HASH=$(sha256sum "$SEED" | cut -c1-12)
RUN_OUT="$OUT/run-$SEED_HASH-$(date +%s)"
mkdir -p "$RUN_OUT"

echo "[concolic] seed=$SEED hash=$SEED_HASH timeout=${TIMEOUT}s"

START=$(date +%s)
ENV_VARS=(
  "SYMCC_OUTPUT_DIR=$RUN_OUT"
  "SYMCC_INPUT_FILE=$SEED"
  "SYMCC_NO_SYMBOLIC_INPUT=0"
  "SYMCC_TIMEOUT=10000"
)

# Run SymCC with seed on stdin, bounded by timeout. Capture output for diagnosis.
LOG="$RUN_OUT/symcc.log"
if timeout "$TIMEOUT" env "${ENV_VARS[@]}" "$BIN" < "$SEED" > "$LOG" 2>&1; then
  STATUS="completed"
elif [ $? -eq 124 ]; then
  STATUS="timeout"
else
  STATUS="error"
fi
ELAPSED=$(($(date +%s) - START))

# Count generated inputs
NEW_INPUTS=$(find "$RUN_OUT" -type f ! -name 'symcc.log' | wc -l | tr -d ' ')

echo "[concolic] status=$STATUS elapsed=${ELAPSED}s new_inputs=$NEW_INPUTS"

# Move generated inputs into the output dir with deterministic names.
# Each new input is named: concolic-<seed-hash>-<sequence>.bin
PROMOTED=0
SEQ=0
for f in "$RUN_OUT"/*; do
  [ -f "$f" ] || continue
  case "$f" in
    *symcc.log) continue;;
    *) ;;
  esac
  # SymCC writes inputs as numeric filenames (000001, 000002, ...).
  # Skip empty inputs - they're degenerate.
  [ -s "$f" ] || { rm -f "$f"; continue; }
  DEST="$OUT/concolic-${SEED_HASH}-$(printf '%04d' $SEQ).bin"
  mv "$f" "$DEST"
  SEQ=$((SEQ + 1))
  PROMOTED=$((PROMOTED + 1))
done
rmdir "$RUN_OUT" 2>/dev/null || true

# Emit machine-readable result
cat <<EOF
{
  "seed": "$SEED",
  "seed_hash": "$SEED_HASH",
  "status": "$STATUS",
  "elapsed_seconds": $ELAPSED,
  "new_inputs": $PROMOTED,
  "target_line": "$TARGET_LINE"
}
EOF

if [ "$STATUS" = "completed" ] || [ "$STATUS" = "timeout" ]; then
  exit 0
else
  exit 1
fi
