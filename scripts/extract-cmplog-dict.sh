#!/usr/bin/env bash
# extract-cmplog-dict.sh
#
# Walks AFL++'s cmplog runtime output and emits a libFuzzer/AFL-format
# dictionary of operands observed at comparison sites. This is "Redqueen lite":
# we let cmplog do its job at runtime, then harvest its observations into a
# dictionary file the LLM agents can read.
#
# Why this script exists:
#   - cmplog's I2S benefit happens inside afl-fuzz automatically (no config).
#   - But the LLM (coverage-analyst, seed-generator) cannot see what cmplog
#     observed; they only see source code and coverage. Surfacing cmplog
#     operands as a dict lets them ground gap classification in runtime
#     evidence: "branch checks magic == 0xDEADBEEF; cmplog already saw that
#     operand, so this is direct_compare, not checksum_barrier."
#
# Output format: libFuzzer/AFL-compatible dictionary (one quoted entry per line).
#
# Usage:
#   extract-cmplog-dict.sh [--aflpp-out <out-dir>] [--output <dict-path>]
#
# Defaults:
#   --aflpp-out  ${FUZZ_OUT_DIR:-out}/default
#   --output     fuzz/state/cmplog-dict-<timestamp>.dict
#
# This script is idempotent and read-only against the AFL++ output directory.
# It does not modify the running fuzzer or its state.

set -u

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
. "$SCRIPT_DIR/_lib/path-anchor.sh"
. "$SCRIPT_DIR/_lib/harness-path.sh"

FUZZ_ROOT="${FUZZ_ROOT:-fuzz}"
STATE_DIR="$FUZZ_ROOT/state"
TS=$(date +%s)

HARNESS=""
AFLPP_OUT=""
OUTPUT=""

while [[ $# -gt 0 ]]; do
  case "$1" in
    --aflpp-out) AFLPP_OUT="$2"; shift 2;;
    --output) OUTPUT="$2"; shift 2;;
    --harness) HARNESS="$2"; shift 2;;
    -h|--help)
      sed -n '2,30p' "$0"
      exit 0
      ;;
    *) echo "ERROR: unknown arg: $1" >&2; exit 2;;
  esac
done

# Multi-mode dispatch: with no --harness in multi mode, recurse once per
# declared harness so callers get a fresh dict for each.
if is_multi && [ -z "$HARNESS" ] && [ -z "$AFLPP_OUT" ]; then
  RC=0
  while IFS= read -r h; do
    [ -n "$h" ] || continue
    bash "$0" --harness "$h" || RC=$?
  done < <(declared_harnesses)
  exit "$RC"
fi

# Default harness in singular mode (ignored by helpers); in multi mode the
# --harness arg has been honored already.
[ -z "$HARNESS" ] && HARNESS=$(default_harness)

# Resolve defaults if not given on CLI
if [ -z "$AFLPP_OUT" ]; then
  if is_multi; then
    AFLPP_OUT="$FUZZ_ROOT/harnesses/$HARNESS/aflpp-out/default"
  else
    AFLPP_OUT="${FUZZ_OUT_DIR:-$PROJECT_ROOT/out}/default"
  fi
fi
if [ -z "$OUTPUT" ]; then
  OUTPUT="$STATE_DIR/$(cmplog_dict_name "$HARNESS" "$TS")"
fi

mkdir -p "$(dirname "$OUTPUT")"

#------------------------------------------------------------------------------
# Find cmplog observation sources.
#
# AFL++ records useful comparison operands in a few places depending on version:
#   1. <out>/default/.cmplog/                — newer AFL++ stores per-op data
#   2. <out>/default/queue/                  — input filenames sometimes carry
#                                              cmp:<addr>,<val> tags via cmplog
#   3. <out>/default/cmplog/                 — older layout
#
# We scan all three, harvest any operand strings/bytes we can find, dedupe,
# and emit a dictionary. If none of the directories exist, the cmplog binary
# wasn't running (or AFL++ is too old to expose this). That's not an error —
# we emit a header-only dict noting the situation.
#------------------------------------------------------------------------------

if [ ! -d "$AFLPP_OUT" ]; then
  echo "ERROR: AFL++ output dir not found: $AFLPP_OUT" >&2
  echo "  (cmplog harvest needs the fuzzer to have run at least once)" >&2
  exit 1
fi

CANDIDATES=(
  "$AFLPP_OUT/.cmplog"
  "$AFLPP_OUT/cmplog"
)

FOUND_ANY=0
RAW_TMP=$(mktemp)
trap 'rm -f "$RAW_TMP"' EXIT

for d in "${CANDIDATES[@]}"; do
  [ -d "$d" ] || continue
  FOUND_ANY=1
  # cmplog data files are typically small binaries; grep printable runs >= 4 chars.
  # We use strings(1) when present, else fall back to grep -aoE.
  if command -v strings >/dev/null 2>&1; then
    find "$d" -type f -print0 | xargs -0 -r strings -n 4 -- 2>/dev/null >> "$RAW_TMP" || true
  else
    find "$d" -type f -print0 | xargs -0 -r grep -ahoE '[ -~]{4,}' >> "$RAW_TMP" 2>/dev/null || true
  fi
done

# Also harvest queue filenames - AFL++ sometimes encodes operand hints in
# them when cmplog or laf-intel is on. Format example:
#   id:000123,src:000045,time:9876,op:havoc,rep:8,+cov
# We don't extract those tags themselves but we do scan the queue file
# CONTENTS for printable runs that look like operand candidates that
# happened to land in the corpus.
if [ -d "$AFLPP_OUT/queue" ]; then
  if command -v strings >/dev/null 2>&1; then
    find "$AFLPP_OUT/queue" -type f -print0 \
      | xargs -0 -r strings -n 4 -- 2>/dev/null \
      | head -c 1048576 >> "$RAW_TMP" || true
  fi
fi

#------------------------------------------------------------------------------
# Dedupe and emit dictionary.
#
# Filtering rules:
#   - Drop entries shorter than 4 bytes (too noisy; likely false positives).
#   - Drop entries longer than 64 bytes (cmplog operands are typically small;
#     long strings are usually corpus data, not comparison operands).
#   - Drop entries containing only whitespace or control chars.
#   - Drop entries that are pure decimal/hex sequences (likely from corpus
#     metadata, not real compare operands worth dictionary-izing).
#   - Cap total entries at 2048 (oversized dicts slow down the fuzzer).
#------------------------------------------------------------------------------

ENTRIES=$(python3 - "$RAW_TMP" <<'PY'
import sys, re
path = sys.argv[1]
seen = set()
out = []
try:
    with open(path, 'r', errors='ignore') as f:
        for line in f:
            s = line.rstrip('\n').rstrip('\r')
            if not (4 <= len(s) <= 64):
                continue
            # Skip pure whitespace / non-printable runs
            if not s.strip():
                continue
            # Skip if mostly digits (likely metadata, not operand)
            digits = sum(1 for c in s if c.isdigit())
            if digits / len(s) > 0.8:
                continue
            # Skip if it looks like a path
            if s.startswith('/') and '/' in s[1:]:
                continue
            if s in seen:
                continue
            seen.add(s)
            out.append(s)
            if len(out) >= 2048:
                break
except FileNotFoundError:
    pass

# Emit AFL/libFuzzer dict format: one "<value>" per line, with C-style escapes.
def escape(s):
    r = []
    for ch in s:
        o = ord(ch)
        if ch == '"':
            r.append('\\"')
        elif ch == '\\':
            r.append('\\\\')
        elif 0x20 <= o < 0x7f:
            r.append(ch)
        else:
            r.append(f'\\x{o:02x}')
    return ''.join(r)

for s in out:
    print(f'"{escape(s)}"')
PY
)

NUM_ENTRIES=$(echo "$ENTRIES" | grep -c '^"' || true)

#------------------------------------------------------------------------------
# Write dict with provenance header.
#------------------------------------------------------------------------------
{
  echo "# cc-fuzzer cmplog-derived dictionary"
  echo "# generated_at: $(date -Iseconds)"
  echo "# source_dir:   $AFLPP_OUT"
  echo "# entries:      $NUM_ENTRIES"
  echo "# format:       libFuzzer / AFL++ dict"
  echo "#"
  echo "# These entries were observed by cmplog at runtime as comparison"
  echo "# operands. The LLM coverage-analyst should treat their presence as"
  echo "# evidence that the corresponding branches are cmplog-solvable"
  echo "# (gap reason: direct_compare), and should NOT dispatch them to"
  echo "# concolic-executor."
  echo "#"
  if [ "$FOUND_ANY" -eq 0 ]; then
    echo "# NOTE: no cmplog directories were found under $AFLPP_OUT."
    echo "#       Either the cmplog binary isn't being passed via -c, or this"
    echo "#       AFL++ version doesn't expose cmplog data on disk. Dictionary"
    echo "#       is empty; coverage-analyst should fall back to source-only"
    echo "#       reasoning for this tick."
  fi
  echo ""
  if [ -n "$ENTRIES" ]; then
    echo "$ENTRIES"
  fi
} > "$OUTPUT"

echo "$OUTPUT"
echo "  entries: $NUM_ENTRIES" >&2
