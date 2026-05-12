#!/usr/bin/env bash
# corpus-quarantine.sh
#
# Validates inputs in fuzz/corpus-quarantine/ and promotes the safe ones into
# fuzz/corpus/. Inputs that crash the harness go to fuzz/crashes/new/ for
# triage. Inputs that hang go to fuzz/crashes/flaky/.
#
# This prevents the launch-blocker we hit in the findutils campaign: a crashing
# seed in fuzz/corpus/ kills libFuzzer at startup before it can do anything.
# All new corpus entries (from seed-generator, concolic-executor) MUST pass
# through this script before reaching fuzz/corpus/.
#
# Usage:
#   corpus-quarantine.sh                # process all files in corpus-quarantine/
#   corpus-quarantine.sh <file> [...]   # process specific files
#
# Exit code:
#   0 if all inputs were classified successfully
#   1 if the harness binary is missing or unrunnable

set -u

# Path anchor - refuses cwd inside fuzz/, refuses recursive fuzz/fuzz/
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
. "$SCRIPT_DIR/_lib/path-anchor.sh"
FUZZ_ROOT="${FUZZ_ROOT:-fuzz}"
STATE_DIR="$FUZZ_ROOT/state"
CORPUS_DIR="$FUZZ_ROOT/corpus"
QUAR_DIR="$FUZZ_ROOT/corpus-quarantine"
CRASHES_NEW="$FUZZ_ROOT/crashes/new"
FLAKY="$FUZZ_ROOT/crashes/flaky"
HARNESS_INFO="$STATE_DIR/harness-built.json"

mkdir -p "$CORPUS_DIR" "$QUAR_DIR" "$CRASHES_NEW" "$FLAKY"

# Resolve the harness binary
if [ ! -f "$HARNESS_INFO" ]; then
  echo "ERROR: $HARNESS_INFO not found - no campaign" >&2
  exit 1
fi
HARNESS=$(python3 -c "
import json
try: print(json.load(open('$HARNESS_INFO')).get('harness_binary', ''))
except: pass
" 2>/dev/null)
if [ -z "$HARNESS" ] || [ ! -x "$HARNESS" ]; then
  echo "ERROR: harness binary missing or not executable: $HARNESS" >&2
  exit 1
fi

# Determine input set
if [ "$#" -gt 0 ]; then
  inputs=("$@")
else
  inputs=()
  while IFS= read -r f; do
    inputs+=("$f")
  done < <(find "$QUAR_DIR" -maxdepth 1 -type f 2>/dev/null)
fi

if [ "${#inputs[@]}" -eq 0 ]; then
  echo "(no inputs to quarantine)"
  exit 0
fi

# Classify each input
PROMOTED=0
CRASHED=0
HUNG=0

for f in "${inputs[@]}"; do
  [ -f "$f" ] || continue

  # Run with a tight timeout. ASan output goes to stderr; we don't capture
  # it here but the exit code tells us what happened.
  #   0   = clean
  #   1   = libFuzzer rejected input (treat as clean - just unusual shape)
  #   77  = libFuzzer crash (asan/ubsan/abort)
  #   124 = timeout (the `timeout` command's exit code)
  #   137 = SIGKILL from --kill-after guard (definite hang)
  # Other non-zero exits are uncategorized; treat as flaky.
  #
  # --kill-after=2: if the process is still alive 2s after the SIGTERM from
  # `timeout`, send SIGKILL. Prevents quarantine from stalling on frozen children.
  set +e
  timeout --kill-after=2 10 "$HARNESS" "$f" >/dev/null 2>&1
  rc=$?
  set -e

  case "$rc" in
    0|1)
      # Safe to promote
      base=$(basename "$f")
      mv "$f" "$CORPUS_DIR/$base"
      PROMOTED=$((PROMOTED + 1))
      ;;
    124|137)
      # Hang (timeout or SIGKILL) - move to flaky for inspection
      base=$(basename "$f")
      mv "$f" "$FLAKY/$base"
      HUNG=$((HUNG + 1))
      ;;
    *)
      # Crashed - hard-link content-addressable into crashes/new/
      base=$(basename "$f")
      hash=$(sha256sum "$f" | cut -c1-16)
      target="$CRASHES_NEW/$hash.bin"
      if [ ! -f "$target" ]; then
        ln "$f" "$target" 2>/dev/null || cp "$f" "$target"
      fi
      mv "$f" "$FLAKY/$base"  # the original goes to flaky as a duplicate
      CRASHED=$((CRASHED + 1))
      ;;
  esac
done

echo "promoted=$PROMOTED   crashed=$CRASHED (-> crashes/new/)   hung=$HUNG (-> flaky/)"
exit 0
