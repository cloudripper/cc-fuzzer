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
. "$SCRIPT_DIR/_lib/harness-path.sh"
FUZZ_ROOT="${FUZZ_ROOT:-fuzz}"
STATE_DIR="$FUZZ_ROOT/state"
CRASHES_NEW="$FUZZ_ROOT/crashes/new"
FLAKY="$FUZZ_ROOT/crashes/flaky"

# Parse --harness early; remaining positional args are explicit input files.
HARNESS_NAME=""
INPUT_ARGS=()
while [ $# -gt 0 ]; do
  case "$1" in
    --harness) HARNESS_NAME="${2:-}"; shift 2 ;;
    -h|--help) sed -n '2,/^$/p' "$0" | sed 's/^# \?//'; exit 0 ;;
    *)         INPUT_ARGS+=("$1"); shift ;;
  esac
done

# Resolve target harness from --harness (or current.json's active_harness as
# fallback).
if [ -z "$HARNESS_NAME" ] && [ -f "$STATE_DIR/current.json" ]; then
  HARNESS_NAME=$(python3 -c "
import json
try: print(json.load(open('$STATE_DIR/current.json')).get('active_harness',''))
except: pass" 2>/dev/null)
fi
if [ -z "$HARNESS_NAME" ]; then
  echo "ERROR: --harness <name> not provided and current.json has no active_harness" >&2
  exit 1
fi
if ! is_known_harness "$HARNESS_NAME"; then
  echo "ERROR: harness '$HARNESS_NAME' is not declared in fuzz-config.json:harnesses[]" >&2
  exit 1
fi

CORPUS_DIR=$(corpus_dir   "$HARNESS_NAME")
QUAR_DIR=$(quarantine_dir "$HARNESS_NAME")
REJECTED_DIR="$QUAR_DIR/rejected"

mkdir -p "$CORPUS_DIR" "$QUAR_DIR" "$REJECTED_DIR" "$CRASHES_NEW" "$FLAKY"

# Resolve the per-harness harness binary
HARNESS=$(harness_binary "$HARNESS_NAME")
if [ -z "$HARNESS" ] || [ ! -x "$HARNESS" ]; then
  echo "ERROR: harness binary missing or not executable: $HARNESS" >&2
  exit 1
fi

# Determine input set
if [ "${#INPUT_ARGS[@]}" -gt 0 ]; then
  inputs=("${INPUT_ARGS[@]}")
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
REJECTED=0

for f in "${inputs[@]}"; do
  [ -f "$f" ] || continue

  # Pre-flight: seed-safety scan. If the file contains an unambiguous
  # destructive payload (rm -rf /, fork bomb, mkfs on a real block device,
  # dd to a real block device, etc), refuse to run the harness on it and
  # move it to corpus-quarantine/rejected/. The scanner is conservative —
  # ordinary parser-fuzz inputs won't trip it. Override with the env var
  # CCFUZZ_ALLOW_DESTRUCTIVE_SEEDS=1 if you have a sandboxed campaign that
  # legitimately needs destructive payloads.
  set +e
  SAFETY_OUT=$(bash "$SCRIPT_DIR/check-seed-safety.sh" "$f" 2>/dev/null)
  SAFETY_RC=$?
  set -e
  if [ "$SAFETY_RC" -eq 3 ]; then
    base=$(basename "$f")
    mv "$f" "$REJECTED_DIR/$base"
    echo "$SAFETY_OUT" | sed "s|^|REJECTED: |"
    REJECTED=$((REJECTED + 1))
    continue
  fi

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
      # Crashed - hard-link content-addressable into crashes/new/. The filename
      # carries the harness prefix so the triager attributes the crash to the
      # right harness (matches detect-crashes.sh's shape).
      base=$(basename "$f")
      hash=$(sha256sum "$f" | cut -c1-16)
      stage_name=$(crash_filename "$HARNESS_NAME" "$hash")
      target="$CRASHES_NEW/$stage_name"
      if [ ! -f "$target" ]; then
        ln "$f" "$target" 2>/dev/null || cp "$f" "$target"
      fi
      mv "$f" "$FLAKY/$base"  # the original goes to flaky as a duplicate
      CRASHED=$((CRASHED + 1))
      ;;
  esac
done

echo "promoted=$PROMOTED   crashed=$CRASHED (-> crashes/new/)   hung=$HUNG (-> flaky/)   rejected=$REJECTED (-> corpus-quarantine/rejected/)"
exit 0
