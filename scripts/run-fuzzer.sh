#!/usr/bin/env bash
# run-fuzzer.sh
#
# Launches the campaign's fuzzer(s). This script is a dispatcher that reads
# fuzz/state/fuzz-config.json (schema fuzz-config/v3) and, for each entry in
# `fuzzer_slots`, invokes scripts/launch-fuzzer-slot.sh. Every campaign is
# multi-harness (schema v12); each slot binds to a declared harness and the
# launcher resolves the slot's binary/corpus per-harness.
#
# Usage:
#   run-fuzzer.sh                          # launch every slot in fuzz-config.json
#   run-fuzzer.sh --slot <name> --harness <h> [--corpus <dir>] [--binary <path>]
#                                          # explicit per-slot form (does NOT
#                                          # touch other slots — safe for
#                                          # running two harnesses side by side)
#
# Engine detection (auto):
#   - If the binary itself is a libFuzzer runner (has LLVMFuzzerTestOneInput),
#     run it directly with libFuzzer flags.
#   - Else if afl-fuzz is available, use AFL++.
#
# Forbidden flags (refused at startup by launch-fuzzer-slot.sh):
#   -ignore_crashes=1     suppresses crash recording, defeats the whole point
#   -detect_leaks=0       disables ASan leak detection
#   -detect_odr_violation=0
#   ASAN_OPTIONS containing abort_on_error=0 or detect_leaks=0
#
# These flags have been added by past agents "to keep the fuzzer running" and
# each time they caused real damage (silent crash loss in the findutils campaign).
# The whitelist is intentional and not user-configurable from this script.

set -u

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
. "$SCRIPT_DIR/_lib/path-anchor.sh"
. "$SCRIPT_DIR/_lib/harness-path.sh"
STATE_DIR="${FUZZ_STATE_DIR:-$FUZZ_ROOT/state}"
mkdir -p "$STATE_DIR"

# Parse args. The explicit `--slot N --harness H [--corpus C] [--binary P]`
# form is the escape hatch that lets a caller launch a single harness without
# killing the others. With no args, every slot in fuzz-config.json is launched.
CLI_BIN=""
CLI_CORPUS=""
CLI_SLOT=""
CLI_HARNESS=""
EXPLICIT_SLOT=false
while [ $# -gt 0 ]; do
  case "$1" in
    --slot)    CLI_SLOT="${2:-}";    EXPLICIT_SLOT=true; shift 2 ;;
    --harness) CLI_HARNESS="${2:-}"; shift 2 ;;
    --binary)  CLI_BIN="${2:-}";     shift 2 ;;
    --corpus)  CLI_CORPUS="${2:-}";  shift 2 ;;
    --help|-h)
      sed -n '2,/^$/p' "$0" | sed 's/^# \?//'
      exit 0
      ;;
    *)
      echo "ERROR: unknown arg '$1' (expected --slot|--harness|--binary|--corpus)" >&2
      exit 2
      ;;
  esac
done
# Do NOT default the corpus here. Each slot's corpus is per-harness and is
# resolved by launch-fuzzer-slot.sh from --harness; forcing a corpus at this
# level would bypass fuzz/harnesses/<name>/corpus. Forward --corpus downstream
# ONLY when the caller explicitly set one.
EXPLICIT_CORPUS=false
[ -n "$CLI_CORPUS" ] && EXPLICIT_CORPUS=true

# Stop existing slots before launching.
#   - Explicit per-slot form (--slot): stop ONLY that slot, leaving other
#     running slots intact. This is what makes side-by-side multi-harness
#     campaigns work.
#   - No --slot (config-driven reload): wipe everything and rebuild from
#     fuzz-config.json (kill-all semantics for the config-replacement path).
TARGET_SLOT="${CLI_SLOT:-main}"
if [ "$EXPLICIT_SLOT" = true ]; then
  # Single-slot stop. stop-fuzzer.sh --slot handles "no such slot" cleanly.
  if [ -x "$SCRIPT_DIR/stop-fuzzer.sh" ]; then
    bash "$SCRIPT_DIR/stop-fuzzer.sh" --slot "$TARGET_SLOT" >/dev/null 2>&1 || true
  fi
elif [ -f "$STATE_DIR/fuzzers.json" ] || ls "$STATE_DIR"/fuzzer-*.pid >/dev/null 2>&1 \
     || [ -f "$STATE_DIR/harness-built.json" ]; then
  bash "$SCRIPT_DIR/kill-harness-processes.sh" --quiet >/dev/null 2>&1 || true
fi

# Each slot binds to a declared harness; launch-fuzzer-slot.sh resolves the
# slot's binary and corpus per-harness. We never compute a campaign-wide binary.

# Resolve slot list. With an explicit --slot, launch only that one slot.
SLOTS_JSON=""
if [ "$EXPLICIT_SLOT" != true ] && [ -f "$STATE_DIR/fuzz-config.json" ]; then
  SLOTS_JSON=$(python3 -c "
import json
try:
    d = json.load(open('$STATE_DIR/fuzz-config.json'))
    slots = d.get('fuzzer_slots') or []
    print(json.dumps(slots))
except Exception:
    print('[]')
" 2>/dev/null)
fi

NUM_SLOTS=$(python3 -c "import json,sys; print(len(json.loads(sys.argv[1] or '[]')))" "${SLOTS_JSON:-[]}" 2>/dev/null || echo 0)
if [ "$EXPLICIT_SLOT" = true ] || [ "$NUM_SLOTS" -eq 0 ]; then
  # Explicit single-slot launch (or no fuzzer_slots[] declared). Bind to the
  # given harness, else the first declared harness.
  HARNESS_TO_USE="$CLI_HARNESS"
  [ -z "$HARNESS_TO_USE" ] && HARNESS_TO_USE=$(default_harness)
  if [ -z "$HARNESS_TO_USE" ]; then
    echo "ERROR: no --harness given and no declared harness resolvable" >&2
    echo "       run 'harness-set.sh init --entry <fn>' + harness-writer first" >&2
    exit 1
  fi
  args=(--slot "$TARGET_SLOT" --engine auto --harness "$HARNESS_TO_USE")
  # Per-harness corpus is resolved by launch-fuzzer-slot.sh from --harness; only
  # forward an explicitly-requested corpus/binary (overrides).
  $EXPLICIT_CORPUS && args+=(--corpus "$CLI_CORPUS")
  [ -n "$CLI_BIN" ] && args+=(--binary "$CLI_BIN")
  bash "$SCRIPT_DIR/launch-fuzzer-slot.sh" "${args[@]}"
  RC=$?
else
  RC=0
  python3 -c "import json,sys; print(json.dumps(json.loads(sys.argv[1])))" "$SLOTS_JSON" | python3 -c "
import json, sys
data = json.load(sys.stdin)
for entry in data:
    print('|'.join([
        entry.get('slot','main'),
        entry.get('engine','auto'),
        entry.get('role','') or '',
        entry.get('afl_power_schedule','') or '',
        str(entry.get('libfuzzer_forks','') if entry.get('libfuzzer_forks') is not None else ''),
        entry.get('harness','') or '',
        str(entry.get('timeout_ms','') if entry.get('timeout_ms') is not None else ''),
    ]))
" | while IFS='|' read -r slot engine role schedule lf_forks slot_harness timeout_ms; do
    args=(--slot "$slot" --engine "$engine")
    # The slot's binary AND corpus are per-harness; pass --harness and let
    # launch-fuzzer-slot.sh resolve both. Do NOT pass --corpus here.
    if [ -z "$slot_harness" ]; then
      echo "ERROR: slot=$slot has no harness binding" >&2
      RC=1
      continue
    fi
    args+=(--harness "$slot_harness")
    # Only forward an explicitly-requested corpus (override); otherwise the
    # launcher resolves the per-harness corpus.
    $EXPLICIT_CORPUS && args+=(--corpus "$CLI_CORPUS")
    [ -n "$role" ]      && args+=(--role "$role")
    [ -n "$schedule" ]  && args+=(--power-schedule "$schedule")
    [ -n "$lf_forks" ]  && args+=(--libfuzzer-forks "$lf_forks")
    [ -n "$timeout_ms" ] && args+=(--timeout-ms "$timeout_ms")
    if ! bash "$SCRIPT_DIR/launch-fuzzer-slot.sh" "${args[@]}"; then
      echo "WARN: launch failed for slot=$slot${slot_harness:+ harness=$slot_harness}" >&2
      RC=1
    fi
  done
fi

# Refresh current.json so the orchestrator sees the new state on its next tick
if [ -x "$SCRIPT_DIR/update-current.sh" ]; then
  FUZZ_STATE_DIR="$STATE_DIR" bash "$SCRIPT_DIR/update-current.sh" >/dev/null 2>&1 || true
fi

exit "$RC"
