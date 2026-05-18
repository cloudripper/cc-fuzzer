#!/usr/bin/env bash
# run-fuzzer.sh
#
# Launches the campaign's fuzzer(s). In v0.17+ this script is a dispatcher
# that reads fuzz/state/fuzz-config.json (schema fuzz-config/v2) and, for
# each entry in `fuzzer_slots`, invokes scripts/launch-fuzzer-slot.sh.
#
# Backward-compat:
#   - When `fuzzer_slots` is missing or empty, a single slot named "main"
#     is launched with engine auto-detected from the binary. This matches
#     v0.15/v0.16 single-fuzzer behavior exactly.
#   - The legacy CLI `run-fuzzer.sh <binary> [corpus]` still works and
#     forces single-slot mode using the given binary.
#
# Usage:
#   run-fuzzer.sh                          # use harness-built.json + config slots
#   run-fuzzer.sh <binary> [corpus-dir]    # legacy single-binary form (slot=main)
#   run-fuzzer.sh --slot <name> --binary <path> [--corpus <dir>]
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

# Parse args. Supports the legacy positional form `<binary> [corpus]` as well
# as the explicit `--slot N --binary P --corpus C` form. The slot flag is the
# escape hatch that lets a caller launch a second harness without killing the
# first one (see commit history / v0.17.0 release notes).
CLI_BIN=""
CLI_CORPUS=""
CLI_SLOT=""
EXPLICIT_SLOT=false
while [ $# -gt 0 ]; do
  case "$1" in
    --slot)    CLI_SLOT="${2:-}";   EXPLICIT_SLOT=true; shift 2 ;;
    --binary)  CLI_BIN="${2:-}";    shift 2 ;;
    --corpus)  CLI_CORPUS="${2:-}"; shift 2 ;;
    --help|-h)
      sed -n '2,/^$/p' "$0" | sed 's/^# \?//'
      exit 0
      ;;
    --*)
      echo "ERROR: unknown flag '$1' (expected --slot|--binary|--corpus)" >&2
      exit 2
      ;;
    *)
      # Legacy positional: first positional is binary, second is corpus.
      if [ -z "$CLI_BIN" ]; then CLI_BIN="$1"
      elif [ -z "$CLI_CORPUS" ]; then CLI_CORPUS="$1"
      else echo "ERROR: unexpected positional arg '$1'" >&2; exit 2
      fi
      shift
      ;;
  esac
done
CLI_CORPUS="${CLI_CORPUS:-fuzz/corpus}"

# Stop existing slots before launching.
#   - Explicit per-slot form (--slot or legacy positional with single binary):
#     stop ONLY that slot, leaving other running slots intact. This is what
#     makes side-by-side multi-binary campaigns work.
#   - No CLI binary (config-driven reload): wipe everything and rebuild from
#     fuzz-config.json. This preserves the v0.16 kill-all semantics for the
#     config-replacement code path.
TARGET_SLOT="${CLI_SLOT:-main}"
if [ -n "$CLI_BIN" ]; then
  # Single-slot stop. stop-fuzzer.sh --slot handles "no such slot" cleanly.
  if [ -x "$SCRIPT_DIR/stop-fuzzer.sh" ]; then
    bash "$SCRIPT_DIR/stop-fuzzer.sh" --slot "$TARGET_SLOT" >/dev/null 2>&1 || true
  fi
elif [ -f "$STATE_DIR/fuzzers.json" ] || ls "$STATE_DIR"/fuzzer-*.pid >/dev/null 2>&1 \
     || [ -f "$STATE_DIR/fuzzer.pid" ] || [ -f "$STATE_DIR/harness-built.json" ]; then
  bash "$SCRIPT_DIR/kill-harness-processes.sh" --quiet >/dev/null 2>&1 || true
fi

# Resolve harness binary. In singular mode (or legacy CLI form), this is a
# single campaign-wide binary. In multi mode, each slot binds to its own
# harness and resolves its own binary — so we don't compute one here.
HARNESS_BIN=""
if [ -n "$CLI_BIN" ]; then
  HARNESS_BIN="$CLI_BIN"
elif ! is_multi; then
  if [ -f "$STATE_DIR/harness-built.json" ]; then
    HARNESS_BIN=$(python3 -c "
import json
try: print(json.load(open('$STATE_DIR/harness-built.json')).get('harness_binary',''))
except: pass" 2>/dev/null)
  fi
  if [ -z "$HARNESS_BIN" ] || [ ! -x "$HARNESS_BIN" ]; then
    echo "ERROR: harness binary missing or not executable: '$HARNESS_BIN'" >&2
    echo "       run /fuzz:harness first, or pass a binary as the first arg" >&2
    exit 1
  fi
fi

CORPUS="$CLI_CORPUS"

# Resolve slot list. If CLI arg was passed, force single-slot mode.
SLOTS_JSON=""
if [ -z "$CLI_BIN" ] && [ -f "$STATE_DIR/fuzz-config.json" ]; then
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

# Default to single 'main' slot if no slot config
NUM_SLOTS=$(python3 -c "import json,sys; print(len(json.loads(sys.argv[1] or '[]')))" "${SLOTS_JSON:-[]}" 2>/dev/null || echo 0)
if [ "$NUM_SLOTS" -eq 0 ]; then
  # No fuzzer_slots[] declared → single 'main' slot.
  # In multi mode this branch shouldn't usually fire (fuzz-config.json:
  # fuzzer_slots[] should be populated for any multi-harness campaign), but
  # if it does, default to launching on the first declared harness.
  args=(--slot "$TARGET_SLOT" --engine auto --corpus "$CORPUS")
  if is_multi; then
    fallback=$(default_harness)
    if [ -z "$fallback" ]; then
      echo "ERROR: multi mode but no slots declared and no default harness resolvable" >&2
      exit 1
    fi
    args+=(--harness "$fallback")
  else
    args+=(--binary "$HARNESS_BIN")
  fi
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
    ]))
" | while IFS='|' read -r slot engine role schedule lf_forks slot_harness; do
    args=(--slot "$slot" --engine "$engine" --corpus "$CORPUS")
    # In multi mode the slot's binary is per-harness; pass --harness and let
    # launch-fuzzer-slot.sh resolve. In singular mode pass --binary directly.
    if is_multi; then
      if [ -z "$slot_harness" ]; then
        echo "ERROR: slot=$slot has no harness binding in multi mode" >&2
        RC=1
        continue
      fi
      args+=(--harness "$slot_harness")
    else
      args+=(--binary "$HARNESS_BIN")
    fi
    [ -n "$role" ]      && args+=(--role "$role")
    [ -n "$schedule" ]  && args+=(--power-schedule "$schedule")
    [ -n "$lf_forks" ]  && args+=(--libfuzzer-forks "$lf_forks")
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
