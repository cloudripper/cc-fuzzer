#!/usr/bin/env bash
# update-current.sh
#
# Atomically rewrites fuzz/state/current.json with everything the orchestrator
# needs to make a tick decision. Called after any state change (snapshot,
# triage, seed gen). The orchestrator reads ONLY this file on warm ticks -
# no source code, no harness inspection, no walking history.
#
# This is the efficiency lever. If the orchestrator can decide from this one
# file, a tick costs 1-3k tokens instead of 30-50k.
#
# Structure: this script is a thin driver. The composition lives in
# _lib/build_current_multi.py, which reads the campaign state and writes
# current.json (cc-fuzzer-current/v2). The derived blocks (tick_coverage /
# consult_state / yolo_state) are merged afterward by _lib/derive-tick-state.py.

set -u

# Path anchor - refuses cwd inside fuzz/, refuses recursive fuzz/fuzz/
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
. "$SCRIPT_DIR/_lib/path-anchor.sh"
. "$SCRIPT_DIR/_lib/harness-path.sh"
STATE_DIR="${FUZZ_STATE_DIR:-fuzz/state}"
SNAPSHOTS_DIR="$STATE_DIR/snapshots"
mkdir -p "$STATE_DIR" "$SNAPSHOTS_DIR"

OUT="$STATE_DIR/current.json"
TMP="$STATE_DIR/.current.json.tmp"

# Refresh the tick-coverage roundup BEFORE composing current.json. The roundup
# is the canonical aggregate the orchestrator consumes; without it, multi-
# harness tick reports show inconsistent per-harness coverage.
if [ -x "$SCRIPT_DIR/tick-coverage-roundup.sh" ]; then
  bash "$SCRIPT_DIR/tick-coverage-roundup.sh" >/dev/null 2>&1 || true
fi

NOW=$(date +%s)

# Compose current.json (schema v12, multi-only): walk declared harnesses and
# write current/v2. The module writes the file atomically (via $TMP -> $OUT)
# and prints the output path, which we suppress here and re-emit once on success.
DECLARED="$(declared_harnesses)" \
STATE_DIR="$STATE_DIR" SNAPSHOTS_DIR="$SNAPSHOTS_DIR" NOW="$NOW" TMP="$TMP" OUT="$OUT" \
  python3 "$SCRIPT_DIR/_lib/build_current_multi.py" >/dev/null
RC=$?

# Merge the mode-agnostic derived blocks (best-effort; never wedges a tick).
python3 "$SCRIPT_DIR/_lib/derive-tick-state.py" "$OUT" >/dev/null 2>&1 || true

[ "$RC" -eq 0 ] && echo "$OUT"
exit "$RC"
