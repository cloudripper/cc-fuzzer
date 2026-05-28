#!/usr/bin/env bash
# ceiling-probe.sh
#
# Deterministic "is this a real coverage ceiling?" probe (no LLM). Cross-references
# the latest coverage snapshot's uncovered functions against gap reasons, code-review
# findings, CVE hotspots, and engine/gap-mix fit to decide whether a plateau is a
# genuine ceiling or just an exhausted *harness design* that needs a reshape
# (entry swap / new harness / mock) or an engine change (libFuzzer → AFL++/Redqueen).
#
# Writes fuzz/state/snapshots/ceiling-probe-<ts>.json (schema ceiling-probe/v1) and
# prints the block to stdout. The same computation is folded into
# current.json.yolo_state.evaluation.ceiling_probe every tick by update-current.sh
# (via yolo_evaluate) — run this script directly only when you want a fresh snapshot
# on disk (e.g. for the pre-halt planner-consult briefing).
#
# Usage: ceiling-probe.sh   (reads fuzz/state/current.json)
set -u

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
. "$SCRIPT_DIR/_lib/path-anchor.sh"

STATE_DIR="${FUZZ_STATE_DIR:-$FUZZ_ROOT/state}"
CUR="$STATE_DIR/current.json"

if [ ! -f "$CUR" ]; then
  echo "ceiling-probe: no current.json at $CUR — run a tick first." >&2
  exit 1
fi

PYTHONPATH="$SCRIPT_DIR/_lib${PYTHONPATH:+:$PYTHONPATH}" \
  python3 "$SCRIPT_DIR/_lib/ceiling_probe.py" "$CUR"
