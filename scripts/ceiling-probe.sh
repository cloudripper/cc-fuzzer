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
#
# Shim onto `cc-fuzzer state ceiling-probe` (cc_fuzzer_core.state.ceiling.probe).

. "$(dirname "${BASH_SOURCE[0]}")/_lib/root.sh"
exec python3 -m cc_fuzzer_core state ceiling-probe
