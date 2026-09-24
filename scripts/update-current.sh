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
# Shim onto `cc-fuzzer state update-current` (cc_fuzzer_core.state.update_current):
# refresh the tick-coverage roundup, compose current.json (cc-fuzzer-current/v2,
# state/build_current.py), then merge the derived tick_coverage / consult_state /
# yolo_state blocks (state/derive_tick.py). Prints the current.json path
# (project-relative) on success.

. "$(dirname "${BASH_SOURCE[0]}")/_lib/root.sh"
exec python3 -m cc_fuzzer_core state update-current
