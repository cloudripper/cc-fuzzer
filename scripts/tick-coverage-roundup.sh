#!/usr/bin/env bash
# tick-coverage-roundup.sh
#
# Aggregates per-harness coverage-*.json snapshots into a single
# tick-coverage-<ts>.json (schema tick-coverage/v1). The orchestrator reads
# this aggregate at the top of every WARM tick instead of re-deriving coverage
# from individual snapshots.
#
# Inputs:
#   fuzz/state/snapshots/coverage-<harness>-<ts>.json
#
# Output:
#   fuzz/state/snapshots/tick-coverage-<ts>.json
#   Echoes the output path to stdout.
#
# Optional env:
#   STALE_THRESHOLD_SECONDS  (default: 600 — flag harnesses whose newest
#                             snapshot is older than this; surfaces silent-
#                             zero instrumentation problems)
#
# Shim onto `cc-fuzzer state roundup` (cc_fuzzer_core.state.roundup).

. "$(dirname "${BASH_SOURCE[0]}")/_lib/root.sh"
exec python3 -m cc_fuzzer_core state roundup
