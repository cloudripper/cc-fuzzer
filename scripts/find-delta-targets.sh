#!/usr/bin/env bash
# find-delta-targets.sh
#
# Computes git-diff-based "recently changed" targets for the active campaign.
# Pure local tooling - no LLM, no fuzzer interruption.
#
# Output: fuzz/state/snapshots/delta-<ts>.json (schema delta-targets/v1)
#
# Usage:
#   find-delta-targets.sh                        # auto-pick range
#   find-delta-targets.sh --range main..HEAD     # explicit range
#
# Auto-pick rules (in order):
#   1. main..HEAD     if `main` exists and HEAD != main
#   2. master..HEAD   if `master` exists and HEAD != master
#   3. HEAD~30..HEAD  fallback (any repo with >=30 commits)
#
# The artifact is OPTIONAL. coverage-analyst consumes it when present and
# ignores delta weighting when absent. There is no implicit enabling.
#
# Shim onto the core's port, `cc-fuzzer delta find` (cc_fuzzer_core.delta).

. "$(dirname "${BASH_SOURCE[0]}")/_lib/root.sh"
exec python3 -m cc_fuzzer_core delta find "$@"
