---
description: Take a coverage snapshot and analyze gaps. Emits machine-readable gap report that seed-generator/harness-writer can consume.
argument-hint: [path-to-coverage-report-or-fuzzer-output-dir]
---

First, run `${CLAUDE_PLUGIN_ROOT}/scripts/snapshot-coverage.sh` to generate the latest snapshot. Then use the **coverage-analyst** subagent on the resulting `fuzz/state/coverage-<ts>.json` (or the path supplied in $ARGUMENTS).

The analyst writes `fuzz/state/gaps-<ts>.json` with up to 15 ranked uncovered branches and a recommended fix per branch. The orchestrator (or you) can then dispatch the recommended agents to apply those fixes.
