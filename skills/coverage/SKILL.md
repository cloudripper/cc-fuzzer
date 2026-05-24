---
name: coverage
description: "Take a coverage snapshot and analyze gaps. Emits a ranked gap report that downstream specialists consume. — usage: [path-to-coverage-snapshot] [--harness <name>] [natural-language guidance...]"
argument-hint: "[path-to-coverage-snapshot] [--harness <name>] [natural-language guidance...]"
disable-model-invocation: true
---

Refreshes coverage via `${CLAUDE_PLUGIN_ROOT}/scripts/snapshot-coverage.sh`, extracts the cmplog dictionary via `extract-cmplog-dict.sh`, then dispatches the **coverage-analyst** subagent (Sonnet, ~$0.15-0.25).

Output: **`fuzz/state/snapshots/gaps-<ts>.json`** (per-harness in multi mode: `gaps-<harness>-<ts>.json`). Capped at 15 gaps, each classified by `reason` with a `recommended_agent`. The orchestrator dispatches the recommended specialists on the next tick.

Additional text in `$ARGUMENTS` is passed to the agent as natural-language guidance (scope focus, skip directives, prioritization hints).

The orchestrator auto-dispatches `coverage-analyst` on plateau. Use this command directly to investigate a stalled campaign, after editing `## Out-of-Scope` in plan.md, or for sanity-checking what the campaign is missing.

Target: $ARGUMENTS
