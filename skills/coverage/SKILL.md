---
name: coverage
description: "Take a coverage snapshot and analyze gaps. Emits a ranked gap report that downstream specialists consume. — usage: [path-to-coverage-snapshot] [--harness <name>] [natural-language guidance...]"
argument-hint: "[path-to-coverage-snapshot] [--harness <name>] [natural-language guidance...]"
---

Under ctxctl the top-level thread cannot run Bash directly. This skill first refreshes header.txt + coverage via **ops-runner**, then dispatches the **coverage-analyst** subagent (Sonnet, ~$0.15-0.25) for the analysis.

## Steps

1. **Refresh header + coverage snapshot.** Dispatch ops-runner:
   ```
   Agent(subagent_type: "ops-runner",
         prompt: "Run two scripts in sequence:
                  Step 1: ${CLAUDE_PLUGIN_ROOT}/scripts/campaign-header.sh > ${FUZZ_STATE_DIR}/header.txt
                  Step 2: ${CLAUDE_PLUGIN_ROOT}/scripts/snapshot-coverage.sh
                  Step 3: ${CLAUDE_PLUGIN_ROOT}/scripts/extract-cmplog-dict.sh (best-effort; OK to fail if no AFL++)
                  Return the captured outputs and the resulting coverage-snapshot path.")
   ```
2. **Dispatch coverage-analyst** with `--harness <name>` (from $ARGUMENTS) and any natural-language guidance also in $ARGUMENTS.
3. Print the analyst's summary to the user.

Output: **`fuzz/state/snapshots/gaps-<ts>.json`** (per-harness in multi mode: `gaps-<harness>-<ts>.json`). Capped at 15 gaps, each classified by `reason` with a `recommended_agent`. The orchestrator selects the recommended specialist on the next tick and emits a `dispatch` directive; the main thread dispatches it.

Additional text in `$ARGUMENTS` is passed to the agent as natural-language guidance (scope focus, skip directives, prioritization hints).

The orchestrator auto-dispatches `coverage-analyst` on plateau. Use this command directly to investigate a stalled campaign, after editing `## Out-of-Scope` in plan.md, or for sanity-checking what the campaign is missing.

Target: $ARGUMENTS
