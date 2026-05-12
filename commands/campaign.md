---
description: Start, resume, or report a fuzzing campaign. Auto-detects campaign state and does the right thing — start fresh if no campaign exists, resume if stopped, report status if already running.
argument-hint: <target-source-or-header> [entry-function] [--budget=20] [--reset]
---

Use the **fuzz-orchestrator** subagent.

Before doing anything else, the orchestrator will:

1. Run `${CLAUDE_PLUGIN_ROOT}/scripts/migrate-state.sh` to handle any schema migrations needed.
2. Run `${CLAUDE_PLUGIN_ROOT}/scripts/check-campaign-state.sh` to classify the current state.
3. Dispatch based on the classification:

| State | Action |
|---|---|
| `none` | COLD start: full ANALYZE → HARNESS → SEED → LAUNCH per the spec |
| `running` | Print status from current.json, do nothing else |
| `stopped` | RESUME: relaunch fuzzer with existing harness/corpus, run one tick |
| `stale` | Refuse to proceed; tell user to use `/cc-fuzzer:campaign --reset` or accept the stale build |
| `corrupted` | Refuse to proceed; print validation errors; tell user to fix or `/cc-fuzzer:reset` |

If `$ARGUMENTS` includes `--reset`, run `${CLAUDE_PLUGIN_ROOT}/scripts/reset-campaign.sh` first (with confirmation), then COLD start.

Target: $ARGUMENTS

The orchestrator must obey **STATE_SCHEMA.md** (`${CLAUDE_PLUGIN_ROOT}/STATE_SCHEMA.md`) for all file paths and JSON shapes.
