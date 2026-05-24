---
name: campaign
description: "Start, resume, or report a fuzzing campaign. Auto-detects state and does the right thing. — usage: <target-source-or-header> [entry-function] [--budget=20] [--reset] [--no-coverage]"
argument-hint: "<target-source-or-header> [entry-function] [--budget=20] [--reset] [--no-coverage]"
---

Dispatches the **fuzz-orchestrator** subagent.

Auto-detects campaign state via `${CLAUDE_PLUGIN_ROOT}/scripts/check-campaign-state.sh` and acts accordingly:

| State | Action |
|---|---|
| `none` | COLD start: plan → build harness → seed → launch |
| `running` | Print status from `current.json`; do nothing else |
| `stopped` | RESUME: relaunch existing harness, one tick |
| `stale` | Refuse — target source changed; use `--reset` or accept the stale build |
| `corrupted` | Refuse — print validation errors |

## Flags

- `--reset` — wipe campaign state (with confirmation) before COLD start
- `--no-coverage` — skip the coverage-binary build (orchestrator otherwise refuses to advance without it)
- `--budget=N` — total LLM spend cap, USD (default 20)
- `--add-harness <name> --entry <fn>` — add a harness to an existing campaign
- `--mutator` — request a custom mutator build for highly-structured inputs
- `--refresh-cve` — re-run CVE intelligence before the next plan revision

Target: $ARGUMENTS

State layout and JSON schemas: `${CLAUDE_PLUGIN_ROOT}/STATE_SCHEMA.md`.
