---
name: campaign
description: "Start, resume, or report a fuzzing campaign. Auto-detects state and does the right thing. — usage: <target-source-or-header> [entry-function] [--budget=20] [--reset] [--no-coverage]"
argument-hint: "<target-source-or-header> [entry-function] [--budget=20] [--reset] [--no-coverage]"
---

Dispatches the **fuzz-orchestrator** subagent.

Auto-detects campaign state via `${CLAUDE_PLUGIN_ROOT}/scripts/check-campaign-state.sh` and acts accordingly:

| State | Action |
|---|---|
| `none` | COLD start: plan → declare harness set → build harness → seed → launch (multi-harness layout from the start) |
| `running` | Print status from `current.json`; do nothing else |
| `stopped` | RESUME: relaunch existing harness, one tick |
| `stale` | Refuse — target source changed; use `--reset` or accept the stale build |
| `corrupted` | Refuse — print validation errors |

The target argument is **required for `guided`/`hybrid`**, but **optional under autonomous `self_loop` YOLO**: with no target given, the `campaign-planner` self-selects one from the project (see campaign-planner "Autonomous target selection") and never asks the user.

## Flags

- `--reset` — wipe campaign state (with confirmation) before COLD start
- `--no-coverage` — skip the coverage-binary build (orchestrator otherwise refuses to advance without it)
- `--budget=N` — total LLM spend cap, USD (default 20)
- `--add-harness <name> --entry <fn>` — add a harness to an existing campaign. On a v0.19.2+ campaign (already multi-harness) this just appends: `harness-set.sh add` then `harness-writer --harness <name>`. A legacy singular campaign first needs the in-place singular→multi upgrade (see STATE_SCHEMA.md "Singular → multi upgrade").
- `--mutator` — request a custom mutator build for highly-structured inputs
- `--refresh-cve` — re-run CVE intelligence before the next plan revision

Target: $ARGUMENTS

State layout and JSON schemas: `${CLAUDE_PLUGIN_ROOT}/STATE_SCHEMA.md`.

## After a COLD start: auto-start the YOLO loop

A campaign doesn't drive itself — the fuzzer runs in the background, but LLM ticks only advance when something fires them. If YOLO is enabled (`yolo.enabled: true` in `fuzz/state/fuzz-config.json`, e.g. the user ran `/cc-fuzzer:yolo on` before this) when a COLD start completes, **immediately start the self-loop**: perform one tick now by following the `/cc-fuzzer:tick` flow (dispatch `fuzz-orchestrator` for one WARM tick, then chain via `ScheduleWakeup` per its `YOLO_NEXT:` line). Then tell the user:

> "Campaign started and YOLO `<mode>` is self-driving — first tick ran now, next in ~`<interval>`. It continues unattended until a hard halt (tick / cost / no-progress / crash-storm cap) or `/cc-fuzzer:yolo off` / `/cc-fuzzer:stop`."

If YOLO is **off**, say nothing about loops — the campaign runs in the background and the user advances it with `/cc-fuzzer:tick`, or starts the self-loop with `/cc-fuzzer:yolo on`.
