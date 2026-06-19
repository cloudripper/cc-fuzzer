---
name: campaign
description: "Start, resume, or report a fuzzing campaign. Auto-detects state and does the right thing. — usage: <target-source-or-header> [entry-function] [--budget=20] [--reset] [--no-coverage]"
argument-hint: "<target-source-or-header> [entry-function] [--budget=20] [--reset] [--no-coverage]"
---

Dispatches the **fuzz-orchestrator** subagent to *decide* the next campaign step; **the main thread performs each step** (the orchestrator has no `Agent` tool and cannot dispatch specialists). Under ctxctl the top-level thread cannot run Bash; the orchestrator (a subagent) runs `check-campaign-state.sh` itself.

**COLD is a main-thread-driven chain.** A cold start is `campaign-planner → harness-writer → seed-generator → launch`, and each of those is a specialist or a launch the main thread must perform. So the loop is: dispatch the orchestrator → it returns one `YOLO_NEXT:` directive naming the next step → the main thread performs it (specialist via `Agent`, bash lever via `ops-runner`) → re-dispatch the orchestrator for the step after → … until it emits `done` (cold start complete) or, under YOLO, a `schedule` that begins the WARM tick chain. Parse and perform each directive exactly as in `${CLAUDE_PLUGIN_ROOT}/skills/tick/SKILL.md` ("Performing the directive"). The directive vocabulary is in `${CLAUDE_PLUGIN_ROOT}/STATE_SCHEMA.md`.

**Header anchor.** Before dispatching the orchestrator, refresh the campaign-header digest so the orchestrator and any specialists it dispatches see current shared context:

```
Agent(subagent_type: "ops-runner",
      prompt: "Run ${CLAUDE_PLUGIN_ROOT}/scripts/campaign-header.sh > ${FUZZ_STATE_DIR}/header.txt and report the captured header.")
```

If this is a fresh project (no `fuzz/state/` yet), the header script prints a minimal "no campaign initialized" digest and exits 0 — that's fine for COLD start. Skip the refresh on `--reset` because state's about to be wiped.

Then dispatch fuzz-orchestrator for the first decision. It auto-detects campaign state via `check-campaign-state.sh` and returns a directive accordingly; the main thread performs it and (for COLD/RESUME) re-enters the chain:

| State | Chain |
|---|---|
| `none` | COLD start: the orchestrator emits one directive per step — `dispatch campaign-planner` → (re-enter) `dispatch harness-writer` → (re-enter) `dispatch seed-generator` → (re-enter) `run run-fuzzer.sh` → (re-enter) `done`/`schedule`. The main thread performs each and re-dispatches the orchestrator for the next. Multi-harness layout from the start. |
| `running` | Orchestrator prints status from `current.json`; emits `done`. Do nothing else. |
| `stopped` | RESUME: `run run-fuzzer.sh` then a WARM tick; orchestrator emits `done`/`schedule`. |
| `stale` | Orchestrator refuses — target source changed; use `--reset` or accept the stale build. |
| `corrupted` | Orchestrator refuses — prints validation errors. |

The target argument is **required for `guided`/`hybrid`**, but **optional under autonomous `self_loop` YOLO**: with no target given, the `campaign-planner` self-selects one from the project (see campaign-planner "Autonomous target selection") and never asks the user.

## Flags

- `--reset` — wipe campaign state (with confirmation) before COLD start
- `--no-coverage` — skip the coverage-binary build (orchestrator otherwise refuses to advance without it)
- `--budget=N` — total LLM spend cap, USD (default 20)
- `--add-harness <name> --entry <fn>` — add a harness to an existing campaign. Every campaign is already multi-harness, so this just appends: `harness-set.sh add` then `harness-writer --harness <name>`.
- `--mutator` — request a custom mutator build for highly-structured inputs
- `--refresh-cve` — re-run CVE intelligence before the next plan revision
- `--oracle <crash|invariant|roundtrip|differential|metamorphic>` — force a logic-bug oracle instead of letting the planner auto-select. Default is auto (crash unless the code review finds a genuine inverse pair / invariant / metamorphic relation). Stateful-sequence harnesses and the UBSan integer suite have no flag — request them in `fuzz/guidance.md`'s `## Oracle` section. See STATE_SCHEMA "Oracle-Driven Fuzzing".
- `--reference <cmd|path|nix-attr>` — supply the second implementation for a `differential` oracle (a CLI command, a prebuilt binary, or a nixpkgs binary on PATH). Required for `--oracle differential`. cc-fuzzer runs it as a subprocess; it does not build the reference.

Target: $ARGUMENTS

State layout and JSON schemas: `${CLAUDE_PLUGIN_ROOT}/STATE_SCHEMA.md`.

## After a COLD start: auto-start the YOLO loop

A campaign doesn't drive itself — the fuzzer runs in the background, but LLM ticks only advance when something fires them. If YOLO is enabled (`yolo.enabled: true` in `fuzz/state/fuzz-config.json`, e.g. the user ran `/cc-fuzzer:yolo on` before this) when a COLD start completes, **immediately start the self-loop**: perform one tick now by following the `/cc-fuzzer:tick` flow (dispatch `fuzz-orchestrator` for one WARM tick, then chain via `ScheduleWakeup` per its `YOLO_NEXT:` line). Then tell the user:

> "Campaign started and YOLO `<mode>` is self-driving — first tick ran now, next in ~`<interval>`. It continues unattended until a hard halt (tick / cost / no-progress / crash-storm cap) or `/cc-fuzzer:yolo off` / `/fuzz-stop`."

If YOLO is **off**, say nothing about loops — the campaign runs in the background and the user advances it with `/cc-fuzzer:tick`, or starts the self-loop with `/cc-fuzzer:yolo on`.
