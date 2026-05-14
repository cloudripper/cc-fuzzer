---
description: Write or revise fuzz/state/plan.md — the campaign strategy document. Runs the Opus-based campaign-planner. Operates in fresh mode at COLD (no prior plan) or revise mode mid-campaign (folds live coverage / findings / gap data into a revised plan; archives the prior version).
argument-hint: <target-source-or-header> [entry-function]
---

Use the **campaign-planner** subagent.

This command is the standalone surface for the planner that the orchestrator already invokes automatically during COLD start. Use it when:

- You want to inspect / generate the plan **before** running `/cc-fuzzer:campaign` (e.g., after editing `fuzz/guidance.md`).
- You're mid-campaign and want the plan **revised** with what the campaign has learned (new findings, plateau character, dispatch-pattern data).

## Two modes (auto-detected)

The planner detects mode based on whether `fuzz/state/plan.md` exists:

| State | Mode | Behavior |
|---|---|---|
| `plan.md` does not exist | **fresh** | Reads target source + `fuzz/guidance.md` (if present) + bundled-dictionary index. Composes a plan from scratch. |
| `plan.md` exists | **revise** | Reads existing plan + `current.json` + latest gap report + `findings.jsonl` + recent coverage snapshots. Archives the existing plan to `fuzz/state/snapshots/plan-{ts}.md`, then writes a revised plan with an added `## Campaign Status & Revisions` section documenting what changed and why. |

## What revise mode can and cannot change

**Cannot change** (harness-locked — baked into the existing build):

- `fuzzing_mode` (`in_process` vs `process_based`)
- Sanitizer set
- Entry function
- `cmplog_enabled`

These are restated verbatim from `fuzz/state/harness-built.json`. If empirical state suggests one should change, the planner says so prominently and recommends `/cc-fuzzer:campaign --reset`.

**Can change**:

- `## Seed Strategy` — refined by what coverage and findings show
- `## Dictionaries` — adjusted based on cmplog activity and per-dict ROI
- `## Concolic Strategy` — hot/cold regions refined by SymCC track record
- `## Coverage Targets` — re-prioritized by finding clusters
- `## Out-of-Scope` — expanded if regions proved irrelevant, contracted if a region turned up bugs
- `## Plateau & Dispatch` — adjusted thresholds based on observed dynamics

## Archive history

Every revise writes `fuzz/state/snapshots/plan-{ts}.md` before replacing the current plan. To see what changed in a revision:

```bash
ls -t fuzz/state/snapshots/plan-*.md | head -2
diff fuzz/state/snapshots/plan-<earlier>.md fuzz/state/plan.md
```

Archives are IMMUTABLE — never deleted except by `/cc-fuzzer:reset`.

## When to revise

The orchestrator never auto-revises. Run `/cc-fuzzer:plan` manually when:

- Several confirmed findings have clustered in a specific area; you want to up its priority.
- A coverage plateau has held for a long time and you suspect the current strategy is unproductive.
- Concolic dispatch has shown 0 ROI (path explosions, no inputs promoted); you want to mark regions cold.
- You updated `fuzz/guidance.md` and want the plan to reflect the new guidance.
- A `/cc-fuzzer:delta` run added new delta targets and you want them folded into strategy.

Target: $ARGUMENTS

The planner must obey **STATE_SCHEMA.md** (`${CLAUDE_PLUGIN_ROOT}/STATE_SCHEMA.md`) for plan.md's required H2 sections, archival rules, and the harness-locked-decisions restatement requirement in revise mode.
