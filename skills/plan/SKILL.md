---
name: plan
description: "Write or revise fuzz/state/plan.md, the campaign strategy document. In fresh mode (no prior plan), composes from source + guidance + CVE intelligence. In revise mode (mid-campaign), folds in live coverage / findings / gap data and archives the prior plan. — usage: <target-source-or-header> [entry-function] [--mode fresh|revise]"
argument-hint: "<target-source-or-header> [entry-function] [--mode fresh|revise]"
---

Dispatches the **campaign-planner** subagent.

Auto-detects mode from `fuzz/state/plan.md`: absent → fresh, present → revise. Override with `--mode`.

Revise mode archives the prior plan to `fuzz/state/snapshots/plan-{ts}.md` (immutable) before writing the new one. To see what changed: `diff fuzz/state/snapshots/plan-<earlier>.md fuzz/state/plan.md`.

`## Harness` decisions (fuzzing mode, sanitizers, entry function, cmplog flag) are pinned by the existing build and cannot change without `/cc-fuzzer:campaign --reset`. All other sections (seed strategy, dictionaries, concolic posture, coverage targets, out-of-scope, plateau thresholds) are revisable.

For full plan.md schema and section content rules: `${CLAUDE_PLUGIN_ROOT}/STATE_SCHEMA.md § state/plan.md`.

Per-tick consult check-ins are handled by the separate `planner-consult` agent, not this command.

Target: $ARGUMENTS
