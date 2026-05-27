---
name: concolic
description: "Manually invoke concolic execution (SymCC) against the current corpus and gap report. Targets checksum_barrier and deep_path_condition gaps. Auto-dispatched by the orchestrator; available standalone for forced runs. — usage: [gap-id | all] [--harness <name>]"
argument-hint: "[gap-id | all] [--harness <name>]"
---

Dispatches the **concolic-executor** subagent (Haiku driver of SymCC, ~5 min per dispatch).

Targets gaps with `reason` in `{checksum_barrier, deep_path_condition}` from the latest gap report. Other reasons are handled by `seed-generator` (cheaper) or cmplog (free at runtime). Dispatching concolic on `value_constraint` or `format_barrier` gaps is a no-op and burns the 5-minute budget.

If `$ARGUMENTS` is empty or `all`, processes all eligible gaps (cap 5 invocations). A specific gap id (e.g., `g003`) targets only that gap.

Outputs:
- New inputs land in `fuzz/corpus-quarantine/` and are promoted to `fuzz/corpus/` by `corpus-quarantine.sh` after validation
- Status report at `fuzz/state/snapshots/concolic-<ts>.json` (per-harness in multi mode)

Prerequisites (the agent checks; surfaces errors if missing): SymCC-instrumented binary at `fuzz/harness/<target>_fuzzer_symcc`, SymCC runtime resolvable, non-empty corpus, eligible gaps in the report.

Target: $ARGUMENTS
