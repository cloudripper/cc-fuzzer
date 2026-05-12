---
description: Manually invoke concolic execution against the current corpus and gap report. Runs SymCC on selected seeds to generate inputs that satisfy hard path constraints. Used internally by fuzz-orchestrator; available standalone for forced concolic runs.
argument-hint: [gap-id-or-all]
---

Use the **concolic-executor** subagent to run SymCC against the current corpus.

If `$ARGUMENTS` is empty or `all`, target every gap in the latest `fuzz/state/gaps-*.json` with reason in {`value_constraint`, `checksum_barrier`, `deep_path_condition`}.

If `$ARGUMENTS` is a specific gap id (e.g. `g003`), only target that gap.

Prerequisites:
- SymCC must be installed (run `${CLAUDE_PLUGIN_ROOT}/scripts/install-symcc.sh` if not)
- A SymCC-instrumented binary must exist at `fuzz/symcc/<harness>_symcc` (run `${CLAUDE_PLUGIN_ROOT}/scripts/build-symcc-target.sh` if not)
- A coverage-analyst gap report must exist (run `/cc-fuzzer:coverage` first if not)

Output: new inputs in `fuzz/corpus/`, status in `fuzz/state/concolic-<ts>.json`. The running fuzzer will pick up the new inputs automatically.
