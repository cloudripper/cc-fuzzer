---
description: Resume a stopped fuzzing campaign without re-analyzing the target. Relaunches the fuzzer with the existing harness and corpus, then runs one tick.
argument-hint: [forks=N]
---

Use the **fuzz-orchestrator** subagent. Specifically:

1. Parse `$ARGUMENTS`. If it contains `forks=N`, set the env var `FUZZ_FORKS_OVERRIDE=N` for the run-fuzzer.sh invocation in step 3.
2. Run `${CLAUDE_PLUGIN_ROOT}/scripts/check-campaign-state.sh`.
3. If it returns anything other than `stopped`, refuse and tell the user what to do (use `/cc-fuzzer:campaign` for `none`, just continue for `running`, fix or reset for `stale`/`corrupted`).
4. If `stopped`:
   - Read `fuzz/state/harness-built.json` to get the harness binary path.
   - Run `${CLAUDE_PLUGIN_ROOT}/scripts/run-fuzzer.sh <harness>` to relaunch in background (with the `FUZZ_FORKS_OVERRIDE` env var from step 1 if set).
   - Run `${CLAUDE_PLUGIN_ROOT}/scripts/snapshot-coverage.sh` and `${CLAUDE_PLUGIN_ROOT}/scripts/update-current.sh`.
   - Append a `campaign_resume` event to `events.jsonl` via `${CLAUDE_PLUGIN_ROOT}/scripts/events.sh campaign_resume`.
   - Print the standard tick status line.
   - Stop.

Do NOT read source code, do NOT re-analyze the target, do NOT rebuild the harness. Resume is a fast path that trusts existing state.
