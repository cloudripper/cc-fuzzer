---
name: resume-campaign
description: "Resume a stopped fuzzing campaign without re-analyzing the target. Relaunches the fuzzer with the existing harness and corpus, then runs one tick. — usage: [forks=N]"
argument-hint: "[forks=N]"
---

Dispatches the **fuzz-orchestrator** subagent to *decide* the resume action; **the main thread performs it** (the orchestrator has no `Agent` tool). Under ctxctl the top-level thread cannot run Bash; the orchestrator (a subagent) runs `check-campaign-state.sh` itself.

**Header anchor.** Before dispatching the orchestrator, refresh the campaign-header digest:

```
Agent(subagent_type: "ops-runner",
      prompt: "Run ${CLAUDE_PLUGIN_ROOT}/scripts/campaign-header.sh > ${FUZZ_STATE_DIR}/header.txt and report the captured header.")
```

Then dispatch fuzz-orchestrator. Its first action is `check-campaign-state.sh`; a `stopped` campaign runs its RESUME path — it emits `run script="run-fuzzer.sh"` (relaunch the existing harness, no source re-analysis or rebuild), which the main thread performs via ops-runner; re-dispatching the orchestrator then runs one WARM tick and emits `done`/`schedule`. Perform each directive as in `${CLAUDE_PLUGIN_ROOT}/skills/tick/SKILL.md` ("Performing the directive"). For any other state the orchestrator refuses with the right next step (`/cc-fuzzer:campaign` for `none`, continue for `running`, fix-or-reset for `stale`/`corrupted`).

Parse `$ARGUMENTS`: if it contains `forks=N`, export `FUZZ_FORKS_OVERRIDE=N` so the relaunch uses N libFuzzer forks.

Arguments: $ARGUMENTS
