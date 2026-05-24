---
name: resume
description: "Resume a stopped fuzzing campaign without re-analyzing the target. Relaunches the fuzzer with the existing harness and corpus, then runs one tick. — usage: [forks=N]"
argument-hint: "[forks=N]"
disable-model-invocation: true
---

Dispatches the **fuzz-orchestrator** subagent. The orchestrator's first action is `check-campaign-state.sh`; a `stopped` campaign runs its RESUME path (relaunch the existing harness, one tick, no source re-analysis or rebuild). For any other state it refuses with the right next step (`/cc-fuzzer:campaign` for `none`, continue for `running`, fix-or-reset for `stale`/`corrupted`).

Parse `$ARGUMENTS`: if it contains `forks=N`, export `FUZZ_FORKS_OVERRIDE=N` so the relaunch uses N libFuzzer forks.

Arguments: $ARGUMENTS
