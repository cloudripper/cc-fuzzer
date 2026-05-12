---
description: Run an existing harness binary in the background (no LLM). Used internally by fuzz-orchestrator; available standalone for manual use.
argument-hint: <harness-binary> [corpus-dir] [forks=N]
allowed-tools: Bash
---

Parse arguments. If `$ARGUMENTS` contains `forks=N` (e.g. `forks=4`), extract N and run:

```
FUZZ_FORKS_OVERRIDE=N ${CLAUDE_PLUGIN_ROOT}/scripts/run-fuzzer.sh <other-args>
```

Otherwise just:

```
${CLAUDE_PLUGIN_ROOT}/scripts/run-fuzzer.sh $ARGUMENTS
```

This launches the fuzzer in the **background** (nohup), records the PID to `fuzz/state/fuzzer.pid`, and tees stdout/stderr to `fuzz/state/fuzzer.log`. Stop with `/cc-fuzzer:stop`.

Fork count resolution (highest priority first):
1. `forks=N` argument to this command
2. `FUZZ_FORKS` environment variable
3. `fuzz/state/fuzz-config.json` "fuzz_forks" field
4. Default: 2

The fork count is capped at `nproc - 1` to leave a core for the orchestrator and system. Set via `${CLAUDE_PLUGIN_ROOT}/scripts/_lib/fuzz-config.sh set fuzz_forks N` to persist for the project.

Engine is auto-detected: libFuzzer if the binary exports `LLVMFuzzerTestOneInput`, AFL++ otherwise (requires `afl-fuzz` in PATH).
