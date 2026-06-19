---
name: fuzz-run
description: "Run an existing harness binary in the background (no LLM). Used internally by fuzz-orchestrator; available standalone for manual use. — usage: <harness-binary> [corpus-dir] [forks=N] | --slot <name> --binary <path>"
argument-hint: "<harness-binary> [corpus-dir] [forks=N] | --slot <name> --binary <path>"
---

Under ctxctl the top-level thread cannot run Bash directly. Dispatch **ops-runner** to launch the fuzzer.

Parse `$ARGUMENTS`. If it contains `forks=N` (e.g. `forks=4`), the `FUZZ_FORKS_OVERRIDE=N` env var must be set when invoking `run-fuzzer.sh`.

## Steps

1. Build the script invocation:
   - If `$ARGUMENTS` contains `forks=N`: `FUZZ_FORKS_OVERRIDE=N ${CLAUDE_PLUGIN_ROOT}/scripts/run-fuzzer.sh <other args>`
   - Otherwise: `${CLAUDE_PLUGIN_ROOT}/scripts/run-fuzzer.sh $ARGUMENTS`
2. Dispatch `Agent(subagent_type: "ops-runner", prompt: "Run this exact command and return the resulting status: <command-from-step-1>. The fuzzer launches in the background (nohup) and writes its PID to fuzz/state/fuzzer-<slot>.pid.")`.
3. Read the Agent's return.
4. Print a one-line status (slot name, engine, PID) plus any warnings the script surfaced.

This launches the fuzzer in the **background** (nohup), records the PID to `fuzz/state/fuzzer-<slot>.pid` (slot defaults to `main`), and tees stdout/stderr to `fuzz/state/fuzzer-<slot>.log`. Stop with `/fuzz-stop`.

**Running two harnesses side by side (manual multi-slot)**: invoke once per harness with an explicit `--slot` name and the surgical stop semantics will preserve any other running slot:

```
${CLAUDE_PLUGIN_ROOT}/scripts/run-fuzzer.sh --slot main  --binary fuzz/harness/<harness-a>
${CLAUDE_PLUGIN_ROOT}/scripts/run-fuzzer.sh --slot alt   --binary fuzz/harness/<harness-b>
```

Without `--slot`, the legacy positional form (`run-fuzzer.sh <binary>`) implicitly uses `slot=main` and will replace whatever is currently running under that slot — but it no longer kills other named slots. The blessed way to declare multi-fuzzer campaigns is still `fuzz/state/fuzz-config.json` `fuzzer_slots[]`; the `--slot` flag is the manual escape hatch.

Fork count resolution (highest priority first):
1. `forks=N` argument to this command
2. `FUZZ_FORKS` environment variable
3. `fuzz/state/fuzz-config.json` "fuzz_forks" field
4. Default: 2

The fork count is capped at `nproc - 1` to leave a core for the orchestrator and system. Set via `${CLAUDE_PLUGIN_ROOT}/scripts/_lib/fuzz-config.sh set fuzz_forks N` to persist for the project.

Engine is auto-detected: libFuzzer if the binary exports `LLVMFuzzerTestOneInput`, AFL++ otherwise (requires `afl-fuzz` in PATH).

No header.txt refresh is needed — `run-fuzzer.sh` reads `fuzz-config.json` and `harnesses.json` directly.
