---
name: doctor
description: Diagnose cc-fuzzer state corruption and plugin file modifications. Read-only — never modifies state. Detects recursive fuzz/fuzz/, multiple fuzzers, modified plugin files, dangerous fuzzer flags, stale PIDs, stray snapshot files, and legacy paths. Suggests fixes for each.
argument-hint: "(no arguments — read-only health check)"
---

Under ctxctl the top-level thread cannot run Bash directly. Dispatch **ops-runner** to run the doctor script.

## Steps

1. Dispatch `Agent(subagent_type: "ops-runner", prompt: "Run ${CLAUDE_PLUGIN_ROOT}/scripts/doctor.sh and return the full output verbatim. This is a pure-shell read-only health check; runs in seconds; never modifies state.")`.
2. Print the Agent's return verbatim.

If anything is found, the script prints the offending paths and a suggested fix. The user applies the fix manually; doctor never auto-modifies state.

Categories checked:
1. Recursive `fuzz/fuzz/` directories (cwd-inside-fuzz bug)
2. Multiple fuzzer processes
3. Plugin file integrity (against MANIFEST.md5)
4. Dangerous flags in active fuzzer (`-ignore_crashes`, `-detect_leaks=0`, etc.)
5. Multiple findings.jsonl files
6. Stale fuzzer.pid
7. Stray snapshot files in wrong directory
8. Legacy fuzz/state/crashes/ path

No header.txt refresh is needed — `doctor.sh` reads state directly.
