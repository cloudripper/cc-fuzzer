---
description: Diagnose cc-fuzzer state corruption and plugin file modifications. Read-only — never modifies state. Detects recursive fuzz/fuzz/, multiple fuzzers, modified plugin files, dangerous fuzzer flags, stale PIDs, stray snapshot files, and legacy paths. Suggests fixes for each.
allowed-tools: Bash
---

Run `${CLAUDE_PLUGIN_ROOT}/scripts/doctor.sh` and print the result verbatim.

The script is pure shell, runs in seconds, and never modifies anything. Use it any time you suspect state corruption or want to confirm the campaign is healthy.

Categories checked:
1. Recursive `fuzz/fuzz/` directories (cwd-inside-fuzz bug)
2. Multiple fuzzer processes
3. Plugin file integrity (against MANIFEST.md5)
4. Dangerous flags in active fuzzer (`-ignore_crashes`, `-detect_leaks=0`, etc.)
5. Multiple findings.jsonl files
6. Stale fuzzer.pid
7. Stray snapshot files in wrong directory
8. Legacy fuzz/state/crashes/ path

If anything is found, the script prints the offending paths and a suggested fix. Apply the fix yourself; doctor never auto-modifies state.
