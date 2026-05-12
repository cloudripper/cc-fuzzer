---
description: Generate a libFuzzer/AFL++ harness for a single target function. Building block - for full LLM-guided fuzzing use /fuzz:campaign instead.
argument-hint: <path-to-target-source-or-header> [entry-function]
---

Use the **harness-writer** subagent to generate a fuzz harness for: $ARGUMENTS

The agent will read the target, write the harness, run the build, and iteratively repair if the build fails (up to 5 attempts). On success, writes `fuzz/state/harness-built.json`.

For an end-to-end LLM-guided campaign (harness + seeds + live coverage feedback + triage), use `/fuzz:campaign` instead.
