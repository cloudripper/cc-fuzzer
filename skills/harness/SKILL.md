---
name: harness
description: "Generate a libFuzzer/AFL++ harness for a target. Building block — for a full campaign use /cc-fuzzer:campaign. — usage: <path-to-target-source-or-header> [entry-function]"
argument-hint: "<path-to-target-source-or-header> [entry-function]"
disable-model-invocation: true
---

Dispatches the **harness-writer** subagent.

Standalone harness build. The agent reads `fuzz/state/plan.md` if present (otherwise source-only), writes the harness, builds three binaries (fuzzing + coverage + verify, plus optional cmplog when AFL++ is available), and iteratively repairs build failures (up to 5 attempts). Writes `fuzz/state/harness-built.json` via `write-harness-built.sh`.

Use this when iterating on harness logic alone, repairing a build after editing target source, or comparing entry points. For end-to-end campaigns (harness + seeds + live feedback + triage), use `/cc-fuzzer:campaign`.

Target: $ARGUMENTS
