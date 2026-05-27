---
name: seed
description: "Generate a starter or targeted seed corpus. Building block for /cc-fuzzer:campaign. — usage: <format-name-or-spec-path> [output-dir]"
argument-hint: "<format-name-or-spec-path> [output-dir]"
---

Use the **seed-generator** subagent to produce seeds for: $ARGUMENTS

In bootstrap mode, generates 10-30 diverse minimal seeds. If `fuzz/state/gaps-*.json` exists from a recent coverage-analyst run, also enters targeted mode and adds seeds aimed at specific uncovered branches.

Default output directory is `fuzz/corpus/`.
