---
description: Re-run every recorded reproducer and write fuzz/state/FINDINGS-REPORT.md with confirmed bugs, copy-pasteable reproducer commands, and false-positive analysis.
argument-hint: (no arguments)
---

Use the **reporting-agent** subagent.

This subagent runs on **Opus** and re-executes every reproducer in `fuzz/state/findings.jsonl` against the current harness binary. The output `fuzz/state/FINDINGS-REPORT.md` is rewritten atomically each invocation.

The agent must obey **STATE_SCHEMA.md** (`${CLAUDE_PLUGIN_ROOT}/STATE_SCHEMA.md`) for all file paths and JSON shapes. It is the only writer of `fuzz/state/FINDINGS-REPORT.md`.

Output: an updated `fuzz/state/FINDINGS-REPORT.md` plus a short stdout summary.
