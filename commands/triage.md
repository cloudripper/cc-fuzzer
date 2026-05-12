---
description: Triage fuzzer-discovered crashes. Dedupes against fuzz/state/findings.jsonl and appends new unique findings.
argument-hint: <path-to-crashes-dir-or-single-crash-file> [harness-binary]
---

Use the **crash-triager** subagent to triage: $ARGUMENTS

This subagent runs on **Opus**. It is the most expensive call in the system - only invoke when there are real crashes to analyze. The orchestrator already calls this automatically when new crash files appear during a campaign; use this command directly only for one-off triage.

Output: updated `fuzz/state/findings.jsonl` and a summary table.
