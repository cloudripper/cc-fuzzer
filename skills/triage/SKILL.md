---
name: triage
description: "Triage fuzzer-discovered crashes through the three-step verification pipeline. Dedups, classifies, builds a quick PoC bundle. Auto-dispatched by the orchestrator; use this for one-off manual triage. — usage: <path-to-crashes-dir-or-single-crash-file> [--harness <name>]"
argument-hint: "<path-to-crashes-dir-or-single-crash-file> [--harness <name>]"
---

Dispatches the **crash-triager** subagent (Opus, ~$0.50-2 per crash).

The agent runs each crash in `fuzz/crashes/new/` through artifact filter → deterministic replay → target-realistic reproducer, dedups by stack hash, and writes findings to `fuzz/state/findings.jsonl` via `findings.sh`. Filtered-out crashes are logged with reasons to `fuzz/state/dropped_crashes.jsonl` (transparency log). Confirmed crashes move to `fuzz/crashes/known/<id>/` with a quick PoC bundle at `fuzz/findings/<id>/repro/`.

**Next step**: after triage confirms a finding, run `/cc-fuzzer:poc <id>` to build a verifiable EXPLOIT (the orchestrator does this automatically; manual triage users should invoke it themselves).

Target: $ARGUMENTS
