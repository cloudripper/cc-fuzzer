---
name: report
description: "Re-run every recorded reproducer and write fuzz/state/FINDINGS-REPORT-<target>.md with confirmed bugs, copy-pasteable reproducer commands, and false-positive analysis. — usage: [--mode pre-contact | maintainer | public]"
argument-hint: "[--mode pre-contact | maintainer | public]"
disable-model-invocation: true
---

Dispatches the **reporting-agent** subagent (Opus). It re-verifies every finding in `fuzz/state/findings.jsonl` — against both the harness binary (sanity check) and the per-finding `fuzz/findings/<id>/repro/` bundle (the maintainer-facing artifact) — then rewrites `fuzz/state/FINDINGS-REPORT-<target>.md` atomically. It is the only writer of that file.

If `$ARGUMENTS` contains `--mode <pre-contact|maintainer|public>`, pass it through to force that disclosure level for ALL findings. Otherwise the agent picks per-finding from each finding's `disclosure_state`. The rendering rules for each mode live in the agent's "Disclosure modes" section — they aren't restated here.

Arguments: $ARGUMENTS
