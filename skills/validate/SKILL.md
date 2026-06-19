---
name: validate
description: Validate the current campaign's state against STATE_SCHEMA.md. Reports any schema violations or filesystem inconsistencies.
argument-hint: "(no arguments)"
---

Under ctxctl the top-level thread cannot run Bash directly. Dispatch **ops-runner** to run the validator.

## Steps

1. Dispatch `Agent(subagent_type: "ops-runner", prompt: "Run ${CLAUDE_PLUGIN_ROOT}/scripts/validate-state.sh and return the full output verbatim.")`.
2. Read the Agent's return.
3. If validation passes, print a brief summary of state (number of findings, snapshots, corpus seeds, fuzzer running status) drawn from the return.
4. If validation fails, print the errors verbatim and suggest one of:
   - `/fuzz-reset` for unfixable corruption or schema-version mismatch (v0.30 requires schema v12; older state cannot be migrated)
   - Manual fixes for individual issues

No header.txt refresh is needed — `validate-state.sh` reads state directly.
