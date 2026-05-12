---
description: Validate the current campaign's state against STATE_SCHEMA.md. Reports any schema violations or filesystem inconsistencies.
allowed-tools: Bash
---

Run `${CLAUDE_PLUGIN_ROOT}/scripts/validate-state.sh` and print the result.

If validation passes, print a brief summary of state (number of findings, snapshots, corpus seeds, fuzzer running status).

If validation fails, print the errors verbatim and suggest one of:
- `${CLAUDE_PLUGIN_ROOT}/scripts/migrate-state.sh` for schema mismatches
- `/cc-fuzzer:reset` for unfixable corruption
- Manual fixes for individual issues
