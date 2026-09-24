#!/usr/bin/env bash
# validate-state.sh
#
# Strict validator for cc-fuzzer state per STATE_SCHEMA.md.
# Returns exit 0 if state is valid, exit 1 with a report if not (exit 2 when
# no project / a recursive fuzz/fuzz/ is found, like every anchored script).
#
# Called by:
#   - fuzz-orchestrator at session start
#   - /cc-fuzzer:campaign before any action
#   - manually by the user via /cc-fuzzer:validate
#
# Shim onto the core's port, `cc-fuzzer schema validate`
# (cc_fuzzer_core.schema: the field lists and schema version live in
# schema/fields.py, the content checks in schema/checks.py). Arguments are
# ignored, as they always were; `cc-fuzzer schema validate --json` gives a
# machine-readable problem list.

. "$(dirname "${BASH_SOURCE[0]}")/_lib/root.sh"
exec python3 -m cc_fuzzer_core schema validate
