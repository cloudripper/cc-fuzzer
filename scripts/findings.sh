#!/usr/bin/env bash
# findings.sh
#
# The ONLY writer of findings.jsonl. Subagents must call this rather than
# editing the file directly, because the in-place dedup edit must be atomic
# and the schema must be enforced.
#
# Usage:
#   findings.sh add <stack_hash> <category> <location> <exploitability> <root_cause> <reproducer> [sanitizer_excerpt]
#   findings.sh dedup <stack_hash>
#   findings.sh count
#   findings.sh list
#   findings.sh find-by-hash <stack_hash>
#   findings.sh import-cr [snapshot-path]    # bridge code-review candidates in
#
# Behavior per STATE_SCHEMA.md:
#   - APPEND-ONLY for new findings
#   - In-place edit ONLY for dedup_count and last_seen
#   - Strict schema (finding/v2; every finding carries harnesses[])
#   - Atomic write via .tmp + mv
#
# Shim onto the core's port, `cc-fuzzer findings <subcommand>`
# (cc_fuzzer_core.findings): same arguments, environment (HARNESS,
# FINDINGS_SKIP_VERIFY, ORACLE_TYPE, DIVERGENCE, FINDINGS_DEDUP_THRESHOLD),
# output and exit codes. `findings.sh help` lists every subcommand.

. "$(dirname "${BASH_SOURCE[0]}")/_lib/root.sh"

# No subcommand / an unknown one prints the help, as before.
case "${1:-}" in
  count|list|find-by-hash|add|dedup|add-harness|verify|stale-mark|list-candidates|\
  promote|remove|drop|import-cr|help) ;;
  *) set -- help ;;
esac
exec python3 -m cc_fuzzer_core findings "$@"
