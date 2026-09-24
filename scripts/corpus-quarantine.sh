#!/usr/bin/env bash
# corpus-quarantine.sh
#
# Validates inputs in fuzz/corpus-quarantine/ and promotes the safe ones into
# fuzz/corpus/. Inputs that crash the harness go to fuzz/crashes/new/ for
# triage. Inputs that hang go to fuzz/crashes/flaky/.
#
# This prevents the launch-blocker we hit in the findutils campaign: a crashing
# seed in fuzz/corpus/ kills libFuzzer at startup before it can do anything.
# All new corpus entries (from seed-generator, concolic-executor) MUST pass
# through this script before reaching fuzz/corpus/.
#
# Usage:
#   corpus-quarantine.sh                # process all files in corpus-quarantine/
#   corpus-quarantine.sh <file> [...]   # process specific files
#
# Exit code:
#   0 if all inputs were classified successfully
#   1 if the harness binary is missing or unrunnable, or an input could not
#     be moved (reported on stderr; the other inputs are still processed)
#
# Shim onto the core's port, `cc-fuzzer quarantine run` (cc_fuzzer_core.quarantine).
# The seed-safety scan runs in-process (the same patterns as check-seed-safety.sh).
# A failed move no longer aborts the run: the script's `set +e ... set -e`
# toggles used to switch errexit on for everything after the first harness run.

. "$(dirname "${BASH_SOURCE[0]}")/_lib/root.sh"
case "${1:-}" in
  -h|--help) sed -n '2,/^$/p' "$0" | sed 's/^# \?//'; exit 0 ;;
esac
exec python3 -m cc_fuzzer_core quarantine run "$@"
