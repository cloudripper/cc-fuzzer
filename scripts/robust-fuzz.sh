#!/usr/bin/env bash
# robust-fuzz.sh
#
# Reference extra patch gate (patch.extra_gates): fuzz the PATCHED libFuzzer
# build for N seconds, seeded with the minimized PoV (and a corpus), and fail
# on any crash that is the original bug or whose top frame is in a function
# the patch touched. Prints one step-result/v1 line; exit 1 = gate fails.
#
# Usage:
#   robust-fuzz.sh <patched-fuzzer-binary> <pov> <seconds> [corpus-dir]
#
# Reads CC_FUZZER_STACK_HASH and CC_FUZZER_TOUCHED_FUNCTIONS, which
# `patch validate` sets for every extra gate. Configure it as:
#
#   {"patch": {"extra_gates": [{"name": "robust", "policy": "preferred",
#     "command": "command:scripts/robust-fuzz.sh {build} {pov} 420"}]}}
#
# Shim onto `cc-fuzzer patch robust-fuzz` (cc_fuzzer_core.patch.robust_fuzz).

set -u

. "$(dirname "${BASH_SOURCE[0]}")/_lib/root.sh"

if [ "$#" -lt 3 ]; then
  echo "usage: robust-fuzz.sh <patched-fuzzer-binary> <pov> <seconds> [corpus-dir]" >&2
  exit 2
fi
if [ -n "${4:-}" ]; then
  exec python3 -m cc_fuzzer_core patch robust-fuzz "$1" "$2" "$3" --corpus "$4"
fi
exec python3 -m cc_fuzzer_core patch robust-fuzz "$1" "$2" "$3"
