#!/usr/bin/env bash
# extract-cmplog-dict.sh
#
# Walks AFL++'s cmplog runtime output and emits a libFuzzer/AFL-format
# dictionary of operands observed at comparison sites. This is "Redqueen lite":
# we let cmplog do its job at runtime, then harvest its observations into a
# dictionary file the LLM agents can read.
#
# Why this script exists:
#   - cmplog's I2S benefit happens inside afl-fuzz automatically (no config).
#   - But the LLM (coverage-analyst, seed-generator) cannot see what cmplog
#     observed; they only see source code and coverage. Surfacing cmplog
#     operands as a dict lets them ground gap classification in runtime
#     evidence: "branch checks magic == 0xDEADBEEF; cmplog already saw that
#     operand, so this is direct_compare, not checksum_barrier."
#
# Output format: libFuzzer/AFL-compatible dictionary (one quoted entry per line).
#
# Usage:
#   extract-cmplog-dict.sh [--aflpp-out <out-dir>] [--output <dict-path>]
#
# Defaults:
#   --aflpp-out  ${FUZZ_OUT_DIR:-out}   (the AFL++ output ROOT; instance subdirs
#                                        default/ or <slot>/ are auto-discovered)
#   --output     fuzz/state/cmplog-dict-<timestamp>.dict
#
# This script is idempotent and read-only against the AFL++ output directory.
# It does not modify the running fuzzer or its state.
#
# Shim onto the core's port, `cc-fuzzer cmplog extract` (cc_fuzzer_core.cmplog):
# same flags, output and exit codes; strings are extracted in-process.

. "$(dirname "${BASH_SOURCE[0]}")/_lib/root.sh"
case "${1:-}" in
  -h|--help) sed -n '2,/^$/p' "$0" | sed 's/^# \?//'; exit 0 ;;
esac
exec python3 -m cc_fuzzer_core cmplog extract "$@"
