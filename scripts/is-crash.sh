#!/usr/bin/env bash
# is-crash.sh — classify sanitizer output as a crash or not.
#
# Reads captured output (stdin or first positional arg = file path) and emits a
# single-line JSON object describing whether the output represents a crash and,
# if so, what kind. Used by:
#   - reporting-agent's Step 3 classification
#   - crash-triager's Step 2 deterministic-replay check
#
# Output schema (always valid JSON, single line):
#   {
#     "is_crash":     <bool>,
#     "category":     "<heap-buffer-overflow|stack-buffer-overflow|global-buffer-overflow|"
#                     "heap-use-after-free|use-of-uninitialized-value|null-deref|"
#                     "stack-overflow|integer-overflow|signed-integer-overflow|"
#                     "assertion-failure|oom|timeout|segfault|abort|generic-crash|none>",
#     "summary_line": "<the sanitizer SUMMARY line if present, else first matching line, else "">",
#     "top_frame":    "<function @ file:line if extractable, else "">",
#     "exit_code":    <int or null — only set if --exit-code passed>
#   }
#
# Exit status:
#   0 — crash detected (is_crash == true)
#   1 — no crash (is_crash == false)
#   2 — usage error
#
# Usage:
#   bash is-crash.sh < captured_output.log
#   bash is-crash.sh captured_output.log
#   bash is-crash.sh --exit-code 134 < captured_output.log
#   bash is-crash.sh --exit-code 134 captured_output.log
#
# The --exit-code flag lets the caller pass the process's actual exit code so
# the classifier can detect crashes that produced no sanitizer output (e.g.,
# a raw SIGSEGV with no debug symbols).
#
# Shim onto the core's port, `cc-fuzzer crash classify`
# (cc_fuzzer_core.crash.classify): same arguments, output line and exit codes.

. "$(dirname "${BASH_SOURCE[0]}")/_lib/root.sh"
case "${1:-}" in
  --help|-h) sed -n '2,/^$/p' "$0" | sed 's/^# \?//'; exit 0 ;;
esac
exec python3 -m cc_fuzzer_core crash classify "$@"
