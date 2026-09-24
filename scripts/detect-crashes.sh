#!/usr/bin/env bash
# detect-crashes.sh
#
# PostToolUse hook. Implements the first stage of the canonical crash flow
# from STATE_SCHEMA.md:
#   - When a fuzzer-discovered crash file appears, hard-link it into
#     fuzz/crashes/new/<harness>__<sha256[:16]>.bin so it's queued for triage.
#   - Crashes from libFuzzer (fuzz/harnesses/<h>/.libfuzzer-cwd/crash-*, and
#     leak-/oom-/timeout-) and AFL++ (fuzz/harnesses/<h>/aflpp-out/<instance>/
#     crashes/id:*) are both handled: the locations launch-fuzzer-slot.sh uses.
#
# Stays silent if no campaign is active.
#
# The detection itself is the core's `cc-fuzzer crash detect`
# (cc_fuzzer_core.crash.detect), which only returns data. This wrapper is the
# Claude Code adapter: it turns "queued N crash file(s)" into hook output.
# Outside any cc-fuzzer project the hook silently no-ops (--missing-ok); a
# recursive fuzz/fuzz/ still fails loudly.

set -u

. "$(dirname "${BASH_SOURCE[0]}")/_lib/root.sh"
cat >/dev/null || true   # consume stdin to avoid SIGPIPE

SUMMARY=$(python3 -m cc_fuzzer_core crash detect --missing-ok) || exit $?

# Tell Claude there's work to do, but only when we actually queued something
# (the core prints "queued N new crash file(s) into <dir>/" only then).
if [ -n "$SUMMARY" ]; then
  cat <<EOF2
{
  "hookSpecificOutput": {
    "hookEventName": "PostToolUse",
    "additionalContext": "cc-fuzzer: $SUMMARY. Next /cc-fuzzer:tick should dispatch crash-triager."
  }
}
EOF2
fi

exit 0
