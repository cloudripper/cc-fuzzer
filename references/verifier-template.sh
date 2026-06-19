#!/usr/bin/env bash
# verifier-template.sh — REFERENCE TEMPLATE, copy-and-edit per finding.
#
# This file lives in references/ and is not executed in place. The poc-builder
# copies it to fuzz/findings/<id>/verify-poc.sh and customises the four hooks
# marked TODO. It is the pattern `findings.sh promote --verifier <path>`
# expects to evaluate.
#
# ============================================================================
# WHY THIS TEMPLATE EXISTS — the measurement-reliability standard
# ============================================================================
#
# Verifying a PoC against the real target is the realism gate (PLUGIN_ISSUES.md
# recommendation B). It is also where the most embarrassing false signals
# happen, because "did the bug fire?" is a question with many answers that look
# right but aren't. A representative end-to-end campaign surfaced four classes
# of false signal, all of them now baked into the order of operations below:
#
#   1) Stale result files from a prior run. The verifier saw a leftover
#      /tmp/cc-fuzz-marker-<id> from yesterday and exited 0. The fix is to
#      CLEAR THE MARKER FIRST, then check for it AFTER the run — and require a
#      fresh mtime so even a same-second leftover doesn't slip through.
#
#   2) Checking too early. Some boundary crossings (auth bypass landing in a
#      log, a topic-write reaching another subscriber, a queue draining) have
#      latency. Polling the marker 1 ms after the trigger says "no effect" when
#      the effect lands 200 ms later. The fix is `sleep $SETTLE` between trigger
#      and read, configurable per finding.
#
#   3) Cleanup deletes evidence before the read. A test harness that rm's its
#      tmp/ on exit, with the read in a trap that fires after rm, will always
#      say "no effect". The fix is the strict ordering: read FIRST, cleanup
#      LAST.
#
#   4) Process-state read as success. "The broker crashed, so the exploit
#      worked." Wrong — the broker crashed because the WRONG target was hit
#      (an ASan build's auto-abort, or a separate crash unrelated to the
#      primitive under test). The fix is to require a MARKER — a value the
#      exploit specifically writes — rather than infer success from ambient
#      process state.
#
# So the canonical order is:
#
#     clear-marker-first
#       → run-trigger-against-real-binary
#         → sleep $SETTLE
#           → stat-marker-and-assert-fresh-mtime
#             → read-marker-contents-as-ground-truth
#               → cleanup AFTER read succeeds
#                 → exit 0 only when stat+read both succeeded
#
# ============================================================================
# REALISM REMINDERS (poc-builder.md "Realism" section is the source of truth)
# ============================================================================
#
# - The trigger must drive the REAL target binary (the non-ASan, non-coverage
#   build the user/maintainer actually ships). NOT the fuzz harness. NOT a
#   from-scratch reimplementation of the vulnerable logic. NOT the target with
#   a protection removed.
# - The marker must live where ONLY the trust-boundary crossing could plant
#   or modify it. A marker the attacker context could write itself proves
#   nothing.
# - The verifier is what `findings.sh promote --verifier <path>` evaluates.
#   Keep it lean: one trigger, one read, one decision (PLUGIN_ISSUES friction
#   item 5).
#
# ============================================================================

set -u

# ---- Config ----------------------------------------------------------------
# Override at invocation: SETTLE=2.5 ./verify-poc.sh
SETTLE="${SETTLE:-1.0}"                 # seconds between trigger and read
SETTLE_SLACK="${SETTLE_SLACK:-2.0}"     # extra slack on the mtime freshness gate
MARKER_PATH="${MARKER_PATH:-/tmp/cc-fuzz-marker-${FINDING_ID:-unknown}-$$}"
EXPECTED_MARKER="${EXPECTED_MARKER:-CCFUZZ_BOUNDARY_CROSSED}"

# ---- Step 1: clear-marker-first --------------------------------------------
# Even if MARKER_PATH includes $$ (per-run unique), guard against the rare
# pid-collision case AND against a templated path the operator didn't realise
# was shared.
rm -f "$MARKER_PATH" 2>/dev/null || true
if [ -e "$MARKER_PATH" ]; then
  echo "VERIFY FAIL: could not clear prior marker at $MARKER_PATH" >&2
  exit 1
fi

# Record the start timestamp for the freshness gate.
START_TS=$(date +%s)

# ---- Step 2: run trigger against the REAL target binary --------------------
# TODO: replace this block with the exploit invocation. Examples:
#
#   # CLI-style trigger (preferred — pasteable, drives a real binary):
#   /usr/sbin/the-real-daemon --config ./poc.conf &
#   DAEMON_PID=$!
#   sleep 0.2
#   ./trigger-payload.sh > "$MARKER_PATH" 2>&1 || true
#   kill -TERM "$DAEMON_PID" 2>/dev/null || true
#   wait "$DAEMON_PID" 2>/dev/null || true
#
#   # Python trigger (when shell can't express the protocol state):
#   python3 ./exploit.py --target 127.0.0.1:1883 --marker "$MARKER_PATH" \
#                        --expected "$EXPECTED_MARKER"
#
# The trigger must arrange for the boundary-crossing effect to write the
# string "$EXPECTED_MARKER" into "$MARKER_PATH" — and ONLY through the bug.
# A trigger that writes the marker itself (via the attacker context) is not a
# proof of crossing.
#
# REPLACE THIS LINE:
echo "TODO: implement the real trigger here" >&2
false  # template self-fails on purpose — copy and customise before promotion

# ---- Step 3: settle --------------------------------------------------------
# Give the effect time to land. Tune SETTLE per finding; the freshness gate
# below uses SETTLE+SETTLE_SLACK as the window.
sleep "$SETTLE"

# ---- Step 4: stat-marker-and-assert-fresh-mtime ----------------------------
if [ ! -f "$MARKER_PATH" ]; then
  echo "VERIFY FAIL: marker $MARKER_PATH was not created by the trigger" >&2
  exit 1
fi

# Linux stat -c %Y → mtime epoch seconds. BSD/Mac uses -f %m. Try GNU first.
MARKER_MTIME=$(stat -c %Y "$MARKER_PATH" 2>/dev/null || stat -f %m "$MARKER_PATH" 2>/dev/null || echo 0)
NOW_TS=$(date +%s)
WINDOW=$(awk "BEGIN { print ($SETTLE + $SETTLE_SLACK) }")

# The marker must have been written AFTER we cleared it (mtime >= START_TS)
# AND within the settle+slack window (NOW - mtime <= WINDOW). The first check
# defeats stale leftovers; the second defeats the rare "this marker was
# written by an UNRELATED concurrent run".
if [ "$MARKER_MTIME" -lt "$START_TS" ] 2>/dev/null; then
  echo "VERIFY FAIL: marker mtime ($MARKER_MTIME) precedes trigger start ($START_TS) — stale file?" >&2
  exit 1
fi
AGE=$((NOW_TS - MARKER_MTIME))
if awk "BEGIN { exit ($AGE > $WINDOW) ? 0 : 1 }"; then
  echo "VERIFY FAIL: marker is older than settle+slack window (${AGE}s > ${WINDOW}s)" >&2
  exit 1
fi

# ---- Step 5: read-marker-contents-as-ground-truth --------------------------
# DO NOT trust "the daemon crashed" or "the connection dropped" — those are
# ambient process-state signals and conflate the real bug with wrong-target
# crashes. The marker contents are the only thing that proves the boundary was
# crossed by THIS PoC.
CONTENTS=$(cat "$MARKER_PATH" 2>/dev/null || true)
if ! printf '%s' "$CONTENTS" | grep -qF "$EXPECTED_MARKER"; then
  echo "VERIFY FAIL: marker present but does not contain expected string '$EXPECTED_MARKER'" >&2
  echo "         actual contents (first 200 bytes):" >&2
  printf '%s\n' "$CONTENTS" | head -c 200 >&2
  exit 1
fi

# ---- Step 6: cleanup AFTER the read succeeded ------------------------------
# Cleanup is last. If we ever cleanup before the read, we lose evidence on a
# failure path. Keep this order even when the marker file looks harmless.
rm -f "$MARKER_PATH" 2>/dev/null || true

# ---- Step 7: success -------------------------------------------------------
echo "VERIFY OK: boundary crossing demonstrated"
echo "  marker:   $MARKER_PATH"
echo "  expected: $EXPECTED_MARKER"
echo "  age:      ${AGE}s (within ${WINDOW}s window)"
exit 0
