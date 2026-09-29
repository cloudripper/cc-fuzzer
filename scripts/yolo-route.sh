#!/usr/bin/env bash
# yolo-route.sh — deterministic main-thread router for the cc-fuzzer loop.
#
# Turns fully-state-determined moves (the COLD/RESUME setup chain, and the WARM
# no-judgment-needed cases) into a YOLO_NEXT directive, so the main thread can
# act on them without paying for an orchestrator dispatch, and so a truncated
# free-text return can never strand the loop on a move that was never a
# judgment call. The directive vocabulary (dispatch / run / schedule /
# orchestrator / halt / done / inactive) is documented in STATE_SCHEMA.md.
#
# Usage:
#   yolo-route.sh                 # the deterministic next directive
#   yolo-route.sh read-directive  # the orchestrator's last persisted directive (fallback)
#
# Shim onto the core: routing is `cc-fuzzer tick route` (cc_fuzzer_core.loop.route).

set -u

. "$(dirname "${BASH_SOURCE[0]}")/_lib/root.sh"

if [ "${1:-}" = "read-directive" ]; then
  # If the orchestrator persisted its directive to disk before returning,
  # surface it so the main thread never depends on the tail of the free-text
  # return surviving the channel. Last non-blank line, by the same contract.
  f="${FUZZ_STATE_DIR:-${FUZZ_ROOT:-fuzz}/state}/next-directive.txt"
  if [ -s "$f" ]; then
    grep -vE '^[[:space:]]*$' "$f" | tail -n 1
  fi
  exit 0
fi

exec python3 -m cc_fuzzer_core tick route
