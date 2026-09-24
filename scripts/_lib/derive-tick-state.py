#!/usr/bin/env python3
"""derive-tick-state.py — shim onto cc_fuzzer_core.state.derive_tick.

Computes the mode-agnostic derived blocks (tick_coverage, consult_state,
yolo_state) and merges them into an already-written current.json
(== `cc-fuzzer state derive <current.json>`).

Usage:
  derive-tick-state.py <path-to-current.json>

Exit 0 always once a path is given (best-effort; a failure here must not wedge
a tick — the doc is already valid without these blocks).
"""
import sys

from cc_fuzzer_core.state import derive_tick

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("usage: derive-tick-state.py <path-to-current.json>", file=sys.stderr)
        sys.exit(2)
    derive_tick.derive(sys.argv[1])
    sys.exit(0)
