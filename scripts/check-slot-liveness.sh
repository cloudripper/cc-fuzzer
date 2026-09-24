#!/usr/bin/env bash
# check-slot-liveness.sh
#
# Per-slot auto-restart for multi-fuzzer campaigns. Walks the slot list
# declared in fuzz/state/fuzz-config.json against the live manifest at
# fuzz/state/fuzzers.json. For each declared slot whose PID is dead (or
# missing), relaunches it via launch-fuzzer-slot.sh and increments the
# slot's restart_count.
#
# Per-slot anti-flap: if a slot has been restarted more than 3 times in
# the last 60 seconds, this script refuses to restart it again and emits
# an error event so the orchestrator can surface the issue. The slot
# entry stays in fuzzers.json with `dead_reason` and zero PID — the user
# decides whether to fix-and-relaunch or remove from fuzz-config.json.
#
# This script does NOT auto-restart anything if fuzz/state/fuzzers.json
# does not exist. That's the post-stop / pre-launch state, and we don't
# want auto-restart to fight against a deliberate stop.
#
# Usage:
#   check-slot-liveness.sh           # restart any dead-but-declared slots
#   check-slot-liveness.sh --dry-run # just report state, no restarts
#
# Output: one line per slot
#   slot=<name> engine=<eng> state=<alive|restarted|deadlocked|dead> [info]
#
# Shim onto the core's port, `cc-fuzzer slots liveness`
# (cc_fuzzer_core.slots.liveness), which relaunches in-process through
# slots.launcher and records its events directly (the old events.sh calls
# passed --error-message / --agent-called flags that events.sh doesn't take).

. "$(dirname "${BASH_SOURCE[0]}")/_lib/root.sh"
exec python3 -m cc_fuzzer_core slots liveness "$@"
