#!/usr/bin/env bash
# Test-only wrapper for commands that launch fuzzer slots:
#   reap-slots.sh <cmd> [args...]
# Runs the command, then for every live pid in <state>/fuzzer-*.pid waits until
# the slot's log is non-empty (the stub fuzzer has recorded its argv), kills it
# and waits for it to exit, so the capture is deterministic and nothing leaks.
# <state> is $FUZZ_STATE_DIR (relative to the cwd) or fuzz/state. Exits with the
# command's status.
rc=0
"$@" || rc=$?
state="${FUZZ_STATE_DIR:-fuzz/state}"
for pf in "$state"/fuzzer-*.pid; do
  [ -f "$pf" ] || continue
  pid=$(tr -d ' \n' < "$pf")
  case "$pid" in ''|*[!0-9]*) continue ;; esac
  kill -0 "$pid" 2>/dev/null || continue
  log="${pf%.pid}.log"
  for _ in $(seq 100); do [ -s "$log" ] && break; sleep 0.05; done
  kill "$pid" 2>/dev/null
  for _ in $(seq 100); do kill -0 "$pid" 2>/dev/null || break; sleep 0.05; done
done
exit "$rc"
