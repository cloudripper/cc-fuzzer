#!/usr/bin/env bash
# hooks/sweep-gate.sh
#
# Stop hook, OPT-IN (not in hooks/hooks.json): a turn may not end while the
# delta sweep has changed sinks with no verdict (cc_fuzzer_core.sweep). For
# autonomous use, where one turn is one work round. Interactively every
# assistant turn ends with Stop, so the plugin never registers it; add it to
# your settings only while working a sweep:
#
#   {"hooks": {"Stop": [{"hooks": [{"type": "command",
#      "command": "${CLAUDE_PLUGIN_ROOT}/hooks/sweep-gate.sh"}]}]}}
#
# Arguments are passed on (e.g. --file <sweep.json>). This script only
# translates: stop_hook_active becomes --continuing, and the core's "block"
# becomes the Stop hook JSON. Never fails a turn on its own error.
set -u
. "$(dirname "${BASH_SOURCE[0]}")/../scripts/_lib/root.sh" 2>/dev/null || exit 0
exec python3 -c '
import json, subprocess, sys
try:
    ev = json.loads(sys.stdin.read() or "{}")
except ValueError:
    ev = {}
cmd = [sys.executable, "-m", "cc_fuzzer_core", "sweep", "gate", "--json", *sys.argv[1:]]
if ev.get("stop_hook_active"):
    cmd.append("--continuing")
try:
    d = json.loads(subprocess.run(cmd, capture_output=True, text=True, timeout=15).stdout or "{}")
except Exception:
    sys.exit(0)
if d.get("decision") == "block":
    print(json.dumps({"decision": "block", "reason": d.get("reason") or "delta sweep incomplete"}))
' "$@"
