#!/usr/bin/env bash
# hooks/dedup-calls.sh
#
# PreToolUse + PostToolBatch hook: a tool call that repeats one already in the
# same response is denied, so it runs once and its result enters the context
# once. Registered in hooks/hooks.json (PreToolUse: Read|Bash|Grep|Glob).
#
# This script only translates: Claude Code's hook input becomes
# `cc-fuzzer hygiene call|batch-end`, and a "deny" becomes the PreToolUse
# JSON. Never blocks on its own error.
set -u
. "$(dirname "${BASH_SOURCE[0]}")/../scripts/_lib/root.sh" 2>/dev/null || exit 0
exec python3 -c '
import json, subprocess, sys
try:
    ev = json.loads(sys.stdin.read() or "{}")
except ValueError:
    sys.exit(0)
core = [sys.executable, "-m", "cc_fuzzer_core", "hygiene"]
name, session = ev.get("hook_event_name"), str(ev.get("session_id") or "")
try:
    if name == "PostToolBatch":
        subprocess.run(core + ["batch-end", "--session", session], timeout=8)
    elif name == "PreToolUse":
        r = subprocess.run(core + ["call", "--session", session, "--prompt", str(ev.get("prompt_id") or ""),
                                   "--id", str(ev.get("tool_use_id") or ""), "--tool", str(ev.get("tool_name") or "")],
                           input=json.dumps(ev.get("tool_input")), capture_output=True, text=True, timeout=8)
        d = json.loads(r.stdout or "{}")
        if d.get("decision") == "deny":
            print(json.dumps({"hookSpecificOutput": {"hookEventName": "PreToolUse",
                                                     "permissionDecision": "deny",
                                                     "permissionDecisionReason": d.get("reason") or "duplicate call"}}))
except Exception:
    pass
'
