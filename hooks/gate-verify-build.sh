#!/usr/bin/env bash
# hooks/gate-verify-build.sh
#
# PreToolUse hook on Bash (UPDATE_ROADMAP.md §12): which binary an action runs
# on is a core decision, not a prompt instruction.
#
# Two things are refused before the command runs:
#
#   1. executing a cmplog, symcc or coverage binary outside the slot launcher.
#      Those are built to feed the fuzzer. A crash that reproduces on one is a
#      statement about the instrumentation, not about the target.
#   2. running a crash input against a build of the harness that is not the one
#      `replay` selects (the verify binary, or the fuzzing binary recorded as
#      weak evidence when no verify binary was built).
#
# This script only translates. Every decision is `cc-fuzzer gate
# classify-command`, the same call the core makes at its own API, so the hook
# and the API cannot disagree about what is allowed.
#
# Claude Code hands this hook the tool call on stdin:
#   {"hook_event_name":"PreToolUse","tool_name":"Bash",
#    "tool_input":{"command":"..."}, "cwd":"..."}
#
# On a refusal it prints a PreToolUse permissionDecision of "deny" with the
# reason AND the command to run instead, so the model has somewhere to go.
# Anything else exits 0 silently: a hook that fails open is a hook that does
# not stop the campaign.

set -u

_log() {
  local d="${CC_FUZZER_STATE_DIR:-}"
  [ -n "$d" ] && [ -d "$d" ] || return 0
  printf '%s gate-verify-build: %s\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)" "$*" \
    >> "$d/gate-hook.log" 2>/dev/null || true
}

_allow() { exit 0; }

INPUT="$(cat 2>/dev/null)" || _allow
[ -n "$INPUT" ] || _allow

. "$(dirname "${BASH_SOURCE[0]}")/../scripts/_lib/root.sh" 2>/dev/null || _allow

# The Bash command this tool call is about ("" for any other tool).
CMD="$(printf '%s' "$INPUT" | python3 -c 'import json,sys
try: d = json.load(sys.stdin)
except Exception: raise SystemExit(0)
if d.get("tool_name") == "Bash":
    sys.stdout.write((d.get("tool_input") or {}).get("command") or "")' 2>/dev/null)" || _allow
[ -n "${CMD:-}" ] || _allow

HOOK_CWD="$(printf '%s' "$INPUT" | python3 -c 'import json,sys
try: sys.stdout.write(json.load(sys.stdin).get("cwd") or ".")
except Exception: sys.stdout.write(".")' 2>/dev/null)" || HOOK_CWD="."
cd "${HOOK_CWD:-.}" 2>/dev/null || _allow

# The decision is the core's, not this script's.
#
# NOTE the `|| true`: `gate classify-command` exits 1 to MEAN deny, which is
# what a caller using it as a test wants. Letting that exit code reach a
# `|| _allow` here turns every refusal into a silent allow -- the one failure
# mode this hook exists to prevent. The decision is read from the JSON, never
# from the exit status.
VERDICT="$(printf '%s' "$CMD" | python3 -m cc_fuzzer_core gate classify-command --json 2>/dev/null || true)"
[ -n "$VERDICT" ] || _allow

# Deny -> a PreToolUse denial carrying the reason AND what to run instead.
OUT="$(printf '%s' "$VERDICT" | python3 -c 'import json,sys
try: v = json.load(sys.stdin)
except Exception: raise SystemExit(0)
if v.get("decision") != "deny": raise SystemExit(0)
reason = v.get("reason") or "refused by cc-fuzzer gate"
if v.get("suggestion"):
    reason += "\n\nRun instead: " + v["suggestion"]
print(json.dumps({"hookSpecificOutput": {
    "hookEventName": "PreToolUse",
    "permissionDecision": "deny",
    "permissionDecisionReason": reason}}))' 2>/dev/null)" || _allow

[ -n "$OUT" ] || _allow
_log "denied: $CMD"
printf '%s\n' "$OUT"
exit 0
