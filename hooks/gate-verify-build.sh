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
# and the API cannot disagree about what is allowed. The call goes through
# hooks/_lib/gate.sh, which is the one place that reads the core's answer --
# an earlier version of this hook read the exit status directly and chained
# it into `|| _allow`, which turned every refusal into a silent permit.
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

. "$(dirname "${BASH_SOURCE[0]}")/_lib/gate.sh"

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

gate_ask classify-command --command "$CMD"

case "$GATE_DECISION" in
  deny)
    _log "denied: $CMD"
    gate_deny_json "$GATE_REASON" "$GATE_SUGGESTION"
    exit 0
    ;;
  allow)
    exit 0
    ;;
  *)
    # unavailable: no verdict. This hook fails OPEN, and that is affordable
    # only because variants.select refuses the same action at the core's API
    # -- the binary a replay runs on is chosen there, not here. A hook that
    # blocked every Bash call whenever the core hiccuped would take the
    # campaign down over its own bug.
    _log "no verdict (core unavailable); allowing: $CMD"
    exit 0
    ;;
esac
