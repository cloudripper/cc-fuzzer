#!/usr/bin/env bash
# hooks/_lib/gate.sh — the ONE place a hook asks the core for a verdict.
#
# Every cc-fuzzer gate hook translates the same way, and the translation has
# exactly one dangerous step: reading the core's answer. `cc-fuzzer gate ...`
# exits non-zero to mean NOT ALLOWED, so the reflex `verdict=$(...) || allow`
# turns every refusal into a silent permit. That is the bug the first version
# of gate-verify-build.sh shipped with, and a gate that fails open is worse
# than no gate because it reads as enforcement.
#
# So no hook calls the core directly. They call:
#
#   gate_ask <gate-args...>
#     Sets GATE_DECISION to one of:
#       allow        the core allowed it
#       deny         the core refused it; GATE_REASON / GATE_SUGGESTION set
#       unavailable  no verdict could be obtained (core missing, crashed,
#                    unparseable output). NOT the same as allow, and the
#                    CALLER decides the posture for it, visibly.
#     Never returns non-zero, so it cannot be chained into a `||`.
#
# The `unavailable` posture is a real choice, so each hook states it in its own
# words rather than inheriting one by accident. Both current hooks fail open on
# it, and they can afford to because the core refuses the same action at its
# API: the hook is the early, explainable layer, not the authority.

gate_ask() {
  GATE_DECISION="unavailable"
  GATE_REASON=""
  GATE_SUGGESTION=""

  local out
  # NOTE: no `||` here. A non-zero exit is the core's way of saying "not
  # allowed", so it must not be conflated with "the call failed" -- the JSON
  # is what decides, and `set +e` semantics are made explicit below.
  out="$(python3 -m cc_fuzzer_core gate "$@" --json 2>/dev/null)" || true
  [ -n "$out" ] || return 0

  local parsed
  parsed="$(printf '%s' "$out" | python3 -c 'import json,sys
try:
    v = json.load(sys.stdin)
except Exception:
    raise SystemExit(0)
d = v.get("decision")
if d not in ("allow", "deny"):
    raise SystemExit(0)
print(d)
print((v.get("reason") or "").replace("\n", " "))
print((v.get("suggestion") or "").replace("\n", " "))' 2>/dev/null)" || return 0
  [ -n "$parsed" ] || return 0

  GATE_DECISION="$(printf '%s' "$parsed" | sed -n 1p)"
  GATE_REASON="$(printf '%s' "$parsed" | sed -n 2p)"
  GATE_SUGGESTION="$(printf '%s' "$parsed" | sed -n 3p)"
  return 0
}

# gate_deny_json <reason> [suggestion] — the PreToolUse denial payload.
gate_deny_json() {
  python3 - "$1" "${2:-}" <<'PY' 2>/dev/null
import json, sys
reason = sys.argv[1] or "refused by cc-fuzzer gate"
if len(sys.argv) > 2 and sys.argv[2]:
    reason += "\n\nRun instead: " + sys.argv[2]
print(json.dumps({"hookSpecificOutput": {
    "hookEventName": "PreToolUse",
    "permissionDecision": "deny",
    "permissionDecisionReason": reason}}))
PY
}
