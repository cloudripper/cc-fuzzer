#!/usr/bin/env bash
# hooks/gate-findings.sh
#
# PreToolUse hook on Write|Edit|MultiEdit|Bash (UPDATE_ROADMAP.md §11):
# nothing enters fuzz/findings/ except through the promote path.
#
# A finding directory is not a convenient place to keep notes -- it IS the
# claim that a crash was verified. Creating one by hand asserts a verification
# that never happened, and downstream that is the never-submit-an-unverified-
# PoV rule, where a false submission costs the accuracy multiplier directly.
# So the only writer is `cc-fuzzer findings promote`, which writes a
# verification marker after a verifier confirms the crash.
#
# This script only translates. The decision is `cc-fuzzer gate classify-write`,
# the same call the core makes at its own API, so the hook and the API cannot
# disagree about what is allowed.
#
# The decision is read through hooks/_lib/gate.sh, which is the one place that
# reads the core's answer: `cc-fuzzer gate` exits non-zero to mean NOT
# ALLOWED, so reading that exit status as "the call failed" is what turns a
# refusal into a silent permit.
#
# Fails open when no verdict can be obtained -- see the posture note at the
# bottom, which says why that is affordable here.

set -u

_allow() { exit 0; }

. "$(dirname "${BASH_SOURCE[0]}")/_lib/gate.sh"

INPUT="$(cat 2>/dev/null)" || _allow
[ -n "$INPUT" ] || _allow

. "$(dirname "${BASH_SOURCE[0]}")/../scripts/_lib/root.sh" 2>/dev/null || _allow

# tool<TAB>command<TAB>path  (empty => not a tool we gate)
FIELDS="$(printf '%s' "$INPUT" | python3 -c 'import json,sys
try: d = json.load(sys.stdin)
except Exception: raise SystemExit(0)
tool = d.get("tool_name") or ""
if tool not in ("Write", "Edit", "MultiEdit", "Bash"): raise SystemExit(0)
ti = d.get("tool_input") or {}
cmd = (ti.get("command") or "").replace("\t", " ").replace("\n", " ")
path = ti.get("file_path") or ti.get("path") or ""
sys.stdout.write(f"{tool}\t{cmd}\t{path}")' 2>/dev/null)" || _allow
[ -n "$FIELDS" ] || _allow

TOOL="$(printf '%s' "$FIELDS" | cut -f1)"
CMD="$(printf '%s' "$FIELDS" | cut -f2)"
TPATH="$(printf '%s' "$FIELDS" | cut -f3)"
[ -n "$TOOL" ] || _allow

gate_ask classify-write --tool "$TOOL" --command "$CMD" --path "$TPATH"

case "$GATE_DECISION" in
  deny)
    gate_deny_json "$GATE_REASON" "$GATE_SUGGESTION"
    exit 0
    ;;
  allow)
    exit 0
    ;;
  *)
    # unavailable: no verdict. Fails OPEN, which is affordable only because
    # pipeline.finalize is still the only thing that can write a valid
    # verification marker. A directory created behind this hook's back never
    # reads as verified -- `gate check-finding` and `schema validate` both
    # report it -- so the rule survives the hook being down.
    exit 0
    ;;
esac
