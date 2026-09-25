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
# Fails open on anything unexpected: a hook that blocks the campaign over its
# own bug is worse than the rule it enforces.

set -u

_allow() { exit 0; }

INPUT="$(cat 2>/dev/null)" || _allow
[ -n "$INPUT" ] || _allow

. "$(dirname "${BASH_SOURCE[0]}")/../scripts/_lib/root.sh" 2>/dev/null || _allow

# tool<TAB>command<TAB>path  (empty tool => not a tool we gate)
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

# NOTE the `|| true`: `gate classify-write` exits 1 to MEAN deny. Letting that
# exit status reach a `|| _allow` would turn every refusal into a silent
# allow -- the failure mode a gate must never have.
VERDICT="$(python3 -m cc_fuzzer_core gate classify-write --json \
             --tool "$TOOL" --command "$CMD" --path "$TPATH" 2>/dev/null || true)"
[ -n "$VERDICT" ] || _allow

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
    "permissionDecisionReason": reason}}))' 2>/dev/null || true)"

[ -n "$OUT" ] || _allow
printf '%s\n' "$OUT"
exit 0
