#!/usr/bin/env bash
# hooks/ledger-append.sh
#
# SubagentStop hook (UPDATE_ROADMAP.md §10): the host, not the orchestrator,
# writes the spend ledger. Every time a subagent finishes, Claude Code hands
# this hook (on stdin) the subagent's id, type and its own transcript:
#
#   {"hook_event_name": "SubagentStop", "cwd": "...", "agent_id": "def456",
#    "agent_type": "cc-fuzzer:crash-triager",
#    "agent_transcript_path": "~/.claude/projects/.../<session>/subagents/agent-def456.jsonl",
#    "transcript_path": "<main session transcript>", ...}
#
# and this hook records it as one agent_call row:
#
#   cc-fuzzer ledger append --source host-hook --call-id <agent_id> \
#       --agent <agent type, plugin scope stripped> --transcript <agent transcript>
#
# The core (ledger.usage_from_transcript) sums the per-message usage of the
# transcript's assistant turns, each message id once, and takes the model from
# it; this script only translates hook input into that call. The append is
# idempotent on the agent id, and host-hook rows supersede the orchestrator's
# own `events.sh agent_call` rows for the same agent and tick.
#
# Never blocks: always exits 0 with nothing on stdout. It is a no-op outside a
# campaign (no fuzz/ above the hook's cwd, or no state dir yet) and for the
# host's internal agents (empty agent_type). Failures go to
# <state dir>/ledger-hook.log.

set -u

. "$(dirname "${BASH_SOURCE[0]}")/../scripts/_lib/root.sh" 2>/dev/null || exit 0

INPUT=$(cat 2>/dev/null) || exit 0

# Hook input -> shell variables (python: jq is not a plugin dependency).
FIELDS=$(HOOK_INPUT="$INPUT" python3 - <<'PY' 2>/dev/null
import json, os, shlex
try:
    d = json.loads(os.environ.get("HOOK_INPUT") or "{}")
except ValueError:
    d = {}
if not isinstance(d, dict):
    d = {}
agent_id = str(d.get("agent_id") or "")
transcript = str(d.get("agent_transcript_path") or "")
if not transcript and agent_id and d.get("transcript_path"):
    # Documented layout: <session>.jsonl + <session>/subagents/agent-<id>.jsonl
    main = str(d["transcript_path"])
    base = main[:-len(".jsonl")] if main.endswith(".jsonl") else main
    transcript = os.path.join(base, "subagents", f"agent-{agent_id}.jsonl")
for k, v in (("HOOK_CWD", d.get("cwd") or ""), ("AGENT_ID", agent_id),
             ("AGENT_TYPE", d.get("agent_type") or ""), ("TRANSCRIPT", transcript)):
    print(f"{k}={shlex.quote(os.path.expanduser(str(v)))}")
PY
) || exit 0
HOOK_CWD="" AGENT_ID="" AGENT_TYPE="" TRANSCRIPT=""
eval "$FIELDS"

if [ -n "$HOOK_CWD" ]; then cd "$HOOK_CWD" 2>/dev/null || exit 0; fi

# Inside a campaign? (--missing-ok: silent exit 1 when there is no fuzz/.)
CAMPAIGN=$(python3 -m cc_fuzzer_core paths campaign --lenient --missing-ok --format sh 2>/dev/null) || exit 0
STATE_DIR=""
eval "$CAMPAIGN"
[ -n "$STATE_DIR" ] && [ -d "$STATE_DIR" ] || exit 0

LOG="$STATE_DIR/ledger-hook.log"
log() { printf '%s ledger-append: %s\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)" "$*" >>"$LOG" 2>/dev/null; }

# Internal host agents (prompt suggestions, side questions) report no type.
[ -n "$AGENT_TYPE" ] || exit 0
if [ -z "$AGENT_ID" ]; then
  log "no agent_id in SubagentStop input (agent_type=$AGENT_TYPE); not recorded"
  exit 0
fi
if [ ! -f "$TRANSCRIPT" ]; then
  log "agent $AGENT_ID ($AGENT_TYPE): transcript '$TRANSCRIPT' not found; not recorded"
  exit 0
fi

# Plugin agents are scoped ("cc-fuzzer:crash-triager"); the ledger and the
# model map use the bare agent name.
AGENT="${AGENT_TYPE##*:}"

ERR=$(python3 -m cc_fuzzer_core ledger append --source host-hook --call-id "$AGENT_ID" \
        --agent "$AGENT" --transcript "$TRANSCRIPT" 2>&1 >/dev/null) \
  || log "agent $AGENT_ID ($AGENT_TYPE): ledger append failed: $ERR"

exit 0
