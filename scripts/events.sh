#!/usr/bin/env bash
# events.sh
#
# The ONLY writer of events.jsonl. The orchestrator must call this rather
# than appending lines directly, so the schema field is always present and
# the format is consistent.
#
# Usage:
#   events.sh tick <branch> <reason> <duration_ms> [agent_called]
#   events.sh agent_call <agent> <tokens_in> <tokens_out>
#   events.sh campaign_start
#   events.sh campaign_resume
#   events.sh campaign_stop
#   events.sh corpus_quarantine <count> <details>
#   events.sh error <message>
#
# Atomic append. Schema: event/v1.

set -u

# Path anchor - refuses cwd inside fuzz/, refuses recursive fuzz/fuzz/
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
. "$SCRIPT_DIR/_lib/path-anchor.sh"
FUZZ_ROOT="${FUZZ_ROOT:-fuzz}"
STATE_DIR="$FUZZ_ROOT/state"
EVENTS="$STATE_DIR/events.jsonl"
mkdir -p "$STATE_DIR"

NOW=$(date +%s)

# Tick number — count "event":"tick" entries via python (grep -c can return
# blank or multiline output if events.jsonl is missing/empty/binary-corrupted).
TICK=0
if [ -f "$EVENTS" ]; then
  TICK=$(python3 -c "
import json
n = 0
try:
    with open('$EVENTS') as f:
        for line in f:
            line = line.strip()
            if not line: continue
            try:
                if json.loads(line).get('event') == 'tick':
                    n += 1
            except: pass
except: pass
print(n)
" 2>/dev/null)
  case "$TICK" in
    ''|*[!0-9]*) TICK=0 ;;
  esac
fi

cmd="${1:-help}"
shift || true

# Helper: emit a JSON line with given extra fields (passed as a JSON string).
# Uses an env var for the extra JSON to avoid shell quoting hell.
emit() {
  local extra_json="${1:-{\}}"
  EXTRA_JSON="$extra_json" CMD="$cmd" NOW="$NOW" TICK="$TICK" EVENTS_FILE="$EVENTS" \
    python3 <<'PY' >> "$EVENTS"
import json, os
d = {
    'schema': 'event/v1',
    'ts': int(os.environ['NOW']),
    'tick': int(os.environ['TICK']),
    'event': os.environ['CMD'],
}
extra = os.environ.get('EXTRA_JSON', '{}')
try:
    d.update(json.loads(extra))
except json.JSONDecodeError:
    pass  # silently ignore bad extras
print(json.dumps(d, separators=(',', ':')))
PY
}

# Helper: build an extra-fields JSON object from a python dict spec
build_extra() {
  python3 -c "import json, sys; print(json.dumps(eval(sys.argv[1])))" "$1"
}

case "$cmd" in
  tick)
    BRANCH="${1:?branch required}"
    REASON="${2:-}"
    DURATION="${3:-0}"
    AGENT="${4:-}"
    extra=$(BRANCH="$BRANCH" REASON="$REASON" DURATION="$DURATION" AGENT="$AGENT" python3 <<'PY'
import json, os
d = {'branch': os.environ['BRANCH'], 'reason': os.environ['REASON'], 'duration_ms': int(os.environ['DURATION'])}
if os.environ.get('AGENT'):
    d['agent_called'] = os.environ['AGENT']
print(json.dumps(d))
PY
)
    emit "$extra"
    ;;

  agent_call)
    AGENT="${1:?agent name required}"
    TOKENS_IN="${2:-0}"
    TOKENS_OUT="${3:-0}"
    extra=$(AGENT="$AGENT" TI="$TOKENS_IN" TO="$TOKENS_OUT" python3 <<'PY'
import json, os
print(json.dumps({'agent_called': os.environ['AGENT'], 'tokens_in': int(os.environ['TI']), 'tokens_out': int(os.environ['TO'])}))
PY
)
    emit "$extra"
    ;;

  campaign_start|campaign_resume|campaign_stop)
    emit '{}'
    ;;

  corpus_quarantine)
    COUNT="${1:-0}"
    DETAILS="${2:-}"
    extra=$(COUNT="$COUNT" DETAILS="$DETAILS" python3 <<'PY'
import json, os
print(json.dumps({'count': int(os.environ['COUNT']), 'details': os.environ['DETAILS']}))
PY
)
    emit "$extra"
    ;;

  error)
    MSG="${1:?error message required}"
    extra=$(MSG="$MSG" python3 <<'PY'
import json, os
print(json.dumps({'error_message': os.environ['MSG']}))
PY
)
    emit "$extra"
    ;;

  help|*)
    cat <<EOF
events.sh - the canonical writer for $EVENTS

Commands:
  tick <branch> <reason> <duration_ms> [agent]
  agent_call <agent> <tokens_in> <tokens_out>
  campaign_start | campaign_resume | campaign_stop
  corpus_quarantine <count> <details>
  error <message>

Per STATE_SCHEMA.md, this is the ONLY tool that should write to events.jsonl.
Always sets schema: event/v1.
EOF
    ;;
esac
