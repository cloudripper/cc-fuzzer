#!/usr/bin/env bash
# Tick status reporter for cc-fuzzer.
#
# Reads fuzz/state/current.json and prints a single-line summary of the
# current campaign tick: coverage percentage, line counts, path count,
# exec/s, plateau status, and seconds since last coverage progress.
#
# Intended for quick status checks during a campaign. Exits non-zero if
# the state file is missing or malformed so callers can detect failure.
set -u

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

#------------------------------------------------------------------------------
# 1. Locate state file
#------------------------------------------------------------------------------
STATE_FILE="fuzz/state/current.json"

if [ ! -f "$STATE_FILE" ]; then
  echo "tick-status: $STATE_FILE not found (are you in a fuzz project?)" >&2
  exit 1
fi

#------------------------------------------------------------------------------
# 2. Parse and emit summary
#------------------------------------------------------------------------------
python3 - "$STATE_FILE" <<'EOF'
import json, sys

try:
    with open(sys.argv[1]) as f:
        d = json.load(f)
except (OSError, json.JSONDecodeError) as e:
    print(f"tick-status: failed to read state: {e}", file=sys.stderr)
    sys.exit(1)

cov   = d.get('coverage', {})
stats = d.get('fuzzer_stats', {})

print(
    f"TICK {d.get('tick_number','?')} | "
    f"cov={cov.get('line_pct','?')}% "
    f"({cov.get('lines_covered','?')}/{cov.get('lines_total','?')}) | "
    f"paths={stats.get('paths','?')} | "
    f"exec/s={stats.get('execs_per_sec','?')} | "
    f"plateau={cov.get('plateau','?')} | "
    f"secs_since_progress={cov.get('seconds_since_progress','?')}"
)
EOF

exit 0
