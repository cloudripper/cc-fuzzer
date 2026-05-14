#!/usr/bin/env bash
# blame-finding.sh
#
# Computes minimal git provenance for a finding's source location. Pure local:
# git blame + git log. No LLM. Output is small structured JSON that the
# reporting-agent embeds verbatim in FINDINGS-REPORT.md per finding.
#
# Usage:
#   blame-finding.sh <file> <line>
#
# Output (single-line JSON on stdout):
#   {
#     "file": "...",
#     "line": N,
#     "git_repo": true | false,
#     "blamed_commit": "<short-sha>" | null,
#     "blamed_date": "YYYY-MM-DD" | null,
#     "blamed_author": "Name <email>" | null,
#     "blamed_summary": "first line of commit message" | null,
#     "function_first_added": "YYYY-MM-DD" | null,
#     "in_delta_range": true | false | null,
#     "delta_range": "<range>" | null
#   }
#
# All fields are optional. `in_delta_range` is null when no delta-*.json exists.
# The agent should treat any missing/null field as "unknown".

set -u

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
. "$SCRIPT_DIR/_lib/path-anchor.sh"

if [ $# -lt 2 ]; then
  echo "Usage: blame-finding.sh <file> <line>" >&2
  exit 1
fi

FILE="$1"
LINE="$2"

case "$LINE" in
  ''|*[!0-9]*)
    echo "ERROR: line must be a positive integer, got '$LINE'" >&2
    exit 1 ;;
esac

# Build a minimal JSON record using python (clean escaping). Variables in env.
emit_json() {
  python3 -c "
import json, os
o = {
    'file': os.environ.get('B_FILE', ''),
    'line': int(os.environ.get('B_LINE', '0')),
    'git_repo': os.environ.get('B_GIT_REPO', 'false') == 'true',
    'blamed_commit': os.environ.get('B_COMMIT') or None,
    'blamed_date': os.environ.get('B_DATE') or None,
    'blamed_author': os.environ.get('B_AUTHOR') or None,
    'blamed_summary': os.environ.get('B_SUMMARY') or None,
    'function_first_added': os.environ.get('B_FILE_FIRST') or None,
    'in_delta_range': {'true': True, 'false': False, 'unknown': None}.get(
        os.environ.get('B_IN_DELTA', 'unknown'), None),
    'delta_range': os.environ.get('B_DELTA_RANGE') or None,
}
print(json.dumps(o))
"
}

# Not a git repo? Emit a minimal record and exit 0 — caller still uses the result.
if ! git -C "$PROJECT_ROOT" rev-parse --git-dir >/dev/null 2>&1; then
  B_FILE="$FILE" B_LINE="$LINE" B_GIT_REPO="false" emit_json
  exit 0
fi

# git blame --porcelain on a single line, stable parseable format.
BLAME_OUT=$(git -C "$PROJECT_ROOT" blame -L "$LINE,$LINE" --porcelain -- "$FILE" 2>/dev/null || true)

B_COMMIT=""
B_DATE=""
B_AUTHOR=""
B_SUMMARY=""

if [ -n "$BLAME_OUT" ]; then
  # First token of first line is the commit hash. Shorten to 12 chars for display.
  FULL_SHA=$(echo "$BLAME_OUT" | awk 'NR==1{print $1}')
  if [ -n "$FULL_SHA" ] && [ "$FULL_SHA" != "0000000000000000000000000000000000000000" ]; then
    B_COMMIT="${FULL_SHA:0:12}"
    AT=$(echo "$BLAME_OUT" | awk '/^author-time /{print $2; exit}')
    if [ -n "$AT" ]; then
      B_DATE=$(date -u -d "@$AT" '+%Y-%m-%d' 2>/dev/null || echo "")
    fi
    AN=$(echo "$BLAME_OUT" | sed -n 's/^author //p' | head -1)
    AM=$(echo "$BLAME_OUT" | sed -n 's/^author-mail //p' | head -1)
    if [ -n "$AN" ]; then
      if [ -n "$AM" ]; then
        B_AUTHOR="$AN $AM"
      else
        B_AUTHOR="$AN"
      fi
    fi
    B_SUMMARY=$(echo "$BLAME_OUT" | sed -n 's/^summary //p' | head -1)
  fi
fi

# When was this file first added to the repo? Cheap proxy for "how old is the code here".
B_FILE_FIRST=$(git -C "$PROJECT_ROOT" log --diff-filter=A --format='%cd' --date=short -- "$FILE" 2>/dev/null | tail -1)

# In-delta check: only meaningful when a delta artifact exists.
B_IN_DELTA="unknown"
B_DELTA_RANGE=""
DELTA_FILE=$(ls -t "$PROJECT_ROOT/fuzz/state/snapshots"/delta-*.json 2>/dev/null | head -1)
if [ -n "$DELTA_FILE" ]; then
  B_DELTA_RANGE=$(python3 -c "
import json
try: print(json.load(open('$DELTA_FILE')).get('range',''))
except: pass" 2>/dev/null)

  if [ -n "$B_DELTA_RANGE" ] && [ -n "$B_COMMIT" ]; then
    BASE="${B_DELTA_RANGE%%..*}"
    TIP="${B_DELTA_RANGE##*..}"
    [ -z "$TIP" ] && TIP="HEAD"
    # blamed_commit is in delta iff it's an ancestor of TIP AND NOT an ancestor of BASE.
    if git -C "$PROJECT_ROOT" merge-base --is-ancestor "$B_COMMIT" "$TIP" 2>/dev/null \
       && ! git -C "$PROJECT_ROOT" merge-base --is-ancestor "$B_COMMIT" "$BASE" 2>/dev/null; then
      B_IN_DELTA="true"
    else
      B_IN_DELTA="false"
    fi
  fi
fi

B_FILE="$FILE" \
B_LINE="$LINE" \
B_GIT_REPO="true" \
B_COMMIT="$B_COMMIT" \
B_DATE="$B_DATE" \
B_AUTHOR="$B_AUTHOR" \
B_SUMMARY="$B_SUMMARY" \
B_FILE_FIRST="$B_FILE_FIRST" \
B_IN_DELTA="$B_IN_DELTA" \
B_DELTA_RANGE="$B_DELTA_RANGE" \
emit_json

exit 0
