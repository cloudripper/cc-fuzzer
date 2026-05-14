#!/usr/bin/env bash
# find-delta-targets.sh
#
# Computes git-diff-based "recently changed" targets for the active campaign.
# Pure local tooling - no LLM, no fuzzer interruption.
#
# Output: fuzz/state/snapshots/delta-<ts>.json (schema delta-targets/v1)
#
# Usage:
#   find-delta-targets.sh                        # auto-pick range
#   find-delta-targets.sh --range main..HEAD     # explicit range
#
# Auto-pick rules (in order):
#   1. main..HEAD     if `main` exists and HEAD != main
#   2. master..HEAD   if `master` exists and HEAD != master
#   3. HEAD~30..HEAD  fallback (any repo with >=30 commits)
#
# The artifact is OPTIONAL. coverage-analyst consumes it when present and
# ignores delta weighting when absent. There is no implicit enabling.

set -u

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
. "$SCRIPT_DIR/_lib/path-anchor.sh"

# -- Argument parsing --------------------------------------------------------
RANGE=""
while [ $# -gt 0 ]; do
  case "$1" in
    --range)    RANGE="$2"; shift 2 ;;
    --range=*)  RANGE="${1#--range=}"; shift ;;
    -h|--help)
      echo "Usage: find-delta-targets.sh [--range <git-range>]"
      echo "Default: main..HEAD if main exists, else master..HEAD, else HEAD~30..HEAD"
      exit 0 ;;
    *) echo "ERROR: unknown argument: $1" >&2; exit 2 ;;
  esac
done

# -- Preconditions -----------------------------------------------------------
if ! git -C "$PROJECT_ROOT" rev-parse --git-dir >/dev/null 2>&1; then
  echo "ERROR: $PROJECT_ROOT is not a git repository - delta mode requires git history" >&2
  exit 2
fi

# -- Range auto-pick ---------------------------------------------------------
if [ -z "$RANGE" ]; then
  CURRENT_BRANCH=$(git -C "$PROJECT_ROOT" rev-parse --abbrev-ref HEAD 2>/dev/null || echo "")
  if git -C "$PROJECT_ROOT" rev-parse --verify --quiet main >/dev/null 2>&1 && [ "$CURRENT_BRANCH" != "main" ]; then
    RANGE="main..HEAD"
  elif git -C "$PROJECT_ROOT" rev-parse --verify --quiet master >/dev/null 2>&1 && [ "$CURRENT_BRANCH" != "master" ]; then
    RANGE="master..HEAD"
  else
    RANGE="HEAD~30..HEAD"
  fi
fi

# Verify both endpoints resolve. We accept either `<base>..<tip>` or `<base>...<tip>`.
BASE="${RANGE%%..*}"
TIP="${RANGE##*..}"
[ -z "$TIP" ] && TIP="HEAD"
if ! git -C "$PROJECT_ROOT" rev-parse --quiet --verify "$BASE" >/dev/null 2>&1; then
  echo "ERROR: base of range '$BASE' does not resolve - unknown ref or commit" >&2
  exit 2
fi
if ! git -C "$PROJECT_ROOT" rev-parse --quiet --verify "$TIP" >/dev/null 2>&1; then
  echo "ERROR: tip of range '$TIP' does not resolve - unknown ref or commit" >&2
  exit 2
fi

# -- Output paths ------------------------------------------------------------
TS=$(date +%s)
STATE_DIR="${FUZZ_STATE_DIR:-fuzz/state}"
SNAPSHOTS_DIR="$STATE_DIR/snapshots"
mkdir -p "$SNAPSHOTS_DIR"
OUT_FILE="$SNAPSHOTS_DIR/delta-$TS.json"
TMP_FILE="$OUT_FILE.tmp"

# -- Commits in the range ----------------------------------------------------
COMMITS_JSON=$(git -C "$PROJECT_ROOT" log --format='%H' "$RANGE" 2>/dev/null \
  | python3 -c "
import sys, json
hashes = [l.strip() for l in sys.stdin if l.strip()]
print(json.dumps(hashes))" 2>/dev/null)
[ -z "$COMMITS_JSON" ] && COMMITS_JSON="[]"

# -- Per-hunk targets --------------------------------------------------------
# Parse `git diff --unified=0`. Hunk header: @@ -O,c +N,c @@ <funcname>
# When the language has a configured 'xfuncname' regex (C/C++ ship defaults),
# git fills in <funcname>; otherwise it's empty. We record it when available.
TARGETS_JSON=$(git -C "$PROJECT_ROOT" diff --unified=0 "$RANGE" 2>/dev/null \
  | python3 -c "
import sys, json, re

targets = []
current_file = None
current_kind = 'modified'

for raw in sys.stdin:
    line = raw.rstrip('\n')
    m = re.match(r'^diff --git a/(.+) b/(.+)$', line)
    if m:
        current_file = m.group(2)
        current_kind = 'modified'
        continue
    if line.startswith('new file'):
        current_kind = 'added'
        continue
    if line.startswith('deleted file'):
        current_kind = 'deleted'
        continue
    m = re.match(r'^@@ -\d+(?:,\d+)? \+(\d+)(?:,(\d+))? @@(.*)$', line)
    if m and current_file:
        start = int(m.group(1))
        count = int(m.group(2)) if m.group(2) is not None else 1
        # A hunk with count=0 is a deletion at line N; report it at line N.
        end = start + max(count - 1, 0) if count > 0 else start
        func = m.group(3).strip() or None
        targets.append({
            'file': current_file,
            'function_context': func,
            'lines_changed': [start, end],
            'kind': current_kind,
        })

print(json.dumps(targets))
" 2>/dev/null)
[ -z "$TARGETS_JSON" ] && TARGETS_JSON="[]"

# Distinct file count from the targets list
FILE_COUNT=$(echo "$TARGETS_JSON" | python3 -c "
import sys, json
try:
    t = json.load(sys.stdin)
    print(len(set(x['file'] for x in t)))
except: print(0)" 2>/dev/null)
case "$FILE_COUNT" in ''|*[!0-9]*) FILE_COUNT=0 ;; esac

# -- Write atomically --------------------------------------------------------
cat > "$TMP_FILE" <<EOF
{
  "schema": "delta-targets/v1",
  "timestamp": $TS,
  "range": "$RANGE",
  "commits": $COMMITS_JSON,
  "files_changed": $FILE_COUNT,
  "targets": $TARGETS_JSON
}
EOF

if ! python3 -c "import json; json.load(open('$TMP_FILE'))" >/dev/null 2>&1; then
  echo "ERROR: produced invalid JSON; refusing to promote $OUT_FILE" >&2
  rm -f "$TMP_FILE"
  exit 2
fi

mv "$TMP_FILE" "$OUT_FILE"
echo "$OUT_FILE"

TARGET_COUNT=$(echo "$TARGETS_JSON" | python3 -c "import sys,json; print(len(json.load(sys.stdin)))" 2>/dev/null || echo 0)
echo "delta: $TARGET_COUNT hunks across $FILE_COUNT files in $RANGE" >&2

exit 0
