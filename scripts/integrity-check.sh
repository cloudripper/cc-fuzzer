#!/usr/bin/env bash
# integrity-check.sh
#
# Verifies plugin scripts haven't been modified since release. Compares md5sum
# of every file in scripts/ against the shipped MANIFEST.md5. Prints a loud
# warning for any drift.
#
# Why this exists: agents have patched plugin files in place three times in
# documented campaigns (snapshot-coverage.sh, update-current.sh, run-fuzzer.sh).
# Each violation defeated the spirit of the read-only rule. This script makes
# drift visible at every session start.
#
# Output:
#   "ok" if all files match MANIFEST.md5
#   "WARN: <N> file(s) modified" with details if any drift detected
#
# Exit code is always 0 (we don't want to break the user's session over this,
# but we want them to see the warning).

set -u

# Locate the plugin root (this script's own directory minus /scripts/)
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PLUGIN_ROOT="$(dirname "$SCRIPT_DIR")"
MANIFEST="$PLUGIN_ROOT/MANIFEST.md5"

if [ ! -f "$MANIFEST" ]; then
  echo "WARN: MANIFEST.md5 missing - cannot verify integrity"
  exit 0
fi

DRIFT_COUNT=0
DRIFT_FILES=()

while IFS= read -r line; do
  [ -z "$line" ] && continue
  case "$line" in '#'*) continue;; esac
  EXPECTED_HASH=$(echo "$line" | awk '{print $1}')
  REL_PATH=$(echo "$line" | awk '{print $2}')
  ABS_PATH="$PLUGIN_ROOT/$REL_PATH"

  if [ ! -f "$ABS_PATH" ]; then
    DRIFT_COUNT=$((DRIFT_COUNT + 1))
    DRIFT_FILES+=("MISSING: $REL_PATH")
    continue
  fi

  ACTUAL_HASH=$(md5sum "$ABS_PATH" | awk '{print $1}')
  if [ "$ACTUAL_HASH" != "$EXPECTED_HASH" ]; then
    DRIFT_COUNT=$((DRIFT_COUNT + 1))
    DRIFT_FILES+=("MODIFIED: $REL_PATH (expected $EXPECTED_HASH, got $ACTUAL_HASH)")
  fi
done < "$MANIFEST"

if [ "$DRIFT_COUNT" -eq 0 ]; then
  echo "ok"
  exit 0
fi

# Drift detected - print loudly
echo ""
echo "================================================================"
echo "  PLUGIN INTEGRITY WARNING - $DRIFT_COUNT file(s) modified"
echo "================================================================"
echo ""
echo "Plugin files have been modified since release. This usually means an"
echo "agent edited a script in place, which is forbidden (see plugin file"
echo "rule in any agent prompt). In-place patches disappear on /plugin update,"
echo "leaving you with mysterious behavior changes and lost fixes."
echo ""
echo "Modified files:"
for f in "${DRIFT_FILES[@]}"; do
  echo "  - $f"
done
echo ""
echo "Recommended fix:"
echo "  /plugin marketplace update <your-marketplace>"
echo "  /plugin install cc-fuzzer@<your-marketplace>"
echo ""
echo "Or restore the canonical version manually from the cc-fuzzer release"
echo "tarball (these hashes are in MANIFEST.md5)."
echo "================================================================"
echo ""

exit 0  # don't break the session, just warn
