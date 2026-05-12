#!/usr/bin/env bash
# reverify-after-rebuild.sh
#
# Re-verifies all findings against the current harness binary. Findings that
# no longer reproduce are moved to fuzz/crashes/stale/ via findings.sh stale-mark.
#
# This addresses the v0.11→v0.12 problem: when a campaign rebuilds the harness
# (different optimization, source change, glibc update), some crash artifacts
# stop reproducing because the binary's layout or ABI shifted. The findings
# aren't fictional - they were real against the OLD binary - but the artifacts
# don't trigger against the NEW binary.
#
# Usage:
#   reverify-after-rebuild.sh           Verify all findings, mark stale ones
#   reverify-after-rebuild.sh --dry-run Show what would change without acting
#
# Exit codes:
#   0  - completed (regardless of how many findings were marked stale)
#   1  - environmental error (no harness, no findings.jsonl, etc.)

set -u

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
. "$SCRIPT_DIR/_lib/path-anchor.sh"

DRY_RUN=0
case "${1:-}" in
  --dry-run|-n) DRY_RUN=1 ;;
esac

STATE_DIR="${FUZZ_STATE_DIR:-$FUZZ_ROOT/state}"
FINDINGS="$STATE_DIR/findings.jsonl"

if [ ! -f "$FINDINGS" ]; then
  echo "no findings.jsonl - nothing to verify" >&2
  exit 0
fi

if [ ! -f "$STATE_DIR/harness-built.json" ]; then
  echo "ERROR: no harness-built.json - cannot verify" >&2
  exit 1
fi

echo "Re-verifying findings against current harness build..."
echo ""

# Run findings.sh verify and capture per-finding results
RESULT=$(bash "$SCRIPT_DIR/findings.sh" verify 2>/dev/null || true)

if [ -z "$RESULT" ]; then
  echo "No findings to verify."
  exit 0
fi

# Print the result table
printf '%-8s %s\n' 'ID' 'STATUS'
printf '%-8s %s\n' '--' '------'
echo "$RESULT" | while IFS=$'\t' read -r id status; do
  printf '%-8s %s\n' "$id" "$status"
done

echo ""

# Count categories
TOTAL=$(echo "$RESULT" | wc -l)
OK=$(echo "$RESULT" | awk -F'\t' '$2=="ok"' | wc -l)
STALE=$(echo "$RESULT" | awk -F'\t' '$2=="stale"' | wc -l)
MISSING=$(echo "$RESULT" | awk -F'\t' '$2=="missing"' | wc -l)

echo "Summary: $TOTAL total, $OK ok, $STALE stale, $MISSING missing"

if [ "$STALE" -eq 0 ] && [ "$MISSING" -eq 0 ]; then
  echo "All findings still reproduce. No action needed."
  exit 0
fi

if [ "$DRY_RUN" -eq 1 ]; then
  echo ""
  echo "(dry run - no changes made)"
  echo "to mark stale findings, run without --dry-run"
  exit 0
fi

# Mark stale findings
echo ""
echo "Marking stale findings..."
echo "$RESULT" | awk -F'\t' '$2=="stale"' | while IFS=$'\t' read -r id _; do
  bash "$SCRIPT_DIR/findings.sh" stale-mark "$id"
done

# Note missing findings (no auto-action - the user should investigate)
if [ "$MISSING" -gt 0 ]; then
  echo ""
  echo "WARNING: $MISSING finding(s) had missing reproducer files:"
  echo "$RESULT" | awk -F'\t' '$2=="missing" {print "  " $1}'
  echo "  (these were not modified - investigate manually)"
fi

echo ""
echo "Done. Review fuzz/crashes/stale/ and findings.jsonl for the new state."
