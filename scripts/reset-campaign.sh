#!/usr/bin/env bash
# reset-campaign.sh
#
# Wipes the campaign with a tarball backup. Asks for confirmation before
# destroying anything. Used by /cc-fuzzer:reset.
#
# Backup location: $FUZZ_ROOT/reset-backup-<ts>.tar.gz
# Backup contains: state/ and crashes/known/

set -u

# Path anchor - refuses cwd inside fuzz/, refuses recursive fuzz/fuzz/
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
. "$SCRIPT_DIR/_lib/path-anchor.sh"
FUZZ_ROOT="${FUZZ_ROOT:-fuzz}"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

if [ ! -d "$FUZZ_ROOT" ]; then
  echo "Nothing to reset: $FUZZ_ROOT does not exist."
  exit 0
fi

# Show what will be deleted
echo "Reset will delete:"
[ -d "$FUZZ_ROOT/state" ]              && echo "  $FUZZ_ROOT/state/"
[ -d "$FUZZ_ROOT/harness" ]            && echo "  $FUZZ_ROOT/harness/"
[ -d "$FUZZ_ROOT/corpus" ]             && echo "  $FUZZ_ROOT/corpus/   ($(ls "$FUZZ_ROOT/corpus" 2>/dev/null | wc -l) seeds)"
[ -d "$FUZZ_ROOT/corpus-quarantine" ]  && echo "  $FUZZ_ROOT/corpus-quarantine/"
[ -d "$FUZZ_ROOT/crashes" ]            && echo "  $FUZZ_ROOT/crashes/   ($(find "$FUZZ_ROOT/crashes" -name '*.bin' 2>/dev/null | wc -l) crash files)"
[ -d "$FUZZ_ROOT/coverage" ]           && echo "  $FUZZ_ROOT/coverage/"
echo ""

# Show findings count
if [ -f "$FUZZ_ROOT/state/findings.jsonl" ]; then
  N=$(grep -c '"schema":"finding/v1"' "$FUZZ_ROOT/state/findings.jsonl" 2>/dev/null || echo 0)
  echo "WARNING: $N unique findings will be archived but no longer accessible to /cc-fuzzer:tick"
  echo ""
fi

# Confirm
if [ -t 0 ]; then
  read -r -p "Proceed with reset? [yes/N] " ANSWER
else
  ANSWER="${RESET_CONFIRM:-no}"
fi
if [ "$ANSWER" != "yes" ]; then
  echo "Aborted."
  exit 1
fi

# Stop the fuzzer first
if [ -x "$SCRIPT_DIR/stop-fuzzer.sh" ]; then
  bash "$SCRIPT_DIR/stop-fuzzer.sh" 2>/dev/null || true
fi

# Backup
BACKUP="$FUZZ_ROOT/reset-backup-$(date +%Y%m%d-%H%M%S).tar.gz"
echo ""
echo "Creating backup: $BACKUP"
tar -czf "$BACKUP" \
  -C "$FUZZ_ROOT" \
  $([ -d "$FUZZ_ROOT/state" ] && echo state) \
  $([ -d "$FUZZ_ROOT/crashes/known" ] && echo crashes/known) \
  2>/dev/null || echo "  (backup creation had warnings)"

# Wipe
rm -rf \
  "$FUZZ_ROOT/state" \
  "$FUZZ_ROOT/harness" \
  "$FUZZ_ROOT/corpus" \
  "$FUZZ_ROOT/corpus-quarantine" \
  "$FUZZ_ROOT/crashes" \
  "$FUZZ_ROOT/coverage"

echo ""
echo "Reset complete."
echo "Backup at $BACKUP"
echo ""
echo "To start a new campaign: /cc-fuzzer:campaign <target>"
