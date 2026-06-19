#!/usr/bin/env bash
# reset-campaign.sh
#
# Wipes the campaign with a tarball backup AND backup-safe staging. Asks for
# confirmation before destroying anything. Used by /fuzz-reset.
#
# Backup locations:
#   1. $FUZZ_ROOT/reset-backup-<ts>.tar.gz   (existing tarball, archive form)
#   2. $FUZZ_ROOT/.trash/<ts>/               (per-tree, browsable, easy salvage)
#
# Backup contains: state/ and crashes/known/. fuzz/findings/ is excluded
# because findings/ is TRACKED by default (fuzz/.gitignore from
# templates/fuzz.gitignore negates the fuzz/* ignore for findings/), so the
# git history IS the backup. PLUGIN_ISSUES friction item 4: do not delete the
# only backup of untracked work.
#
# .trash/<ts>/ GC policy: stale staged trees are reaped by a 7-day sweep
# (planned followup). For v0.30 we only STAGE; the sweep itself is not
# implemented here. Until the sweep ships, .trash/ accumulates — manually
# `rm -rf fuzz/.trash/<older-ts>/` when you're sure the campaign is dead.

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
  N=$(grep -c '"schema":"finding/v2"' "$FUZZ_ROOT/state/findings.jsonl" 2>/dev/null || echo 0)
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

# Backup — both tarball (archive) AND per-tree stage to .trash/<ts>/ (browsable).
TS_STAMP=$(date +%Y%m%d-%H%M%S)
BACKUP="$FUZZ_ROOT/reset-backup-$TS_STAMP.tar.gz"
TRASH_BASE="$FUZZ_ROOT/.trash/$TS_STAMP"
echo ""
echo "Creating backup: $BACKUP"
tar -czf "$BACKUP" \
  -C "$FUZZ_ROOT" \
  $([ -d "$FUZZ_ROOT/state" ] && echo state) \
  $([ -d "$FUZZ_ROOT/crashes/known" ] && echo crashes/known) \
  2>/dev/null || echo "  (backup creation had warnings)"

# Stage to .trash/<ts>/ before hard-delete (PLUGIN_ISSUES friction 4 — keep a
# browsable salvage copy, not just the tarball). We move (not copy) so we don't
# double the disk pressure on a reset, and the subsequent rm -rf is a no-op
# for trees we already staged. The .trash subtree is reaped by the 7-day GC
# sweep (planned followup).
mkdir -p "$TRASH_BASE"
for sub in state crashes findings; do
  if [ -d "$FUZZ_ROOT/$sub" ]; then
    mkdir -p "$(dirname "$TRASH_BASE/$sub")"
    mv "$FUZZ_ROOT/$sub" "$TRASH_BASE/$sub" 2>/dev/null && \
      echo "  staged $FUZZ_ROOT/$sub -> $TRASH_BASE/$sub"
  fi
done

# Wipe everything else (harness/corpus/coverage are regeneratable; nothing
# user-authored lives there). The staged trees above are already moved.
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
