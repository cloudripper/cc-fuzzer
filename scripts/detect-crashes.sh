#!/usr/bin/env bash
# detect-crashes.sh
#
# PostToolUse hook. Implements the first stage of the canonical crash flow
# from STATE_SCHEMA.md:
#   - When a fuzzer-discovered crash file appears, hard-link it into
#     fuzz/crashes/new/<sha256>.bin so it's queued for triage.
#   - Crashes from libFuzzer (./crash-*) and AFL++ (out/default/crashes/id:*)
#     are both handled.
#
# Stays silent if no campaign is active.

set -u

# Fast project-presence check. If there's no fuzz/ anywhere in our parent
# chain, this is a Bash call outside any cc-fuzzer project — silently
# no-op. We do this BEFORE sourcing path-anchor.sh because that library
# exits 2 with a stderr message in this case, which the PostToolUse hook
# framework surfaces as a blocking error on every Bash call. Duplicates
# ~6 lines of detection logic from path-anchor.sh on purpose: the hook is
# the only caller that should silently no-op outside a project, while every
# other consumer of path-anchor.sh should keep its fail-loud semantics.
_d="$PWD"
while [ "$_d" != "/" ]; do
  if [ -d "$_d/fuzz" ] && [ "$(basename "$_d")" != "fuzz" ]; then
    break
  fi
  _d=$(dirname "$_d")
done
[ "$_d" = "/" ] && exit 0

# Path anchor - refuses cwd inside fuzz/, refuses recursive fuzz/fuzz/
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
. "$SCRIPT_DIR/_lib/path-anchor.sh"
cat >/dev/null || true   # consume stdin to avoid SIGPIPE

FUZZ_ROOT="${FUZZ_ROOT:-fuzz}"
STATE_DIR="$FUZZ_ROOT/state"
NEW_DIR="$FUZZ_ROOT/crashes/new"
KNOWN_DIR="$FUZZ_ROOT/crashes/known"
FLAKY_DIR="$FUZZ_ROOT/crashes/flaky"

# Only act when a campaign is running
[ -f "$STATE_DIR/fuzzer.pid" ] || exit 0
PID=$(cat "$STATE_DIR/fuzzer.pid" 2>/dev/null)
[ -n "$PID" ] && kill -0 "$PID" 2>/dev/null || exit 0

mkdir -p "$NEW_DIR"

# Find new crash files in canonical engine locations modified in the last 5 min.
# We use mmin -5 (not -1) to avoid races with the hook firing rate.
QUEUED=0
while IFS= read -r f; do
  [ -f "$f" ] || continue

  # Skip files already moved into our queue
  case "$f" in
    "$NEW_DIR"/*) continue;;
    "$KNOWN_DIR"/*) continue;;
    "$FLAKY_DIR"/*) continue;;
  esac

  # Compute content hash and queue
  HASH=$(sha256sum "$f" | cut -c1-16)
  TARGET="$NEW_DIR/$HASH.bin"

  if [ -f "$TARGET" ]; then
    continue   # already queued
  fi

  # Skip if hash matches an already-known finding's repro or duplicate
  if [ -d "$KNOWN_DIR" ]; then
    if find "$KNOWN_DIR" -name "$HASH.bin" -o -name "repro.bin" 2>/dev/null \
         | xargs -I{} sha256sum {} 2>/dev/null \
         | grep -q "^$(sha256sum "$f" | awk '{print $1}')"; then
      continue
    fi
  fi

  # Hard-link if same fs, copy as fallback
  ln "$f" "$TARGET" 2>/dev/null || cp "$f" "$TARGET"
  QUEUED=$((QUEUED + 1))
done < <(find . -maxdepth 5 \( \
    -path '*/crashes/id:*' -o \
    -name 'crash-*' -o \
    -name 'leak-*' -o \
    -name 'oom-*' -o \
    -name 'timeout-*' \
  \) -mmin -5 -type f 2>/dev/null \
  | grep -v "^$NEW_DIR" \
  | grep -v "^$KNOWN_DIR" \
  | grep -v "^$FLAKY_DIR")

# Tell Claude there's work to do, but only when we actually queued something
if [ "$QUEUED" -gt 0 ]; then
  cat <<EOF
{
  "hookSpecificOutput": {
    "hookEventName": "PostToolUse",
    "additionalContext": "cc-fuzzer: queued $QUEUED new crash file(s) into $NEW_DIR/. Next /cc-fuzzer:tick should dispatch crash-triager."
  }
}
EOF
fi

exit 0
