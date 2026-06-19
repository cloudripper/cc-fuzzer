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
. "$SCRIPT_DIR/_lib/harness-path.sh"
cat >/dev/null || true   # consume stdin to avoid SIGPIPE

FUZZ_ROOT="${FUZZ_ROOT:-fuzz}"
STATE_DIR="$FUZZ_ROOT/state"
NEW_DIR="$FUZZ_ROOT/crashes/new"
KNOWN_DIR="$FUZZ_ROOT/crashes/known"
FLAKY_DIR="$FUZZ_ROOT/crashes/flaky"

# Only act when at least one fuzzer slot is alive. We check fuzzers.json for any
# live slot, falling back to the legacy fuzzer.pid if no manifest exists.
any_slot_alive() {
  if [ -f "$STATE_DIR/fuzzers.json" ]; then
    MF="$STATE_DIR/fuzzers.json" python3 - <<'PY' 2>/dev/null
import json, os, sys
try:
    doc = json.load(open(os.environ['MF']))
    for s in doc.get('slots', []):
        pid = s.get('pid','')
        try:
            if pid and int(pid) > 0:
                os.kill(int(pid), 0)
                sys.exit(0)
        except (ValueError, OSError, ProcessLookupError):
            continue
except Exception:
    pass
sys.exit(1)
PY
    return $?
  fi
  if [ -f "$STATE_DIR/fuzzer.pid" ]; then
    local pid
    pid=$(cat "$STATE_DIR/fuzzer.pid" 2>/dev/null)
    [ -n "$pid" ] && kill -0 "$pid" 2>/dev/null
    return $?
  fi
  return 1
}
any_slot_alive || exit 0

mkdir -p "$NEW_DIR"

# Map a found crash file path to its source harness. The
# launcher arranges per-harness output paths so the harness name is recoverable
# from the path's components:
#   fuzz/harnesses/<harness>/.libfuzzer-cwd/crash-*
#   fuzz/harnesses/<harness>/aflpp-out/...
# Returns the harness name on stdout, or empty if not derivable.
path_to_harness() {
  local p="$1"
  # Strip leading ./ for stable matching
  p="${p#./}"
  if [[ "$p" =~ ^(.*/)?fuzz/harnesses/([a-z0-9][a-z0-9_-]{0,31})/ ]]; then
    echo "${BASH_REMATCH[2]}"
    return 0
  fi
  echo ""
  return 1
}

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

  # Compute content hash and the staged filename. Prepend the source harness so
  # the triager can attribute the crash.
  HASH=$(sha256sum "$f" | cut -c1-16)
  H=$(path_to_harness "$f")
  if [ -z "$H" ]; then
    # We can't attribute the crash. An unattributable crash is an evidentiary
    # problem — stage it anyway under a sentinel harness name "unknown" so it
    # isn't dropped, and let the triager flag it.
    H="unknown"
  fi
  STAGE_NAME=$(crash_filename "$H" "$HASH")
  TARGET="$NEW_DIR/$STAGE_NAME"

  if [ -f "$TARGET" ]; then
    continue   # already queued
  fi

  # Skip if hash matches an already-known finding's repro or duplicate
  if [ -d "$KNOWN_DIR" ]; then
    if find "$KNOWN_DIR" -name "*$HASH*.bin" -o -name "repro.bin" 2>/dev/null \
         | xargs -I{} sha256sum {} 2>/dev/null \
         | grep -q "^$(sha256sum "$f" | awk '{print $1}')"; then
      continue
    fi
  fi

  # Hard-link if same fs, copy as fallback
  ln "$f" "$TARGET" 2>/dev/null || cp "$f" "$TARGET"
  QUEUED=$((QUEUED + 1))
done < <(find . -maxdepth 6 \( \
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
