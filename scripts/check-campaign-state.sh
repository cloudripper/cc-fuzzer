#!/usr/bin/env bash
# check-campaign-state.sh
#
# Classifies the current campaign state for /cc-fuzzer:campaign dispatch.
# Prints exactly one of:
#   none        - no campaign exists; cold start needed
#   running     - campaign exists, fuzzer is alive; just print status
#   stopped     - campaign exists, fuzzer is not running; resume needed
#   stale       - target source has changed since last build; user must choose
#   corrupted   - state directory exists but fails validation; user must fix or reset
#
# Always exits 0; the classification is on stdout. Diagnostic detail on stderr.

set -u

# Path anchor - refuses cwd inside fuzz/, refuses recursive fuzz/fuzz/
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
. "$SCRIPT_DIR/_lib/path-anchor.sh"
FUZZ_ROOT="${FUZZ_ROOT:-fuzz}"
STATE_DIR="$FUZZ_ROOT/state"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# 1. No state at all
if [ ! -d "$STATE_DIR" ] || [ ! -f "$STATE_DIR/harness-built.json" ]; then
  echo "none"
  exit 0
fi

# 2. Validate state - if it's broken, classify as corrupted
VALIDATE_OUT=$(FUZZ_ROOT="$FUZZ_ROOT" bash "$SCRIPT_DIR/validate-state.sh" 2>&1)
if [ "$?" -ne 0 ]; then
  echo "corrupted"
  echo "$VALIDATE_OUT" >&2
  exit 0
fi

# 3. Check if target source has changed
TARGET_SOURCE=""
RECORDED_HASH=""
if [ -f "$STATE_DIR/harness-built.json" ]; then
  TARGET_SOURCE=$(python3 -c "
import json
try: print(json.load(open('$STATE_DIR/harness-built.json')).get('target_source', ''))
except: pass" 2>/dev/null)
  RECORDED_HASH=$(python3 -c "
import json
try: print(json.load(open('$STATE_DIR/harness-built.json')).get('target_source_hash', ''))
except: pass" 2>/dev/null)
fi

if [ -n "$TARGET_SOURCE" ] && [ -f "$TARGET_SOURCE" ] && [ -n "$RECORDED_HASH" ]; then
  CURRENT_HASH=$(sha256sum "$TARGET_SOURCE" | cut -c1-16)
  if [ "$CURRENT_HASH" != "$RECORDED_HASH" ]; then
    echo "stale"
    echo "target source changed: $TARGET_SOURCE" >&2
    echo "  recorded hash: $RECORDED_HASH" >&2
    echo "  current hash:  $CURRENT_HASH" >&2
    exit 0
  fi
fi

# 4. Check if fuzzer is running
if [ -f "$STATE_DIR/fuzzer.pid" ]; then
  PID=$(cat "$STATE_DIR/fuzzer.pid")
  if kill -0 "$PID" 2>/dev/null; then
    echo "running"
    exit 0
  fi
fi

# 5. Otherwise it's stopped, ready to resume
echo "stopped"
exit 0
