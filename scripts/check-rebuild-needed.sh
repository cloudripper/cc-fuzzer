#!/usr/bin/env bash
# check-rebuild-needed.sh
#
# Determines whether the fuzz harness genuinely needs to be rebuilt. The
# orchestrator should call this before invoking harness-writer to avoid
# wasting tokens (and CPU) on rebuilds that produce identical output.
#
# Returns:
#   exit 0  + "rebuild" on stdout : rebuild is needed
#   exit 0  + "skip"    on stdout : skip rebuild, harness is current
#   exit 1                        : error (treat as rebuild)
#
# Reasons for rebuild are printed on stderr.

set -u

# Path anchor - refuses cwd inside fuzz/, refuses recursive fuzz/fuzz/
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
. "$SCRIPT_DIR/_lib/path-anchor.sh"
STATE_DIR="${FUZZ_STATE_DIR:-fuzz/state}"
HARNESS_INFO="$STATE_DIR/harness-built.json"

if [ ! -f "$HARNESS_INFO" ]; then
  echo "no harness-built.json - first build" >&2
  echo "rebuild"
  exit 0
fi

# Extract from harness-built.json: harness binary path, harness source path,
# the recorded target source hash (if any), and the recorded build command hash.
read HARNESS_BIN HARNESS_SRC RECORDED_TARGET_HASH RECORDED_BUILD_HASH < <(python3 -c "
import json, sys
try:
    d = json.load(open('$HARNESS_INFO'))
    print(d.get('harness_binary', ''),
          d.get('harness_source', ''),
          d.get('target_source_hash', ''),
          d.get('build_command_hash', ''))
except Exception as e:
    print('', '', '', '', file=sys.stderr)
    sys.exit(1)
")

# 1. If the binary doesn't exist, rebuild
if [ -z "$HARNESS_BIN" ] || [ ! -x "$HARNESS_BIN" ]; then
  echo "harness binary missing or not executable: $HARNESS_BIN" >&2
  echo "rebuild"
  exit 0
fi

# 2. If the harness source doesn't exist, rebuild
if [ -z "$HARNESS_SRC" ] || [ ! -f "$HARNESS_SRC" ]; then
  echo "harness source missing: $HARNESS_SRC" >&2
  echo "rebuild"
  exit 0
fi

# 3. If the harness source is newer than the binary, rebuild
if [ "$HARNESS_SRC" -nt "$HARNESS_BIN" ]; then
  echo "harness source modified since last build" >&2
  echo "rebuild"
  exit 0
fi

# 4. Check target source hash - if target source changed, rebuild
TARGET_SOURCE="${FUZZ_TARGET_SOURCE:-}"
if [ -n "$TARGET_SOURCE" ] && [ -f "$TARGET_SOURCE" ]; then
  CURRENT_TARGET_HASH=$(sha256sum "$TARGET_SOURCE" | cut -c1-16)
  if [ -n "$RECORDED_TARGET_HASH" ] && [ "$CURRENT_TARGET_HASH" != "$RECORDED_TARGET_HASH" ]; then
    echo "target source changed (hash mismatch)" >&2
    echo "rebuild"
    exit 0
  fi
fi

# All checks pass - harness is current
echo "harness is current (binary exists, source unchanged)" >&2
echo "skip"
exit 0
