#!/usr/bin/env bash
# enforce-readonly.sh
#
# Filesystem-level enforcement of the plugin-read-only rule. Sets a-w on
# every file under ${CLAUDE_PLUGIN_ROOT} (EXCEPT flake.lock, which nix must be
# able to write) so any agent that tries to Edit or Write a plugin source file
# gets EACCES.
#
# Why this exists: the prompt-level read-only rule has been violated four
# times in documented campaigns (snapshot-coverage.sh, update-current.sh,
# run-fuzzer.sh, and snapshot-coverage.sh again). Each violation passed
# through the integrity check too late. This script makes the violation
# fail at write-time instead of being detected after the fact.
#
# Disable: export CC_FUZZER_DISABLE_READONLY_LOCK=1 before launching Claude
# Code. Useful when developing the plugin itself.
#
# Idempotent. Runs at SessionStart via env-check.sh.

set -u

PLUGIN_ROOT="${CLAUDE_PLUGIN_ROOT:-$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)}"

if [ "${CC_FUZZER_DISABLE_READONLY_LOCK:-0}" = "1" ]; then
  echo "cc-fuzzer: read-only lock DISABLED (CC_FUZZER_DISABLE_READONLY_LOCK=1)"
  # Make sure things are writable for development
  chmod -R u+w "$PLUGIN_ROOT" 2>/dev/null || true
  exit 0
fi

if [ ! -d "$PLUGIN_ROOT" ]; then
  echo "cc-fuzzer: plugin root not found at $PLUGIN_ROOT" >&2
  exit 0
fi

# chmod a-w on regular files. Directories stay writable so the plugin
# install/update process can still add or remove files; what we want to
# block is editing of existing files.
#
# Caveat: the root user can write to any file regardless of permissions, so
# this enforcement is bypassable when Claude Code runs as root. In that case
# you also lose the prompt-banner protection because the agent has free run
# of the system. Don't run Claude Code as root.
# Exclude flake.lock: it is nix-managed state, NOT plugin source. The plugin
# ships without a committed lock (gitignored, not in MANIFEST), so nix writes/
# refreshes it in place whenever the plugin flake is evaluated (`nix develop
# <plugin>`, `nix run <plugin>#init`). Locking it read-only makes nix fail with
# "cannot write modified lock file … Permission denied". Keep it writable.
find "$PLUGIN_ROOT" -type f ! -name flake.lock -exec chmod a-w {} \; 2>/dev/null
[ -f "$PLUGIN_ROOT/flake.lock" ] && chmod u+w "$PLUGIN_ROOT/flake.lock" 2>/dev/null || true

# Verify - check that the chmod actually changed mode bits
if [ -f "$PLUGIN_ROOT/MANIFEST.md5" ]; then
  MODE=$(stat -c '%a' "$PLUGIN_ROOT/MANIFEST.md5" 2>/dev/null)
  case "$MODE" in
    *[2367])
      # Last digit indicates "other" perms; 2/3/6/7 mean +w for other
      echo "cc-fuzzer: WARN - chmod a-w didn't take effect (filesystem may not support permissions)" >&2
      ;;
  esac
fi

exit 0
