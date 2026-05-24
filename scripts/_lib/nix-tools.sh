#!/usr/bin/env bash
# _lib/nix-tools.sh
#
# Sourceable helpers for resolving Nix-provided tools from a captured
# fuzz/state/nix-env.json snapshot. Eliminates per-script /nix/store walks.
#
# Functions (safe under set -u; none modify the caller's PATH):
#
#   nix_tool <name>      Echo absolute path or empty. Resolution order:
#                        1. fuzz/state/nix-env.json tools[<name>]
#                        2. PATH (command -v fallback)
#                        Returns 0 when found, 1 when not.
#
#   nix_require <name>   Echo absolute path or print a fix-it diagnostic and
#                        exit 2. Use in scripts where the tool is mandatory.
#
#   nix_env_file         Echo the path to nix-env.json (or empty if missing).
#
# Refreshing the snapshot: scripts/capture-nix-env.sh (auto-runs at session
# start via the env-check.sh SessionStart hook).

_nix_tools_state_dir() {
  if [ -n "${FUZZ_STATE_DIR:-}" ]; then
    echo "$FUZZ_STATE_DIR"
  elif [ -n "${FUZZ_ROOT:-}" ]; then
    echo "$FUZZ_ROOT/state"
  else
    echo "fuzz/state"
  fi
}

nix_env_file() {
  local f
  f="$(_nix_tools_state_dir)/nix-env.json"
  [ -f "$f" ] && echo "$f"
}

nix_tool() {
  local name="${1:-}"
  [ -n "$name" ] || return 1
  local f
  f=$(nix_env_file)
  if [ -n "$f" ]; then
    local p
    p=$(NIX_ENV_FILE="$f" NIX_ENV_NAME="$name" python3 - <<'PY' 2>/dev/null
import json, os
try:
    d = json.load(open(os.environ["NIX_ENV_FILE"]))
    print(d.get("tools", {}).get(os.environ["NIX_ENV_NAME"], "") or "")
except Exception:
    print("")
PY
)
    if [ -n "$p" ] && [ -x "$p" ]; then
      echo "$p"
      return 0
    fi
  fi
  local cmd_path
  cmd_path=$(command -v "$name" 2>/dev/null || true)
  if [ -n "$cmd_path" ]; then
    echo "$cmd_path"
    return 0
  fi
  return 1
}

nix_require() {
  local name="${1:-}"
  local p
  if p=$(nix_tool "$name") && [ -n "$p" ]; then
    echo "$p"
    return 0
  fi
  echo "ERROR: required tool '$name' not found." >&2
  echo "       Resolution order: fuzz/state/nix-env.json then PATH." >&2
  if [ -z "$(nix_env_file)" ]; then
    echo "       (nix-env.json missing — run scripts/capture-nix-env.sh, or it" >&2
    echo "        auto-runs at session start when fuzz/ exists in cwd)" >&2
  fi
  echo "       Fix: nix develop \$CLAUDE_PLUGIN_ROOT before launching claude" >&2
  exit 2
}
