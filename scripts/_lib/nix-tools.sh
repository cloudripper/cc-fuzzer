#!/usr/bin/env bash
# _lib/nix-tools.sh
#
# Sourceable helpers for resolving Nix-provided tools from a captured
# fuzz/state/nix-env.json snapshot. Eliminates per-script /nix/store walks.
#
# This is the plugin-side tool provider: the core's own lookup
# (cc_fuzzer_core.tools.which) never scans host layouts.
#
# Functions (safe under set -u; none modify the caller's PATH):
#
#   nix_tool <name>      Echo absolute path or empty. Resolution order:
#                        1-3. `cc-fuzzer tool which <name>`: $CC_FUZZER_TOOL_<NAME>,
#                             then fuzz/state/nix-env.json tools[<name>], then PATH
#                        4.   host scans (/usr/lib/llvm-NN/bin/<name>)
#                        Returns 0 when found, 1 when not.
#
#   nix_export_tools <name>...
#                        Export CC_FUZZER_TOOL_<NAME> for tools only the host
#                        scans find, before calling into the core.
#
#   nix_require <name>   Echo absolute path or print a fix-it diagnostic and
#                        exit 2. Use in scripts where the tool is mandatory.
#
#   nix_env_file         Echo the path to nix-env.json (or empty if missing).
#
# Refreshing the snapshot: scripts/capture-nix-env.sh (auto-runs at session
# start via the env-check.sh SessionStart hook).

. "$(dirname "${BASH_SOURCE[0]}")/root.sh"

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

# Host-layout fallbacks the core deliberately doesn't know about (the core's
# cc_fuzzer_core.tools.which stops at $CC_FUZZER_TOOL_<NAME>, the nix-env.json
# pin and PATH). Debian/Ubuntu/Kali ship versioned LLVM tools in
# /usr/lib/llvm-NN/bin/ without putting them on PATH; highest version wins.
_nix_tools_host_scan() {
  local name="$1" v
  for v in 21 20 19 18 17 16 15 14 13 12 11; do
    if [ -x "/usr/lib/llvm-$v/bin/$name" ]; then
      echo "/usr/lib/llvm-$v/bin/$name"
      return 0
    fi
  done
  return 1
}

nix_tool() {
  local name="${1:-}"
  [ -n "$name" ] || return 1
  local p
  # 1-3: the core's lookup ($CC_FUZZER_TOOL_<NAME>, nix-env.json pin, PATH).
  if p=$(python3 -m cc_fuzzer_core tool which "$name" 2>/dev/null) && [ -n "$p" ]; then
    echo "$p"
    return 0
  fi
  # 4: plugin-side host scans.
  _nix_tools_host_scan "$name"
}

# nix_export_tools <name>...
# Plugin-side tool provider for core calls: for each tool the core would NOT
# find on its own but the host scans do, export CC_FUZZER_TOOL_<NAME> so a
# following `python3 -m cc_fuzzer_core ...` resolves it. Always returns 0.
nix_export_tools() {
  local name var p
  for name in "$@"; do
    var="CC_FUZZER_TOOL_$(printf '%s' "$name" | tr -c 'A-Za-z0-9' '_' | tr 'a-z' 'A-Z')"
    # ${var+set}, not ${var:-}: an explicitly EMPTY override pins the tool as
    # unavailable (same contract as the core's tools.which), so a host scan
    # must not quietly put it back.
    [ -n "${!var+set}" ] && continue
    python3 -m cc_fuzzer_core tool which "$name" >/dev/null 2>&1 && continue
    if p=$(_nix_tools_host_scan "$name"); then
      export "$var=$p"
    fi
  done
  return 0
}

nix_require() {
  local name="${1:-}"
  local p
  if p=$(nix_tool "$name") && [ -n "$p" ]; then
    echo "$p"
    return 0
  fi
  echo "ERROR: required tool '$name' not found." >&2
  echo "       Resolution order: \$CC_FUZZER_TOOL_<NAME>, fuzz/state/nix-env.json, PATH, /usr/lib/llvm-*/bin." >&2
  if [ -z "$(nix_env_file)" ]; then
    echo "       (nix-env.json missing — run scripts/capture-nix-env.sh, or it" >&2
    echo "        auto-runs at session start when fuzz/ exists in cwd)" >&2
  fi
  echo "       Fix: nix develop \$CLAUDE_PLUGIN_ROOT before launching claude" >&2
  exit 2
}

# nix_check_store_path <path>
# Returns 0 if the path exists in /nix/store and is accessible, 1 otherwise.
nix_check_store_path() {
  local p="${1:-}"
  [ -z "$p" ] && return 1
  # Must be under /nix/store and exist
  case "$p" in /nix/store/*) ;; *) return 1 ;; esac
  [ -e "$p" ] && return 0
  return 1
}

# nix_hash_file <path>
# Prints the first 16 hex chars of the SHA-256 of a file. Returns 1 if absent.
nix_hash_file() {
  local p="${1:-}"
  [ -f "$p" ] || return 1
  python3 -c "
import hashlib, sys
try:
    h = hashlib.sha256(open(sys.argv[1],'rb').read()).hexdigest()[:16]
    print(h)
except Exception:
    sys.exit(1)
" "$p"
}

# nix_get_flake_rev
# Prints the current project-flake git rev, or "dirty" if untracked changes,
# or "" if not in a git repo / no flake.nix. Resolution order:
#   1. CC_FUZZER_FLAKE_REV env var (set by buildFHSEnv profile)
#   2. git rev-parse HEAD on the directory containing flake.nix
nix_get_flake_rev() {
  if [ -n "${CC_FUZZER_FLAKE_REV:-}" ]; then
    echo "$CC_FUZZER_FLAKE_REV"
    return 0
  fi
  if git -C "${CC_FUZZER_PROJECT_ROOT:-$PWD}" rev-parse HEAD >/dev/null 2>&1; then
    local rev dirty
    rev=$(git -C "${CC_FUZZER_PROJECT_ROOT:-$PWD}" rev-parse HEAD 2>/dev/null)
    dirty=$(git -C "${CC_FUZZER_PROJECT_ROOT:-$PWD}" status --porcelain 2>/dev/null | head -1)
    if [ -n "$dirty" ]; then echo "dirty"; else echo "$rev"; fi
    return 0
  fi
  echo ""
  return 1
}
