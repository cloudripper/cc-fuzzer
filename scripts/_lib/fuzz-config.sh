#!/usr/bin/env bash
# _lib/fuzz-config.sh
#
# Resolves cc-fuzzer per-project configuration. Sourced after path-anchor.sh
# so $FUZZ_ROOT is set.
#
# Resolution order for any setting (highest to lowest priority):
#   1. Environment variable (e.g. FUZZ_FORKS=N)
#   2. CLI argument passed via FUZZ_FORKS_OVERRIDE (set by command wrappers)
#   3. fuzz/state/fuzz-config.json (per-project)
#   4. Built-in default
#
# Settings provided:
#   FUZZ_FORKS    libFuzzer -fork=N (default 2, capped at nproc-1)
#
# Reads/writes:
#   $FUZZ_ROOT/state/fuzz-config.json
#
# This library is read-only by default. To modify config, use:
#   bash scripts/_lib/fuzz-config.sh set <key> <value>

set -u

CONFIG_FILE="${FUZZ_ROOT:-fuzz}/state/fuzz-config.json"

# Compute the cap: nproc - 1, with a floor of 1
_compute_fork_cap() {
  local n
  n=$(nproc 2>/dev/null || echo 2)
  n=$((n - 1))
  [ "$n" -lt 1 ] && n=1
  echo "$n"
}

# Read a setting from the config file (returns empty string if file missing or key absent)
_config_get() {
  local key="$1"
  [ -f "$CONFIG_FILE" ] || { echo ""; return; }
  python3 -c "
import json
try:
    d = json.load(open('$CONFIG_FILE'))
    v = d.get('$key', '')
    print(v if v != '' else '')
except: pass
" 2>/dev/null
}

# Resolve fork count with the four-step precedence
resolve_fuzz_forks() {
  local cap want default
  cap=$(_compute_fork_cap)
  default=2

  if [ -n "${FUZZ_FORKS:-}" ]; then
    want="$FUZZ_FORKS"
  elif [ -n "${FUZZ_FORKS_OVERRIDE:-}" ]; then
    want="$FUZZ_FORKS_OVERRIDE"
  else
    want=$(_config_get fuzz_forks)
    [ -z "$want" ] && want="$default"
  fi

  # Validate integer; treat 0 as explicit "no fork" (single-process mode)
  case "$want" in
    ''|*[!0-9]*) want="$default" ;;
  esac
  # 0 is a valid sentinel meaning "disable fork mode" — do not reset to default
  [ "$want" -gt 0 ] 2>/dev/null || [ "$want" = "0" ] 2>/dev/null || want="$default"

  # Apply cap with a warning if user requested more than cap
  if [ "$want" -gt "$cap" ] 2>/dev/null; then
    echo "WARN: requested fuzz_forks=$want exceeds cap (nproc-1=$cap); using $cap" >&2
    want="$cap"
  fi

  echo "$want"
}

# Top-level dispatch when called as a script (not sourced)
if [ "${BASH_SOURCE[0]}" = "$0" ]; then
  cmd="${1:-help}"
  case "$cmd" in
    get)
      key="${2:?key required (e.g. fuzz_forks)}"
      case "$key" in
        fuzz_forks) resolve_fuzz_forks ;;
        *) _config_get "$key" ;;
      esac
      ;;
    set)
      key="${2:?key required}"
      value="${3:?value required}"
      mkdir -p "$(dirname "$CONFIG_FILE")"
      CFG="$CONFIG_FILE" K="$key" V="$value" python3 <<'PY'
import json, os
path = os.environ['CFG']
key = os.environ['K']
value = os.environ['V']
try:
    d = json.load(open(path))
except:
    d = {}
d['schema'] = 'fuzz-config/v1'
d[key] = int(value) if value.isdigit() else value
json.dump(d, open(path, 'w'), indent=2, sort_keys=True)
print(f"set {key} = {value} in {path}")
PY
      ;;
    show)
      echo "Resolved fuzz_forks: $(resolve_fuzz_forks)"
      echo "  cap (nproc-1):     $(_compute_fork_cap)"
      echo "  env FUZZ_FORKS:    ${FUZZ_FORKS:-(unset)}"
      echo "  config file value: $(_config_get fuzz_forks)"
      echo "  config file:       $CONFIG_FILE"
      ;;
    help|*)
      cat <<EOF
fuzz-config.sh - per-project cc-fuzzer configuration

Commands:
  get <key>          Print resolved value (env > override > file > default)
  set <key> <value>  Write to fuzz/state/fuzz-config.json
  show               Show resolution trace for fuzz_forks

Recognized keys:
  fuzz_forks         libFuzzer -fork=N. Default 2, cap nproc-1.

Resolution order: FUZZ_FORKS env > FUZZ_FORKS_OVERRIDE > config file > default
EOF
      ;;
  esac
fi
