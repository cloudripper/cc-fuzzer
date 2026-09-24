#!/usr/bin/env bash
# _lib/fuzz-config.sh
#
# Resolves cc-fuzzer per-project configuration. Shim onto the core's port,
# `cc-fuzzer config <verb>` (cc_fuzzer_core.config), which owns the
# fuzz-config.json reading/writing (including nested blocks: dotted keys such
# as `yolo.max_ticks` reach into them).
#
# Resolution order for any setting (highest to lowest priority):
#   1. Environment variable (e.g. FUZZ_FORKS=N)
#   2. CLI argument passed via FUZZ_FORKS_OVERRIDE (set by command wrappers)
#   3. <state dir>/fuzz-config.json (per-project; honours FUZZ_STATE_DIR)
#   4. Built-in default
#
# Settings provided:
#   FUZZ_FORKS    libFuzzer -fork=N (default 2, capped at nproc-1)
#
# Sourced (launch-fuzzer-slot.sh): provides resolve_fuzz_forks.
# Executed:
#   bash scripts/_lib/fuzz-config.sh get <key> | set <key> <value> | show | help

set -u

. "$(dirname "${BASH_SOURCE[0]}")/root.sh"

# Resolve fork count with the four-step precedence (prints the value; a
# "requested more than the cap" warning goes to stderr).
resolve_fuzz_forks() {
  python3 -m cc_fuzzer_core config get fuzz_forks
}

# Top-level dispatch when called as a script (not sourced)
if [ "${BASH_SOURCE[0]}" = "$0" ]; then
  case "${1:-help}" in
    get)
      [ $# -ge 2 ] || { echo "fuzz-config.sh: key required (e.g. fuzz_forks)" >&2; exit 1; }
      exec python3 -m cc_fuzzer_core config get "$2" ;;
    set)
      [ $# -ge 2 ] || { echo "fuzz-config.sh: key required" >&2; exit 1; }
      [ $# -ge 3 ] && [ -n "$3" ] || { echo "fuzz-config.sh: value required" >&2; exit 1; }
      exec python3 -m cc_fuzzer_core config set "$2" "$3" ;;
    show)
      exec python3 -m cc_fuzzer_core config show ;;
    *)
      exec python3 -m cc_fuzzer_core config help ;;
  esac
fi
