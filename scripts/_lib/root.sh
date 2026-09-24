#!/usr/bin/env bash
# _lib/root.sh
#
# The ONE place the plugin resolves its root. Sourced first by every script:
#
#   . "$(dirname "${BASH_SOURCE[0]}")/_lib/root.sh"     # from scripts/*.sh
#   SCRIPT_DIR="$CC_FUZZER_ROOT/scripts"                # sibling calls
#
# Provides (exported):
#   CC_FUZZER_ROOT  plugin root (the dir holding scripts/, src/, rules/, ...)
#   PYTHONPATH      $CC_FUZZER_ROOT/src prepended when this checkout carries the
#                   core package (plugin / dev layout), so `python3 -m
#                   cc_fuzzer_core` resolves to the core shipped with these
#                   scripts rather than some other installed copy.
#
# Resolution order for CC_FUZZER_ROOT:
#   1. $CC_FUZZER_ROOT            (the core's own variable; containers set it)
#   2. $CLAUDE_PLUGIN_ROOT        (compat: Claude Code sets it for hooks/agents.
#                                  This shim is the ONLY place that reads it —
#                                  the core never does.)
#   3. this file's location       (BASH_SOURCE/../..)
# A candidate from 1/2 that does not actually contain scripts/_lib/root.sh is
# ignored with a warning (a stale env var must not redirect every sibling call
# to a tree that isn't a cc-fuzzer checkout).
#
# Safe under `set -euo pipefail`; idempotent (re-sourcing is a no-op).

_cc_root_self="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
_cc_root_pick=""
for _cc_root_cand in "${CC_FUZZER_ROOT:-}" "${CLAUDE_PLUGIN_ROOT:-}"; do
  [ -n "$_cc_root_cand" ] || continue
  if [ -f "$_cc_root_cand/scripts/_lib/root.sh" ]; then
    _cc_root_pick="$(cd "$_cc_root_cand" && pwd)"
    break
  fi
  echo "cc-fuzzer: ignoring root '$_cc_root_cand' (no scripts/_lib/root.sh there); using $_cc_root_self" >&2
done
CC_FUZZER_ROOT="${_cc_root_pick:-$_cc_root_self}"
export CC_FUZZER_ROOT

if [ -d "$CC_FUZZER_ROOT/src/cc_fuzzer_core" ]; then
  case ":${PYTHONPATH:-}:" in
    *":$CC_FUZZER_ROOT/src:"*) ;;
    *) PYTHONPATH="$CC_FUZZER_ROOT/src${PYTHONPATH:+:$PYTHONPATH}" ;;
  esac
  export PYTHONPATH
fi

unset _cc_root_self _cc_root_pick _cc_root_cand
