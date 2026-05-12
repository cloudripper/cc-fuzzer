#!/usr/bin/env bash
# _lib/path-anchor.sh
#
# Sourced by every cc-fuzzer script that touches fuzz/. Anchors execution to
# the project root so the recursive fuzz/fuzz/ bug can't recur.
#
# Provides:
#   PROJECT_ROOT  - absolute path to the directory containing fuzz/
#   FUZZ_ROOT     - absolute path to fuzz/ inside it
#
# Behavior:
#   - If invoked from inside fuzz/ or any nested subtree, walks up to find
#     the canonical project root (parent that contains fuzz/ but is not named fuzz).
#   - Refuses to operate if a recursive fuzz/fuzz/ exists (state corruption).
#   - cd's to PROJECT_ROOT so all relative paths resolve consistently.

# Walk up from $PWD looking for a directory that contains fuzz/ but is itself
# NOT named "fuzz". That's the canonical project root.
_anchor_detect_root() {
  local d="$PWD"
  while [ "$d" != "/" ]; do
    if [ -d "$d/fuzz" ] && [ "$(basename "$d")" != "fuzz" ]; then
      echo "$d"
      return 0
    fi
    d=$(dirname "$d")
  done
  return 1
}

# Honor explicit PROJECT_ROOT if set
if [ -n "${PROJECT_ROOT:-}" ]; then
  if [ ! -d "$PROJECT_ROOT/fuzz" ]; then
    echo "ERROR: PROJECT_ROOT=$PROJECT_ROOT does not contain fuzz/" >&2
    exit 2
  fi
  PROJECT_ROOT=$(cd "$PROJECT_ROOT" && pwd)
else
  PROJECT_ROOT=$(_anchor_detect_root) || {
    echo "ERROR: not inside a cc-fuzzer project (no fuzz/ directory found in any parent)" >&2
    echo "       run from the project root, or set PROJECT_ROOT=/path/to/project" >&2
    exit 2
  }
fi

# Refuse to operate if recursive fuzz/fuzz/ exists. This is the bug pattern
# we hit in the findutils campaign where an agent ran scripts from inside
# fuzz/ and libFuzzer created fuzz/fuzz/, fuzz/fuzz/fuzz/, etc.
if [ -d "$PROJECT_ROOT/fuzz/fuzz" ]; then
  echo "ERROR: recursive fuzz/fuzz/ detected at $PROJECT_ROOT/fuzz/fuzz/" >&2
  echo "       this is state corruption - run /cc-fuzzer:doctor to diagnose and fix" >&2
  echo "       (most likely: a script ran with cwd inside fuzz/, creating nested copies)" >&2
  exit 2
fi

FUZZ_ROOT="$PROJECT_ROOT/fuzz"

# Anchor cwd. Now relative paths like "fuzz/state/foo" resolve consistently.
cd "$PROJECT_ROOT" || {
  echo "ERROR: cannot cd to $PROJECT_ROOT" >&2
  exit 2
}

export PROJECT_ROOT FUZZ_ROOT
