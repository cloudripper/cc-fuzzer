#!/usr/bin/env bash
# gen-manifest.sh
#
# Regenerates MANIFEST.md5 (the file integrity-check.sh verifies against).
# Shim onto `cc-fuzzer manifest write`; the core tracks its own sources and
# this plugin-side shim adds the Claude Code adapter trees (.claude-plugin/,
# agents/, skills/), which the core deliberately knows nothing about.
#
# Run after every change to a tracked file, before committing / releasing.
#
# Usage:
#   gen-manifest.sh            # rewrite <plugin-root>/MANIFEST.md5
#   gen-manifest.sh --check    # report drift instead (exit 1 if stale)

set -u

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(dirname "$SCRIPT_DIR")"
export PYTHONPATH="$ROOT/src${PYTHONPATH:+:$PYTHONPATH}"

PLUGIN_INCLUDES=(--include .claude-plugin --include agents --include skills)

if [ "${1:-}" = "--check" ]; then
  exec python3 -m cc_fuzzer_core manifest check --root "$ROOT" "${PLUGIN_INCLUDES[@]}"
fi
exec python3 -m cc_fuzzer_core manifest write --root "$ROOT" "${PLUGIN_INCLUDES[@]}" "$@"
