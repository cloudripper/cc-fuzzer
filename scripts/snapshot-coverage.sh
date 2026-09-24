#!/usr/bin/env bash
# snapshot-coverage.sh
#
# Produces fuzz/state/snapshots/coverage-<ts>.json strictly per
# STATE_SCHEMA.md. Fails loudly when instrumentation is broken rather than
# producing silent-zero snapshots.
#
# What's included:
#   1. LLVM tool probing - finds llvm-cov / llvm-profdata in /usr/lib/llvm-*/bin/
#      when not in PATH, instead of silently giving up.
#   2. Fork-mode-aware libFuzzer log parsing - when -fork=N is in use, the
#      libFuzzer parent log line format includes trailing colons (e.g. "#1971:")
#      and per-fork temp dirs at /tmp/libFuzzerTemp.FuzzWithFork<PID>.dir/.
#   3. Coverage binary support - if harness-built.json declares a coverage_binary,
#      we run it against the corpus to produce profraw, merge with llvm-profdata,
#      and read with llvm-cov export. No silent zeros.
#   4. Strict instrumentation field - every snapshot carries an "instrumentation"
#      object so downstream code can tell "real zero" from "broken zero".
#
# Shim onto the core's port, `cc-fuzzer coverage snapshot`
# (cc_fuzzer_core.coverage; the old _lib/snapshot_helpers.py lives there too).
# The core finds llvm-cov / llvm-profdata via CC_FUZZER_TOOL_<NAME>, the
# nix-env.json pin or PATH; nix_export_tools (the plugin-side provider) adds
# the /usr/lib/llvm-NN/bin host fallback on top.

. "$(dirname "${BASH_SOURCE[0]}")/_lib/root.sh"
. "$CC_FUZZER_ROOT/scripts/_lib/nix-tools.sh"
nix_export_tools llvm-cov llvm-profdata
case "${1:-}" in
  -h|--help) sed -n '2,/^$/p' "$0" | sed 's/^# \?//'; exit 0 ;;
esac
exec python3 -m cc_fuzzer_core coverage snapshot "$@"
