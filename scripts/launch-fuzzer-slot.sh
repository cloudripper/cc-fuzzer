#!/usr/bin/env bash
# launch-fuzzer-slot.sh
#
# Launches a single fuzzer slot in the background. A "slot" is one fuzzer
# process within a (possibly multi-fuzzer, always multi-harness) campaign. A
# slot has its own pid/log/engine files and engine-specific flags, and binds to
# a specific harness (`--harness <name>`); its binary/corpus/output paths are
# resolved per-harness via _lib/harness-path.sh.
#
# Slots are declared in fuzz/state/fuzz-config.json under `fuzzer_slots`, each
# bound to a declared harness. A single-harness campaign is the degenerate case
# (one harness bundle under fuzz/harnesses/<name>/).
#
# Usage:
#   launch-fuzzer-slot.sh \
#     --slot <name>                       (default: main)
#     --engine libfuzzer|aflpp            (required; auto-detect if "auto")
#     [--harness <name>]                  (required; defaults to first declared)
#     [--binary <harness-binary>]         (defaults to per-harness harness_binary)
#     [--corpus <dir>]                    (defaults to per-harness corpus dir)
#     [--role master|secondary]           (AFL++ only)
#     [--power-schedule <name>]           (AFL++ only)
#     [--libfuzzer-forks <N>]             (libFuzzer only; overrides fuzz-config)
#     [--restart-of <slot>]               (internal use by check-slot-liveness.sh)
#
# Side effects:
#   - Launches the fuzzer with nohup; PID written to fuzz/state/fuzzer-<slot>.pid
#   - Engine written to fuzz/state/fuzzer-<slot>.engine
#   - Stdout/stderr tee'd into fuzz/state/fuzzer-<slot>.log
#   - Slot entry created/updated in fuzz/state/fuzzers.json (schema fuzzers/v2)
#   - Each slot runs in its own cwd (libFuzzer) or out-dir (AFL++) under
#       fuzz/harnesses/<harness>/ so crash files attribute to the harness.
#
# Refuses to launch if:
#   - The slot is already running (existing PID is alive)
#   - The binary doesn't exist or isn't executable
#   - The engine value is bogus
#   - --harness is missing/unresolvable or references an undeclared harness
#   - Forbidden ASAN_OPTIONS / UBSAN_OPTIONS env vars are set
#
# Shim onto the core's port, `cc-fuzzer slots launch`
# (cc_fuzzer_core.slots.launcher): same flags, messages and exit codes. The
# engine launch, per-slot files and the fuzzers.json upsert (formerly
# _lib/launch_slot.py) all live there; nm / afl-fuzz resolve through
# `cc-fuzzer tool which`.

. "$(dirname "${BASH_SOURCE[0]}")/_lib/root.sh"
case "${1:-}" in
  -h|--help) sed -n '2,/^$/p' "$0" | sed 's/^# \?//'; exit 0 ;;
esac
exec python3 -m cc_fuzzer_core slots launch "$@"
