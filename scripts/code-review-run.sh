#!/usr/bin/env bash
# code-review-run.sh
#
# Three-tier code-review pipeline orchestrator. Runs Tier-1 (deterministic
# prescan) directly here, then exposes the prescan artifact so the calling
# context (the campaign command, /fuzz-review, or the orchestrator
# agent) can dispatch the `code-reviewer` subagent for Tier-2 (Sonnet) and
# optionally Tier-3 (Opus).
#
# This script does NOT call subagents itself — that's the dispatcher's job.
# The script's contract is:
#
#   1. Resolve the target source root (from --target-root or
#      harness-built.json:target_source).
#   2. Read fuzz-config.json:code_review for defaults.
#   3. Cross-link the latest cve-context-*.json so the prescan can use the
#      hotspot data.
#   4. Run the prescan, write fuzz/state/snapshots/code-review-prescan-<ts>.json.
#   5. Echo a "READY: <prescan-path>" line on stdout for the caller.
#
# The caller (campaign command or /fuzz-review) then:
#   - Reads the prescan
#   - Dispatches `code-reviewer` agent (Sonnet) on the top-N functions
#   - Optionally dispatches the Opus deep-pass on the agent's high-confidence findings
#   - Writes fuzz/state/snapshots/code-review-<ts>.json + fuzz/state/code-review.md
#
# Usage:
#   scripts/code-review-run.sh \\
#       [--target-root <path>] \\
#       [--max-functions <N>|all] \\
#       [--sweep]              (review EVERY function: max-functions=all, mode=sweep)
#       [--batch-size <S>]     (reviewer window size; default 30)
#       [--excluded-paths <comma-list>] \\
#       [--sast off|auto|on]   (Tier-1 external SAST; default auto)
#       [--no-sast]            (alias for --sast off)
#       [--sast-rules <dirs>]  (extra semgrep rule dirs; bundled pack always included)
#       [--codeql-db <path>]   (analyze a PREBUILT CodeQL database; skipped if absent)
#       [--refresh]   (ignore stale-source-hash check)
#       [--no-cve-context]   (skip cross-linking the latest cve-context)
#
#   scripts/code-review-run.sh merge-code-review \\
#       --prescan <prescan.json> --out <code-review-<ts>.json> --md <code-review.md> \\
#       [--target <name>] -- <window-partial.json> [<window-partial.json> ...]
#
# The prescan run prints a machine-readable plan line the caller parses:
#   BATCH_PLAN windows=<n> batch_size=<S> candidates=<c> mode=<capped|sweep>
#
# Exit codes:
#   0  prescan ran (or was skipped because already-fresh) / merge succeeded
#   2  bad arguments or no target source available
#
# Shim onto the core's port, `cc-fuzzer prescan run` / `prescan merge`
# (cc_fuzzer_core.prescan): same flags, output lines and exit codes.

. "$(dirname "${BASH_SOURCE[0]}")/_lib/root.sh"

if [ "${1:-}" = "merge-code-review" ]; then
  shift
  exec python3 -m cc_fuzzer_core prescan merge "$@"
fi
exec python3 -m cc_fuzzer_core prescan run "$@"
