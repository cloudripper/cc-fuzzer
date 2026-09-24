#!/usr/bin/env bash
# check-seed-safety.sh
#
# Scans seed files for unambiguous destructive shell payloads. Refuses to
# allow files containing primitives like "rm -rf /", fork bombs, "mkfs" on
# a real block device, or "dd" overwriting a real block device, from being
# promoted into the live corpus.
#
# This is a guardrail for LLM-generated seeds. The pattern list is
# intentionally narrow — only patterns where the *intent* is unambiguously
# destructive get flagged. Anything more permissive would false-positive on
# legitimate fuzz inputs for shell parsers, find harnesses, etc.
#
# It does NOT scan the fuzzer's runtime mutations — those live in process
# memory and never hit disk before being executed. The right defense there
# is to sandbox the campaign (container, VM, or chroot). This script is the
# pre-promotion checkpoint for seeds written by humans, agents, or scripts.
#
# Usage:
#   check-seed-safety.sh <file> [<file> ...]      # check explicit files
#   check-seed-safety.sh                          # read paths from stdin
#
# Exit:
#   0 — all files safe (or override env set)
#   2 — usage error / no input
#   3 — at least one file matched a destructive pattern
#
# Override (use with care, document why in fuzz/state/plugin-issues.md):
#   CCFUZZ_ALLOW_DESTRUCTIVE_SEEDS=1     bypass the check entirely
#
# Output: for each unsafe file, prints
#   UNSAFE <path>: <one-line reason>
# Returns the list verbatim; the caller decides where to quarantine.
#
# Shim onto the core's port, `cc-fuzzer quarantine safety`
# (cc_fuzzer_core.quarantine.SEED_SAFETY_PATTERNS).

. "$(dirname "${BASH_SOURCE[0]}")/_lib/root.sh"
exec python3 -m cc_fuzzer_core quarantine safety "$@"
