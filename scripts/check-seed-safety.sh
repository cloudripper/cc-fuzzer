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

set -u

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
. "$SCRIPT_DIR/_lib/path-anchor.sh"

if [ "${CCFUZZ_ALLOW_DESTRUCTIVE_SEEDS:-0}" = "1" ]; then
  # User has explicitly opted out. Echo a banner so this can't go unnoticed
  # in CI logs / orchestrator output, then exit 0.
  echo "check-seed-safety.sh: CCFUZZ_ALLOW_DESTRUCTIVE_SEEDS=1 — safety check bypassed" >&2
  exit 0
fi

# Gather input list
inputs=()
if [ "$#" -gt 0 ]; then
  for f in "$@"; do inputs+=("$f"); done
else
  if [ -t 0 ]; then
    echo "ERROR: no files given and stdin is a terminal" >&2
    echo "Usage: $0 <file> [<file> ...]   OR   ls files | $0" >&2
    exit 2
  fi
  while IFS= read -r line; do
    [ -n "$line" ] && inputs+=("$line")
  done
fi

if [ "${#inputs[@]}" -eq 0 ]; then
  exit 0
fi

# Destructive-intent patterns. All are extended regex; -a makes grep treat
# the file as text even when it contains binary bytes (seeds often do). The
# patterns are written to minimize false positives on parser-fuzz seeds:
# they require the *full* destructive verb-plus-target, not just a substring.
#
# Pattern format:  REGEX|||short-reason
PATTERNS=$(cat <<'EOF'
\brm[[:space:]]+-[a-zA-Z]*[rR][a-zA-Z]*[fF][a-zA-Z]*[[:space:]]+/[^"']|||rm -rf with absolute-path target
\brm[[:space:]]+-[a-zA-Z]*[fF][a-zA-Z]*[rR][a-zA-Z]*[[:space:]]+/[^"']|||rm -fr with absolute-path target
\bmkfs(\.[a-z0-9]+)?[[:space:]]+/dev/(sd[a-z]|nvme[0-9]|hd[a-z]|mmcblk[0-9]|vd[a-z]|xvd[a-z])|||mkfs on a real block device
\bdd[[:space:]][^|]*\bof=/dev/(sd[a-z]|nvme[0-9]|hd[a-z]|mmcblk[0-9]|vd[a-z]|xvd[a-z])|||dd writing to a real block device
:[[:space:]]*\([[:space:]]*\)[[:space:]]*\{[[:space:]]*:[[:space:]]*\|[[:space:]]*:[[:space:]]*&[[:space:]]*\}[[:space:]]*;[[:space:]]*:|||fork bomb signature
\bshred[[:space:]][^|]*[[:space:]]/dev/(sd[a-z]|nvme[0-9]|hd[a-z])|||shred on a real block device
\bchmod[[:space:]]+(--no-preserve-root|-R[[:space:]]+777)[[:space:]]+/|||chmod on / (root recursive)
>[[:space:]]*/dev/(sd[a-z]|nvme[0-9]|hd[a-z]|mmcblk[0-9])[0-9]*[[:space:]]*$|||stdout redirect into a real block device
>[[:space:]]*/proc/sysrq-trigger|||write to /proc/sysrq-trigger (kernel control)
EOF
)

UNSAFE=0
for f in "${inputs[@]}"; do
  [ -f "$f" ] || continue
  # Cap scan to first 64 KiB — seeds larger than that are atypical, and the
  # destructive patterns are short, so any meaningful match will be near the
  # top.
  head -c 65536 -- "$f" > /tmp/.ccfuzz-seed-safety-$$ 2>/dev/null || continue
  while IFS= read -r line; do
    [ -z "$line" ] && continue
    pat="${line%%|||*}"
    reason="${line##*|||}"
    if grep -aEq -- "$pat" /tmp/.ccfuzz-seed-safety-$$ 2>/dev/null; then
      echo "UNSAFE $f: $reason"
      UNSAFE=1
      break
    fi
  done <<< "$PATTERNS"
done
rm -f /tmp/.ccfuzz-seed-safety-$$

exit $((UNSAFE * 3))
