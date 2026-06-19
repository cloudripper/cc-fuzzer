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
#       [--max-functions <N>] \\
#       [--excluded-paths <comma-list>] \\
#       [--refresh]   (ignore stale-source-hash check)
#       [--no-cve-context]   (skip cross-linking the latest cve-context)
#
# Exit codes:
#   0  prescan ran (or was skipped because already-fresh)
#   2  bad arguments or no target source available

set -u

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
. "$SCRIPT_DIR/_lib/path-anchor.sh"

STATE_DIR="${FUZZ_STATE_DIR:-$FUZZ_ROOT/state}"
SNAPSHOTS_DIR="$STATE_DIR/snapshots"
mkdir -p "$STATE_DIR" "$SNAPSHOTS_DIR"

CLI_TARGET_ROOT=""
CLI_MAX=""
CLI_EXCLUDES=""
CLI_REFRESH=false
CLI_NO_CVE=false

while [ $# -gt 0 ]; do
  case "$1" in
    --target-root)    CLI_TARGET_ROOT="${2:-}";  shift 2 ;;
    --max-functions)  CLI_MAX="${2:-}";          shift 2 ;;
    --excluded-paths) CLI_EXCLUDES="${2:-}";     shift 2 ;;
    --refresh)        CLI_REFRESH=true;          shift ;;
    --no-cve-context) CLI_NO_CVE=true;           shift ;;
    --help|-h)        sed -n '2,/^$/p' "$0" | sed 's/^# \?//'; exit 0 ;;
    *) echo "ERROR: unknown arg '$1'" >&2; exit 2 ;;
  esac
done

# ---------------------------------------------------------------------------
# Resolve config defaults
# ---------------------------------------------------------------------------
CFG_FILE="$STATE_DIR/fuzz-config.json"
CFG_TARGET_ROOT=""
CFG_MAX=""
CFG_EXCLUDES=""
if [ -f "$CFG_FILE" ]; then
  # One field per line, read line-by-line. The target root is a filesystem path
  # (can contain spaces) and excludes is a joined list; a single `read -r A B C`
  # would word-split them across the other fields. Reading whole lines keeps
  # space-containing values intact.
  { read -r CFG_TARGET_ROOT
    read -r CFG_MAX
    read -r CFG_EXCLUDES
  } <<< "$(python3 - <<PY
import json
try:
    d = json.load(open("$CFG_FILE"))
    cr = (d.get("code_review") or {})
    paths = cr.get("scan_paths") or ""
    if isinstance(paths, list):
        paths = paths[0] if paths else ""
    excl = cr.get("excluded_paths") or []
    if isinstance(excl, list):
        excl = ",".join(excl)
    print(paths or "")
    print(cr.get("max_functions_to_review", "") or "")
    print(excl or "")
except Exception:
    print(); print(); print()
PY
)"
fi

# Auto-detect target root from harness-built.json if neither CLI nor config gave us one.
AUTO_TARGET_ROOT=""
HBJ="$STATE_DIR/harness-built.json"
if [ -f "$HBJ" ]; then
  AUTO_TARGET_ROOT=$(python3 -c "
import json, os
try:
    d = json.load(open('$HBJ'))
    ts = d.get('target_source','')
    if ts:
        # target_source is a relative path to a source file; parent dir is the root
        ts = os.path.normpath(ts)
        if os.path.isfile(ts):
            print(os.path.dirname(os.path.abspath(ts)) or '.')
        elif os.path.isdir(ts):
            print(os.path.abspath(ts))
except Exception:
    pass
" 2>/dev/null || true)
fi

TARGET_ROOT="${CLI_TARGET_ROOT:-${CFG_TARGET_ROOT:-$AUTO_TARGET_ROOT}}"
MAX_FUNCTIONS="${CLI_MAX:-${CFG_MAX:-50}}"
EXCLUDES="${CLI_EXCLUDES:-$CFG_EXCLUDES}"

if [ -z "$TARGET_ROOT" ] || [ ! -d "$TARGET_ROOT" ]; then
  echo "ERROR: cannot resolve target source root." >&2
  echo "       Tried: --target-root, fuzz-config.json:code_review.scan_paths," >&2
  echo "       and auto-detect from harness-built.json:target_source." >&2
  echo "       Pass --target-root <dir> or set code_review.scan_paths in fuzz-config.json." >&2
  exit 2
fi

# ---------------------------------------------------------------------------
# Cross-link the latest cve-context (Tier-1 uses it for hotspot scoring)
# ---------------------------------------------------------------------------
CVE_CONTEXT_PATH=""
if [ "$CLI_NO_CVE" != "true" ]; then
  CVE_CONTEXT_PATH=$(ls -t "$SNAPSHOTS_DIR"/cve-context-*.json 2>/dev/null | head -1 || true)
fi

# ---------------------------------------------------------------------------
# Run prescan
# ---------------------------------------------------------------------------
TS=$(date +%s)
PRESCAN_OUT="$SNAPSHOTS_DIR/code-review-prescan-${TS}.json"

PRESCAN_ARGS=(
  --target-root  "$TARGET_ROOT"
  --out          "$PRESCAN_OUT"
  --max-functions "$MAX_FUNCTIONS"
)
[ -n "$EXCLUDES" ]           && PRESCAN_ARGS+=(--excluded-paths "$EXCLUDES")
[ -n "$CVE_CONTEXT_PATH" ]   && PRESCAN_ARGS+=(--cve-context    "$CVE_CONTEXT_PATH")

echo "[code-review] running prescan: target=$TARGET_ROOT max=$MAX_FUNCTIONS" >&2
[ -n "$CVE_CONTEXT_PATH" ] && echo "[code-review] cve-context: $CVE_CONTEXT_PATH" >&2

if ! python3 "$SCRIPT_DIR/_lib/code_review_prescan.py" "${PRESCAN_ARGS[@]}" >/dev/null; then
  echo "ERROR: prescan failed" >&2
  exit 2
fi

# Summary for the caller
TOP_COUNT=$(python3 -c "
import json
d = json.load(open('$PRESCAN_OUT'))
print(len(d.get('top_candidates') or []))
" 2>/dev/null)

echo "[code-review] prescan complete: $TOP_COUNT top-candidate function(s)" >&2
echo "READY: $PRESCAN_OUT"
exit 0
