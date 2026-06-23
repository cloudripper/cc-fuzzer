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

set -u

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
. "$SCRIPT_DIR/_lib/path-anchor.sh"

STATE_DIR="${FUZZ_STATE_DIR:-$FUZZ_ROOT/state}"
SNAPSHOTS_DIR="$STATE_DIR/snapshots"
mkdir -p "$STATE_DIR" "$SNAPSHOTS_DIR"

# ---------------------------------------------------------------------------
# Subcommand: merge-code-review — combine window partials into the canonical
# snapshot + markdown (delegates to _lib/code_review_merge.py). The caller
# passes through all the merge flags after the subcommand verb.
# ---------------------------------------------------------------------------
if [ "${1:-}" = "merge-code-review" ]; then
  shift
  exec python3 "$SCRIPT_DIR/_lib/code_review_merge.py" "$@"
fi

CLI_TARGET_ROOT=""
CLI_MAX=""
CLI_EXCLUDES=""
CLI_REFRESH=false
CLI_NO_CVE=false
CLI_SWEEP=false
CLI_BATCH_SIZE=""
CLI_SAST=""          # off|auto|on ; empty => config/default
CLI_SAST_RULES=""
CLI_CODEQL_DB=""

while [ $# -gt 0 ]; do
  case "$1" in
    --target-root)    CLI_TARGET_ROOT="${2:-}";  shift 2 ;;
    --max-functions)  CLI_MAX="${2:-}";          shift 2 ;;
    --sweep)          CLI_SWEEP=true;            shift ;;
    --batch-size)     CLI_BATCH_SIZE="${2:-}";   shift 2 ;;
    --excluded-paths) CLI_EXCLUDES="${2:-}";     shift 2 ;;
    --sast)           CLI_SAST="${2:-}";          shift 2 ;;
    --no-sast)        CLI_SAST="off";             shift ;;
    --sast-rules)     CLI_SAST_RULES="${2:-}";    shift 2 ;;
    --codeql-db)      CLI_CODEQL_DB="${2:-}";     shift 2 ;;
    --refresh)        CLI_REFRESH=true;          shift ;;
    --no-cve-context) CLI_NO_CVE=true;           shift ;;
    --help|-h)        sed -n '2,/^$/p' "$0" | sed 's/^# \?//'; exit 0 ;;
    *) echo "ERROR: unknown arg '$1'" >&2; exit 2 ;;
  esac
done

# --sweep is sugar for --max-functions all. Explicit --max-functions wins only
# if --sweep was NOT passed (sweep is the stronger intent).
if [ "$CLI_SWEEP" = "true" ]; then
  CLI_MAX="all"
fi
BATCH_SIZE="${CLI_BATCH_SIZE:-30}"

# ---------------------------------------------------------------------------
# Resolve config defaults
# ---------------------------------------------------------------------------
CFG_FILE="$STATE_DIR/fuzz-config.json"
CFG_TARGET_ROOT=""
CFG_MAX=""
CFG_EXCLUDES=""
CFG_SAST=""
CFG_CODEQL_DB=""
if [ -f "$CFG_FILE" ]; then
  # One field per line, read line-by-line. The target root is a filesystem path
  # (can contain spaces) and excludes is a joined list; a single `read -r A B C`
  # would word-split them across the other fields. Reading whole lines keeps
  # space-containing values intact.
  { read -r CFG_TARGET_ROOT
    read -r CFG_MAX
    read -r CFG_EXCLUDES
    read -r CFG_SAST
    read -r CFG_CODEQL_DB
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
    sast = (cr.get("sast") or {})
    # sast may be a bool (enabled) or an object; normalize to a mode string.
    if isinstance(sast, bool):
        sast_mode = "auto" if sast else "off"
        codeql_db = ""
    else:
        sast_mode = sast.get("mode", "") or ("off" if sast.get("enabled") is False else "")
        codeql_db = sast.get("codeql_db", "") or ""
    print(paths or "")
    print(cr.get("max_functions_to_review", "") or "")
    print(excl or "")
    print(sast_mode or "")
    print(codeql_db or "")
except Exception:
    print(); print(); print(); print(); print()
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
# SAST mode precedence: CLI > config > default(auto). The prescan auto-includes
# the bundled rules/semgrep pack; --sast-rules only ADDS extra dirs.
SAST_MODE="${CLI_SAST:-${CFG_SAST:-auto}}"
SAST_RULES="$CLI_SAST_RULES"
CODEQL_DB="${CLI_CODEQL_DB:-$CFG_CODEQL_DB}"

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
  --sast         "$SAST_MODE"
)
[ -n "$EXCLUDES" ]           && PRESCAN_ARGS+=(--excluded-paths "$EXCLUDES")
[ -n "$CVE_CONTEXT_PATH" ]   && PRESCAN_ARGS+=(--cve-context    "$CVE_CONTEXT_PATH")
[ -n "$SAST_RULES" ]         && PRESCAN_ARGS+=(--sast-rules     "$SAST_RULES")
[ -n "$CODEQL_DB" ]          && PRESCAN_ARGS+=(--codeql-db      "$CODEQL_DB")

echo "[code-review] running prescan: target=$TARGET_ROOT max=$MAX_FUNCTIONS sast=$SAST_MODE" >&2
[ -n "$CVE_CONTEXT_PATH" ] && echo "[code-review] cve-context: $CVE_CONTEXT_PATH" >&2

if ! python3 "$SCRIPT_DIR/_lib/code_review_prescan.py" "${PRESCAN_ARGS[@]}" >/dev/null; then
  echo "ERROR: prescan failed" >&2
  exit 2
fi

# Summary for the caller. Read scope back from the prescan so mode/candidates
# come from the authoritative artifact rather than re-deriving here.
{ read -r TOP_COUNT
  read -r SCAN_MODE
} <<< "$(python3 -c "
import json
d = json.load(open('$PRESCAN_OUT'))
scope = d.get('scope') or {}
print(scope.get('candidates_selected', len(d.get('top_candidates') or [])))
print(scope.get('mode', 'capped'))
" 2>/dev/null)"
TOP_COUNT="${TOP_COUNT:-0}"
SCAN_MODE="${SCAN_MODE:-capped}"

# Window plan: ceil(candidates / batch_size). Capped mode reviews in one window
# of the cap; sweep mode fans the full ranked list across ceil(N/batch) windows.
NUM_WINDOWS=$(python3 -c "
import math
c = int('$TOP_COUNT' or 0)
b = int('$BATCH_SIZE' or 30)
print(0 if c == 0 else math.ceil(c / b))
" 2>/dev/null)
NUM_WINDOWS="${NUM_WINDOWS:-1}"

echo "[code-review] prescan complete: $TOP_COUNT candidate function(s), mode=$SCAN_MODE" >&2
# Machine-readable plan the skill parses to drive the windowed reviewer dispatch.
echo "BATCH_PLAN windows=$NUM_WINDOWS batch_size=$BATCH_SIZE candidates=$TOP_COUNT mode=$SCAN_MODE"
echo "READY: $PRESCAN_OUT"
exit 0
