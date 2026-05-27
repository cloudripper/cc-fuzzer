#!/usr/bin/env bash
# oracle-smoke-test.sh
#
# COLD pre-launch validation of a logic oracle. A mis-specified oracle (one that
# asserts a property the target does not actually guarantee) is a false-positive
# factory; the cheapest evidence that it is mis-specified is that it trips on an
# ORDINARY, VALID input — i.e. a seed.
#
# This runs the seed corpus (known-good inputs) through the verify_binary and
# looks for the CCFUZZ_ORACLE_VIOLATION marker. Because the harness's accept-gate
# only emits the marker when the target ACCEPTED the input, a marker here means
# "the target accepted a seed and the oracle property still failed" — the smoking
# gun for a bad oracle (a seed the target rejects produces no marker and cannot
# cause a false alarm).
#
# On a trip we do NOT decide bad-oracle-vs-real-bug here (they are
# indistinguishable at this stage). Per STATE_SCHEMA "Oracle-Driven Fuzzing", we
# stage the tripping seed(s) into fuzz/crashes/new/ and let the crash-triager's
# oracle-validity gate adjudicate before the campaign commits fuzzing cycles:
#   - genuine finding  -> recorded; the oracle is validated; launch proceeds.
#   - bad oracle       -> dropped + a harness-correction is written; harness
#                         rebuilds crash-only.
# A clean pass costs nothing (native runs, no LLM) and is the common case.
#
# Usage:  oracle-smoke-test.sh [--harness <name>] [--max-seeds N] [--stage-max M]
#
# Exit codes:
#   0   pass, or skipped (crash-only oracle | no verify_binary | empty corpus)
#   10  oracle TRIPPED — tripping seed(s) staged to fuzz/crashes/new/;
#       the caller (orchestrator) must dispatch crash-triager before launch.

set -u

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
. "$SCRIPT_DIR/_lib/path-anchor.sh"
. "$SCRIPT_DIR/_lib/harness-path.sh"

FUZZ_ROOT="${FUZZ_ROOT:-fuzz}"
STATE_DIR="${FUZZ_STATE_DIR:-$FUZZ_ROOT/state}"

HARNESS_NAME=""
MAX_SEEDS=32          # how many seeds to sample
STAGE_MAX=3           # how many distinct tripping seeds to stage for triage
while [ $# -gt 0 ]; do
  case "$1" in
    --harness)   HARNESS_NAME="${2:-}"; shift 2 ;;
    --max-seeds) MAX_SEEDS="${2:-32}"; shift 2 ;;
    --stage-max) STAGE_MAX="${2:-3}"; shift 2 ;;
    -h|--help)   sed -n '2,/^$/p' "$0" | sed 's/^# \?//'; exit 0 ;;
    *) echo "oracle-smoke-test: unknown arg '$1'" >&2; exit 2 ;;
  esac
done

# Resolve the harness name (multi mode). In singular mode the name is ignored by
# the harness-path helpers.
if [ -z "$HARNESS_NAME" ] && is_multi; then
  HARNESS_NAME="$(default_harness)"
fi

# --- Read the oracle type + verify_binary from the per-harness record ----------
read_record() {
  python3 - "$STATE_DIR" "$HARNESS_NAME" <<'PY'
import json, os, sys
state_dir, name = sys.argv[1], sys.argv[2]
def emit(t, vb): print(f"{t or ''}\t{vb or ''}")
hs = os.path.join(state_dir, "harnesses.json")
hb = os.path.join(state_dir, "harness-built.json")
rec = None
try:
    doc = json.load(open(hs))
    for h in doc.get("harnesses", []):
        if not name or h.get("name") == name:
            rec = h; break
except Exception:
    rec = None
if rec is None:
    try:
        rec = json.load(open(hb))
    except Exception:
        rec = {}
oracle = rec.get("oracle") or {}
emit((oracle.get("type") if isinstance(oracle, dict) else "") or "crash",
     rec.get("verify_binary") or "")
PY
}

REC="$(read_record)"
ORACLE_TYPE="$(printf '%s' "$REC" | cut -f1)"
VERIFY_BIN="$(printf '%s' "$REC" | cut -f2)"

# --- Skip conditions (all benign: exit 0) --------------------------------------
if [ -z "$ORACLE_TYPE" ] || [ "$ORACLE_TYPE" = "crash" ]; then
  echo "oracle-smoke-test: crash-only oracle — nothing to validate (skip)"
  exit 0
fi

if [ -z "$VERIFY_BIN" ] || [ "$VERIFY_BIN" = "None" ] || [ ! -x "$VERIFY_BIN" ]; then
  echo "oracle-smoke-test: WARN — no usable verify_binary; oracle '$ORACLE_TYPE' UNVALIDATED (proceeding)" >&2
  exit 0
fi

CORPUS="$(corpus_dir "$HARNESS_NAME")"
mapfile -t SEEDS < <(find "$CORPUS" -maxdepth 1 -type f 2>/dev/null | head -n "$MAX_SEEDS")
if [ "${#SEEDS[@]}" -eq 0 ]; then
  echo "oracle-smoke-test: WARN — empty corpus at $CORPUS; oracle '$ORACLE_TYPE' UNVALIDATED (proceeding)" >&2
  exit 0
fi

# --- Run each seed through the verify_binary -----------------------------------
NEW_DIR="$FUZZ_ROOT/crashes/new"
mkdir -p "$NEW_DIR"
staged=0
checked=0
declare -A staged_hash=()

for seed in "${SEEDS[@]}"; do
  checked=$((checked + 1))
  OUT=$(UBSAN_OPTIONS=print_stacktrace=1 ASAN_OPTIONS=abort_on_error=1:print_stacktrace=1 \
        timeout 10 "$VERIFY_BIN" "$seed" 2>&1)
  RC=$?
  # A seed that the target REJECTS produces no marker and does not crash — the
  # accept-gate guarantees that, so it is correctly ignored.
  if printf '%s' "$OUT" | grep -q 'CCFUZZ_ORACLE_VIOLATION'; then
    KIND="oracle-trip"
  elif [ "$RC" -ge 128 ] 2>/dev/null || printf '%s' "$OUT" | grep -qE 'SUMMARY: (AddressSanitizer|UndefinedBehaviorSanitizer|LeakSanitizer)|runtime error:'; then
    KIND="seed-crash"   # a known-good seed faulted the target — also worth triaging
  else
    continue
  fi

  HASH=$(sha256sum "$seed" 2>/dev/null | awk '{print $1}')
  [ -z "$HASH" ] && continue
  if [ -n "${staged_hash[$HASH]:-}" ]; then continue; fi   # dedup identical seeds
  if [ "$staged" -ge "$STAGE_MAX" ]; then continue; fi      # cap staged material

  DEST="$NEW_DIR/$(crash_filename "$HARNESS_NAME" "$HASH")"
  cp "$seed" "$DEST" 2>/dev/null || continue
  staged_hash[$HASH]=1
  staged=$((staged + 1))
  echo "oracle-smoke-test: TRIP ($KIND) on seed $(basename "$seed") -> staged $DEST" >&2
done

if [ "$staged" -eq 0 ]; then
  echo "oracle-smoke-test: PASS — oracle '$ORACLE_TYPE' did not trip on $checked seed(s)"
  exit 0
fi

cat >&2 <<EOF
oracle-smoke-test: oracle '$ORACLE_TYPE' TRIPPED on $staged of $checked seed(s).
  An oracle that fails on ordinary valid inputs is likely mis-specified.
  Staged the tripping seed(s) to $NEW_DIR — dispatch crash-triager BEFORE launch.
  The triager's oracle-validity gate decides: real finding (oracle validated,
  launch) vs bad oracle (harness-correction written -> rebuild crash-only).
EOF
exit 10
