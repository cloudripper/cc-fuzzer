#!/usr/bin/env bash
# tick-coverage-roundup.sh
#
# Aggregates per-harness coverage-*.json snapshots into a single
# tick-coverage-<ts>.json (schema tick-coverage/v1). The orchestrator reads
# this aggregate at the top of every WARM tick instead of re-deriving coverage
# from individual snapshots.
#
# Inputs:
#   fuzz/state/snapshots/coverage-*.json    (singular mode)
#   fuzz/state/snapshots/coverage-<harness>-<ts>.json  (multi mode)
#
# Output:
#   fuzz/state/snapshots/tick-coverage-<ts>.json
#   Echoes the output path to stdout.
#
# Optional env:
#   STALE_THRESHOLD_SECONDS  (default: 600 — flag harnesses whose newest
#                             snapshot is older than this; surfaces silent-
#                             zero instrumentation problems)
#
# Why this exists:
#   Multi-harness tick reports were showing inconsistent coverage — sometimes
#   only one harness, sometimes stale numbers, sometimes zero on healthy
#   instrumentation. Centralising the aggregation in one script with strict
#   rules makes the tick output deterministic.

set -u

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
. "$SCRIPT_DIR/_lib/path-anchor.sh"
. "$SCRIPT_DIR/_lib/harness-path.sh"

STATE_DIR="${FUZZ_STATE_DIR:-$FUZZ_ROOT/state}"
SNAPSHOTS_DIR="$STATE_DIR/snapshots"
mkdir -p "$SNAPSHOTS_DIR"

STALE_THRESHOLD_SECONDS="${STALE_THRESHOLD_SECONDS:-600}"
TS=$(date +%s)
OUT_FILE="$SNAPSHOTS_DIR/tick-coverage-${TS}.json"

# Resolve mode + declared harnesses. In singular mode the harness list is a
# single synthetic entry derived from harness-built.json:entry_function.
MODE="singular"
if is_multi; then
  MODE="multi"
fi

DECLARED_LIST=""
if [ "$MODE" = "multi" ]; then
  DECLARED_LIST=$(declared_harnesses | tr '\n' '|' | sed 's/|$//')
else
  DECLARED_LIST=$(default_harness)
fi

# Hand off to Python — JSON aggregation in bash is a hazard.
MODE="$MODE" \
DECLARED_LIST="$DECLARED_LIST" \
SNAPSHOTS_DIR="$SNAPSHOTS_DIR" \
STATE_DIR="$STATE_DIR" \
PROJECT_ROOT="$PROJECT_ROOT" \
OUT_FILE="$OUT_FILE" \
TS="$TS" \
STALE_THRESHOLD_SECONDS="$STALE_THRESHOLD_SECONDS" \
python3 - <<'PY'
import json, os, glob, re, time

mode = os.environ["MODE"]
declared = [h for h in os.environ["DECLARED_LIST"].split("|") if h]
snaps_dir = os.environ["SNAPSHOTS_DIR"]
project_root = os.environ["PROJECT_ROOT"]
out_file = os.environ["OUT_FILE"]
ts = int(os.environ["TS"])
stale_threshold = int(os.environ["STALE_THRESHOLD_SECONDS"])

# Load every coverage-*.json once. We sort/select per harness below.
all_cov = []
for path in glob.glob(os.path.join(snaps_dir, "coverage-*.json")):
    try:
        with open(path) as f:
            doc = json.load(f)
    except Exception:
        continue
    if doc.get("schema") != "coverage-snapshot/v2":
        continue
    all_cov.append((path, doc))

def harness_of(path, doc):
    """Return the harness name a coverage snapshot belongs to.
    Multi mode uses filename prefix `coverage-<harness>-<ts>.json` or an
    explicit top-level `harness` field. Singular mode has no harness label."""
    base = os.path.basename(path)
    m = re.match(r'^coverage-([a-z0-9][a-z0-9_-]{0,31})-\d+\.json$', base)
    if m:
        return m.group(1)
    explicit = doc.get("harness")
    if explicit:
        return explicit
    return None  # singular-shaped filename

# Select newest snapshot per harness.
per_harness_newest = {}
for path, doc in all_cov:
    h = harness_of(path, doc)
    if mode == "singular":
        # Treat all singular-shaped files as belonging to the lone harness
        # (use empty string as the key; we re-tag later).
        h = ""
    else:
        if h is None:
            # Multi mode but filename has no harness segment — legacy or
            # orphaned snapshot. Skip; the validator surfaces these.
            continue
        if declared and h not in declared:
            # Snapshot belongs to a harness that's no longer declared. Skip.
            continue
    cur = per_harness_newest.get(h)
    snap_ts = int(doc.get("timestamp", 0))
    if cur is None or snap_ts > cur[2]:
        per_harness_newest[h] = (path, doc, snap_ts)

# Find the previous tick-coverage roundup (if any) for delta computation.
prev_roundup = None
prev_paths = sorted(glob.glob(os.path.join(snaps_dir, "tick-coverage-*.json")))
for p in reversed(prev_paths):
    try:
        with open(p) as f:
            prev_roundup = json.load(f)
        break
    except Exception:
        continue

def prev_lines_covered(harness_name):
    if not prev_roundup:
        return None
    for h in prev_roundup.get("harnesses", []):
        if h.get("name") == harness_name:
            return h.get("lines_covered", 0)
    return None

# Build the per-harness output array.
harness_rows = []
overall_covered = 0
overall_total = 0
stale_harnesses = []

# Iterate declared order (multi) or the lone singular harness.
if mode == "multi":
    iter_list = declared
else:
    # Use the default harness name (entry_function) as the singular row label.
    singular_name = declared[0] if declared else "main"
    iter_list = [singular_name]

for name in iter_list:
    key = "" if mode == "singular" else name
    triple = per_harness_newest.get(key)
    if triple is None:
        # No snapshot for this declared harness yet.
        harness_rows.append({
            "name": name,
            "lines_covered": 0,
            "lines_total": 0,
            "pct": 0.0,
            "delta_since_last_tick": 0,
            "first_seen": True,
            "instrumentation_ok": False,
            "snapshot_file": None,
            "snapshot_ts": 0,
            "snapshot_age_seconds": None,
            "stale": True,
        })
        stale_harnesses.append(name)
        continue

    path, doc, snap_ts = triple
    cov = doc.get("coverage", {})
    instr = doc.get("instrumentation", {})
    lines_covered = int(cov.get("lines_covered", 0))
    lines_total = int(cov.get("lines_total", 0))
    pct = round((lines_covered / lines_total * 100.0), 2) if lines_total else 0.0
    instr_ok = bool(instr.get("ok", False))
    age = ts - snap_ts
    stale = age > stale_threshold

    prev_lc = prev_lines_covered(name)
    first_seen = prev_lc is None
    delta = 0 if first_seen else (lines_covered - int(prev_lc))

    if stale:
        stale_harnesses.append(name)

    overall_covered += lines_covered
    overall_total += lines_total

    harness_rows.append({
        "name": name,
        "lines_covered": lines_covered,
        "lines_total": lines_total,
        "pct": pct,
        "delta_since_last_tick": delta,
        "first_seen": first_seen,
        "instrumentation_ok": instr_ok,
        "snapshot_file": os.path.relpath(path, project_root),
        "snapshot_ts": snap_ts,
        "snapshot_age_seconds": age,
        "stale": stale,
    })

overall_pct = round((overall_covered / overall_total * 100.0), 2) if overall_total else 0.0

snapshot = {
    "schema": "tick-coverage/v1",
    "timestamp": ts,
    "mode": mode,
    "harnesses": harness_rows,
    "overall": {
        "lines_covered": overall_covered,
        "lines_total": overall_total,
        "weighted_pct": overall_pct,
    },
    "stale_harnesses": stale_harnesses,
    "stale_threshold_seconds": stale_threshold,
}

with open(out_file, "w") as f:
    json.dump(snapshot, f, indent=2)
    f.write("\n")

print(out_file)
PY
