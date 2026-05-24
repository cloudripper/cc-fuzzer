#!/usr/bin/env bash
# tick-briefing.sh
#
# Composes a small JSON briefing the orchestrator hands to campaign-planner
# in consult mode. The point: surface the last few ticks' coverage trend,
# active gap mix, and specialists already dispatched, so Opus can make a
# strategic call about WHERE to push next — without re-reading the full plan.
#
# Output: fuzz/state/snapshots/tick-briefing-<ts>.json (schema tick-briefing/v1)
# Echoes the absolute path of the file written.
#
# Inputs read:
#   fuzz/state/current.json        — tick_number, tick_coverage, recommendation, gaps
#   fuzz/state/snapshots/tick-coverage-*.json — last N for the coverage trend
#   fuzz/state/snapshots/gaps-*.json — latest for the active-gap mix
#   fuzz/state/events.jsonl        — specialists dispatched since last consult
#   fuzz/state/findings.jsonl      — findings recorded since last consult
#   fuzz/state/snapshots/planner-consult-*.json — last_consult_ts baseline
#
# Optional env:
#   TRIGGER (default "scheduled") — "scheduled" | "coverage_stall" | "manual"
#
# Cost intent: the briefing should be ~1 KB so Opus consult is cheap.

set -u

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
. "$SCRIPT_DIR/_lib/path-anchor.sh"

STATE_DIR="${FUZZ_STATE_DIR:-$FUZZ_ROOT/state}"
SNAPSHOTS_DIR="$STATE_DIR/snapshots"
mkdir -p "$SNAPSHOTS_DIR"

TS=$(date +%s)
TRIGGER="${TRIGGER:-scheduled}"
OUT_FILE="$SNAPSHOTS_DIR/tick-briefing-${TS}.json"

STATE_DIR="$STATE_DIR" \
SNAPSHOTS_DIR="$SNAPSHOTS_DIR" \
OUT_FILE="$OUT_FILE" \
TS="$TS" \
TRIGGER="$TRIGGER" \
python3 - <<'PY'
import json, os, glob, time

state_dir = os.environ["STATE_DIR"]
snaps_dir = os.environ["SNAPSHOTS_DIR"]
out_file = os.environ["OUT_FILE"]
ts = int(os.environ["TS"])
trigger = os.environ["TRIGGER"]

def _load_json(path, default=None):
    try:
        with open(path) as f:
            return json.load(f)
    except Exception:
        return default

current = _load_json(os.path.join(state_dir, "current.json"), {}) or {}

tick_number = int(current.get("tick_number", 0) or 0)
recommendation = current.get("recommendation", {}) or {}
gaps_summary = current.get("gaps", {}) or {}
tick_coverage_block = current.get("tick_coverage") or {}

# --- Coverage history (last 5 tick-coverage roundups) ---
cov_paths = sorted(glob.glob(os.path.join(snaps_dir, "tick-coverage-*.json")))
hist = []
for p in cov_paths[-5:]:
    d = _load_json(p)
    if not d:
        continue
    hist.append({
        "ts": d.get("timestamp"),
        "weighted_pct": (d.get("overall") or {}).get("weighted_pct"),
        "stale_harnesses": d.get("stale_harnesses") or [],
    })

# Coverage delta across the window we sampled.
coverage_delta_window = 0.0
if len(hist) >= 2:
    first = hist[0].get("weighted_pct") or 0.0
    last  = hist[-1].get("weighted_pct") or 0.0
    coverage_delta_window = round(last - first, 2)

# --- Active gap mix (latest gaps report) ---
gap_paths = sorted(glob.glob(os.path.join(snaps_dir, "gaps-*.json")))
gap_mix = {}
gap_examples = []
if gap_paths:
    g = _load_json(gap_paths[-1])
    if g:
        for entry in g.get("gaps", []) or []:
            reason = entry.get("reason") or "unknown"
            gap_mix[reason] = gap_mix.get(reason, 0) + 1
            # First example per reason — keeps the briefing concrete without
            # ballooning. Only include id + file + function + recommended_agent.
            if not any(ex["reason"] == reason for ex in gap_examples) and len(gap_examples) < 8:
                gap_examples.append({
                    "id": entry.get("id"),
                    "reason": reason,
                    "file": entry.get("file"),
                    "function": entry.get("function"),
                    "recommended_agent": entry.get("recommended_agent"),
                    "hint": (entry.get("hint") or "")[:140],
                })

# --- Last consult baseline (for "since last consult" counters) ---
consult_paths = sorted(glob.glob(os.path.join(snaps_dir, "planner-consult-*.json")))
last_consult_ts = 0
last_consult_tick = 0
if consult_paths:
    last = _load_json(consult_paths[-1])
    if last:
        last_consult_ts = int(last.get("ts") or last.get("timestamp") or 0)
        last_consult_tick = int(last.get("tick_number") or 0)

# --- Specialists dispatched since last consult ---
dispatched = []
events_path = os.path.join(state_dir, "events.jsonl")
if os.path.exists(events_path):
    try:
        with open(events_path) as f:
            for line in f:
                line = line.strip()
                if not line: continue
                try:
                    e = json.loads(line)
                except Exception:
                    continue
                if int(e.get("ts") or 0) < last_consult_ts:
                    continue
                if e.get("event") == "agent_call":
                    dispatched.append({
                        "agent": e.get("agent_called"),
                        "tick": e.get("tick"),
                        "tokens_in": e.get("tokens_in"),
                        "tokens_out": e.get("tokens_out"),
                    })
    except Exception:
        pass

# Compact dispatched: cap at 15 entries to keep the briefing small.
if len(dispatched) > 15:
    dispatched = dispatched[-15:]

# --- Findings recorded since last consult ---
findings_path = os.path.join(state_dir, "findings.jsonl")
findings_new = 0
findings_recent_ids = []
if os.path.exists(findings_path):
    try:
        with open(findings_path) as f:
            for line in f:
                line = line.strip()
                if not line: continue
                try:
                    d = json.loads(line)
                except Exception:
                    continue
                # findings carry ISO8601 first_seen; convert to epoch for the
                # comparison. Cheap parse — fall through on failure.
                fs = d.get("first_seen", "")
                fs_ts = 0
                try:
                    import datetime as _dt
                    if fs.endswith("Z"):
                        fs_ts = int(_dt.datetime.strptime(fs, "%Y-%m-%dT%H:%M:%SZ").timestamp())
                except Exception:
                    pass
                if fs_ts >= last_consult_ts:
                    findings_new += 1
                    if len(findings_recent_ids) < 8:
                        findings_recent_ids.append(d.get("id"))
    except Exception:
        pass

# --- Sonnet's recommendation (what the orchestrator would do absent consult) ---
sonnet_rec = {
    "branch": recommendation.get("branch") or "",
    "reason": recommendation.get("reason") or "",
}

briefing = {
    "schema": "tick-briefing/v1",
    "ts": ts,
    "tick_number": tick_number,
    "trigger": trigger,
    "last_consult_ts": last_consult_ts,
    "last_consult_tick": last_consult_tick,
    "ticks_since_last_consult": (tick_number - last_consult_tick) if last_consult_tick else tick_number,
    "coverage": {
        "current_overall_pct": (tick_coverage_block.get("overall") or {}).get("weighted_pct") if tick_coverage_block else None,
        "history": hist,
        "delta_across_window": coverage_delta_window,
        "stale_harnesses": (tick_coverage_block or {}).get("stale_harnesses") or [],
    },
    "active_gaps": {
        "total_pending": gaps_summary.get("total_pending", 0),
        "mix_by_reason": gap_mix,
        "examples": gap_examples,
    },
    "dispatched_since_last_consult": dispatched,
    "findings_since_last_consult": {
        "count": findings_new,
        "ids": findings_recent_ids,
    },
    "sonnet_recommendation": sonnet_rec,
}

with open(out_file, "w") as f:
    json.dump(briefing, f, indent=2)
    f.write("\n")

print(out_file)
PY
