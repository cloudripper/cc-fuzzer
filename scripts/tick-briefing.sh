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

# --- Toolbox lever board (already computed in current.json; free to surface) ---
# Lets the consult reason about strategic lever choice when gaps are exhausted.
# Compact: drop the per-lever agent label (the consult names levers, not agents)
# and keep it to short fields so the briefing stays ~1 KB.
_eval = (current.get("yolo_state") or {}).get("evaluation") or {}
_toolbox = _eval.get("toolbox") or {}
toolbox_brief = {}
if _toolbox:
    toolbox_brief = {
        "top_lever": _toolbox.get("top_lever"),
        "ranked_levers": _toolbox.get("ranked_levers") or [],
        "neglected_levers": _toolbox.get("neglected_levers") or [],
        "tunnel_vision": bool(_toolbox.get("tunnel_vision")),
        "suggested_lever": _toolbox.get("suggested_lever"),
        "eligible_levers": [
            {
                "lever": l.get("lever"),
                "evidence": l.get("evidence"),
                "idle_ticks": l.get("idle_ticks"),
                "cost_tier": l.get("cost_tier"),
                "suppressed": l.get("suppressed"),
            }
            for l in (_toolbox.get("eligible_levers") or [])
        ],
    }

# --- impact_review board state (v0.30, recommendation C) ---
# Specifically surface eligibility + last-run-tick for the impact_review lever
# so the consult's pre-halt rubric can call it cleanly. The consult looks here
# (and at the same lever in eligible_levers[]) before approving an honest halt.
impact_review_brief = {
    "eligible": False,
    "last_run_tick": None,
    "evidence": None,
}
if _toolbox:
    for l in (_toolbox.get("eligible_levers") or []):
        if l.get("lever") == "impact_review":
            impact_review_brief["eligible"] = True
            impact_review_brief["evidence"] = l.get("evidence")
            break
# Find last impact_review tick from events.jsonl
if os.path.exists(events_path):
    try:
        with open(events_path) as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    e = json.loads(line)
                except Exception:
                    continue
                agent = e.get("agent_called") or e.get("agent") or ""
                reason = e.get("reason") or ""
                if (agent == "code-reviewer-deep"
                        and (reason.startswith("structural:impact_review")
                             or "impact_review" in reason)):
                    impact_review_brief["last_run_tick"] = e.get("tick")
    except Exception:
        pass

# --- Ceiling probe (self_loop only): the pre-halt consult's most important input.
# When ladder_stage == 2 the campaign plateaued, exhausted its structural reshapes,
# and this consult is the last gate before it parks. Surface what was tried + what
# surface remains so the consult can find a move the deterministic ladder couldn't.
_ceiling = _eval.get("ceiling_probe") or {}
ceiling_brief = {}
if _ceiling:
    ceiling_brief = {
        "ladder_stage": _ceiling.get("ladder_stage"),
        "is_real_ceiling": _ceiling.get("is_real_ceiling"),
        "ticks_since_gain": _ceiling.get("ticks_since_gain"),
        "summary": _ceiling.get("summary"),
        "attempted_since_plateau": _ceiling.get("attempted_since_plateau") or [],
        "untried_candidates": [
            {"function": c.get("function"), "suggested_action": c.get("suggested_action"),
             "proposed_entry": c.get("proposed_entry"), "why": c.get("why")}
            for c in (_ceiling.get("untried_candidates") or [])
        ][:6],
        "engine_fit": _ceiling.get("engine_fit") or {},
        "dead_count": _ceiling.get("dead_count"),
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
    "toolbox": toolbox_brief,
    "ceiling": ceiling_brief,
    "impact_review": impact_review_brief,
}

with open(out_file, "w") as f:
    json.dump(briefing, f, indent=2)
    f.write("\n")

print(out_file)
PY
