#!/usr/bin/env python3
"""yolo_evaluate.py — the deterministic ground truth for dynamic YOLO.

YOLO's per-tick decision (wait / act / consult, and which action) should be
shaped by signals the model is bad at tracking across a long unattended run:
how much has been spent (especially on Opus agents), whether a given agent is
looping without producing results, and whether the fuzzer is still climbing on
its own. Those are cheap to compute deterministically and don't drift — so we
compute them here, every tick, and hand them to the orchestrator. The model
reasons over this block; it does not re-derive it.

This is consumed by all three YOLO modes:
  - guided    : the orchestrator's deterministic precedence table (legacy);
                the ledger only suppresses obviously-looping agents.
  - hybrid    : the orchestrator (Sonnet) reasons over `suggested_disposition`
                and the ledger to choose wait/act/which; table is a fallback.
  - self_loop : the orchestrator reasons freely from these signals + the plan;
                the table is a menu, not a mandate. Caps still bind.

Output is the `evaluation` sub-block of `yolo_state` (see compute below). It is
ADVISORY: hard halts (tick/cost/no_progress/crash_storm) remain in
compute_yolo_state; this block never halts, it only recommends.
"""
from __future__ import annotations
import datetime
import glob
import json
import os


# Agents dispatched at each model tier. Opus agents are the cost/spam risk YOLO
# must watch; the per-model estimate below is advisory (the hard cost_cap in
# compute_yolo_state still uses the legacy blended rate, unchanged).
OPUS_AGENTS = {
    "planner-consult", "poc-builder", "campaign-planner",
    "reporting-agent", "crash-triager", "code-reviewer-deep",
}

# Coverage-driving specialists whose redundancy is judged against coverage gain.
COVERAGE_AGENTS = {"seed-generator", "mutator", "coverage-analyst", "concolic-executor"}

# recommendation.branch -> the agent it dispatches (for throttle/suppression).
BRANCH_AGENT = {
    "triage": "crash-triager",
    "analyze_gaps": "coverage-analyst",
    "reanalyze_gaps": "coverage-analyst",
    "generate_seeds": "seed-generator",
    "concolic": "concolic-executor",
    "mutator": "mutator",
}

# Advisory per-model rates ($/token), in/out. Coarse — a spam signal, not billing.
_RATE = {
    "opus":   (15e-6, 75e-6),
    "sonnet": (3e-6, 15e-6),
    "haiku":  (0.8e-6, 4e-6),
}


def _load(path):
    try:
        with open(path) as f:
            return json.load(f)
    except Exception:
        return None


def _load_jsonl(path):
    rows = []
    if not os.path.exists(path):
        return rows
    try:
        with open(path) as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    rows.append(json.loads(line))
                except Exception:
                    pass
    except Exception:
        pass
    return rows


def _agent_of(evt):
    return evt.get("agent_called") or evt.get("agent") or ""


def _roundup_series(snaps_dir, since_ts):
    """(ts, weighted_pct) for tick-coverage roundups since since_ts, in order."""
    series = []
    for p in sorted(glob.glob(os.path.join(snaps_dir, "tick-coverage-*.json"))):
        d = _load(p)
        if not d:
            continue
        ts = int(d.get("timestamp") or 0)
        if ts < since_ts:
            continue
        pct = (d.get("overall") or {}).get("weighted_pct")
        if pct is not None:
            series.append((ts, float(pct)))
    return series


def _last_gain_ts(series, floor_ts):
    """Timestamp of the most recent roundup that improved on the prior one."""
    gain_ts = floor_ts
    for i in range(1, len(series)):
        if series[i][1] > series[i - 1][1]:
            gain_ts = series[i][0]
    return gain_ts


def _iso_to_ts(s):
    try:
        if s.endswith("Z"):
            return int(datetime.datetime.strptime(s, "%Y-%m-%dT%H:%M:%SZ").timestamp())
    except Exception:
        pass
    return 0


def evaluate(state_dir, snaps_dir, cfg, doc, enabled_at_ts, enabled_at_tick, tick_n, now):
    """Compute the advisory evaluation block. `cfg` is the fuzz-config yolo dict;
    `doc` is the current.json being written (for recommendation/gaps)."""
    yolo = cfg or {}
    mode = yolo.get("mode", "hybrid")
    if mode not in ("guided", "hybrid", "self_loop"):
        mode = "hybrid"
    redundancy_threshold = int(yolo.get("redundancy_threshold", 2))
    soft_fraction = float(yolo.get("soft_cost_fraction", 0.6))
    max_cost = float(yolo.get("max_cost_usd", 10.0))
    interval = int(yolo.get("interval_seconds", 1800))
    max_backoff = int(yolo.get("max_backoff_multiplier", 4))

    events = _load_jsonl(os.path.join(state_dir, "events.jsonl"))
    series = _roundup_series(snaps_dir, enabled_at_ts)
    gain_ts = _last_gain_ts(series, enabled_at_ts)

    # ---- cost (total uses legacy blended rate; per-model advisory) ----------
    total_usd = 0.0
    opus_usd = 0.0
    opus_calls = 0
    for e in events:
        if e.get("event") not in ("agent_call", "tick"):
            continue
        if int(e.get("ts") or 0) < enabled_at_ts:
            continue
        ti = int(e.get("tokens_in") or 0)
        to = int(e.get("tokens_out") or 0)
        if not (ti or to):
            continue
        total_usd += (ti * 5e-6) + (to * 25e-6)   # legacy blended — keep cost_cap stable
        agent = _agent_of(e)
        if agent in OPUS_AGENTS:
            ri, ro = _RATE["opus"]
            opus_usd += (ti * ri) + (to * ro)
            opus_calls += 1
    fraction = (total_usd / max_cost) if max_cost > 0 else 0.0
    if fraction >= 1.0:
        posture = "halt"
    elif fraction >= soft_fraction:
        posture = "throttle"
    else:
        posture = "normal"

    # ---- per-agent redundancy ledger ----------------------------------------
    dispatch_ts = {}   # agent -> [ts, ...] since enable
    for e in events:
        if int(e.get("ts") or 0) < enabled_at_ts:
            continue
        a = _agent_of(e)
        if a:
            dispatch_ts.setdefault(a, []).append(int(e.get("ts") or 0))

    # crash-triager productivity = a new finding recorded.
    findings = _load_jsonl(os.path.join(state_dir, "findings.jsonl"))
    last_finding_ts = enabled_at_ts
    for d in findings:
        fs = _iso_to_ts(d.get("first_seen", "") or "")
        if fs > last_finding_ts:
            last_finding_ts = fs

    # concolic productivity = its latest result promoted inputs.
    concolic_promoted = None
    cfiles = sorted(glob.glob(os.path.join(snaps_dir, "concolic-*.json")))
    if cfiles:
        cd = _load(cfiles[-1]) or {}
        concolic_promoted = int(cd.get("inputs_promoted_to_corpus") or 0)

    ledger = {}
    suppressed = []
    for agent, tss in dispatch_ts.items():
        tss = sorted(tss)
        if agent == "crash-triager":
            unproductive = sum(1 for t in tss if t > last_finding_ts)
        elif agent in COVERAGE_AGENTS:
            unproductive = sum(1 for t in tss if t > gain_ts)
            # concolic that promoted inputs is productive even if coverage lags.
            if agent == "concolic-executor" and concolic_promoted:
                unproductive = 0
        else:
            # No productivity model for this agent (planner, harness-writer, …).
            unproductive = 0
        is_suppressed = unproductive >= redundancy_threshold
        ledger[agent] = {
            "dispatches": len(tss),
            "consecutive_unproductive": unproductive,
            "suppressed": is_suppressed,
        }
        if is_suppressed:
            suppressed.append(agent)

    # ---- progress -----------------------------------------------------------
    self_climbing = len(series) >= 2 and series[-1][1] > series[-2][1]
    ticks_since_gain = 0
    if series:
        ticks_since_gain = sum(1 for ts, _ in series if ts > gain_ts)

    # ---- adaptive wait backoff ---------------------------------------------
    consecutive_waits = 0
    for e in reversed(events):
        if e.get("event") != "tick":
            continue
        if int(e.get("ts") or 0) < enabled_at_ts:
            break
        if e.get("branch") in ("sleep", "wait"):
            consecutive_waits += 1
        else:
            break
    backoff_mult = min(2 ** consecutive_waits, max_backoff) if max_backoff > 0 else 1
    wait_seconds = interval * max(1, backoff_mult)

    # ---- suggested disposition (advisory) -----------------------------------
    rec = (doc or {}).get("recommendation") or {}
    branch = rec.get("branch") or ""
    branch_agent = BRANCH_AGENT.get(branch, "")
    branch_suppressed = branch_agent in suppressed
    branch_is_opus = branch_agent in OPUS_AGENTS

    if posture == "halt":
        disposition, rationale = "wait", "cost cap reached; halt pending"
    elif branch in ("", "sleep", "stop"):
        disposition, rationale = "wait", "no actionable recommendation this tick"
    elif self_climbing:
        disposition = "wait"
        rationale = f"fuzzer still climbing (last roundup gained); let it run (backoff x{backoff_mult})"
    elif branch_suppressed:
        # The recommended agent is looping. If everything actionable is spent,
        # ask Opus for a new tactic — unless throttling, then wait.
        if posture == "throttle":
            disposition, rationale = "wait", f"{branch_agent} looping and cost throttled; wait"
        else:
            disposition, rationale = "consult", f"{branch_agent} looping ({ledger.get(branch_agent,{}).get('consecutive_unproductive')}x no result); reconsider tactic"
    elif posture == "throttle" and branch_is_opus:
        disposition, rationale = "wait", f"cost throttled; defer Opus action ({branch_agent})"
    else:
        disposition, rationale = "act", f"act on '{branch}' ({branch_agent or 'infra'})"

    return {
        "mode": mode,
        "cost": {
            "total_usd": round(total_usd, 4),
            "opus_usd": round(opus_usd, 4),
            "opus_calls": opus_calls,
            "fraction_of_cap": round(fraction, 3),
            "posture": posture,
            "soft_cost_fraction": soft_fraction,
        },
        "agent_ledger": ledger,
        "suppressed_agents": sorted(suppressed),
        "progress": {
            "fuzzer_self_climbing": self_climbing,
            "ticks_since_coverage_gain": ticks_since_gain,
            "consecutive_waits": consecutive_waits,
        },
        "suggested_disposition": disposition,
        "suggested_wait_seconds": wait_seconds,
        "redundancy_threshold": redundancy_threshold,
        "rationale": rationale,
    }


# CLI for testing: evaluate against a written current.json + its campaign state.
if __name__ == "__main__":
    import sys
    cur_path = sys.argv[1]
    doc = _load(cur_path) or {}
    state_dir = os.path.dirname(os.path.abspath(cur_path))
    snaps_dir = os.path.join(state_dir, "snapshots")
    cfg = (_load(os.path.join(state_dir, "fuzz-config.json")) or {}).get("yolo") or {}
    now = int(doc.get("now") or 0)
    out = evaluate(
        state_dir, snaps_dir, cfg, doc,
        int(cfg.get("enabled_at_ts", 0)), int(cfg.get("enabled_at_tick", 0)),
        int(doc.get("tick_number", 0) or 0), now,
    )
    print(json.dumps(out, indent=2))
