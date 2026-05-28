#!/usr/bin/env python3
"""derive-tick-state.py — compute the mode-agnostic derived state blocks and
merge them into an already-written current.json.

`update-current.sh` writes current.json in one of two mode-specific paths
(multi-harness or singular). The three derived blocks below depend only on
files on disk plus the tick number already in current.json, so they are
identical regardless of mode. Computing them here once — as a post-pass over
the written current.json — removes the ~195-line duplication that previously
lived in both code paths.

Blocks merged in:
  - tick_coverage : the latest tick-coverage-<ts>.json roundup, inlined
  - consult_state : whether a strategic check-in is due this tick
  - yolo_state    : YOLO halt/continue computation

Usage:
  derive-tick-state.py <path-to-current.json>

Reads tick_number + now from the doc; infers state_dir from the doc's path.
Writes the merged doc back atomically. Exit 0 always (best-effort; a failure
here must not wedge a tick — the doc is already valid without these blocks).
"""
from __future__ import annotations
import datetime
import glob
import json
import os
import sys
import time

try:
    import yolo_evaluate  # sibling _lib module (advisory dynamic-YOLO signals)
except Exception:
    yolo_evaluate = None


def _load(path):
    try:
        with open(path) as f:
            return json.load(f)
    except Exception:
        return None


def compute_tick_coverage(snaps_dir, project_root):
    """Inline the latest tick-coverage roundup (or None)."""
    tcs = sorted(glob.glob(os.path.join(snaps_dir, "tick-coverage-*.json")))
    if not tcs:
        return None
    tc = _load(tcs[-1])
    if tc is None:
        return None
    tc["snapshot_file"] = os.path.relpath(tcs[-1], project_root)
    return tc


def compute_consult_state(state_dir, snaps_dir, tick_n):
    cs = {
        "last_consult_ts": 0,
        "last_consult_tick": 0,
        "ticks_since_last_consult": tick_n,
        "due": False,
        "trigger": None,
    }
    every_n = 5
    stall_enabled = True
    cfg = _load(os.path.join(state_dir, "fuzz-config.json")) or {}
    tick_cfg = cfg.get("tick") or {}
    if isinstance(tick_cfg.get("consult_every_n"), int) and tick_cfg["consult_every_n"] > 0:
        every_n = tick_cfg["consult_every_n"]
    if "consult_on_coverage_stall" in tick_cfg:
        stall_enabled = bool(tick_cfg["consult_on_coverage_stall"])

    pcs = sorted(glob.glob(os.path.join(snaps_dir, "planner-consult-*.json")))
    if pcs:
        last = _load(pcs[-1]) or {}
        cs["last_consult_ts"] = int(last.get("ts", 0) or 0)
        cs["last_consult_tick"] = int(last.get("tick_number", 0) or 0)

    cs["ticks_since_last_consult"] = tick_n - cs["last_consult_tick"]
    if cs["ticks_since_last_consult"] >= every_n:
        cs["due"] = True
        cs["trigger"] = "scheduled"
    elif stall_enabled:
        # Coverage stall = no weighted_pct gain across the last 5 roundups.
        tcs_all = sorted(glob.glob(os.path.join(snaps_dir, "tick-coverage-*.json")))[-5:]
        if len(tcs_all) >= 5:
            pcts = []
            for p in tcs_all:
                d = _load(p) or {}
                pcts.append((d.get("overall") or {}).get("weighted_pct"))
            pcts = [x for x in pcts if x is not None]
            if len(pcts) >= 2 and (pcts[-1] - pcts[0]) <= 0.0:
                cs["due"] = True
                cs["trigger"] = "coverage_stall"
    cs["consult_every_n"] = every_n
    return cs


def compute_yolo_state(state_dir, snaps_dir, tick_n, now, doc=None):
    ys = {"active": False, "halt_triggered": False, "halt_reason": None}
    cfg = _load(os.path.join(state_dir, "fuzz-config.json")) or {}
    yolo_cfg = cfg.get("yolo") or {}
    if not yolo_cfg.get("enabled"):
        return ys

    # .get(key, default) — NOT `or default` — so user-set 0 (e.g. max_ticks=0
    # to disable the cap) survives.
    interval = int(yolo_cfg.get("interval_seconds", 1800))
    max_ticks = int(yolo_cfg.get("max_ticks", 24))
    max_cost = float(yolo_cfg.get("max_cost_usd", 10.0))
    # --no-cap removes cost as a constraint entirely: no soft throttle (see
    # yolo_evaluate) AND no hard cost halt below. Other halts still bind.
    cost_cap_enabled = bool(yolo_cfg.get("cost_cap_enabled", True))
    stop_no_prog = int(yolo_cfg.get("stop_on_no_progress_ticks", 30))
    crash_storm = int(yolo_cfg.get("crash_storm_threshold", 10))
    enabled_at_tick = int(yolo_cfg.get("enabled_at_tick", 0))
    enabled_at_ts = int(yolo_cfg.get("enabled_at_ts", 0))
    ticks_used = max(0, tick_n - enabled_at_tick)
    tick_remaining = max(0, max_ticks - ticks_used)

    # Cost estimate: sum agent_call tokens since enable. Coarse blended rate.
    cost_used = 0.0
    events_path = os.path.join(state_dir, "events.jsonl")
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
                    if e.get("event") != "agent_call":
                        continue
                    if int(e.get("ts") or 0) < enabled_at_ts:
                        continue
                    ti = int(e.get("tokens_in") or 0)
                    to = int(e.get("tokens_out") or 0)
                    cost_used += (ti * 5e-6) + (to * 25e-6)
        except Exception:
            pass
    cost_remaining = max(0.0, max_cost - cost_used)

    # No-progress: weighted_pct flat across the last stop_no_prog roundups
    # taken since yolo was enabled.
    consecutive_no_progress = 0
    try:
        tcs = sorted(glob.glob(os.path.join(snaps_dir, "tick-coverage-*.json")))
        recent = []
        for p in tcs:
            d = _load(p)
            if d and int(d.get("timestamp") or 0) >= enabled_at_ts:
                recent.append(d)
        recent = recent[-stop_no_prog:]
        if len(recent) >= stop_no_prog:
            pcts = [(d.get("overall") or {}).get("weighted_pct") for d in recent]
            pcts = [x for x in pcts if x is not None]
            if len(pcts) >= 2 and (pcts[-1] - pcts[0]) <= 0.0:
                consecutive_no_progress = stop_no_prog
    except Exception:
        pass

    # Crash storm: new findings within the last interval.
    new_findings_last_tick = 0
    try:
        findings_path = os.path.join(state_dir, "findings.jsonl")
        if os.path.exists(findings_path):
            cutoff = (now - interval) if now else 0
            with open(findings_path) as f:
                for line in f:
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        d = json.loads(line)
                    except Exception:
                        continue
                    fs = d.get("first_seen", "")
                    try:
                        if fs.endswith("Z"):
                            fs_ts = int(datetime.datetime.strptime(fs, "%Y-%m-%dT%H:%M:%SZ").timestamp())
                            if fs_ts >= cutoff:
                                new_findings_last_tick += 1
                    except Exception:
                        pass
    except Exception:
        pass

    # Advisory dynamic-YOLO signals (cost posture, redundancy ledger, progress,
    # the ceiling probe + its escalation-ladder stage). Computed BEFORE the halt
    # decision so the no_progress gate below reads the SAME ladder stage the
    # disposition layer used. Never halts itself — that's the block below.
    evaluation = None
    if yolo_evaluate is not None:
        try:
            evaluation = yolo_evaluate.evaluate(
                state_dir, snaps_dir, yolo_cfg, doc,
                enabled_at_ts, enabled_at_tick, tick_n, now,
            )
        except Exception:
            evaluation = None
    aggressiveness = (evaluation or {}).get("aggressiveness")
    if aggressiveness not in ("conservative", "balanced", "aggressive"):
        mode = yolo_cfg.get("mode", "hybrid")
        aggressiveness = {"guided": "conservative", "hybrid": "balanced",
                          "self_loop": "aggressive"}.get(mode, "balanced")
    ceiling = (evaluation or {}).get("ceiling_probe") or {}
    ladder_stage = int(ceiling.get("ladder_stage", 0) or 0)

    # No-progress halt. Under guided/balanced this is the legacy flat-count halt.
    # Under aggressive (self_loop) a coverage plateau is NOT terminal — it triggers
    # the structural escalation ladder (reshape the harness / swap the engine) and
    # a pre-halt consult. The halt fires only when that ladder reaches stage 3
    # (structural avenues attempted AND a consult already ran, coverage still flat),
    # so the campaign breaks through the ceiling before it ever parks.
    if aggressiveness == "aggressive":
        no_progress_halt = ladder_stage >= 3
    else:
        no_progress_halt = consecutive_no_progress >= stop_no_prog

    halt_conditions = {
        "tick_cap":    ticks_used >= max_ticks,
        "cost_cap":    cost_cap_enabled and cost_used >= max_cost,
        "no_progress": no_progress_halt,
        "crash_storm": new_findings_last_tick >= crash_storm,
    }
    halt_triggered = any(halt_conditions.values())
    halt_reason = None
    if halt_triggered:
        # Honest no_progress reason under aggressive: name what the ladder tried.
        if aggressiveness == "aggressive" and no_progress_halt:
            attempted = ceiling.get("attempted_since_plateau") or []
            flat_ticks = ceiling.get("ticks_since_gain", consecutive_no_progress)
            tried = ", ".join(attempted[:4]) if attempted else "no structural move available"
            no_progress_reason = (
                f"structural ceiling: reshape/engine moves attempted ({tried}) and a "
                f"pre-halt consult ran; coverage flat {flat_ticks} ticks")
        else:
            no_progress_reason = f"no coverage progress for {consecutive_no_progress} ticks"
        for k, v in halt_conditions.items():
            if v:
                halt_reason = {
                    "tick_cap":    f"tick cap reached ({ticks_used}/{max_ticks})",
                    "cost_cap":    f"cost cap reached (${cost_used:.2f}/${max_cost:.2f})",
                    "no_progress": no_progress_reason,
                    "crash_storm": f"crash storm: {new_findings_last_tick} new findings in last interval (>= {crash_storm})",
                }[k]
                break
    out = {
        "active": True,
        "enabled_at_tick": enabled_at_tick,
        "enabled_at_ts": enabled_at_ts,
        "ticks_since_enable": ticks_used,
        "tick_quota_used": ticks_used,
        "tick_quota_remaining": tick_remaining,
        "estimated_cost_usd": round(cost_used, 4),
        "cost_quota_remaining_usd": round(cost_remaining, 4),
        "consecutive_no_progress_ticks": consecutive_no_progress,
        "new_findings_last_interval": new_findings_last_tick,
        "halt_conditions": halt_conditions,
        "halt_triggered": halt_triggered,
        "halt_reason": halt_reason,
        "interval_seconds": interval,
    }
    # Reuse the evaluation block computed above (single ceiling/ladder computation
    # per tick, so the halt gate and the disposition can never disagree).
    if evaluation is not None:
        out["evaluation"] = evaluation
    return out


def main():
    if len(sys.argv) < 2:
        print("usage: derive-tick-state.py <path-to-current.json>", file=sys.stderr)
        return 2
    cur_path = sys.argv[1]
    doc = _load(cur_path)
    if doc is None:
        # Nothing to do; the caller's doc is either missing or invalid.
        return 0

    state_dir = os.path.dirname(os.path.abspath(cur_path))
    snaps_dir = os.path.join(state_dir, "snapshots")
    project_root = os.path.dirname(state_dir)
    tick_n = int(doc.get("tick_number", 0) or 0)
    now = int(doc.get("now") or time.time())

    try:
        doc["tick_coverage"] = compute_tick_coverage(snaps_dir, project_root)
    except Exception:
        doc.setdefault("tick_coverage", None)
    try:
        doc["consult_state"] = compute_consult_state(state_dir, snaps_dir, tick_n)
    except Exception:
        pass
    try:
        doc["yolo_state"] = compute_yolo_state(state_dir, snaps_dir, tick_n, now, doc)
    except Exception:
        pass

    tmp = cur_path + ".derive.tmp"
    with open(tmp, "w") as f:
        json.dump(doc, f, indent=2)
    os.replace(tmp, cur_path)
    return 0


if __name__ == "__main__":
    sys.exit(main())
