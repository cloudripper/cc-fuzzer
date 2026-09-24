"""cc_fuzzer_core.state.derive_tick (was scripts/_lib/derive-tick-state.py) —
compute the mode-agnostic derived state blocks and merge them into an
already-written current.json.

update_current() writes current.json via build_current. The three
derived blocks below depend only on files on disk plus the tick number already
in current.json, so they are computed here once as a post-pass over the written
current.json.

Blocks merged in:
  - tick_coverage : the latest tick-coverage-<ts>.json roundup, inlined
  - consult_state : whether a strategic check-in is due this tick
  - yolo_state    : YOLO halt/continue computation

derive(cur_path) (`cc-fuzzer state derive <current.json>`; the
derive-tick-state.py shim) reads tick_number + now from the doc, infers
state_dir from the doc's path, and writes the merged doc back atomically.
Best-effort: a failure here must not wedge a tick — the doc is already valid
without these blocks.
"""
from __future__ import annotations
import datetime
import glob
import json
import os
import time
from dataclasses import dataclass

from cc_fuzzer_core import config as _config
from cc_fuzzer_core import models
from cc_fuzzer_core.state import yolo_evaluate
from cc_fuzzer_core.state._common import load_json as _load
from cc_fuzzer_core.state.yolo_state import YoloSettings


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
    tick_cfg = _config.block(state_dir, "tick")
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


def compute_yolo_state(state_dir, snaps_dir, tick_n, now, doc=None, fuzz_dir=None):
    ys = {"active": False, "halt_triggered": False, "halt_reason": None}
    settings = YoloSettings.load(state_dir)
    yolo_cfg = settings.block
    if not settings.enabled:
        return ys

    # Defaults live in yolo_state.YOLO_DEFAULTS (read with .get(key, default),
    # so a user-set 0 such as max_ticks=0 survives).
    interval = settings.int("interval_seconds")
    max_ticks = settings.int("max_ticks")
    max_cost = settings.float("max_cost_usd")
    # --no-cap removes cost as a constraint entirely: no soft throttle (see
    # yolo_evaluate) AND no hard cost halt below. Other halts still bind.
    cost_cap_enabled = settings.bool("cost_cap_enabled")
    stop_no_prog = settings.int("stop_on_no_progress_ticks")
    crash_storm = settings.int("crash_storm_threshold")
    enabled_at_tick = settings.int("enabled_at_tick")
    enabled_at_ts = settings.int("enabled_at_ts")
    ticks_used = max(0, tick_n - enabled_at_tick)
    tick_remaining = max(0, max_ticks - ticks_used)

    # Cost estimate: agent_call tokens since enable, each priced at its own
    # model's rate (cc_fuzzer_core.models). Advisory, not billing.
    try:
        mm, models_error = models.load(state_dir), None
    except models.ModelsError as e:
        # A broken override must not silence the halt gate: price with the
        # packaged mapping and say so.
        mm, models_error = models.load(None, env={}), str(e)
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
                    cost_used += mm.event_cost(e)
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
    try:
        evaluation = yolo_evaluate.evaluate(
            state_dir, snaps_dir, yolo_cfg, doc,
            enabled_at_ts, enabled_at_tick, tick_n, now, fuzz_dir=fuzz_dir, model_map=mm,
        )
    except Exception:
        evaluation = None
    aggressiveness = (evaluation or {}).get("aggressiveness")
    if aggressiveness not in ("conservative", "balanced", "aggressive"):
        aggressiveness = settings.aggressiveness
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
    if models_error:
        out["models_error"] = models_error
    # Reuse the evaluation block computed above (single ceiling/ladder computation
    # per tick, so the halt gate and the disposition can never disagree).
    if evaluation is not None:
        out["evaluation"] = evaluation
    return out


@dataclass(frozen=True)
class DeriveResult:
    doc: dict | None   # the merged current.json (None: nothing to merge into)
    written: bool


def derive(cur_path, *, fuzz_dir=None) -> DeriveResult:
    """Merge tick_coverage / consult_state / yolo_state into cur_path."""
    cur_path = os.fspath(cur_path)
    doc = _load(cur_path)
    if doc is None:
        # Nothing to do; the caller's doc is either missing or invalid.
        return DeriveResult(None, False)

    state_dir = os.path.dirname(os.path.abspath(cur_path))
    snaps_dir = os.path.join(state_dir, "snapshots")
    # NB: historically named project_root, but it is the state dir's parent
    # (fuzz/), so tick_coverage.snapshot_file reads "state/snapshots/...".
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
        doc["yolo_state"] = compute_yolo_state(state_dir, snaps_dir, tick_n, now, doc, fuzz_dir=fuzz_dir)
    except Exception:
        pass

    tmp = cur_path + ".derive.tmp"
    with open(tmp, "w") as f:
        json.dump(doc, f, indent=2)
    os.replace(tmp, cur_path)
    return DeriveResult(doc, True)
