"""cc_fuzzer_core.state.yolo_evaluate — the deterministic ground truth for dynamic YOLO.

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

Each mode carries an `aggressiveness` posture (overridable via the config field
of the same name): guided→conservative, hybrid→balanced, self_loop→aggressive.
The posture shapes `suggested_disposition` (how readily we say `act` vs `wait`)
and the wait-backoff (aggressive does not compound, so priorities stay fresh).

Output is the `evaluation` sub-block of `yolo_state` (see compute below). It is
ADVISORY: hard halts (tick/cost/no_progress/crash_storm) remain in
compute_yolo_state; this block never halts, it only recommends.
"""
from __future__ import annotations
import glob
import os

from cc_fuzzer_core import ledger as spend_ledger, models
from cc_fuzzer_core.state import ceiling as ceiling_probe
from cc_fuzzer_core.state import toolbox as toolbox_eval
from cc_fuzzer_core.state._common import (iso_to_ts as _iso_to_ts, last_gain_ts as _last_gain_ts,
                                          load_json as _load, load_jsonl as _load_jsonl,
                                          roundup_series as _roundup_series, ticks_since)
from cc_fuzzer_core.state.yolo_state import YoloSettings


# Which agents are "deep" (the Opus-class cost/spam risk YOLO must watch) and
# what a call costs come from cc_fuzzer_core.models (data/models.json +
# overrides): deep_agents() replaces the old hard-coded Opus agent set, and
# every spend estimate — the posture here and the hard cost_cap in
# compute_yolo_state — prices each call at its own model's rate.
def deep_agents(mm) -> frozenset:
    return mm.agents_in_tier(models.DEEP)


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

def _agent_of(evt):
    return evt.get("agent_called") or evt.get("agent") or ""


def evaluate(state_dir, snaps_dir, cfg, doc, enabled_at_ts, enabled_at_tick, tick_n, now,
             fuzz_dir=None, model_map=None):
    """Compute the advisory evaluation block. `cfg` is the fuzz-config yolo dict;
    `doc` is the current.json being written (for recommendation/gaps)."""
    ys = YoloSettings(cfg)
    yolo = ys.block
    mode = ys.mode
    # Aggressiveness posture governs how readily the deterministic disposition
    # says `act` vs `wait`, and how hard the wait-backoff compounds. An explicit
    # `aggressiveness` field wins; otherwise it's derived from the mode so the
    # mode name carries the posture (self_loop is aggressive by default).
    aggressiveness = ys.aggressiveness
    redundancy_threshold = ys.int("redundancy_threshold")
    soft_fraction = ys.float("soft_cost_fraction")
    # --no-cap removes cost as a constraint: no soft throttle here AND no hard
    # cost halt in compute_yolo_state. posture then never leaves `normal`.
    cost_cap_enabled = ys.bool("cost_cap_enabled")
    max_cost = ys.float("max_cost_usd")
    interval = ys.int("interval_seconds")
    max_backoff = ys.int("max_backoff_multiplier")
    plateau_escalate_ticks = ys.int("plateau_escalate_ticks")

    events = _load_jsonl(os.path.join(state_dir, "events.jsonl"))
    series = _roundup_series(snaps_dir, enabled_at_ts)
    gain_ts = _last_gain_ts(series, enabled_at_ts)

    # ---- cost (each call at its model's rate; deep-tier share advisory) -----
    # opus_usd / opus_calls keep their schema names: they are the deep tier.
    # Spend comes only from the ledger (agent_call rows, host-measured rows
    # superseding the orchestrator's); `tick` rows are not billable.
    mm = model_map if model_map is not None else models.load(state_dir)
    deep = deep_agents(mm)
    spent = spend_ledger.spend(state_dir, since_ts=enabled_at_ts, model_map=mm, rows=events)
    total_usd = spent.usd
    opus_usd = spent.usd_for(deep)
    opus_calls = spent.calls_for(deep)
    fraction = (total_usd / max_cost) if max_cost > 0 else 0.0
    if not cost_cap_enabled:
        posture = "normal"   # --no-cap: cost never throttles or halts
    elif fraction >= 1.0:
        posture = "halt"
    elif fraction >= soft_fraction:
        posture = "throttle"
    else:
        posture = "normal"

    # ---- per-agent redundancy ledger ----------------------------------------
    dispatch_ts = {}   # agent -> [ts, ...] since enable
    ignored = spend_ledger.dropped(events)   # superseded / duplicate agent_call rows
    for e in events:
        if int(e.get("ts") or 0) < enabled_at_ts or id(e) in ignored:
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
    ticks_since_gain = ticks_since(series, gain_ts)

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
    # Aggressive posture keeps ticks frequent: the wait-backoff does NOT compound,
    # so priorities never go stale across a long idle stretch. Balanced and
    # conservative compound up to the configured cap (legacy behavior).
    eff_max_backoff = 1 if aggressiveness == "aggressive" else max_backoff
    backoff_mult = min(2 ** consecutive_waits, eff_max_backoff) if eff_max_backoff > 0 else 1
    wait_seconds = interval * max(1, backoff_mult)

    # ---- ceiling probe (plateau / structural-ceiling ground truth) ---------
    # Computed before the toolbox so its structural_candidates can light up the
    # plateau-breaking levers, and returned in the block so compute_yolo_state
    # (halt gate) and the consult briefing read the SAME ladder stage we do.
    # Aggressive (self_loop) ONLY: the ladder and structural levers are a self_loop
    # feature; guided/balanced keep legacy halts and their evaluation output stays
    # byte-identical (ceiling stays None ⇒ toolbox adds no structural levers ⇒ no
    # ceiling_probe key in the returned block).
    ceiling = None
    if aggressiveness == "aggressive":
        try:
            ceiling = ceiling_probe.compute(
                state_dir, snaps_dir, doc, events, enabled_at_ts, gain_ts,
                ticks_since_gain, plateau_escalate_ticks, now,
            )
        except Exception:
            ceiling = None

    # ---- toolbox lever board (the whole toolbox, materialized) -------------
    try:
        toolbox = toolbox_eval.compute(
            state_dir, snaps_dir, yolo, doc, events, findings,
            enabled_at_ts, posture, suppressed, redundancy_threshold, now,
            ceiling=ceiling, fuzz_dir=fuzz_dir, model_map=mm,
        )
    except Exception:
        toolbox = None
    tunnel = bool(toolbox and toolbox.get("tunnel_vision"))
    suggested_lever = (toolbox or {}).get("suggested_lever")
    top_lever = (toolbox or {}).get("top_lever")

    def _lever_label(lever):
        """'lever (agent)' for the rationale, agent looked up from the board."""
        if not lever:
            return ""
        for l in (toolbox or {}).get("eligible_levers", []):
            if l.get("lever") == lever:
                a = l.get("agent")
                return f"{lever} ({a})" if a and a != "infra/skill" else lever
        return lever

    def _structural_label(cand):
        """'action → entry (why)' for a ceiling-probe structural candidate."""
        if not cand:
            return ""
        act = cand.get("suggested_action") or "reshape"
        tgt = (cand.get("proposed_entry") or cand.get("function")
               or cand.get("engine_recommendation") or "?")
        why = cand.get("why") or ""
        return f"{act} → {tgt}" + (f" ({why})" if why else "")

    # Plateau escalation ladder stage (computed once in ceiling_probe so the halt
    # gate in compute_yolo_state agrees with us): 0 normal, 1 escalate structural,
    # 2 pre-halt consult, 3 honest halt.
    ladder_stage = (ceiling or {}).get("ladder_stage", 0)
    rec_struct = (ceiling or {}).get("recommended_structural")

    # ---- suggested disposition (advisory, posture-aware) --------------------
    rec = (doc or {}).get("recommendation") or {}
    branch = rec.get("branch") or ""
    branch_agent = BRANCH_AGENT.get(branch, "")
    branch_suppressed = branch_agent in suppressed
    branch_is_opus = branch_agent in deep
    # The gap-closing recommendation engine only covers triage/coverage/seed/
    # concolic/mutator. When it has no move (`sleep`/empty), the *strategic*
    # toolbox (harness extension, CVE intel, code review, PoC, plan revision) is
    # still available — that's invisible here, so an aggressive posture treats it
    # as a reason to act, not idle.
    no_gap_move = branch in ("", "sleep", "stop")

    def _loop_reason(a):
        n = ledger.get(a, {}).get("consecutive_unproductive")
        return f"{a} looping ({n}x no result); reconsider tactic"

    if posture == "halt":
        disposition, rationale = "wait", "cost cap reached; halt pending"

    elif aggressiveness == "aggressive":
        # self_loop default. A self-climbing fuzzer is NOT a reason to idle:
        # pursue the strategic toolbox in parallel. Only the hard cost halt
        # (handled above) forces a true wait.
        #
        # PLATEAU LADDER FIRST. A coverage plateau is NOT a stopping point — it's
        # the cue to RESHAPE the harness (entry swap / new harness / mock) or switch
        # the engine, and only park once those are exhausted AND a pre-halt consult
        # returned nothing. This takes precedence over the generic toolbox flow,
        # except that broken instrumentation (always top_lever) is fixed first.
        if ladder_stage in (1, 2) and top_lever == "instrumentation":
            disposition, rationale = "act", (
                f"instrumentation broken — fix before breaking the ceiling "
                f"('{_lever_label(top_lever)}')")
        elif ladder_stage == 1 and rec_struct:
            disposition, rationale = "act", (
                f"plateau {ticks_since_gain} ticks: break the structural ceiling "
                f"via {_structural_label(rec_struct)}")
        elif ladder_stage == 2:
            # One-shot pre-halt consult — throttle-exempt (a single ~Opus check is
            # worth it before parking the whole campaign; reaching stage 3 then
            # lets the honest halt fire).
            disposition, rationale = "consult", (
                "structural candidates exhausted; pre-halt consult before parking "
                "(reshape avenues tried, coverage still flat)")
        elif tunnel and suggested_lever:
            # Riding one lever family while others sit eligible — redirect to the
            # highest-priority neglected lever to force toolbox breadth.
            disposition, rationale = "act", f"tunnel vision (rode {(toolbox or {}).get('distinct_recent_families', 1)} lever family); switch to neglected lever '{suggested_lever}'"
        elif tunnel and posture != "throttle":
            disposition, rationale = "consult", "tunnel vision and no affordable neglected lever; reconsider strategy"
        elif branch_suppressed and posture != "throttle":
            disposition, rationale = "consult", _loop_reason(branch_agent)
        elif no_gap_move:
            if top_lever:
                disposition, rationale = "act", f"no gap-closing move; take top strategic lever '{_lever_label(top_lever)}'"
            else:
                disposition, rationale = "act", "no gap-closing move; no lever materialized — reason from plan/guidance/references"
        elif posture == "throttle" and branch_is_opus:
            if top_lever:
                disposition, rationale = "act", f"cost throttled; take non-Opus top lever '{_lever_label(top_lever)}' instead of {branch_agent}"
            else:
                disposition, rationale = "act", f"cost throttled; act on a non-Opus lever instead of {branch_agent}"
        else:
            tail = " alongside self-climbing fuzzer" if self_climbing else ""
            disposition, rationale = "act", f"act on '{branch}' ({branch_agent or 'infra'}){tail}"

    elif aggressiveness == "balanced":
        # hybrid default. Act on a concrete, affordable gap move even while the
        # fuzzer climbs; only idle when there's genuinely no gap move (let it run)
        # or a constraint binds. Does NOT chase the strategic toolbox on its own.
        if no_gap_move:
            disposition, rationale = "wait", "no gap-closing move; let the fuzzer run"
        elif branch_suppressed:
            if posture == "throttle":
                disposition, rationale = "wait", f"{branch_agent} looping and cost throttled; wait"
            else:
                disposition, rationale = "consult", _loop_reason(branch_agent)
        elif posture == "throttle" and branch_is_opus:
            disposition, rationale = "wait", f"cost throttled; defer Opus action ({branch_agent})"
        else:
            tail = " while fuzzer also climbs" if self_climbing else ""
            disposition, rationale = "act", f"act on '{branch}' ({branch_agent or 'infra'}){tail}"

    else:  # conservative (guided) — legacy precedence, unchanged.
        if no_gap_move:
            disposition, rationale = "wait", "no actionable recommendation this tick"
        elif self_climbing:
            disposition = "wait"
            rationale = f"fuzzer still climbing (last roundup gained); let it run (backoff x{backoff_mult})"
        elif branch_suppressed:
            if posture == "throttle":
                disposition, rationale = "wait", f"{branch_agent} looping and cost throttled; wait"
            else:
                disposition, rationale = "consult", _loop_reason(branch_agent)
        elif posture == "throttle" and branch_is_opus:
            disposition, rationale = "wait", f"cost throttled; defer Opus action ({branch_agent})"
        else:
            disposition, rationale = "act", f"act on '{branch}' ({branch_agent or 'infra'})"

    result = {
        "mode": mode,
        "aggressiveness": aggressiveness,
        "cost": {
            "total_usd": round(total_usd, 4),
            "opus_usd": round(opus_usd, 4),
            "opus_calls": opus_calls,
            "fraction_of_cap": round(fraction, 3),
            "posture": posture,
            "soft_cost_fraction": soft_fraction,
            "cost_cap_enabled": cost_cap_enabled,
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
        "toolbox": toolbox,
    }
    # Aggressive-only (keeps guided/balanced output byte-identical to pre-feature).
    if ceiling is not None:
        result["ceiling_probe"] = ceiling
    return result


def evaluate_from_current(cur_path):
    """evaluate() against a written current.json + its campaign state (the old
    yolo_evaluate.py CLI)."""
    doc = _load(cur_path) or {}
    state_dir = os.path.dirname(os.path.abspath(cur_path))
    ys = YoloSettings.load(state_dir)
    return evaluate(state_dir, os.path.join(state_dir, "snapshots"), ys.block, doc,
                    ys.int("enabled_at_ts"), ys.int("enabled_at_tick"),
                    int(doc.get("tick_number", 0) or 0), int(doc.get("now") or 0))
