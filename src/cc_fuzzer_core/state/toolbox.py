"""cc_fuzzer_core.state.toolbox (was scripts/_lib/toolbox_eval.py) — the deterministic *lever board* for dynamic YOLO.

The dynamic-YOLO disposition (yolo_evaluate.py) only knows the gap-closing
agents the recommendation engine emits (seedgen / concolic / coverage / triage /
mutator). Everything else in the orchestrator's toolbox — harness extension,
CVE-intel refresh, code review, PoC building, PoC upgrading, plan revision,
dictionary tuning, slot/engine changes — is invisible to it. So in `self_loop`
the model tunnel-visions on the two or three levers that happen to be
materialized, and the rest of the toolbox is reached for only if the model
remembers to do the "cheap survey" it routinely skips.

This module materializes the WHOLE known toolbox every tick: for each lever it
computes eligibility from cheap deterministic signals (gap counts, finding
fields, file mtimes, the event log), how long it's sat idle, its cost tier, and
whether it's suppressed. It also computes a `tunnel_vision` signal (the campaign
has been riding ≤1 lever family while others sit eligible) so yolo_evaluate can
break the loop.

CRITICAL FRAMING — the board is a FLOOR, not a ceiling. `non_exhaustive: true`
is always set. The known levers are the moves we can detect deterministically;
the orchestrator is expected to ALSO reason creatively beyond them, especially
from operator-supplied steering. `references` surfaces `fuzz/guidance.md` and any
`fuzz/docs/` material precisely so the model folds that domain knowledge in and
invents moves the catalog doesn't list. A lever board that quietly became a
closed checklist would defeat the point of self_loop.

Output is the `evaluation.toolbox` sub-block. Advisory only — never halts.
"""
from __future__ import annotations
import glob
import os

from cc_fuzzer_core import config as _config
from cc_fuzzer_core import enums, features as _features, models
from cc_fuzzer_core.state._common import load_json as _load_json, load_jsonl as _load_jsonl


# lever -> cost tier (cc_fuzzer_core.models tiers: deep | standard | fast, or
# `none` for a deterministic lever that dispatches no model). Agent-backed
# levers take their agent's tier from the model mapping (so an agent-level
# override moves its lever too); this table covers the levers with no agent.
COST_TIER = {
    "instrumentation":      models.TIER_NONE,
    "dictionary":           models.TIER_NONE,
    "slot_engine":          models.TIER_NONE,
    "cve_refresh":          models.STANDARD,
    "code_review":          models.STANDARD,
}


def lever_tier(lever, mm):
    """The cost tier of a lever under model mapping `mm`."""
    agent = LEVER_AGENT.get(lever)
    if agent:
        return mm.tier_of(agent) or mm.default_tier
    return COST_TIER.get(lever, models.STANDARD)


# lever -> the agent whose dispatch counts as "using" it (for idle tracking).
# File-backed levers (cve/code_review/dictionary/plan) track recency by mtime
# instead and are handled separately.
LEVER_AGENT = {
    "coverage_reanalysis":  "coverage-analyst",
    "seedgen":              "seed-generator",
    "concolic":             "concolic-executor",
    "mutator":              "mutator",
    "harness_extend":       "harness-writer",
    "harness_rewrite":      "harness-writer",
    "harness_new":          "harness-writer",
    "mock_env":             "harness-writer",
    "engine_swap":          "harness-writer",
    "impact_review":        "code-reviewer-deep",
    "verification_fill":    "crash-triager",
    "poc_build":            "poc-builder",
    "poc_upgrade":          "poc-builder",
    "plan_revise":          "campaign-planner",
}

# recommendation.branch / recorded tick branch -> lever family (for tunnel
# vision). Unknown non-wait branches are treated as their own family.
BRANCH_LEVER = {
    "analyze_gaps":     "coverage_reanalysis",
    "reanalyze_gaps":   "coverage_reanalysis",
    "generate_seeds":   "seedgen",
    "concolic":         "concolic",
    "mutator":          "mutator",
    "triage":           "verification_fill",
    "harness":          "harness_extend",
    "harness_rewrite":  "harness_rewrite",
    "harness_new":      "harness_new",
    "mock_env":         "mock_env",
    "engine_swap":      "engine_swap",
    "impact_review":    "impact_review",
    "slot_engine":      "slot_engine",
    "refresh_cve":      "cve_refresh",
    "review":           "code_review",
    "poc":              "poc_build",
    "poc_upgrade":      "poc_upgrade",
    "plan_revise":      "plan_revise",
    "restart_fuzzer":   "instrumentation",
    "fix_instrumentation": "instrumentation",
}

# Suggestion priority when breaking tunnel vision (high → low). Also the
# ranking used for `top_lever` — the single best affordable, non-suppressed
# eligible lever to anchor each tick on (independent of neglect/tunnel).
SUGGEST_PRIORITY = [
    "instrumentation", "poc_build", "poc_upgrade", "verification_fill",
    "harness_rewrite", "harness_new", "mock_env", "engine_swap",
    "impact_review",
    "harness_extend", "coverage_reanalysis", "concolic", "seedgen", "mutator",
    "cve_refresh", "code_review", "plan_revise", "dictionary", "slot_engine",
]
_PRIORITY_INDEX = {lever: i for i, lever in enumerate(SUGGEST_PRIORITY)}


def _priority(lever):
    return _PRIORITY_INDEX.get(lever, len(SUGGEST_PRIORITY))

NEGLECT_IDLE_TICKS = 3      # eligible + idle this many ticks ⇒ neglected
TUNNEL_WINDOW = 4           # look back this many act-ticks
DIVERSITY_FLOOR = 1         # ≤ this many distinct lever families ⇒ tunnel


def _latest(snaps_dir, pattern):
    files = sorted(glob.glob(os.path.join(snaps_dir, pattern)))
    return files[-1] if files else None


def _mtime(path):
    try:
        return int(os.path.getmtime(path))
    except Exception:
        return 0


def _confirmed(f):
    """A finding worth exploiting: replayed clean (or at least not a known
    harness artifact) and not flagged harness-artifact."""
    if f.get("exploitability") == "harness-artifact":
        return False
    v = f.get("verification") or {}
    if v.get("deterministic_replay") == "pass":
        return True
    # Older findings predate the verification block; treat a real category +
    # reproducer as confirmed-enough for lever eligibility.
    return bool(f.get("reproducer")) and f.get("category") != "harness-artifact"


def _has_poc(f, fuzz_dir):
    if (f.get("verification") or {}).get("exploit_built") is True:
        return True
    pp = f.get("poc_path")
    if pp:
        cand = pp if os.path.isabs(pp) else os.path.join(os.path.dirname(fuzz_dir), pp)
        if os.path.isdir(cand) or os.path.isdir(os.path.join(fuzz_dir, os.path.basename(pp.rstrip("/")))):
            return True
    return False


def _weak_poc(f, n_confirmed):
    """Has an exploit bundle but it's upgradeable: Tier C (exploit_built false),
    weaponization attempted-not-achieved, or single-finding when a chain is
    possible (other confirmed findings exist and this one isn't chained)."""
    v = f.get("verification") or {}
    if v.get("exploit_built") is False:
        return True
    w = f.get("weaponization") or {}
    if w.get("attempted") and not w.get("achieved"):
        return True
    if not (f.get("chained_findings") or []) and n_confirmed >= 2:
        return True
    return False


def compute(state_dir, snaps_dir, cfg, doc, events, findings,
            enabled_at_ts, posture, suppressed, redundancy_threshold, now,
            ceiling=None, fuzz_dir=None, model_map=None):
    """Build the `evaluation.toolbox` block. Inputs are the same ones
    yolo_evaluate already has in hand, so this is cheap. `ceiling` is the
    ceiling-probe block (ceiling_probe.compute) — when present, its
    `structural_candidates` light up the plateau-breaking levers
    (harness_rewrite / harness_new / mock_env / engine_swap) so a coverage
    plateau hands the orchestrator a concrete reshape to take instead of parking.
    `fuzz_dir` defaults to the state dir's parent (the default layout)."""
    fuzz_dir = str(fuzz_dir) if fuzz_dir is not None else os.path.dirname(os.path.abspath(state_dir))
    mm = model_map if model_map is not None else models.load(state_dir)
    gaps = (doc or {}).get("gaps") or {}
    harness = (doc or {}).get("harness") or {}
    cov = (doc or {}).get("coverage") or {}
    cfg = cfg or {}
    suppressed = set(suppressed or [])

    # ---- ordered tick timeline since enable (for idle counting) -------------
    tick_ts = sorted(int(e.get("ts") or 0) for e in events
                     if e.get("event") == "tick" and int(e.get("ts") or 0) >= enabled_at_ts)
    ticks_since_enable = len(tick_ts)

    # last agent_call ts per agent, since enable.
    last_agent_ts = {}
    for e in events:
        if int(e.get("ts") or 0) < enabled_at_ts:
            continue
        a = e.get("agent_called") or e.get("agent") or ""
        if a:
            last_agent_ts[a] = max(last_agent_ts.get(a, 0), int(e.get("ts") or 0))

    def _idle_ticks_after(ts):
        if not ts:
            return ticks_since_enable
        return sum(1 for t in tick_ts if t > ts)

    def _lever_idle(lever, file_recency_ts=None):
        if file_recency_ts is not None:
            return _idle_ticks_after(file_recency_ts), (file_recency_ts or None)
        agent = LEVER_AGENT.get(lever)
        ts = last_agent_ts.get(agent, 0) if agent else 0
        return _idle_ticks_after(ts), (ts or None)

    # ---- findings-derived signals ------------------------------------------
    confirmed = [f for f in findings if _confirmed(f)]
    n_conf = len(confirmed)
    need_verif = [f for f in confirmed if not (f.get("verification") or {}).get("deterministic_replay")]
    need_poc = [f for f in confirmed if not _has_poc(f, fuzz_dir)]
    # config gates (§9 feature flags; cve.enabled is the advisory_lookup alias)
    full_cfg = _full_config(state_dir)
    feats = _features.load(full_cfg)
    impact_on = feats.enabled(_features.IMPACT_TIERING)
    advisory_on = feats.enabled(_features.ADVISORY_LOOKUP)
    # _weak_poc is an impact-tier judgement (Tier C / weaponization / chaining):
    # quiet when impact_tiering is off.
    weak_poc = [f for f in confirmed
                if impact_on and _has_poc(f, fuzz_dir) and _weak_poc(f, n_conf)]

    pending_crashes = int(((doc or {}).get("fuzzer_stats") or {}).get("new_crashes_since_previous") or 0)

    # ---- file-backed recency ------------------------------------------------
    cve_latest = _latest(snaps_dir, "cve-context-*.json")
    cve_ts = _mtime(cve_latest) if cve_latest else 0
    code_review_md = os.path.join(state_dir, "code-review.md")
    code_review_ts = _mtime(code_review_md) if os.path.exists(code_review_md) else 0
    plan_md = os.path.join(state_dir, "plan.md")
    plan_ts = _mtime(plan_md) if os.path.exists(plan_md) else 0
    gaps_latest = _latest(snaps_dir, "gaps-*.json")
    gaps_ts = _mtime(gaps_latest) if gaps_latest else 0
    cmplog = sorted(glob.glob(os.path.join(state_dir, "cmplog-dict-*.dict")))
    cmplog_latest = cmplog[-1] if cmplog else None

    cve_enabled = advisory_on
    cve_ttl_days = int((full_cfg.get("cve") or {}).get("cache_ttl_days", 30) or 30)
    cr_cfg = full_cfg.get("code_review") or {}
    cr_enabled = cr_cfg.get("enabled", True)
    hb = _load_json(os.path.join(state_dir, "harness-built.json")) or {}
    target_source = hb.get("target_source")

    # instrumentation health from tick_coverage
    instr_bad = False
    instr_note = ""
    tc = (doc or {}).get("tick_coverage") or {}
    for h in (tc.get("harnesses") or []):
        if h.get("instrumentation_ok") is False or h.get("stale") is True:
            instr_bad = True
            instr_note = f"{h.get('harness','harness')}: " + (
                "instrumentation_ok=false" if h.get("instrumentation_ok") is False else "stale")
            break

    running_slots = sum(1 for s in ((doc or {}).get("fuzzers") or []) if s.get("running"))

    # ---- eligibility predicates --------------------------------------------
    # (lever, eligible, evidence)
    candidates = []

    def add(lever, eligible, evidence):
        if eligible:
            candidates.append((lever, evidence))

    add("instrumentation", instr_bad, instr_note or "instrumentation/slot health")
    add("coverage_reanalysis", gaps_ts and (now - gaps_ts) > 900,
        f"gap report {int((now - gaps_ts) / 60)}m old")
    add("seedgen", (gaps.get("for_seedgen", 0) or 0) > 0 or (gaps.get("direct_compare", 0) or 0) > 0,
        f"for_seedgen={gaps.get('for_seedgen', 0)}, direct_compare={gaps.get('direct_compare', 0)}")
    add("concolic", (gaps.get("for_concolic", 0) or 0) > 0 and harness.get("symcc_available"),
        f"for_concolic={gaps.get('for_concolic', 0)}, symcc available")
    add("mutator", (gaps.get("for_mutator", 0) or 0) > 0,
        f"for_mutator={gaps.get('for_mutator', 0)}")
    add("dictionary", (gaps.get("direct_compare", 0) or 0) > 0 and bool(cmplog_latest),
        "fresh cmplog dict vs active — review for new operands")
    add("harness_extend", (gaps.get("for_harness", 0) or 0) > 0,
        f"for_harness={gaps.get('for_harness', 0)} (also check uncovered CVE hotspots)")

    # Plateau-breaking structural levers — eligible when the ceiling-probe surfaces
    # an UNTRIED candidate of the matching action. These express the moves the gap
    # engine can't (entry swap / new harness / mock / engine change); on a plateau
    # the disposition ladder forces one of them instead of parking. A probe `extend`
    # candidate is already covered by `harness_extend` above, so it isn't re-levered.
    _cands = (ceiling or {}).get("untried_candidates") or []
    _actions = {c.get("suggested_action") for c in _cands}

    def _struct_evi(action):
        cs = [c for c in _cands if c.get("suggested_action") == action]
        c0 = cs[0] if cs else {}
        tgt = (c0.get("proposed_entry") or c0.get("function")
               or c0.get("engine_recommendation") or "?")
        extra = f" (+{len(cs) - 1} more)" if len(cs) > 1 else ""
        return f"{action} → {tgt}{extra} [{c0.get('why')}]"

    add("harness_rewrite", "entry_swap" in _actions, _struct_evi("entry_swap"))
    add("harness_new", "new_harness" in _actions, _struct_evi("new_harness"))
    add("mock_env", ("mock" in _actions or "driver" in _actions),
        _struct_evi("mock" if "mock" in _actions else "driver"))
    add("engine_swap", "engine_swap" in _actions,
        ((ceiling or {}).get("engine_fit") or {}).get("rationale", "engine fit favours a change"))

    # impact_review — a plateau-breaking lever (v0.30, recommendation C). Coverage
    # plateaued but maybe the existing findings haven't been re-examined under the
    # logic-oracle + poc-builder realism lens. Eligible when the ceiling-probe
    # reports stage ≥ 1 AND (any open candidates with a high-impact oracle_kind
    # OR no `code-reviewer-deep` dispatch since the last coverage gain).
    _stage = (ceiling or {}).get("ladder_stage", 0)
    # The probe reports ticks_since_gain (roundups since the last coverage
    # gain), not a gain timestamp; map it onto this board's tick timeline: the
    # gain landed at or before the (ticks_since_gain + 1)-th most recent tick.
    _since = (ceiling or {}).get("ticks_since_gain")
    if isinstance(_since, int) and 0 <= _since < len(tick_ts):
        _gain_ts = tick_ts[-(_since + 1)]
    else:
        _gain_ts = enabled_at_ts
    last_impact_ts = 0
    for e in events:
        if int(e.get("ts") or 0) < _gain_ts:
            continue
        if (e.get("agent_called") or e.get("agent")) == "code-reviewer-deep":
            r = (e.get("reason") or "")
            # Only impact_review dispatches count — a plain code-reviewer-deep
            # dispatched via the Tier-3 pipeline doesn't satisfy this lever.
            if r.startswith("structural:impact_review") or "impact_review" in r:
                last_impact_ts = max(last_impact_ts, int(e.get("ts") or 0))
    # Match oracle_kind and category against their OWN vocabularies (they differ:
    # oracle_kind is underscore_case + coarse; category is hyphenated). The old
    # set mixed the two plus an invented "logic" and a pattern token "auth_bypass".
    _impact_candidates = [
        f for f in findings
        if (f.get("oracle_kind") in enums.HIGH_IMPACT_ORACLE_KINDS
            or f.get("category") in enums.HIGH_IMPACT_CATEGORIES)
    ]
    impact_eligible = (
        impact_on
        and _stage >= 1
        and (bool(_impact_candidates) or last_impact_ts == 0)
    )
    if _impact_candidates and impact_eligible:
        _ev = f"plateau stage {_stage}; {len(_impact_candidates)} candidate(s) with impact-relevant oracle_kind; impact_review not run since last gain"
    elif impact_eligible:
        _ev = f"plateau stage {_stage}; no impact_review since last coverage gain"
    else:
        _ev = None
    add("impact_review", impact_eligible, _ev or "")

    add("cve_refresh", cve_enabled and (not cve_latest or (now - cve_ts) > cve_ttl_days * 86400),
        "no CVE intel" if not cve_latest else f"CVE intel {int((now - cve_ts) / 86400)}d old (ttl {cve_ttl_days}d)")
    add("code_review", cr_enabled and bool(target_source) and not os.path.exists(code_review_md),
        "no code-review.md yet" if not os.path.exists(code_review_md) else "code review present")
    add("verification_fill", bool(need_verif) and pending_crashes < 3 and posture != "throttle",
        f"{len(need_verif)} confirmed finding(s) lack verification")
    add("poc_build", bool(need_poc),
        f"{len(need_poc)} confirmed finding(s) without an exploit bundle")
    add("poc_upgrade", bool(weak_poc),
        f"{len(weak_poc)} exploit(s) upgradeable (Tier C / unchained / not weaponized)")
    add("plan_revise",
        (not os.path.exists(plan_md)) or (plan_ts and plan_ts < enabled_at_ts) or len(suppressed) >= 2,
        "no plan.md" if not os.path.exists(plan_md)
        else (f"{len(suppressed)} agents suppressed — strategy may be stale"
              if len(suppressed) >= 2 else "plan predates this YOLO run"))
    add("slot_engine", running_slots == 1,
        "single slot running — an alternate engine could add diversity")

    # ---- assemble lever entries (eligible only, compact) -------------------
    file_recency = {
        "cve_refresh": cve_ts, "code_review": code_review_ts,
        "plan_revise": plan_ts, "dictionary": _mtime(cmplog_latest) if cmplog_latest else 0,
        "coverage_reanalysis": gaps_ts,
    }
    levers = []
    neglected = []
    for lever, evidence in candidates:
        idle, _ = _lever_idle(lever, file_recency.get(lever))
        agent = LEVER_AGENT.get(lever)
        is_sup = bool(agent and agent in suppressed)
        tier = lever_tier(lever, mm)
        affordable = not (posture == "throttle" and tier == models.DEEP)
        levers.append({
            "lever": lever,
            "agent": agent or "infra/skill",
            "evidence": evidence,
            "cost_tier": tier,
            "idle_ticks": idle,
            "suppressed": is_sup,
            "affordable": affordable,
        })
        if (lever != "instrumentation" and not is_sup and affordable
                and idle >= NEGLECT_IDLE_TICKS):
            neglected.append(lever)

    eligible_names = [l["lever"] for l in levers]

    # ---- ranked board + the single best pick (the per-tick anchor) ----------
    # `ranked_levers` is every eligible lever ordered high→low by priority so the
    # board is never an unordered pile. `top_lever` is the highest-priority lever
    # that's also affordable and not suppressed — the concrete default the
    # orchestrator anchors on every tick (not just when something's been
    # neglected, which is all `suggested_lever` covers). instrumentation wins
    # when broken because it's first in the priority list.
    ranked_levers = sorted(eligible_names, key=_priority)
    top_lever = next(
        (l["lever"] for l in sorted(levers, key=lambda x: _priority(x["lever"]))
         if l["affordable"] and not l["suppressed"]),
        None,
    )

    # impact_review override (v0.30, recommendation C). The plain priority order
    # ranks structural levers (harness_rewrite/new/mock/engine_swap) above
    # impact_review, so when both are eligible the structural lever wins on the
    # first plateau tick — correct. But if a structural lever already ran in the
    # last plateau tick AND impact_review is still eligible AND it hasn't been
    # taken since the last gain, swap top_lever to impact_review for this tick.
    # Also: when no structural candidate remains untried but impact_review is
    # eligible, ensure top_lever is impact_review.
    if "impact_review" in eligible_names and not any(
            l["suppressed"] for l in levers if l["lever"] == "impact_review"):
        _struct_untried = bool((ceiling or {}).get("untried_candidates"))
        # Did a structural lever run on the very last act-tick?
        _last_struct_tick = False
        for e in reversed(events):
            if e.get("event") != "tick" or int(e.get("ts") or 0) < enabled_at_ts:
                continue
            br = e.get("branch") or ""
            if br in ("wait", "sleep", ""):
                continue
            if br in ("harness", "harness_rewrite", "harness_new",
                      "mock_env", "engine_swap", "slot_engine"):
                _last_struct_tick = True
            break
        # affordability / suppression
        _ir_entry = next((l for l in levers if l["lever"] == "impact_review"), None)
        if _ir_entry and _ir_entry["affordable"] and not _ir_entry["suppressed"]:
            if not _struct_untried:
                top_lever = "impact_review"
            elif _last_struct_tick:
                top_lever = "impact_review"

    # ---- tunnel vision ------------------------------------------------------
    recent_families = []
    acted = 0
    for e in reversed(events):
        if e.get("event") != "tick" or int(e.get("ts") or 0) < enabled_at_ts:
            continue
        br = e.get("branch") or ""
        if br in ("wait", "sleep", ""):
            continue
        fam = BRANCH_LEVER.get(br, br)
        recent_families.append(fam)
        acted += 1
        if acted >= TUNNEL_WINDOW:
            break
    distinct = len(set(recent_families))
    tunnel_vision = (acted >= 3 and distinct <= DIVERSITY_FLOOR
                     and (len(neglected) >= 1 or len(eligible_names) >= 2))

    # highest-priority neglected lever to break the rut (throttle-aware).
    suggested = None
    for lever in SUGGEST_PRIORITY:
        if lever in neglected:
            suggested = lever
            break

    # ---- operator-supplied references (the creativity hook) ----------------
    references = _references(fuzz_dir, enabled_at_ts, now, state_dir=state_dir,
                             advisory=advisory_on)

    return {
        "non_exhaustive": True,
        "note": ("Floor, not ceiling: these are the levers detectable "
                 "deterministically. Also reason creatively beyond them — "
                 "fold in `references` (guidance.md / fuzz/docs) and invent "
                 "moves the catalog doesn't list."),
        "eligible_levers": levers,
        "eligible_count": len(levers),
        "ranked_levers": ranked_levers,
        "top_lever": top_lever,
        "neglected_levers": neglected,
        "recent_lever_families": list(reversed(recent_families)),
        "distinct_recent_families": distinct,
        "tunnel_vision": tunnel_vision,
        "suggested_lever": suggested,
        "references": references,
    }


def _references(fuzz_dir, enabled_at_ts, now, *, state_dir=None, advisory=True):
    """Surface operator steering AND already-built intel so the model re-reads it
    and reasons beyond the catalog. We report presence + recency, NOT contents —
    the orchestrator reads the files itself when prompted. `cve_patterns_md` is
    the CVE-review output (<state_dir>/cve-patterns.md; the campaign state dir,
    which FUZZ_STATE_DIR may move out of fuzz/): surfaced here so the model
    reads the patterns it already paid for instead of re-running `cve_refresh`.
    Omitted when advisory_lookup is off."""
    out = {"guidance_md": None, "cve_patterns_md": None, "docs": [],
           "changed_recently": False}
    g = os.path.join(fuzz_dir, "guidance.md")
    if os.path.exists(g):
        mt = _mtime(g)
        changed = mt >= enabled_at_ts
        out["guidance_md"] = {"path": "fuzz/guidance.md", "mtime": mt,
                              "changed_since_enable": changed}
        out["changed_recently"] = out["changed_recently"] or changed
    project_root = os.path.dirname(fuzz_dir)
    state_dir = str(state_dir) if state_dir is not None else os.path.join(fuzz_dir, "state")
    cve_md = os.path.join(state_dir, "cve-patterns.md")
    if advisory and os.path.exists(cve_md):
        mt = _mtime(cve_md)
        changed = mt >= enabled_at_ts
        out["cve_patterns_md"] = {
            "path": _display_path(cve_md, project_root), "mtime": mt,
            "changed_since_enable": changed,
            "note": "CVE-review output already built — read this instead of "
                    "re-dispatching cve_refresh."}
        out["changed_recently"] = out["changed_recently"] or changed
    docs_dir = os.path.join(fuzz_dir, "docs")
    if os.path.isdir(docs_dir):
        files = []
        for root, _, names in os.walk(docs_dir):
            for n in names:
                p = os.path.join(root, n)
                mt = _mtime(p)
                rel = os.path.relpath(p, project_root)   # e.g. "fuzz/docs/spec.md"
                files.append((mt, rel))
                if mt >= enabled_at_ts:
                    out["changed_recently"] = True
        files.sort(reverse=True)
        out["docs"] = [{"path": rel, "mtime": mt} for mt, rel in files[:12]]
    if out["guidance_md"] is None and not out["docs"]:
        out["hint"] = ("No operator steering found. fuzz/guidance.md and a "
                       "fuzz/docs/ dir, when present, are read for domain "
                       "knowledge and creative direction.")
    return out


def _display_path(path, project_root):
    """Project-relative (e.g. "fuzz/state/cve-patterns.md") when under the
    project root, else absolute."""
    ap, root = os.path.abspath(path), os.path.abspath(project_root)
    return os.path.relpath(ap, root) if ap.startswith(root + os.sep) else ap


def _full_config(state_dir):
    return _config.load(state_dir)


def compute_from_current(cur_path, *, posture="normal", suppressed=(), redundancy_threshold=None):
    """The lever board against a written current.json + its campaign state
    (the old toolbox_eval.py CLI)."""
    from cc_fuzzer_core.state.yolo_state import YoloSettings

    doc = _load_json(cur_path) or {}
    sd = os.path.dirname(os.path.abspath(cur_path))
    ys = YoloSettings.load(sd)
    events = _load_jsonl(os.path.join(sd, "events.jsonl"))
    findings = _load_jsonl(os.path.join(sd, "findings.jsonl"))
    return compute(sd, os.path.join(sd, "snapshots"), ys.block, doc, events, findings,
                   ys.int("enabled_at_ts"), posture, list(suppressed),
                   ys.int("redundancy_threshold") if redundancy_threshold is None else redundancy_threshold,
                   int(doc.get("now") or 0))
