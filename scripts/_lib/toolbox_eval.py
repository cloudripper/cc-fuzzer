#!/usr/bin/env python3
"""toolbox_eval.py — the deterministic *lever board* for dynamic YOLO.

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
import json
import os


# lever -> the model tier its dispatch costs (for throttle-aware suggestion).
COST_TIER = {
    "instrumentation":      "cheap",
    "coverage_reanalysis":  "sonnet",
    "seedgen":              "haiku",
    "concolic":             "haiku",
    "mutator":              "haiku",
    "dictionary":           "cheap",
    "harness_extend":       "sonnet",
    "cve_refresh":          "sonnet",
    "code_review":          "sonnet",
    "verification_fill":    "opus",
    "poc_build":            "opus",
    "poc_upgrade":          "opus",
    "plan_revise":          "opus",
    "slot_engine":          "cheap",
}

# lever -> the agent whose dispatch counts as "using" it (for idle tracking).
# File-backed levers (cve/code_review/dictionary/plan) track recency by mtime
# instead and are handled separately.
LEVER_AGENT = {
    "coverage_reanalysis":  "coverage-analyst",
    "seedgen":              "seed-generator",
    "concolic":             "concolic-executor",
    "mutator":              "mutator",
    "harness_extend":       "harness-writer",
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
    "refresh_cve":      "cve_refresh",
    "review":           "code_review",
    "poc":              "poc_build",
    "poc_upgrade":      "poc_upgrade",
    "plan_revise":      "plan_revise",
    "restart_fuzzer":   "instrumentation",
    "fix_instrumentation": "instrumentation",
}

# Suggestion priority when breaking tunnel vision (high → low).
SUGGEST_PRIORITY = [
    "instrumentation", "poc_build", "poc_upgrade", "verification_fill",
    "harness_extend", "coverage_reanalysis", "concolic", "seedgen", "mutator",
    "cve_refresh", "code_review", "plan_revise", "dictionary", "slot_engine",
]

NEGLECT_IDLE_TICKS = 3      # eligible + idle this many ticks ⇒ neglected
TUNNEL_WINDOW = 4           # look back this many act-ticks
DIVERSITY_FLOOR = 1         # ≤ this many distinct lever families ⇒ tunnel


def _load_jsonl(path):
    rows = []
    if not os.path.exists(path):
        return rows
    try:
        with open(path) as f:
            for line in f:
                line = line.strip()
                if line:
                    try:
                        rows.append(json.loads(line))
                    except Exception:
                        pass
    except Exception:
        pass
    return rows


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
            enabled_at_ts, posture, suppressed, redundancy_threshold, now):
    """Build the `evaluation.toolbox` block. Inputs are the same ones
    yolo_evaluate already has in hand, so this is cheap."""
    fuzz_dir = os.path.dirname(os.path.abspath(state_dir))   # .../fuzz
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
    weak_poc = [f for f in confirmed if _has_poc(f, fuzz_dir) and _weak_poc(f, n_conf)]

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

    # config gates
    full_cfg = _full_config(state_dir)
    cve_enabled = (full_cfg.get("cve") or {}).get("enabled", True)
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
        tier = COST_TIER.get(lever, "sonnet")
        levers.append({
            "lever": lever,
            "agent": agent or "infra/skill",
            "evidence": evidence,
            "cost_tier": tier,
            "idle_ticks": idle,
            "suppressed": is_sup,
        })
        affordable = not (posture == "throttle" and tier == "opus")
        if (lever != "instrumentation" and not is_sup and affordable
                and idle >= NEGLECT_IDLE_TICKS):
            neglected.append(lever)

    eligible_names = [l["lever"] for l in levers]

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
    references = _references(fuzz_dir, enabled_at_ts, now)

    return {
        "non_exhaustive": True,
        "note": ("Floor, not ceiling: these are the levers detectable "
                 "deterministically. Also reason creatively beyond them — "
                 "fold in `references` (guidance.md / fuzz/docs) and invent "
                 "moves the catalog doesn't list."),
        "eligible_levers": levers,
        "eligible_count": len(levers),
        "neglected_levers": neglected,
        "recent_lever_families": list(reversed(recent_families)),
        "distinct_recent_families": distinct,
        "tunnel_vision": tunnel_vision,
        "suggested_lever": suggested,
        "references": references,
    }


def _references(fuzz_dir, enabled_at_ts, now):
    """Surface operator steering AND already-built intel so the model re-reads it
    and reasons beyond the catalog. We report presence + recency, NOT contents —
    the orchestrator reads the files itself when prompted. `cve_patterns_md` is
    the CVE-review output (fuzz/state/cve-patterns.md): surfaced here so the model
    reads the patterns it already paid for instead of re-running `cve_refresh`."""
    out = {"guidance_md": None, "cve_patterns_md": None, "docs": [],
           "changed_recently": False}
    g = os.path.join(fuzz_dir, "guidance.md")
    if os.path.exists(g):
        mt = _mtime(g)
        changed = mt >= enabled_at_ts
        out["guidance_md"] = {"path": "fuzz/guidance.md", "mtime": mt,
                              "changed_since_enable": changed}
        out["changed_recently"] = out["changed_recently"] or changed
    cve_md = os.path.join(fuzz_dir, "state", "cve-patterns.md")
    if os.path.exists(cve_md):
        mt = _mtime(cve_md)
        changed = mt >= enabled_at_ts
        out["cve_patterns_md"] = {
            "path": "fuzz/state/cve-patterns.md", "mtime": mt,
            "changed_since_enable": changed,
            "note": "CVE-review output already built — read this instead of "
                    "re-dispatching cve_refresh."}
        out["changed_recently"] = out["changed_recently"] or changed
    docs_dir = os.path.join(fuzz_dir, "docs")
    project_root = os.path.dirname(fuzz_dir)
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


def _load_json(path):
    try:
        with open(path) as f:
            return json.load(f)
    except Exception:
        return None


def _full_config(state_dir):
    return _load_json(os.path.join(state_dir, "fuzz-config.json")) or {}


# CLI for testing.
if __name__ == "__main__":
    import sys
    cur = sys.argv[1]
    doc = _load_json(cur) or {}
    sd = os.path.dirname(os.path.abspath(cur))
    snaps = os.path.join(sd, "snapshots")
    cfg = (_full_config(sd).get("yolo") or {})
    events = _load_jsonl(os.path.join(sd, "events.jsonl"))
    findings = _load_jsonl(os.path.join(sd, "findings.jsonl"))
    out = compute(sd, snaps, cfg, doc, events, findings,
                  int(cfg.get("enabled_at_ts", 0)), "normal", [], 2,
                  int(doc.get("now") or 0))
    print(json.dumps(out, indent=2))
