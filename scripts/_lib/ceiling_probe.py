#!/usr/bin/env python3
"""ceiling_probe.py — the deterministic "is this a real coverage ceiling?" probe.

A coverage plateau is NOT the same thing as an exhausted target. The blunt
`no_progress` halt (compute_yolo_state) can only see "weighted_pct flat for N
ticks" — it cannot tell a genuinely-finished campaign from one whose *current
harness designs* simply can't reach the rest of the interesting surface. Left to
that signal alone, `self_loop` YOLO parks itself the moment it plateaus and
rationalizes it as a "structural ceiling," when the productive move is to RESHAPE
the harness (swap the entry function, add a new harness, mock a hostile peer) or
switch the engine (libFuzzer → AFL++/Redqueen) and keep going.

This module answers the question deterministically, with no LLM. It cross-references
the latest coverage snapshot's uncovered functions against:
  - gap reasons (esp. the new `harness_action` sub-classification),
  - code-review findings (high/medium confidence) still uncovered,
  - CVE hotspots still uncovered,
  - engine/gap-mix fit (checksum/format-barrier-heavy mix + cmplog inactive → Redqueen).
Every uncovered function with such a signal — minus anything the analyst proved
`dead` — becomes a `structural_candidate` with a concrete `suggested_action`.

It also computes the **escalation ladder stage** (centralised here so the
disposition layer and the halt layer agree byte-for-byte):

  stage 0  normal       coverage climbing, or flat < plateau_escalate_ticks
  stage 1  escalate      plateau AND an untried structural candidate exists
  stage 2  pre-consult   plateau, all candidates attempted, no consult yet
  stage 3  honest halt   plateau, candidates attempted, a consult already ran

`is_real_ceiling` is true only at stage 3 (or trivially when there is genuinely no
structural move and a pre-halt consult has already run). compute_yolo_state gates
the `no_progress` halt on stage 3; yolo_evaluate steers the disposition on stages
1/2. Both read this one block, so they never disagree.

Pure: `compute()` writes nothing. The CLI (`__main__`, via ceiling-probe.sh) writes
a `ceiling-probe/v1` snapshot for audit + the pre-halt consult briefing.
"""
from __future__ import annotations
import glob
import json
import os
import sys
from pathlib import Path

# SSOT for all state enums. Same sibling-import pattern as cve-context-builder.py.
sys.path.insert(0, str(Path(__file__).resolve().parent))
import enums  # type: ignore  # noqa: E402

# Non-default engines whose appearance in an event reason signals an engine-swap
# attempt (libFuzzer is the default, so a swap is toward any other ENGINES member).
_NON_DEFAULT_ENGINES = enums.ENGINES - {"libfuzzer"}


# Gap reasons that mean "a harness reshape can reach this" (not a seed/concolic move).
HARNESS_CLASS_REASONS = ("harness_gap", "state_precondition")
# Gap reasons whose density argues for AFL++/Redqueen (cmplog input-to-state).
REDQUEEN_FAVOURED_REASONS = (
    "checksum_barrier", "direct_compare", "deep_path_condition",
    "format_barrier", "value_constraint",
)
REDQUEEN_GAP_THRESHOLD = 3       # this many such gaps + cmplog inactive ⇒ recommend
# Action priority when picking the single best untried structural move (high→low).
# Specific gap-directed reshapes first; engine swap and broad signals after.
_ACTION_RANK = {
    "entry_swap": 0, "new_harness": 1, "mock": 2, "driver": 2,
    "extend": 3, "engine_swap": 4,
}
# Why-signal priority (used to break ties between candidates of equal action).
_WHY_RANK = {
    "gap_harness_action": 0, "code_review": 1, "cve_hotspot": 2,
    "uncovered_interesting": 3,
}


def _load(path):
    try:
        with open(path) as f:
            return json.load(f)
    except Exception:
        return None


def _latest(snaps_dir, kind, harness=None):
    """Newest `<kind>-[<harness>-]<ts>.json` in snaps_dir (lexical ts sort)."""
    if harness:
        files = sorted(glob.glob(os.path.join(snaps_dir, f"{kind}-{harness}-*.json")))
        if files:
            return files[-1]
    files = sorted(glob.glob(os.path.join(snaps_dir, f"{kind}-*.json")))
    return files[-1] if files else None


def _cand_key(c):
    """Identity of a candidate for attempted-set matching: '<action>:<entry>'."""
    return f"{c.get('suggested_action')}:{c.get('proposed_entry') or c.get('function') or ''}"


def _cand_sort_key(c):
    return (_ACTION_RANK.get(c.get("suggested_action"), 9),
            _WHY_RANK.get(c.get("why"), 9),
            c.get("function") or "")


def compute(state_dir, snaps_dir, doc, events, enabled_at_ts, gain_ts,
            ticks_since_gain, plateau_escalate_ticks, now=0):
    """Build the ceiling-probe block. Inputs are the same ones yolo_evaluate
    already has in hand (events, gain_ts, ticks_since_gain), so this is cheap and
    never re-reads the campaign from scratch."""
    doc = doc or {}
    harness = doc.get("active_harness")

    # ---- latest coverage snapshot: uncovered functions ----------------------
    cov_path = _latest(snaps_dir, "coverage", harness)
    cov = _load(cov_path) or {}
    uncovered = list(cov.get("top_unreached_functions") or [])
    current_engine = (cov.get("engine") or "libfuzzer").lower()

    # ---- latest gap report: reasons, harness_action, redqueen-favoured mix --
    gaps_path = _latest(snaps_dir, "gaps", harness)
    gaps_doc = _load(gaps_path) or {}
    gaps = gaps_doc.get("gaps") or []
    dead_funcs = {g.get("function") for g in gaps if g.get("reason") == "dead"}
    redqueen_gap_count = sum(1 for g in gaps if g.get("reason") in REDQUEEN_FAVOURED_REASONS)

    # ---- code-review findings (high/medium) still uncovered -----------------
    cr_path = _latest(snaps_dir, "code-review", harness) or _latest(snaps_dir, "code-review")
    cr_doc = _load(cr_path) or {}
    cr_by_func = {}
    for f in (cr_doc.get("findings") or []):
        if f.get("confidence") in ("high", "medium") and f.get("function"):
            cr_by_func.setdefault(f["function"], f)

    # ---- CVE hotspots -------------------------------------------------------
    cve_path = _latest(snaps_dir, "cve-context", harness) or _latest(snaps_dir, "cve-context")
    cve_doc = _load(cve_path) or {}
    hot = (cve_doc.get("hotspots") or {})
    cve_funcs = {h.get("name") for h in (hot.get("by_function") or []) if h.get("name")}
    for bf in (hot.get("by_file") or []):
        for fn in (bf.get("top_funcs") or []):
            cve_funcs.add(fn)

    # ---- engine / cmplog status --------------------------------------------
    hb = _load(os.path.join(state_dir, "harness-built.json")) or {}
    cmplog_active = bool(hb.get("cmplog_enabled"))

    # ---- assemble structural candidates ------------------------------------
    candidates = []
    seen = set()

    def _add(function, action, why, source_ref=None, proposed_entry=None,
             mock_target=None, engine_recommendation=None):
        c = {
            "function": function,
            "file": None,
            "why": why,
            "suggested_action": action,
            "proposed_entry": proposed_entry or (function if action != "engine_swap" else None),
            "mock_target": mock_target,
            "engine_recommendation": engine_recommendation,
            "source_ref": source_ref,
        }
        k = _cand_key(c)
        if k in seen:
            return
        seen.add(k)
        candidates.append(c)

    # (a) gaps the analyst directly tagged with a harness_action — most specific.
    for g in gaps:
        ha = g.get("harness_action")
        if ha:
            c = {
                "function": g.get("function"),
                "file": g.get("file"),
                "why": "gap_harness_action",
                "suggested_action": ha,
                "proposed_entry": g.get("proposed_entry") or g.get("function"),
                "mock_target": g.get("mock_target"),
                "engine_recommendation": None,
                "source_ref": g.get("id"),
            }
            k = _cand_key(c)
            if k not in seen:
                seen.add(k)
                candidates.append(c)
        elif g.get("reason") in HARNESS_CLASS_REASONS:
            # Back-compat: a harness-class gap with no harness_action still means
            # the current harness can't reach it. Default to 'extend' (cheapest);
            # the analyst is expected to refine to entry_swap/new_harness/mock.
            _add(g.get("function"), "extend", "gap_harness_action",
                 source_ref=g.get("id"))

    # (b) uncovered functions a reviewer flagged high/medium — reachable by
    #     pointing a harness at them (entry swap / new harness). Default entry_swap.
    for fn in uncovered:
        if fn in dead_funcs:
            continue
        if fn in cr_by_func:
            _add(fn, "entry_swap", "code_review", source_ref=cr_by_func[fn].get("id"))
        elif fn in cve_funcs:
            _add(fn, "entry_swap", "cve_hotspot")

    # (c) engine swap — a campaign-wide move, not tied to a function.
    engine_rec = None
    gap_mix_favors = None
    if (redqueen_gap_count >= REDQUEEN_GAP_THRESHOLD
            and current_engine == "libfuzzer" and not cmplog_active):
        engine_rec = "add_aflpp_cmplog_slot"
        gap_mix_favors = "redqueen"
        _add(None, "engine_swap", "gap_harness_action",
             source_ref="engine_fit", engine_recommendation=engine_rec)
    engine_fit = {
        "current_engine": current_engine,
        "cmplog_active": cmplog_active,
        "redqueen_favoured_gaps": redqueen_gap_count,
        "gap_mix_favors": gap_mix_favors,
        "recommendation": engine_rec,
        "rationale": (
            f"{redqueen_gap_count} checksum/format-barrier gap(s); engine "
            f"{current_engine}, cmplog {'on' if cmplog_active else 'off'}"
            if engine_rec else
            f"engine {current_engine}; gap mix does not favour an engine change"),
    }

    candidates.sort(key=_cand_sort_key)

    # ---- attempted-since-plateau (from events since the last coverage gain) -
    attempted_tokens = set()
    harness_writer_dispatches = 0
    engine_attempts = 0
    consult_since_plateau = False
    floor_ts = gain_ts or enabled_at_ts
    for e in events or []:
        if int(e.get("ts") or 0) < floor_ts:
            continue
        agent = e.get("agent_called") or e.get("agent") or ""
        branch = e.get("branch") or ""
        reason = e.get("reason") or ""
        if agent == "harness-writer":
            harness_writer_dispatches += 1
        if agent in ("planner-consult", "campaign-planner"):
            consult_since_plateau = True
        if branch in ("slot_engine", "restart_fuzzer") and \
                any(eng in reason.lower() for eng in _NON_DEFAULT_ENGINES):
            engine_attempts += 1
        # Precise attempt tags: reason="structural:<action>:<entry>".
        if reason.startswith("structural:"):
            attempted_tokens.add(reason[len("structural:"):])
            if reason.startswith("structural:engine_swap"):
                engine_attempts += 1

    def _attempted(c):
        if _cand_key(c) in attempted_tokens:
            return True
        if c.get("suggested_action") == "engine_swap":
            return engine_attempts > 0
        # Coarse fallback when no precise tag was recorded: if harness-writer has
        # been dispatched at least as many times as there are reshape candidates
        # since the plateau began, treat the reshape avenue as attempted.
        return False

    reshape_candidates = [c for c in candidates if c.get("suggested_action") != "engine_swap"]
    untried = [c for c in candidates if not _attempted(c)]
    # Coarse exhaustion: harness-writer ran ≥ (#reshape candidates) times since the
    # plateau and coverage still flat ⇒ the reshape avenue is spent even if tags
    # were not recorded precisely. Engine swap (if recommended+untried) survives this.
    if reshape_candidates and harness_writer_dispatches >= len(reshape_candidates):
        untried = [c for c in untried if c.get("suggested_action") == "engine_swap"
                   and engine_attempts == 0]
    attempted_since_plateau = sorted(
        _cand_key(c) for c in candidates if c not in untried)

    recommended = untried[0] if untried else None

    # ---- ladder stage (single source of truth) ------------------------------
    plateau_active = ticks_since_gain >= plateau_escalate_ticks
    if not plateau_active:
        stage = 0
    elif untried:
        stage = 1
    elif not consult_since_plateau:
        stage = 2
    else:
        stage = 3
    is_real_ceiling = stage == 3

    if stage == 0:
        summary = f"no plateau (flat {ticks_since_gain}/{plateau_escalate_ticks} ticks)"
    elif stage == 1:
        a = recommended or {}
        tgt = a.get("proposed_entry") or a.get("function") or a.get("engine_recommendation") or "?"
        summary = (f"plateau {ticks_since_gain} ticks: {len(untried)} untried "
                   f"structural move(s); next = {a.get('suggested_action')} → {tgt}")
    elif stage == 2:
        summary = ("plateau: structural candidates exhausted; force a pre-halt "
                   "consult before parking")
    else:
        summary = ("structural ceiling: candidates attempted and a consult already "
                   f"ran; coverage flat {ticks_since_gain} ticks — halt justified")

    return {
        "schema": "ceiling-probe/v1",
        "harness": harness,
        "plateau_active": plateau_active,
        "ladder_stage": stage,
        "is_real_ceiling": is_real_ceiling,
        "ticks_since_gain": ticks_since_gain,
        "plateau_escalate_ticks": plateau_escalate_ticks,
        "structural_candidates": candidates,
        "untried_candidates": untried,
        "recommended_structural": recommended,
        "attempted_since_plateau": attempted_since_plateau,
        "harness_writer_dispatches_since_plateau": harness_writer_dispatches,
        "consult_since_plateau": consult_since_plateau,
        "engine_fit": engine_fit,
        "dead_count": len(dead_funcs),
        "summary": summary,
    }


# ---- CLI: compute against a current.json + campaign state, write a snapshot ---
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


def _roundup_gain(snaps_dir, since_ts):
    """(gain_ts, ticks_since_gain) from tick-coverage roundups since since_ts —
    a small local copy of yolo_evaluate's logic so the CLI has no import cycle."""
    series = []
    for p in sorted(glob.glob(os.path.join(snaps_dir, "tick-coverage-*.json"))):
        d = _load(p)
        if not d or int(d.get("timestamp") or 0) < since_ts:
            continue
        pct = (d.get("overall") or {}).get("weighted_pct")
        if pct is not None:
            series.append((int(d.get("timestamp") or 0), float(pct)))
    gain_ts = since_ts
    for i in range(1, len(series)):
        if series[i][1] > series[i - 1][1]:
            gain_ts = series[i][0]
    ticks_since_gain = sum(1 for ts, _ in series if ts > gain_ts)
    return gain_ts, ticks_since_gain


if __name__ == "__main__":
    import sys
    import time
    cur_path = sys.argv[1]
    doc = _load(cur_path) or {}
    state_dir = os.path.dirname(os.path.abspath(cur_path))
    snaps_dir = os.path.join(state_dir, "snapshots")
    cfg = (_load(os.path.join(state_dir, "fuzz-config.json")) or {}).get("yolo") or {}
    enabled_at_ts = int(cfg.get("enabled_at_ts", 0))
    plateau_escalate_ticks = int(cfg.get("plateau_escalate_ticks", 8))
    events = _load_jsonl(os.path.join(state_dir, "events.jsonl"))
    gain_ts, ticks_since_gain = _roundup_gain(snaps_dir, enabled_at_ts)
    now = int(doc.get("now") or time.time())
    out = compute(state_dir, snaps_dir, doc, events, enabled_at_ts, gain_ts,
                  ticks_since_gain, plateau_escalate_ticks, now)
    ts = now
    os.makedirs(snaps_dir, exist_ok=True)
    out_ts = dict(out)
    out_ts["timestamp"] = ts
    dest = os.path.join(snaps_dir, f"ceiling-probe-{ts}.json")
    tmp = dest + ".tmp"
    with open(tmp, "w") as f:
        json.dump(out_ts, f, indent=2)
    os.replace(tmp, dest)
    print(json.dumps(out, indent=2))
    print(f"\nceiling-probe: stage {out['ladder_stage']} | "
          f"{out['summary']}\n  → {dest}", file=sys.stderr)
