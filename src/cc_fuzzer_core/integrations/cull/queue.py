"""Which candidates the model works on, in what order (recommendation 5).

cull ranks; it never filters. A candidate whose reachability nothing showed
(`none-found`) is in the list, ranked low, and presence is NOT reachability:
spending a model call on it before the reached candidates is spending it on
the least likely bug in the list. So:

    1. the reached candidates (`harness`, `indirect`, `unknown`: a cull that
       predates reachability) in cull's own rank order. cull's score already
       weighs whether attacker data reaches each one; sorting by tier first
       counted that twice and threw away the rest of its evidence. On the
       qualification runs it moved lcms' CPV from 816th to ~1,600th and
       sqlite3's from 375th to ~9,000th (tiers of 1,110 and 8,991
       candidates). The tier only breaks ties.
    2. `none-found` only once the reached tiers are exhausted (every one of
       them is in `done`), or while the budget left is at least
       cull.none_found_budget_floor (default 0.3)

`budget_remaining` is a fraction in [0, 1]; None means "not tracked", which
admits none-found only after the reached tiers.

Delta mode (`delta=True`) asks what the diff introduced. The reached
candidates nearest the change come first, by `diff_proximity`: in-diff,
changed-function, diff-flow, near-change, changed-file, then none; position
breaks ties, then tier. A held none-found candidate
is admitted anyway when its label is in-diff, changed-function or diff-flow:
the call graph that found no path misses edges, and the diff says the code
changed right there.
"""
from __future__ import annotations

from typing import Iterable, Mapping

from cc_fuzzer_core.integrations.cull import settings

REACHED = ("harness", "indirect", "unknown")
# diff_proximity labels, nearest the change first (cull.scoping's bands)
PROXIMITY = ("in-diff", "changed-function", "diff-flow", "near-change", "changed-file")
# a none-found candidate this near the change is admitted in delta mode
DELTA_ADMIT = ("in-diff", "changed-function", "diff-flow")


def proximity(c: Mapping) -> str | None:
    """A candidate's diff_proximity label ({label, hops} or a bare label)."""
    p = c.get("diff_proximity")
    label = p.get("label") if isinstance(p, Mapping) else p
    return label if label in PROXIMITY else None


def _band(c: Mapping) -> int:
    label = proximity(c)
    return PROXIMITY.index(label) if label else len(PROXIMITY)


def order(candidates: Iterable[Mapping], *, done: Iterable[str] = (),
          budget_remaining: float | None = None, config: Mapping | None = None,
          delta: bool = False) -> dict:
    """{"queue": [...], "held": [...], "reason": str} -- held are the
    none-found candidates not admitted yet."""
    floor = float(settings(config)["none_found_budget_floor"])
    done = set(done)
    cands = [c for c in candidates if c.get("candidate_id") not in done]
    def by_rank(c):
        tier = REACHED.index(c["reach_tier"]) if c.get("reach_tier") in REACHED else len(REACHED)
        return ((_band(c),) if delta else ()) + (c.get("position") or 10**9, tier)
    reached = sorted((c for c in cands if c.get("reach_tier") in REACHED), key=by_rank)
    none_found = sorted((c for c in cands if c.get("reach_tier") not in REACHED), key=by_rank)
    if not reached:
        why = "reached tiers exhausted"
        admit = True
    elif budget_remaining is not None and budget_remaining >= floor:
        why = f"budget remaining {budget_remaining:.2f} >= floor {floor:.2f}"
        admit = True
    else:
        why = (f"{len(reached)} reached candidate(s) left"
               + ("" if budget_remaining is None else
                  f"; budget remaining {budget_remaining:.2f} < floor {floor:.2f}"))
        admit = False
    if admit:
        return {"queue": reached + none_found, "held": [],
                "reason": "none-found admitted: " + why}
    near = [c for c in none_found if delta and proximity(c) in DELTA_ADMIT]
    held = [c for c in none_found if not (delta and proximity(c) in DELTA_ADMIT)]
    if near:
        why += f"; {len(near)} near the change admitted (delta)"
    return {"queue": reached + near, "held": held,
            "reason": "none-found held: " + why}
