"""Which candidates the model works on, in what order (recommendation 5).

cull ranks; it never filters. A candidate whose reachability nothing showed
(`none-found`) is in the list, ranked low, and presence is NOT reachability:
spending a model call on it before the reached candidates is spending it on
the least likely bug in the list. So:

    1. rank order within `harness`, then `indirect`, then `unknown`
       (`unknown`: a cull that predates reachability; ordered by rank alone)
    2. `none-found` only once the reached tiers are exhausted (every one of
       them is in `done`), or while the budget left is at least
       cull.none_found_budget_floor (default 0.3)

`budget_remaining` is a fraction in [0, 1]; None means "not tracked", which
admits none-found only after the reached tiers.

Delta mode (`delta=True`) asks what the diff introduced. Inside each tier
the candidates nearest the change come first, by `diff_proximity`: in-diff,
changed-function, diff-flow, near-change, changed-file, then none; position
breaks ties. No candidate moves between tiers. A held none-found candidate
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
    if delta:
        by_rank = lambda c: (_band(c), c.get("position") or 10**9)   # noqa: E731
    else:
        by_rank = lambda c: (c.get("position") or 10**9)             # noqa: E731
    reached = []
    for tier in REACHED:
        reached += sorted((c for c in cands if c.get("reach_tier") == tier), key=by_rank)
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
