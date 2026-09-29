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
"""
from __future__ import annotations

from typing import Iterable, Mapping

from cc_fuzzer_core.integrations.cull import settings

REACHED = ("harness", "indirect", "unknown")


def order(candidates: Iterable[Mapping], *, done: Iterable[str] = (),
          budget_remaining: float | None = None, config: Mapping | None = None) -> dict:
    """{"queue": [...], "held": [...], "reason": str} -- held are the
    none-found candidates not admitted yet."""
    floor = float(settings(config)["none_found_budget_floor"])
    done = set(done)
    cands = [c for c in candidates if c.get("candidate_id") not in done]
    by_rank = lambda c: (c.get("position") or 10**9)          # noqa: E731
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
    return {"queue": reached + (none_found if admit else []),
            "held": [] if admit else none_found,
            "reason": ("none-found admitted: " if admit else "none-found held: ") + why}
