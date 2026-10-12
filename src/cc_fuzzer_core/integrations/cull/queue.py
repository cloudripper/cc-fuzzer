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

Full scan (`delta=False`, cull.per_function, default on): the order is
spread over functions. Each function's best candidate comes first, in cull's
order; its further candidates only after every function has had one; and a
repeat of the same (function, line, family) under another path is dropped.
cull lists every sink line, so one function can fill the queue: sqlite3's
generated parser yy_reduce held the first ~25 places, and the model, ~10
cards a round, never got near the CPVs (places 365 and 460). Over the 35
full-mode CPVs cull has a candidate for, the median place goes 235 -> 71,
and none moves down (finals Q45).

Delta mode once the sweep is complete (`sweep_done`, cull.rare_after_sweep,
default on): the diff's lines all have a verdict, and what is left in delta
order is far from the diff in cull's order. The best candidate of each rare
class (a pattern with at most cull.rare_class_max candidates: a hang, a
lifetime, a null) goes first, once per class. file's ReDoS CPV is out of the
diff and was 88th; it becomes 2nd. Before the sweep completes, nothing moves.

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


def spread(queue: list, worked: set = frozenset()) -> list:
    """One candidate per function first (in the given order), then the rest;
    repeats of (function, line, family) under another path dropped. Functions
    in `worked` (a candidate of theirs is done) get no first place: the queue
    is rebuilt every round, and their next line must not crowd out a function
    no round has looked at."""
    seen, uniq = set(), []
    for c in queue:
        k = (c.get("function"), c.get("line"), c.get("family"))
        if c.get("function") and k in seen:
            continue
        seen.add(k)
        uniq.append(c)
    firsts, rest, fns = [], [], set()
    for c in uniq:
        fn = c.get("function")
        if fn and (fn in fns or fn in worked):
            rest.append(c)
        else:
            firsts.append(c)
            if fn:
                fns.add(fn)
    return firsts + rest


def rare_first(queue: list, all_candidates: list, done: set, max_size: int) -> list:
    """The best (cull position) candidate of each class with at most `max_size`
    candidates, first; once per class: a class with a done candidate is not
    lifted again (the queue is rebuilt every round)."""
    size: dict = {}
    for c in all_candidates:
        size[c.get("pattern")] = size.get(c.get("pattern"), 0) + 1
    worked = {c.get("pattern") for c in all_candidates if c.get("candidate_id") in done}
    firsts, seen = [], set()
    for c in sorted(queue, key=lambda c: c.get("position") or 10**9):
        p = c.get("pattern")
        if p and size.get(p, 0) <= max_size and p not in worked and p not in seen:
            seen.add(p)
            firsts.append(c)
    ids = {id(c) for c in firsts}
    return firsts + [c for c in queue if id(c) not in ids]


def order(candidates: Iterable[Mapping], *, done: Iterable[str] = (),
          budget_remaining: float | None = None, config: Mapping | None = None,
          delta: bool = False, sweep_done: bool = False) -> dict:
    """{"queue": [...], "held": [...], "reason": str} -- held are the
    none-found candidates not admitted yet."""
    st = settings(config)
    floor = float(st["none_found_budget_floor"])
    done = set(done)
    candidates = list(candidates)
    worked = {c.get("function") for c in candidates if c.get("candidate_id") in done and c.get("function")}
    cands = [c for c in candidates if c.get("candidate_id") not in done]
    def by_rank(c):
        tier = REACHED.index(c["reach_tier"]) if c.get("reach_tier") in REACHED else len(REACHED)
        return ((_band(c),) if delta else ()) + (c.get("position") or 10**9, tier)
    reached = sorted((c for c in cands if c.get("reach_tier") in REACHED), key=by_rank)
    none_found = sorted((c for c in cands if c.get("reach_tier") not in REACHED), key=by_rank)
    if not delta and st.get("per_function", True):
        reached, none_found = spread(reached, worked), spread(none_found, worked)
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
    lift = delta and sweep_done and st.get("rare_after_sweep", True)
    if admit:
        q = reached + none_found
        if lift:
            q = rare_first(q, candidates, done, int(st.get("rare_class_max", 25)))
        return {"queue": q, "held": [], "reason": "none-found admitted: " + why}
    near = [c for c in none_found if delta and proximity(c) in DELTA_ADMIT]
    held = [c for c in none_found if not (delta and proximity(c) in DELTA_ADMIT)]
    if near:
        why += f"; {len(near)} near the change admitted (delta)"
    q = reached + near
    if lift:
        q = rare_first(q, candidates, done, int(st.get("rare_class_max", 25)))
    return {"queue": q, "held": held, "reason": "none-found held: " + why}
