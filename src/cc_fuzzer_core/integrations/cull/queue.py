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

Full scan, cull.entry_boost (default on): before the spread, a candidate's
place is cull's position divided by its boost, so cull's order holds wherever
the boost is equal (finals Q77). A short call chain from the harness counts:
(4 / max(length, 2)) ** 1.5, so a function two calls from the entry goes 2.8
times as early and one eight calls away 2.8 times as late. A chain into the
fuzzer's own harness code is not boosted. A candidate cull gives medium or
high confidence counts twice; the fixed-offset and ambiguous-capacity tiers
and CWE-690 count half. On the 16 full-mode survey benchmarks (38 CPVs with a
candidate) the CPVs in the first 30 places go 13 -> 16 and the geometric mean
of their first places 52 -> 37 (at worst x2.4); on the 38 delta databases in
full order (67 CPVs) the first 30 go 16 -> 19 and the first 10 6 -> 8.

Delta mode once the sweep is complete (`sweep_done`, cull.rare_after_sweep,
default on): the diff's lines all have a verdict, and what is left in delta
order is far from the diff in cull's order. The best candidate of each rare
class (a pattern with at most cull.rare_class_max candidates: a hang, a
lifetime, a null) goes first, once per class. file's ReDoS CPV is out of the
diff and was 88th; it becomes 2nd. Before the sweep completes, nothing moves.

Triage (`triage`: {candidate_id: score 0-10}, a model's first look at the
head of the queue, cull.triage): a card scored cull.triage_promote (6) or more
goes first, highest score first; one scored cull.triage_demote (0) or less goes
behind the last card that was scored; every other card keeps its place. On the
16 full-mode survey benchmarks (first 100 cards scored by GLM-5.3-Flash, 24 CPVs
with a card there) the CPVs in the first 30 go 16 -> 19, the median place
17 -> 8.5, 14 earlier and 3 later; of the 8 CPVs past place 30, 6 come into the
first 30 (finals Q88). Promotion alone moves nothing later by more than 2
places but brings in only 3 of the 8; the rest come from the demotion, which
also costs the one large loss (a CPV card scored 0, 52 places). An unscored
card is not moved, so a failed or partial triage leaves cull's order.

Delta mode (`delta=True`) asks what the diff introduced. The reached
candidates nearest the change come first, by `diff_proximity`: in-diff,
changed-function, diff-flow, near-change, changed-file, then none; position
breaks ties, then tier. Inside each band the order is spread over functions
(cull.delta_spread, default on), as a full scan is over the whole queue: a
large diff puts a thousand in-diff lines in a few functions, and a CPV in
another changed function sat behind them (median 170 cards ahead, 50
functions). On the 38 delta databases (70 CPVs, cull 0.4.4 reranked with each
task's diff) the CPVs worked within 3 rounds of 10 cards go 49 -> 56, within
10 rounds 56 -> 61, past round 300 2 -> 0; 22 earlier, none later (finals
Q85). The bands keep their order. A held none-found candidate
is admitted anyway when its label is in-diff, changed-function or diff-flow:
the call graph that found no path misses edges, and the diff says the code
changed right there.
"""
from __future__ import annotations

from itertools import groupby
from typing import Iterable, Mapping

from cc_fuzzer_core.integrations.cull import settings

REACHED = ("harness", "indirect", "unknown")
# diff_proximity labels, nearest the change first (cull.scoping's bands)
PROXIMITY = ("in-diff", "changed-function", "diff-flow", "near-change", "changed-file")
# a none-found candidate this near the change is admitted in delta mode
DELTA_ADMIT = ("in-diff", "changed-function", "diff-flow")
# full scan, cull.entry_boost: tiers whose candidates sat ahead of the CPVs far
# more often than on them (finals Q77)
WEAK_TIERS = ("fixed-offset", "ambiguous-capacity")


def proximity(c: Mapping) -> str | None:
    """A candidate's diff_proximity label ({label, hops} or a bare label)."""
    p = c.get("diff_proximity")
    label = p.get("label") if isinstance(p, Mapping) else p
    return label if label in PROXIMITY else None


def _band(c: Mapping) -> int:
    label = proximity(c)
    return PROXIMITY.index(label) if label else len(PROXIMITY)


def boost(c: Mapping) -> float:
    """How many times earlier than cull's position a full-scan candidate goes."""
    m = 1.0
    n = len(c.get("call_chain") or [])
    if n and "fuzz" not in (c.get("path") or "").lower():
        m *= (4 / max(n, 2)) ** 1.5
    if c.get("confidence") in ("medium", "high"):
        m *= 2
    if c.get("tier") in WEAK_TIERS or c.get("family") == "CWE-690":
        m *= 0.5
    return m


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


def band_spread(queue: list, worked: set = frozenset()) -> list:
    """Delta mode: `spread` inside each diff band of a queue in band order;
    the bands keep their order."""
    out: list = []
    for _, grp in groupby(queue, key=_band):
        out += spread(list(grp), worked)
    return out


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


def triaged(queue: list, scores: Mapping, promote: float = 6, demote: float = 0) -> list:
    """Order by a first look (`scores`: candidate_id -> 0-10): promoted cards
    first (highest score, then queue order), demoted ones behind the last
    scored card, the rest in place."""
    def score(c):
        return scores.get(c.get("candidate_id"))
    scored = [i for i, c in enumerate(queue) if score(c) is not None]
    if not scored:
        return list(queue)
    end = scored[-1]
    up = sorted((c for c in queue if (score(c) if score(c) is not None else -1) >= promote),
                key=lambda c: -score(c))
    down = [c for c in queue[:end + 1] if score(c) is not None and score(c) <= demote]
    moved = {id(c) for c in up} | {id(c) for c in down}
    keep = [c for c in queue[:end + 1] if id(c) not in moved]
    return up + keep + down + [c for c in queue[end + 1:] if id(c) not in moved]


def order(candidates: Iterable[Mapping], *, done: Iterable[str] = (),
          budget_remaining: float | None = None, config: Mapping | None = None,
          delta: bool = False, sweep_done: bool = False,
          triage: Mapping | None = None) -> dict:
    """{"queue": [...], "held": [...], "reason": str} -- held are the
    none-found candidates not admitted yet."""
    st = settings(config)
    floor = float(st["none_found_budget_floor"])
    done = set(done)
    candidates = list(candidates)
    worked = {c.get("function") for c in candidates if c.get("candidate_id") in done and c.get("function")}
    cands = [c for c in candidates if c.get("candidate_id") not in done]
    boosted = not delta and st.get("entry_boost", True)
    def by_rank(c):
        tier = REACHED.index(c["reach_tier"]) if c.get("reach_tier") in REACHED else len(REACHED)
        pos = c.get("position")
        pos = (pos / boost(c) if boosted else pos) if pos else 10**9
        return ((_band(c),) if delta else ()) + (pos, tier)
    reached = sorted((c for c in cands if c.get("reach_tier") in REACHED), key=by_rank)
    none_found = sorted((c for c in cands if c.get("reach_tier") not in REACHED), key=by_rank)
    if not delta and st.get("per_function", True):
        reached, none_found = spread(reached, worked), spread(none_found, worked)
    elif delta and st.get("delta_spread", True):
        reached, none_found = band_spread(reached, worked), band_spread(none_found, worked)
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
    first_look = triage if triage and st.get("triage", True) else None
    def looked(q):
        return (triaged(q, first_look, float(st.get("triage_promote", 6)),
                        float(st.get("triage_demote", 0))) if first_look else q)
    if admit:
        q = looked(reached + none_found)
        if lift:
            q = rare_first(q, candidates, done, int(st.get("rare_class_max", 25)))
        return {"queue": q, "held": [], "reason": "none-found admitted: " + why}
    near = [c for c in none_found if delta and proximity(c) in DELTA_ADMIT]
    held = [c for c in none_found if not (delta and proximity(c) in DELTA_ADMIT)]
    if near:
        why += f"; {len(near)} near the change admitted (delta)"
    q = looked(reached + near)
    if lift:
        q = rare_first(q, candidates, done, int(st.get("rare_class_max", 25)))
    return {"queue": q, "held": held, "reason": "none-found held: " + why}
