"""Candidate cards for a model's context, token-bounded (recommendation 7).

A card is what a seed generator, a mutator or a PoV builder needs to aim at
one candidate: why cull flagged it, how input gets there, where the sink is,
the guards on the way, and input hints when cull has them. Rendered from the
intake file, never by re-running cull.

Bounds: the top cull.cards_top_k candidates in queue order, each card cut to
cull.card_max_tokens, and the whole block to cull.cards_max_tokens. Tokens
are estimated at four characters each: the caps are a budget, not a promise
about a tokenizer.

A card should let the model triage without opening the file (finals Q46):
with `source_root` it shows the sink line itself; cull's phrasing for an
unsized access ("no comparison is possible: missing sink.dest_capacity", on 7
of sqlite3's first 10 cards) is said plainly; input hints keep the printable
words first and drop the second byte order of an integer (`\x00\x00\x00d` and
`d\x00\x00\x00`), and stop at cull.card_max_hints; with `pool` (the whole
queue) a card says how many more candidates its function has.
"""
from __future__ import annotations

import math
import re
from pathlib import Path
from typing import Iterable, Mapping

from cc_fuzzer_core.integrations.cull import settings

CHARS_PER_TOKEN = 4
ELLIPSIS = "…"


def tokens(text: str) -> int:
    return math.ceil(len(text) / CHARS_PER_TOKEN)


def _cut(text: str, max_tokens: int) -> str:
    limit = max_tokens * CHARS_PER_TOKEN
    return text if len(text) <= limit else text[:max(0, limit - 1)].rstrip() + ELLIPSIS


# cull's wording -> what it means for the reader
_PLAIN = ((re.compile(r"no comparison is possible: missing sink\.dest_capacity"),
           "cull could not determine the buffer size here, so nothing bounds this access in its "
           "analysis (a lead, not a measured overflow)"),)


def plain_why(why: str) -> str:
    for rx, text in _PLAIN:
        why = rx.sub(text, why)
    return why


def _hint_text(h) -> str:
    return str(h.get("value", h) if isinstance(h, Mapping) else h)


def hints(raw, limit: int) -> list:
    """Input hints, at most `limit`: text first, then integers the input
    reaches (cull's `tainted`), then the rest; an integer seen in the other
    byte order is dropped."""
    def rank(h):
        if not isinstance(h, Mapping):
            return (1, 1)
        return (0 if h.get("kind") != "int" and len(str(h.get("value", ""))) >= 2 else 1,
                0 if h.get("tainted") else 1)
    items = sorted(list(raw or []), key=rank)
    out, seen = [], set()
    for h in items:
        hx = (h.get("hex") or "") if isinstance(h, Mapping) else ""
        key = hx or _hint_text(h)
        if hx and len(hx) in (4, 8, 16):
            rev = "".join(reversed([hx[i:i + 2] for i in range(0, len(hx), 2)]))
            key = min(hx, rev)
        if key in seen:
            continue
        seen.add(key)
        out.append(_hint_text(h))
        if len(out) >= limit:
            break
    return out


def source_line(c: Mapping, root) -> str:
    """The candidate's line from the source tree ("" when unreadable)."""
    if not root or not c.get("path") or not c.get("line"):
        return ""
    try:
        lines = (Path(root) / str(c["path"])).read_text(errors="replace").splitlines()
        text = lines[int(c["line"]) - 1].strip()
    except (OSError, IndexError, ValueError):
        return ""
    return text[:200]


def card(c: Mapping, max_tokens: int, *, source_root=None, siblings: list | None = None,
         max_hints: int = 8) -> str:
    head = (f"### {c.get('function') or '?'} ({c.get('path')}:{c.get('line')}) "
            f"[{c.get('family')}, {c.get('tier') or c.get('verdict')}, reach {c.get('reach_tier')}, "
            f"id {c.get('candidate_id')}]")
    lines = [head]
    code = source_line(c, source_root)
    if code:
        lines.append(f"code: `{code}`")
    lines.append(f"why: {plain_why(c.get('why') or '-')}")
    if c.get("call_chain"):
        lines.append("path: " + " → ".join(c["call_chain"]))
    guards = [g.get("text") for g in c.get("guards") or [] if g.get("text")]
    if guards:
        lines.append("guards: " + "; ".join(guards))
    hs = hints(c.get("input_hints"), max_hints)
    if hs:
        lines.append("input hints: " + ", ".join(hs))
    if siblings:
        more = sorted({int(x) for x in siblings if x})[:8]
        lines.append(f"also in {c.get('function')}: {len(siblings)} more candidate(s)"
                     + (f", lines {', '.join(map(str, more))}" if more else ""))
    return _cut("\n".join(lines), max_tokens)


def render(candidates: Iterable[Mapping], *, config: Mapping | None = None,
           top_k: int | None = None, source_root=None, pool: Iterable[Mapping] | None = None) -> dict:
    """{"text", "cards", "tokens", "omitted"}. `source_root`: the tree the
    candidates' paths are relative to (cards then show the sink line); `pool`:
    the queue the cards came from (cards then count their function's others)."""
    cfg = settings(config)
    k = int(top_k if top_k is not None else cfg["cards_top_k"])
    per, total = int(cfg["card_max_tokens"]), int(cfg["cards_max_tokens"])
    max_hints = int(cfg.get("card_max_hints", 8))
    by_fn: dict = {}
    for c in pool or []:
        if c.get("function"):
            by_fn.setdefault(c["function"], []).append(c)
    header = "## Static candidates (cull)\n"
    out, used, shown = [header], tokens(header), 0
    cands = list(candidates)
    for c in cands[:k]:
        sib = [x.get("line") for x in by_fn.get(c.get("function"), [])
               if x.get("candidate_id") != c.get("candidate_id")] if pool is not None else None
        text = card(c, per, source_root=source_root, siblings=sib, max_hints=max_hints)
        cost = tokens(text) + 1
        if used + cost > total:
            break
        out.append(text)
        used += cost
        shown += 1
    return {"text": "\n\n".join(out).rstrip() + "\n", "cards": shown, "tokens": used,
            "omitted": len(cands) - shown}
