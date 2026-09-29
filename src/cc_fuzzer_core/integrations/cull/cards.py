"""Candidate cards for a model's context, token-bounded (recommendation 7).

A card is what a seed generator, a mutator or a PoV builder needs to aim at
one candidate: why cull flagged it, how input gets there, where the sink is,
the guards on the way, and input hints when cull has them. Rendered from the
intake file, never by re-running cull.

Bounds: the top cull.cards_top_k candidates in queue order, each card cut to
cull.card_max_tokens, and the whole block to cull.cards_max_tokens. Tokens
are estimated at four characters each: the caps are a budget, not a promise
about a tokenizer.
"""
from __future__ import annotations

import math
from typing import Iterable, Mapping

from cc_fuzzer_core.integrations.cull import settings

CHARS_PER_TOKEN = 4
ELLIPSIS = "…"


def tokens(text: str) -> int:
    return math.ceil(len(text) / CHARS_PER_TOKEN)


def _cut(text: str, max_tokens: int) -> str:
    limit = max_tokens * CHARS_PER_TOKEN
    return text if len(text) <= limit else text[:max(0, limit - 1)].rstrip() + ELLIPSIS


def card(c: Mapping, max_tokens: int) -> str:
    head = (f"### {c.get('function') or '?'} ({c.get('path')}:{c.get('line')}) "
            f"[{c.get('family')}, {c.get('tier') or c.get('verdict')}, reach {c.get('reach_tier')}, "
            f"id {c.get('candidate_id')}]")
    lines = [head, f"why: {c.get('why') or '-'}"]
    if c.get("call_chain"):
        lines.append("path: " + " → ".join(c["call_chain"]))
    guards = [g.get("text") for g in c.get("guards") or [] if g.get("text")]
    if guards:
        lines.append("guards: " + "; ".join(guards))
    if c.get("input_hints"):
        lines.append("input hints: " + ", ".join(str(h.get("value", h) if isinstance(h, Mapping)
                                                     else h) for h in c["input_hints"]))
    return _cut("\n".join(lines), max_tokens)


def render(candidates: Iterable[Mapping], *, config: Mapping | None = None,
           top_k: int | None = None) -> dict:
    """{"text", "cards", "tokens", "omitted"}."""
    cfg = settings(config)
    k = int(top_k if top_k is not None else cfg["cards_top_k"])
    per, total = int(cfg["card_max_tokens"]), int(cfg["cards_max_tokens"])
    header = "## Static candidates (cull)\n"
    out, used, shown = [header], tokens(header), 0
    cands = list(candidates)
    for c in cands[:k]:
        text = card(c, per)
        cost = tokens(text) + 1
        if used + cost > total:
            break
        out.append(text)
        used += cost
        shown += 1
    return {"text": "\n\n".join(out).rstrip() + "\n", "cards": shown, "tokens": used,
            "omitted": len(cands) - shown}
