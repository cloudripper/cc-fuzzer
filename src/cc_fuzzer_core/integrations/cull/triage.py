"""A model's first look at the head of the queue (finals Q87/Q88).

Static ranking ran out in full mode: three rounds of within-score features
moved the late CPVs later as often as earlier, because what tells a bug from
a decoy is whether the guard is there and right, which a feature only
proxies. A model reading each card and its function's source does better: on
the 16 full-mode survey benchmarks, the first 100 cards scored 0-10 in windows
of 10 by GLM-5.3-Flash (no tools, this prompt), of the 8 CPVs past place 30, 6
came into the first 30 (queue.triaged's rule); a repeat run held every high
score, and with the CPV's fix applied 4 of the 5 cards whose shown code the
fix changed scored lower.

This module builds the windows and parses the replies; it makes no model call
(the host does, through its own gateway). The scores only order the queue
(queue.order's `triage`): nothing is dropped, and nothing is fed back to cull.

    windows(queue, pool, source_root) -> [(card numbers, prompt text), ...]
    parse(reply, numbers)             -> {card number: score}
"""
from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Iterable, Mapping

from cc_fuzzer_core.integrations.cull import cards

PROMPT = """You triage static-analysis candidates for a fuzzing campaign on a C/C++ project.
Each candidate below is a card from the static analyser (a possible memory-safety or
undefined-behaviour sink, the call chain from the fuzz harness, input hints) followed
by the source of the function that holds it.

Give each candidate a preliminary score: how likely is it that some input from the
fuzz harness makes the program crash under AddressSanitizer or UndefinedBehaviorSanitizer
at or near this sink? Most candidates are false positives: the access is bounded by a
check, the values cannot come from the input, or the path is not reachable. Judge from
the code shown; you cannot run anything.

0 = clearly safe or unreachable, 3 = no visible guard but no reason to suspect it,
6 = a plausible missing or wrong check on input-derived values, 9-10 = a visible bug.

Reply with exactly one JSON object per line, one line per candidate, nothing else:
{"card": <number>, "score": <0-10>, "why": "<at most 20 words>"}

"""
# the function source shown with a card: whole when it fits, else its head
# and the lines around the sink
MAX_SOURCE_LINES = 160


def function_source(c: Mapping, source_root) -> str:
    sp = c.get("function_span") or {}
    a, b = sp.get("start") or sp.get("start_line"), sp.get("end") or sp.get("end_line")
    try:
        lines = (Path(source_root) / (c.get("path") or "")).read_text(errors="replace").splitlines()
    except (OSError, TypeError):
        return "(source not available)"
    if not (a and b):
        a, b = max(1, (c.get("line") or 1) - 40), (c.get("line") or 1) + 40
    rng = list(range(a, min(b, len(lines)) + 1))
    if len(rng) > MAX_SOURCE_LINES:
        s = c.get("line") or a
        rng = sorted(set(range(a, a + 6)) | set(range(max(a, s - 100), min(b, s + 54, len(lines)) + 1)))
    out, prev = [], None
    for n in rng:
        if prev is not None and n != prev + 1:
            out.append("   ...")
        out.append(f"{n:6d}  {lines[n - 1]}")
        prev = n
    return "\n".join(out)


def windows(queue: list, pool: Iterable[Mapping], source_root, *, size: int = 10,
            card_tokens: int = 300, max_hints: int = 8) -> list:
    """The queue's cards, numbered from 1 in queue order, in windows of `size`:
    [(numbers, prompt text)]. `pool`: every candidate (a card counts its
    function's others)."""
    by_fn: dict = {}
    for x in pool:
        if x.get("function"):
            by_fn.setdefault(x["function"], []).append(x)
    texts = []
    for i, c in enumerate(queue):
        sib = [x.get("line") for x in by_fn.get(c.get("function"), []) if x is not c]
        texts.append(f"### Candidate {i + 1}\n"
                     f"{cards.card(c, card_tokens, source_root=source_root, siblings=sib, max_hints=max_hints)}"
                     f"\n\nSource of {c.get('function')} ({c.get('path')}):\n```c\n"
                     f"{function_source(c, source_root)}\n```\n")
    out = []
    for s in range(0, len(queue), size):
        nums = list(range(s + 1, min(s + size, len(queue)) + 1))
        out.append((nums, PROMPT + "\n".join(texts[n - 1] for n in nums)))
    return out


def parse(reply: str, numbers: Iterable[int]) -> dict:
    """{card number: score in [0, 10]} for the numbers asked; anything else in
    the reply is ignored."""
    want, out = set(numbers), {}
    for m in re.finditer(r"\{[^{}]*\"card\"[^{}]*\}", reply or ""):
        try:
            o = json.loads(m.group(0))
            n, s = int(o["card"]), float(o["score"])
        except (ValueError, KeyError, TypeError):
            continue
        if n in want and 0 <= s <= 10:
            out[n] = s
    return out
