"""cull's input hints into a harness dictionary (recommendation 12).

When cull ships `input_hints` (a later wave), each candidate may carry
values an input needs to reach its sink: magic bytes, tags, keywords. They
join the harness's libFuzzer dictionary beside the cmplog one, deduplicated,
under a `# cull` comment. Until cull ships them there is nothing to merge
and this is a no-op.

Escaping is validated before anything is written: libFuzzer refuses the
WHOLE dictionary over one malformed line, so a hint that cannot be encoded
is dropped and reported, never written.
"""
from __future__ import annotations

import re
from pathlib import Path
from typing import Iterable, Mapping

_LINE = re.compile(r'^(?:[A-Za-z0-9_]+=)?"(?:[^"\\]|\\\\|\\"|\\x[0-9A-Fa-f]{2})*"$')


def encode(value) -> str:
    """A libFuzzer dictionary token for a str or bytes value."""
    data = value.encode("utf-8") if isinstance(value, str) else bytes(value)
    out = []
    for b in data:
        ch = chr(b)
        if ch == "\\":
            out.append("\\\\")
        elif ch == '"':
            out.append('\\"')
        elif 0x20 <= b < 0x7f:
            out.append(ch)
        else:
            out.append(f"\\x{b:02X}")
    return '"' + "".join(out) + '"'


def valid(line: str) -> bool:
    return bool(_LINE.match(line.strip()))


def _values(candidates: Iterable[Mapping]) -> list:
    vals = []
    for c in candidates:
        for h in c.get("input_hints") or []:
            v = h.get("value") if isinstance(h, Mapping) else h
            if isinstance(v, (str, bytes)) and v:
                vals.append(v)
    return vals


def merge(candidates: Iterable[Mapping], dict_path) -> dict:
    """Append the candidates' hints to `dict_path`; {added, skipped, invalid}."""
    p = Path(dict_path)
    existing = p.read_text().splitlines() if p.is_file() else []
    have = {ln.split("=", 1)[-1].strip() for ln in existing
            if ln.strip() and not ln.lstrip().startswith("#")}
    new, invalid, skipped = [], [], 0
    for v in _values(candidates):
        tok = encode(v)
        if not valid(tok):
            invalid.append(repr(v))
            continue
        if tok in have:
            skipped += 1
            continue
        have.add(tok)
        new.append(f"cull_{len(new) + 1}={tok}")
    if new:
        p.parent.mkdir(parents=True, exist_ok=True)
        block = ["# cull: input hints from the static candidates"] + new
        # every new line was validated above; existing lines are the file's own
        p.write_text("\n".join(existing + block) + "\n")
    return {"added": len(new), "skipped": skipped, "invalid": invalid, "path": str(p)}
