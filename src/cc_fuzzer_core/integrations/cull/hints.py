"""cull's input hints into a harness dictionary (recommendation 12).

From evidence 1.8.0 each candidate carries `input_hints`: values an input
needs to reach its sink (magic bytes, tags, keywords). They join the
harness's libFuzzer dictionary beside the cmplog one, deduplicated, under a
`# cull` comment. A cull older than 1.8.0 has none, and this is a no-op.

A token is built from the hint's `hex`, the exact bytes. `value` is only a
rendering of them: text when every byte is printable, else already escaped
the libFuzzer way (`"encoding": "escaped"`, `\\x89PNG`), which escaping
again would write as a backslash, `x`, `8`, `9`. A hint with no `hex` is
taken from `value` only when it is text; an escaped one is dropped.

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


def _bytes(h):
    """The hint's exact bytes, or None when they cannot be known."""
    if not isinstance(h, Mapping):
        return h if isinstance(h, (str, bytes)) and h else None
    if h.get("hex") is not None:
        try:
            return bytes.fromhex(str(h["hex"])) or None
        except ValueError:
            return None
    if h.get("encoding") == "escaped":
        return None
    v = h.get("value")
    return v if isinstance(v, (str, bytes)) and v else None


def _values(candidates: Iterable[Mapping]) -> tuple:
    """(values, dropped): each hint's bytes; dropped are the hints whose
    bytes cannot be known (escaped, no hex; or a malformed hex)."""
    vals, dropped = [], []
    for c in candidates:
        for h in c.get("input_hints") or []:
            v = _bytes(h)
            if v is None:
                dropped.append(repr(h.get("value") if isinstance(h, Mapping) else h))
            else:
                vals.append(v)
    return vals, dropped


def merge(candidates: Iterable[Mapping], dict_path) -> dict:
    """Append the candidates' hints to `dict_path`; {added, skipped, invalid}."""
    p = Path(dict_path)
    existing = p.read_text().splitlines() if p.is_file() else []
    have = {ln.split("=", 1)[-1].strip() for ln in existing
            if ln.strip() and not ln.lstrip().startswith("#")}
    new, skipped = [], 0
    values, invalid = _values(candidates)
    for v in values:
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
