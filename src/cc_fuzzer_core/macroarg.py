"""Function-like macro calls whose arguments are expressions (sweep class macro-arg).

A macro substitutes its arguments as text. `CHECKOVERFLOW(off, size, 6+8+4)`
looks like a bounds check of off against size - 18, but the macro's body
`(off > datasize - structsize)` expands to `size - 6+8+4`, which is size + 6:
the check passes inputs 24 bytes too long. On libexif delta-02 the agent read
the line, reached it with an input, and marked it "a pure refactor" of the
old check; it never expanded the macro (finals Q38).

    calls(line)                  ALL-CAPS function-like macro calls on a line
                                 with an argument that has a top-level binary
                                 operator: [(name, [args])]
    find_define(name, root, near)  the #define of name: the calling file first,
                                 then its directory, then headers under root
    check(params, body, args)    where an argument's operator binds looser than
                                 the operator next to its parameter in the body:
                                 ["`datasize - structsize` becomes `datasize - 6 + 8 + 4`"]
    expand(params, body, args)   the body with the arguments substituted

Text-level, no preprocessor: it reads one #define (with line continuations),
skips stringified (#p) and pasted (##) parameters, and treats a parameter
wrapped as `(p)` as safe. It decides nothing on its own: the sweep shows the
expansion and the precedence finding as evidence for the item's verdict.
"""
from __future__ import annotations

import os
import re
from pathlib import Path

# C binary operators by precedence (higher binds tighter)
_PREC = {"*": 13, "/": 13, "%": 13, "+": 12, "-": 12, "<<": 11, ">>": 11,
         "<": 10, "<=": 10, ">": 10, ">=": 10, "==": 9, "!=": 9, "&": 8, "^": 7, "|": 6,
         "&&": 5, "||": 4, "?": 3, ":": 3}
_TOKEN = re.compile(r"\s*(->|\+\+|--|<<=|>>=|<<|>>|<=|>=|==|!=|&&|\|\||[-+*/%<>&^|!~?:=,()\[\].]"
                    r"|\"(?:\\.|[^\"\\])*\"|'(?:\\.|[^'\\])*'|[A-Za-z_]\w*|\d[\w.]*|\S)")
_CALL = re.compile(r"\b([A-Z][A-Z0-9_]{2,})\s*\(")
_HEADER_EXT = (".h", ".hh", ".hpp", ".hxx", ".inc")
_SOURCE_EXT = (".c", ".cc", ".cpp", ".cxx") + _HEADER_EXT
MAX_FILES = 20000
MAX_BYTES = 2_000_000


def _tokens(s: str) -> list[str]:
    return [m.group(1) for m in _TOKEN.finditer(s)]


def _is_operand_end(tok: str) -> bool:
    """A token after which an operator is binary (an operand just ended)."""
    return bool(re.match(r"[\w\"']", tok)) or tok in (")", "]", "++", "--")


def _top_ops(toks: list[str]) -> list[str]:
    """Binary operators outside any parentheses or brackets."""
    depth, out, prev = 0, [], None
    for t in toks:
        if t in ("(", "["):
            depth += 1
        elif t in (")", "]"):
            depth -= 1
        elif depth == 0 and t in _PREC and prev is not None and _is_operand_end(prev):
            out.append(t)
        prev = t
    return out


def _split_args(s: str, start: int):
    """The top-level comma-separated arguments of the call whose '(' is at
    s[start]; None when the call does not close on this text."""
    depth, cur, args, i = 0, [], [], start
    while i < len(s):
        c = s[i]
        if c in "\"'":
            j = i + 1
            while j < len(s) and s[j] != c:
                j += 2 if s[j] == "\\" else 1
            cur.append(s[i:j + 1])
            i = j + 1
            continue
        if c in "([{":
            depth += 1
            if depth == 1:
                i += 1
                continue
        elif c in ")]}":
            depth -= 1
            if depth == 0:
                args.append("".join(cur).strip())
                return args
        elif c == "," and depth == 1:
            args.append("".join(cur).strip())
            cur = []
            i += 1
            continue
        cur.append(c)
        i += 1
    return None


def calls(line: str) -> list[tuple[str, list[str]]]:
    """ALL-CAPS function-like macro calls on `line` with at least one argument
    that has a top-level binary operator."""
    out = []
    # a macro name inside a string ("... WBT_FRAME_END (0x%x)") is not a call
    line = re.sub(r"\"(?:\\.|[^\"\\])*\"|'(?:\\.|[^'\\])*'", '""', line)
    for m in _CALL.finditer(line):
        args = _split_args(line, m.end() - 1)
        if args and any(_top_ops(_tokens(a)) for a in args):
            out.append((m.group(1), args))
    return out


def _define_in(text: str, name: str):
    """(params, body, line) of `#define name(params) body` in text, or None."""
    rx = re.compile(r"^[ \t]*#[ \t]*define[ \t]+" + re.escape(name) + r"\(([^)]*)\)((?:[^\n]*\\\n)*[^\n]*)",
                    re.M)
    m = rx.search(text)
    if not m:
        return None
    params = [p.strip() for p in re.sub(r"\\\n", " ", m.group(1)).split(",") if p.strip()]
    body = re.sub(r"\\\n", " ", m.group(2)).strip()
    body = re.sub(r"/\*.*?\*/|//.*$", " ", body).strip()
    return params, body, text.count("\n", 0, m.start()) + 1


def _read(p: Path) -> str:
    try:
        if p.stat().st_size > MAX_BYTES:
            return ""
        return p.read_text(errors="replace")
    except OSError:
        return ""


def repo_root(root, near: str) -> Path:
    """The tree a diff path `near` is relative to: root itself, or the one
    directory under it that holds the file (OSS-Fuzz: /src holds the
    project's repository, /src/<project>, beside its dependencies)."""
    root = Path(root)
    if not near or (root / near).is_file():
        return root
    try:
        subs = sorted(d for d in root.iterdir() if d.is_dir() and (d / near).is_file())
    except OSError:
        return root
    return subs[0] if len(subs) == 1 else root


def find_define(name: str, root, near: str = ""):
    """(params, body, relpath, line) of name's function-like #define: in the
    calling file `near` (relative to the repository under root, see
    repo_root) first, then its directory, then every header of that
    repository (at most MAX_FILES files). None if not found."""
    root = repo_root(root, near)
    seen = set()
    first = []
    if near:
        f = root / near
        first = [f] + sorted(p for p in f.parent.glob("*") if p.suffix in _SOURCE_EXT and p != f)
    for p in first:
        seen.add(p)
        d = _define_in(_read(p), name) if p.is_file() else None
        if d:
            return d[0], d[1], str(p.relative_to(root)), d[2]
    n = 0
    for dirpath, dirnames, files in os.walk(root):
        dirnames[:] = [d for d in dirnames if not d.startswith(".")]
        for fn in files:
            if not fn.endswith(_HEADER_EXT):
                continue
            n += 1
            if n > MAX_FILES:
                return None
            p = Path(dirpath) / fn
            if p in seen:
                continue
            text = _read(p)
            if name in text:
                d = _define_in(text, name)
                if d:
                    return d[0], d[1], str(p.relative_to(root)), d[2]
    return None


def _min_prec(ops: list[str]) -> int:
    return min(_PREC[o] for o in ops)


def check(params: list[str], body: str, args: list[str]) -> list[str]:
    """Each place an argument with a top-level operator is substituted where
    a neighbouring operator binds tighter (or, on the left, equally, unless
    both are + or both *): the expansion then groups differently than the
    call reads."""
    if len(params) != len(args):
        return []
    toks = _tokens(body)
    found = []
    for p, a in zip(params, args):
        ops = _top_ops(_tokens(a))
        if not ops:
            continue
        pa = _min_prec(ops)
        for i, t in enumerate(toks):
            if t != p:
                continue
            left = toks[i - 1] if i else None
            right = toks[i + 1] if i + 1 < len(toks) else None
            if left in ("#", "##") or right == "##":
                continue
            if left == "(" and right == ")":
                continue                                    # (p): safe
            bad = False
            if left in _PREC and i >= 2 and _is_operand_end(toks[i - 2]):     # binary on the left
                pl = _PREC[left]
                same_assoc = (left == "+" and set(ops) <= {"+"}) or (left == "*" and set(ops) <= {"*"})
                bad = pl > pa or (pl == pa and not same_assoc)
            elif left in ("-", "+", "!", "~", "*", "&") or (left == ")" and i >= 2 and toks[i - 2] != "("
                                                            and _is_cast(toks, i - 1)):
                bad = True                                  # unary operator or cast on the left
            if not bad and right in _PREC and right not in ("?", ":"):
                bad = _PREC[right] > pa
            if bad:
                lo, hi = _window(toks, i)
                ctx = toks[lo:hi]
                found.append(f"`{_join(ctx)}` becomes `{_join(ctx[:i - lo] + _tokens(a) + ctx[i - lo + 1:])}`")
    return found


def _window(toks: list[str], i: int) -> tuple[int, int]:
    """[lo, hi) around toks[i]: two tokens each side, widened left to open a
    cast or group it closes, with unmatched parentheses at the edges dropped."""
    lo, hi = max(0, i - 2), min(len(toks), i + 3)
    depth = 0
    for k in range(i - 1, lo - 1, -1):                  # a ')' before i opens further left
        depth += {")": 1, "(": -1}.get(toks[k], 0)
    while depth > 0 and lo > 0:
        lo -= 1
        depth += {")": 1, "(": -1}.get(toks[lo], 0)
    while lo < i and toks[lo] == "(" and toks[lo:i].count("(") > toks[lo:i].count(")"):
        lo += 1
    while hi > i + 1 and toks[hi - 1] == ")" and toks[i + 1:hi].count(")") > toks[i + 1:hi].count("("):
        hi -= 1
    return lo, hi


def _is_cast(toks: list[str], close: int) -> bool:
    """toks[close] is ')' ending a cast like (size_t) or (unsigned int)."""
    j = close - 1
    words = 0
    while j >= 0 and toks[j] != "(":
        if not re.match(r"[A-Za-z_]\w*$|\*$", toks[j]):
            return False
        words += 1
        j -= 1
    return j >= 0 and words > 0 and (j == 0 or not _is_operand_end(toks[j - 1]))


def _join(toks: list[str]) -> str:
    out = ""
    for t in toks:
        if out and not (t in (")", "]", ",", ".", "->") or out[-1] in "([.") and not out.endswith("->"):
            out += " "
        out += t
    return out


def expand(params: list[str], body: str, args: list[str]) -> str:
    """The body with each parameter replaced by its argument's text."""
    if len(params) != len(args):
        return body
    sub = dict(zip(params, args))
    return re.sub(r"[A-Za-z_]\w*", lambda m: sub.get(m.group(0), m.group(0)), body)
