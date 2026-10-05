"""Delta sweep: every risky line a diff changed gets a verdict (delta-sweep/v1).

A delta that plants a bug is reviewed by a model that reads it, finds the
first suspicious call, and chases that. When the diff holds several flaws the
one that is scored can go unexamined: on a qualification delta the planted
format string sat in the same added block as an over-read the agent crashed
on, and it was never classified. The sweep turns the diff into a checklist
and refuses to let the work end while an item has no verdict.

    init(diff)       one item per changed line that looks like a sink (below),
                     plus one per hunk that has none; hunks in files that are
                     not C/C++ source (docs, build files, tests) are closed
                     as `not-code` up front
    mark(id, ...)    a verdict with a reason; `crash` and `reached` must name
                     an input file that exists (the evidence that it was run)
    gate(...)        the Stop-hook check: open items block the end of the
                     turn, with the list, at most MAX_BLOCKS times, and only
                     again after progress (Claude Code's own advice is to let
                     a turn end once stop_hook_active is set; it overrides a
                     hook after 8 consecutive blocks)

Sink classes are generic C/C++ shapes, matched on added lines, one item per
line with every class it matches: format-string (a printf-family call with no
string literal among its arguments; a project's own wrappers count when the
diff shows them taking a literal elsewhere, see format_wrappers), copy (incl.
*_copy/*_cpy wrappers), alloc-size and alloc (a computed or constant size),
ptr-arith, len-arith (a length or offset accumulated in place), index and
index-write, scan (strlen/strchr-style reads that need a terminator), div,
cast-deref, eq-bound (a counter compared for equality with a limit),
int-type, free (incl. *_free wrappers), abort, loop. Two more come from the
diff's shape: const-change (an added line equal to a removed one but for
its numbers: a bound or size moved) and removed-check (a removed guard,
comparison or length computation: deleting it can make unchanged code below
vulnerable, so the deletion is the item). They pick what to look at; they
decide nothing.

Measured against the ground truth of 47 delta benchmarks (79 CPVs): an item
sits on the vulnerable line of 64, within a line of 67, and on the removed
guard that causes 3 more. The rest are deltas that make existing code
reachable rather than change it, which no line checklist can point at.

CLI: `cc-fuzzer sweep init|show|mark|gate [--file F]`. The file defaults to
$CC_FUZZER_SWEEP_FILE, else <state>/delta-sweep.json in the campaign.
"""
from __future__ import annotations

import json
import os
import re
import sys
import time
from pathlib import Path

from cc_fuzzer_core import delta as _delta

SCHEMA = "delta-sweep/v1"
FILENAME = "delta-sweep.json"
MAX_BLOCKS = 3
SHOW_LIMIT = 25

VERDICTS = {
    "crash": "an input reached it and crashed (give --input)",
    "reached": "an input reached it and did not crash (give --input)",
    "unreachable": "the harness cannot reach it, and why",
    "safe": "reachable, but bounded or checked, and why",
}
CLOSED = ("not-code",)          # set by init, never by mark
MIN_REASON = 12

_CODE_EXT = (".c", ".cc", ".cpp", ".cxx", ".h", ".hh", ".hpp", ".hxx", ".inc", ".ipp")
_NOT_SOURCE_DIR = re.compile(r"(^|/)(tests?|testing|docs?|examples?|fuzz(ing)?|ci|\.github)/")

_INT_TYPE = (r"(?:unsigned|signed|short|long|int|char|size_t|ssize_t|off_t|ptrdiff_t|"
             r"u?int(?:8|16|32|64)_t|u?intptr_t|U?INT(?:8|16|32|64)|BYTE|WORD|DWORD|UINT)")
_SINKS = (
    ("format-string", re.compile(r"\b(\w*printf\w*|syslog|vsyslog)\s*\(([^;]*)")),
    ("copy", re.compile(r"\b(memcpy|memmove|strcpy|strncpy|strcat|strncat|stpcpy|wcscpy|gets|"
                        r"sprintf|vsprintf|bcopy|CopyMemory|\w*_(?:copy|cpy|memcpy|move))\s*\(")),
    ("alloc-size", re.compile(r"\b(malloc|calloc|realloc|reallocarray|alloca|new\s*\w+\s*\[|"
                              r"\w*_(?:alloc|malloc|calloc|realloc))\s*\(?[^;]*[-+*/<>]")),
    ("alloc", re.compile(r"\b(\w*_(?:alloc|malloc|calloc)|alloca)\s*\(\s*[A-Z_][A-Z0-9_]*\s*[,)]")),
    ("len-arith", re.compile(r"\b\w*(?:len|size|sz|count|cnt|num|off|offset|pos|idx|total)\w*"
                             r"\s*(?:[-+*]=|<<=)", re.I)),
    ("div", re.compile(r"[^/*\s]\s*[/%]\s*\(?\s*[A-Za-z_][\w.>-]*")),
    ("cast-deref", re.compile(r"\*\s*\(\s*[A-Za-z_][\w\s]*\*+\s*\)")),
    # a counter or index compared for equality with a limit: an off-by-one shape
    ("eq-bound", re.compile(r"(\+\+|--)\s*[A-Za-z_][\w.>-]*\s*[!=]=|[!=]=\s*[\w.>-]*(?:max|limit|cap)\w*",
                            re.I)),
    ("abort", re.compile(r"\b(abort|assert|__builtin_trap|__builtin_unreachable)\s*\(")),
    ("index-write", re.compile(r"\w\s*\[\s*[A-Za-z_][\w.>-]*\s*\]\s*=[^=]")),
    ("ptr-arith", re.compile(r"[(,]\s*[A-Za-z_]\w*(?:(?:->|\.)\w+)*\s*[+-](?![>=+-])\s*[^,;)]*\w")),
    ("index", re.compile(r"\w\s*\[[^\]]*[-+*/][^\]]*\]")),
    ("scan", re.compile(r"\b(strlen|strnlen|strchr|strrchr|strstr|strtok|strcmp|strncmp|strcasecmp|"
                        r"strspn|strcspn|strpbrk|sscanf|atoi|atol|strtol|strtoul)\s*\(")),
    ("int-type", re.compile(r"(^|[;{(,]\s*)(const\s+)?" + _INT_TYPE + r"\b\s+\w+\s*[=;,)\[]"
                            r"|\(\s*" + _INT_TYPE + r"\s*\)")),
    ("free", re.compile(r"\b(free|realloc|delete\b|\w*_free\w*)\s*[\(\[]?")),
    ("loop", re.compile(r"\b(for|while)\s*\(")),
)


class SweepError(ValueError):
    pass


def _is_code(path: str) -> bool:
    return path.lower().endswith(_CODE_EXT) and not _NOT_SOURCE_DIR.search(path)


def _has_literal(args: str) -> bool:
    return '"' in args


_WRAPPER_CALL_RE = re.compile(r"\b([A-Za-z_]\w{2,}f)\s*\(([^;]*)")


def format_wrappers(diff_text: str) -> set:
    """Project printf wrappers the diff itself reveals: functions named *f
    (sendf, logf, errorf ...) called somewhere in the diff, added or context
    lines, with a string literal argument. A call to one with no literal is
    then a format-string candidate like printf(buf)."""
    out = set()
    for raw in diff_text.split("\n"):
        if raw[:1] in ("+", " ") and not raw.startswith("+++"):
            for m in _WRAPPER_CALL_RE.finditer(raw):
                if _has_literal(m.group(2)) and not m.group(1).endswith("printf"):
                    out.add(m.group(1))
    return out - {"sizeof", "if"}


def _is_comment(line: str) -> bool:
    s = line.strip()
    return not s or s.startswith(("//", "/*")) or bool(re.match(r"\*(\s|/|$)", s))


def sinks_of(line: str, wrappers: frozenset | set = frozenset()) -> list[str]:
    """The sink classes an added source line matches (none for comments)."""
    s = line.strip()
    if not s or s.startswith(("//", "/*", "#include")) or re.match(r"\*(\s|/|$)", s):
        return []
    found = []
    for cls, rx in _SINKS:
        m = rx.search(s)
        if cls == "format-string" and not m and wrappers:
            m = next((w for w in _WRAPPER_CALL_RE.finditer(s) if w.group(1) in wrappers), None)
        if not m:
            continue
        # a literal anywhere in the call, or a call that goes on to the next
        # line (its format may be there): not judged from this line
        if cls == "format-string" and (_has_literal(m.group(2)) or ")" not in m.group(2)):
            continue
        if cls == "free" and not re.search(r"\b(free|realloc|\w*_free\w*)\s*\(|\bdelete\b", s):
            continue
        if cls == "div" and re.search(r"//|/\*|#include|\"[^\"]*[/%][^\"]*\"", s):
            continue            # a comment, a path or a format string, not a division
        found.append(cls)
    return found


# A removed line that was a guard: deleting it can make unchanged code below
# vulnerable, so the deletion itself is an item.
_CHECK_RE = re.compile(r"\b(if|while)\s*\(|\b[A-Z_]*CHECK\w*\s*\(|\bassert\s*\(|\b(memcmp|strn?cmp)\s*\("
                       r"|[<>]=?|[!=]=|\b\w*(?:len|size|count)\w*\s*[-+*/]?=[^=]", re.I)


def _norm(line: str) -> str:
    return re.sub(r"\s+", "", line)


def _hunks(diff_text: str):
    """(path, new_start, new_count, context, [(tag, new_line, text)]) per hunk;
    tag is '+', '-' (new_line = where the removal sits) or ' '."""
    path, hunk, new_line = None, None, 0
    for raw in diff_text.split("\n"):
        if raw.startswith("+++ "):
            p = raw[4:].split("\t")[0]
            path = None if p == "/dev/null" else (p[2:] if p.startswith("b/") else p)
            hunk = None
            continue
        if raw.startswith("--- ") or raw.startswith("diff --git"):
            hunk = None
            continue
        m = re.match(r"^@@ -\d+(?:,\d+)? \+(\d+)(?:,(\d+))? @@(.*)$", raw)
        if m and path:
            new_line = int(m.group(1))
            count = int(m.group(2)) if m.group(2) is not None else 1
            hunk = (path, new_line, count, m.group(3).strip() or None, [])
            yield hunk
            continue
        if hunk is None:
            continue
        if raw.startswith("+"):
            hunk[4].append(("+", new_line, raw[1:]))
            new_line += 1
        elif raw.startswith("-"):
            hunk[4].append(("-", new_line, raw[1:]))
        elif raw.startswith(" "):
            new_line += 1


def build(diff_text: str, *, source: str = "") -> dict:
    """The checklist for a diff (git or plain unified)."""
    items = []
    wrappers = format_wrappers(diff_text)
    for n, (path, start, count, ctx, lines) in enumerate(list(_hunks(diff_text)), 1):
        it = {"id": f"h{n}", "file": path, "lines": [start, start + max(count - 1, 0)],
              "function": ctx, "sinks": []}
        added = {_norm(t) for tag, _, t in lines if tag == "+"}
        removed_digits = {re.sub(r"\d+", "N", _norm(t)) for tag, _, t in lines if tag == "-"}
        found = []                                  # (line, classes, text)
        for tag, ln, text in lines:
            if tag == "+":
                classes = sinks_of(text, wrappers)
                # the same line with only a number changed: a bound or size moved
                if (classes or not _is_comment(text)) and (re.search(r"\d", text) and re.sub(r"\d+", "N", _norm(text)) in removed_digits
                        and _norm(text) not in {_norm(t) for g, _, t in lines if g == "-"}):
                    classes = classes + ["const-change"]
                if classes:
                    found.append((ln, classes, text.strip()))
            elif tag == "-" and _norm(text) not in added and _CHECK_RE.search(text) \
                    and not text.strip().startswith(("//", "/*", "*")):
                found.append((ln, ["removed-check"], "removed: " + text.strip()))
        for k, (ln, classes, text) in enumerate(found, 1):
            it["sinks"].append({"id": f"{it['id']}.s{k}", "line": ln, "class": classes[0],
                                "classes": classes, "text": text[:160]})
        items.append(it)
    verdicts = {}
    for it in items:
        if not _is_code(it["file"]):
            verdicts[it["id"]] = {"verdict": "not-code", "reason": "not C/C++ source", "ts": 0}
    return {"schema": SCHEMA, "source": source, "created": int(time.time()),
            "items": items, "verdicts": verdicts, "gate": {"blocks": 0, "open_at_block": None}}


def required(doc: dict) -> list[dict]:
    """What needs a verdict: each sink of a code hunk, or the hunk itself
    when it has none. A closed hunk closes its sinks."""
    out = []
    for it in doc["items"]:
        if doc["verdicts"].get(it["id"], {}).get("verdict") in CLOSED:
            continue
        if it["sinks"]:
            out += [{**s, "file": it["file"], "function": it["function"], "hunk": it["id"]}
                    for s in it["sinks"]]
        else:
            out.append({"id": it["id"], "line": it["lines"][0], "class": "hunk",
                        "text": f"lines {it['lines'][0]}-{it['lines'][1]}", "file": it["file"],
                        "function": it["function"], "hunk": it["id"]})
    return out


def open_items(doc: dict) -> list[dict]:
    return [r for r in required(doc) if r["id"] not in doc["verdicts"]]


# sinks most often planted first, so the list shows them before loops
_ORDER = {c: i + 2 for i, (c, _) in enumerate(_SINKS)}
_ORDER.update({"format-string": 0, "removed-check": 1, "const-change": 1, "hunk": len(_ORDER) + 2})


def show(doc: dict, *, limit: int = SHOW_LIMIT) -> str:
    req, opn = required(doc), open_items(doc)
    lines = [f"delta sweep: {len(req) - len(opn)}/{len(req)} items have a verdict"]
    for r in sorted(opn, key=lambda r: (_ORDER.get(r["class"], 99), r["file"], r["line"]))[:limit]:
        where = f"{r['file']}:{r['line']}"
        cls = ",".join(r.get("classes") or [r["class"]])
        lines.append(f"  {r['id']:<8} {cls:<22} {where}  {r['text']}")
    if len(opn) > limit:
        lines.append(f"  ... and {len(opn) - limit} more")
    if opn:
        lines.append("Record each: cc-fuzzer sweep mark <id> <" + "|".join(VERDICTS) +
                     "> \"<why>\" [--input <file>]")
    return "\n".join(lines)


def mark(doc: dict, item: str, verdict: str, reason: str, *, input_path: str = "") -> dict:
    ids = {r["id"] for r in required(doc)} | {it["id"] for it in doc["items"]}
    if item not in ids:
        raise SweepError(f"no sweep item {item!r} (see `cc-fuzzer sweep show`)")
    if verdict not in VERDICTS:
        raise SweepError(f"verdict must be one of {', '.join(VERDICTS)}")
    if len(reason.strip()) < MIN_REASON:
        raise SweepError(f"give a reason of at least {MIN_REASON} characters: {VERDICTS[verdict]}")
    if verdict in ("crash", "reached"):
        if not input_path or not Path(input_path).is_file():
            raise SweepError(f"`{verdict}` needs --input <file> naming the input you ran")
    rec = {"verdict": verdict, "reason": reason.strip()[:400], "ts": int(time.time())}
    if input_path:
        rec["input"] = str(Path(input_path).resolve())
    # a whole hunk marked closes its sinks too
    hunk = next((it for it in doc["items"] if it["id"] == item), None)
    targets = [item] + ([s["id"] for s in hunk["sinks"]] if hunk else [])
    for t in targets:
        doc["verdicts"][t] = rec
    return doc


def gate(doc: dict, *, stop_hook_active: bool = False, max_blocks: int = MAX_BLOCKS) -> tuple:
    """(block, message). Blocks while items are open, up to max_blocks times,
    and while Claude Code is already continuing for a hook only if the agent
    closed something since the last block."""
    opn = open_items(doc)
    g = doc.setdefault("gate", {"blocks": 0, "open_at_block": None})
    if not opn:
        return False, "delta sweep complete"
    if g["blocks"] >= max_blocks:
        return False, f"delta sweep: {len(opn)} items still open; gate gave up after {g['blocks']} blocks"
    if stop_hook_active and g.get("open_at_block") is not None and len(opn) >= g["open_at_block"]:
        return False, f"delta sweep: {len(opn)} items open, no progress since the last block"
    g["blocks"] += 1
    g["open_at_block"] = len(opn)
    return True, ("Not done: the delta sweep has items with no verdict. Every changed sink "
                  "must be classified before you finish.\n" + show(doc, limit=12))


# ---------------------------------------------------------------------------
# file and CLI
# ---------------------------------------------------------------------------

SWEEP_FILE_ENV = "CC_FUZZER_SWEEP_FILE"


def default_file() -> Path:
    """$CC_FUZZER_SWEEP_FILE (a host without a campaign sets it once), else
    the campaign's <state>/delta-sweep.json."""
    if os.environ.get(SWEEP_FILE_ENV):
        return Path(os.environ[SWEEP_FILE_ENV])
    from cc_fuzzer_core.paths import campaign
    return campaign().state_dir / FILENAME


def load(path) -> dict:
    try:
        doc = json.loads(Path(path).read_text())
    except FileNotFoundError:
        raise SweepError(f"no delta sweep at {path} (run `cc-fuzzer sweep init`)") from None
    if doc.get("schema") != SCHEMA:
        raise SweepError(f"{path}: not a {SCHEMA} document")
    return doc


def save(doc: dict, path) -> None:
    p = Path(path)
    p.parent.mkdir(parents=True, exist_ok=True)
    tmp = p.with_suffix(p.suffix + ".tmp")
    tmp.write_text(json.dumps(doc, indent=1))
    os.replace(tmp, p)


def _file(a) -> Path:
    return Path(a.file) if a.file else default_file()


def _cmd_init(a):
    src = a.diff
    p = Path(src)
    if p.is_file():
        text = p.read_text(errors="replace")
    else:
        from cc_fuzzer_core.paths import campaign
        r = _delta._git(campaign().project_root, "diff", "--unified=3", src)
        if r.returncode != 0:
            print(f"error: {src} is neither a diff file nor a git range", file=sys.stderr)
            return 2
        text = r.stdout.decode(errors="replace")
    path = _file(a)
    if path.exists() and not a.force:
        print(f"{path} exists; --force to rebuild it (verdicts are lost)", file=sys.stderr)
        return 2
    doc = build(text, source=src)
    save(doc, path)
    print(show(doc))
    return 0


def _cmd_show(a):
    print(show(load(_file(a)), limit=a.limit))
    return 0


def _cmd_mark(a):
    path = _file(a)
    doc = load(path)
    try:
        mark(doc, a.item, a.verdict, a.reason, input_path=a.input or "")
    except SweepError as e:
        print(f"error: {e}", file=sys.stderr)
        return 2
    save(doc, path)
    print(f"{a.item}: {a.verdict}. {len(open_items(doc))} open.")
    return 0


def _cmd_gate(a):
    """Without --hook: exit 0 when complete, 1 when items are open. With
    --hook: read the Stop hook input on stdin and answer in the documented
    Stop hook JSON; a sweep that is missing or unreadable never blocks."""
    path = _file(a) if (a.file or not a.hook) else None
    if a.hook:
        try:
            event = json.loads(sys.stdin.read() or "{}")
        except ValueError:
            event = {}
        try:
            path = path or default_file()
            doc = load(path)
        except Exception:  # noqa: BLE001 - no sweep, nothing to enforce
            return 0
        block, msg = gate(doc, stop_hook_active=bool(event.get("stop_hook_active")),
                          max_blocks=a.max_blocks)
        save(doc, path)
        if block:
            print(json.dumps({"decision": "block", "reason": msg}))
        return 0
    doc = load(path)
    opn = open_items(doc)
    print(show(doc, limit=a.limit))
    return 1 if opn else 0


def register_cli(subparsers):
    from cc_fuzzer_core.cli import add_subsystem
    _p, verbs = add_subsystem(subparsers, "sweep",
                              "delta sweep: a verdict for every risky line a diff changed")

    def common(v):
        v.add_argument("--file", help=f"default: ${SWEEP_FILE_ENV}, else <state>/{FILENAME}")
        return v

    v = common(verbs.add_parser("init", help="build the checklist from a diff file or git range"))
    v.add_argument("diff")
    v.add_argument("--force", action="store_true")
    v.set_defaults(func=_cmd_init)
    v = common(verbs.add_parser("show", help="the items with no verdict yet"))
    v.add_argument("--limit", type=int, default=SHOW_LIMIT)
    v.set_defaults(func=_cmd_show)
    v = common(verbs.add_parser("mark", help="record a verdict for an item"))
    v.add_argument("item")
    v.add_argument("verdict", choices=sorted(VERDICTS))
    v.add_argument("reason")
    v.add_argument("--input", help="the input you ran (required for crash and reached)")
    v.set_defaults(func=_cmd_mark)
    v = common(verbs.add_parser("gate", help="exit 1 while items are open; --hook: a Stop hook"))
    v.add_argument("--hook", action="store_true")
    v.add_argument("--max-blocks", type=int, default=MAX_BLOCKS)
    v.add_argument("--limit", type=int, default=SHOW_LIMIT)
    v.set_defaults(func=_cmd_gate)
