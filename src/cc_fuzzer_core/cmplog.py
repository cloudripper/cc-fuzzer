"""Harvest AFL++ cmplog observations into a fuzzing dictionary (port of
scripts/extract-cmplog-dict.sh).

extract(campaign, harness=..., aflpp_out=..., output=...) -> CmplogResult.
"Redqueen lite": cmplog's input-to-state benefit happens inside afl-fuzz, but
the LLM agents only see source and coverage. Surfacing the comparison operands
cmplog saw as a dictionary lets them classify a gap as direct_compare (cmplog
already solves it) rather than checksum_barrier.

Sources, per AFL++ instance dir (default/ or <slot>/ under the output root, plus
the root itself so a single instance dir can be passed): printable runs (>= 4
chars, like strings(1)) of every file under .cmplog/ and cmplog/, and of the
queue inputs (capped at 1 MiB per instance). Filtered to 4..64 chars, not
mostly digits, not a path, deduplicated, at most 2048 entries.

A missing output dir or no cmplog dirs is not an error: the dict is written
with a NOTE header and no entries, so "refresh, then read the newest dict"
always finds a valid file.

Strings are extracted in-process (no strings(1) dependency).
"""
from __future__ import annotations

import os
import re
import sys
import time
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path

from cc_fuzzer_core.paths import Campaign, CampaignError, HarnessLayout, campaign as _campaign, state_dir_text

MIN_LEN, MAX_LEN, MAX_ENTRIES = 4, 64, 2048
QUEUE_CAP = 1048576
_PRINTABLE = re.compile(rb"[\x20-\x7e\t]{%d,}" % MIN_LEN)


@dataclass
class CmplogResult:
    output: str          # the dict path as given / defaulted (relative paths: to the project root)
    entries: int
    source_dir: str
    source_missing: bool
    found_cmplog: bool


def printable_runs(data: bytes) -> bytes:
    """strings -n 4: each run of >= 4 printable ASCII (or tab) bytes + "\\n"."""
    return b"".join(m.group(0) + b"\n" for m in _PRINTABLE.finditer(data))


def _files(d: str):
    """Regular files under d, depth-first in directory order (find -type f)."""
    try:
        entries = list(os.scandir(d))
    except OSError:
        return
    for e in entries:
        try:
            if e.is_file(follow_symlinks=False):
                yield e.path
            elif e.is_dir(follow_symlinks=False):
                yield from _files(e.path)
        except OSError:
            continue


def _strings_of(d: str) -> bytes:
    out = []
    for f in _files(d):
        try:
            with open(f, "rb") as fh:
                out.append(printable_runs(fh.read()))
        except OSError:
            continue
    return b"".join(out)


def filter_entries(raw: str) -> list[str]:
    seen, out = set(), []
    for line in raw.split("\n"):
        s = line.rstrip("\n").rstrip("\r")
        if not (MIN_LEN <= len(s) <= MAX_LEN):
            continue
        if not s.strip():
            continue
        if sum(1 for ch in s if ch.isdigit()) / len(s) > 0.8:  # metadata, not an operand
            continue
        if s.startswith("/") and "/" in s[1:]:                  # a path
            continue
        if s in seen:
            continue
        seen.add(s)
        out.append(s)
        if len(out) >= MAX_ENTRIES:
            break
    return out


def escape(s: str) -> str:
    """AFL/libFuzzer dict escaping: \\" \\\\ and \\xNN for non-printables."""
    r = []
    for ch in s:
        o = ord(ch)
        if ch == '"':
            r.append('\\"')
        elif ch == "\\":
            r.append("\\\\")
        elif 0x20 <= o < 0x7F:
            r.append(ch)
        else:
            r.append(f"\\x{o:02x}")
    return "".join(r)


def extract(c: Campaign, *, harness: str = "", aflpp_out: str = "", output: str = "",
            now: int | None = None) -> CmplogResult:
    """Write one harness's cmplog dict (see module docstring). Relative
    aflpp_out / output resolve against the project root."""
    root = c.project_root
    lay = c.layout()
    ts = int(time.time()) if now is None else now
    harness = harness or lay.default_harness()
    aflpp_out = aflpp_out or str(lay.harness_root(harness) / "aflpp-out")
    output = output or f"{state_dir_text(c)}/{HarnessLayout.cmplog_dict_name(harness, ts)}"

    def io(p: str) -> str:
        return p if os.path.isabs(p) else os.path.join(root, p)

    out_path = Path(io(output))
    out_path.parent.mkdir(parents=True, exist_ok=True)

    missing = not os.path.isdir(io(aflpp_out))
    if missing:
        sys.stderr.write(f"note: AFL++ output dir not present yet: {aflpp_out} (emitting empty cmplog dict)\n")

    scan = [str(p) for p in HarnessLayout.afl_instances(io(aflpp_out))] + [io(aflpp_out)]
    found_any = False
    raw = []
    for base in scan:
        for d in (os.path.join(base, ".cmplog"), os.path.join(base, "cmplog")):
            if os.path.isdir(d):
                found_any = True
                raw.append(_strings_of(d))
    for base in scan:
        q = os.path.join(base, "queue")
        if os.path.isdir(q):
            raw.append(_strings_of(q)[:QUEUE_CAP])
    entries = filter_entries(b"".join(raw).decode("utf-8", "ignore"))

    header = [
        "# cc-fuzzer cmplog-derived dictionary",
        f"# generated_at: {datetime.fromtimestamp(ts).astimezone().isoformat(timespec='seconds')}",
        f"# source_dir:   {aflpp_out}",
        f"# entries:      {len(entries)}",
        "# format:       libFuzzer / AFL++ dict",
        "#",
        "# These entries were observed by cmplog at runtime as comparison",
        "# operands. The LLM coverage-analyst should treat their presence as",
        "# evidence that the corresponding branches are cmplog-solvable",
        "# (gap reason: direct_compare), and should NOT dispatch them to",
        "# concolic-executor.",
        "#",
    ]
    if missing:
        header += [f"# NOTE: AFL++ output dir {aflpp_out} does not exist yet.",
                   "#       Either this is a libFuzzer campaign (no cmplog data), or AFL++",
                   "#       has not run yet. Dictionary is empty; coverage-analyst should",
                   "#       fall back to source-only reasoning for this tick."]
    elif not found_any:
        header += [f"# NOTE: no cmplog directories were found under {aflpp_out}.",
                   "#       Either the cmplog binary isn't being passed via -c, or this",
                   "#       AFL++ version doesn't expose cmplog data on disk. Dictionary",
                   "#       is empty; coverage-analyst should fall back to source-only",
                   "#       reasoning for this tick."]
    header.append("")
    lines = header + [f'"{escape(s)}"' for s in entries]
    out_path.write_text("\n".join(lines) + "\n")
    return CmplogResult(output, len(entries), aflpp_out, missing, found_any)


# ---------------------------------------------------------------------------
# CLI: cc-fuzzer cmplog extract
# ---------------------------------------------------------------------------

HELP = """\
cc-fuzzer cmplog extract - harvest AFL++ cmplog operands into a dictionary.

Usage: cc-fuzzer cmplog extract [--harness <name>] [--aflpp-out <out-dir>] [--output <dict-path>]

  --harness    default: every declared harness (one dict each) when neither
               --harness nor --aflpp-out is given, else the first declared
  --aflpp-out  default: fuzz/harnesses/<harness>/aflpp-out (the AFL++ output
               root; instance subdirs are discovered)
  --output     default: <state>/cmplog-dict-<harness>-<ts>.dict

Prints the dict path; "  entries: N" goes to stderr.
"""


def _cmd_extract(a):
    opts = {"--harness": "", "--aflpp-out": "", "--output": ""}
    args = list(a.args)
    while args:
        arg = args.pop(0)
        if arg in opts:
            opts[arg] = args.pop(0) if args else ""
        elif arg in ("-h", "--help"):
            sys.stdout.write(HELP)
            return 0
        else:
            sys.stderr.write(f"ERROR: unknown arg: {arg}\n")
            return 2
    try:
        c = _campaign()
    except CampaignError as e:
        sys.stderr.write(f"{e}\n")
        return e.code
    if not opts["--harness"] and not opts["--aflpp-out"]:
        runs = [{"harness": h} for h in c.layout().declared_harnesses()]
    else:
        runs = [{"harness": opts["--harness"], "aflpp_out": opts["--aflpp-out"], "output": opts["--output"]}]
    for kw in runs:
        r = extract(c, **kw)
        sys.stdout.write(f"{r.output}\n")
        sys.stdout.flush()
        sys.stderr.write(f"  entries: {r.entries}\n")
    return 0


def register_cli(subparsers):
    from cc_fuzzer_core.cli import add_raw_verb, add_subsystem

    _p, verbs = add_subsystem(subparsers, "cmplog", "AFL++ cmplog dictionary harvesting")
    add_raw_verb(verbs, "cmplog", "extract", _cmd_extract,
                 "write a cmplog-derived dict (port of extract-cmplog-dict.sh); --help for flags")
