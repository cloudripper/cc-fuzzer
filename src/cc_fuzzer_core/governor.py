"""Behaviour governor: after many reading calls with no input run, say so.

On the qualification runs 88-89% of the agent's tool calls were reading and
searching the source and 1-2% ran an input through the harness (Q13): a
hypothesis was traced by hand for dozens of calls when one crafted input would
have answered it in a second. The governor watches each finished batch of tool
calls and, once `threshold` reading calls have gone by since the last input
run, returns a short nudge for the host to put in front of the model before
its next request (Claude Code: a PostToolBatch hook's additionalContext). It
repeats only after another `threshold` reading calls, so a long investigation
is nudged a few times, never every turn.

    observe(session, calls) -> nudge text or None
        calls: [{"tool_name": ..., "tool_input": {...}}, ...] of one batch

What counts:
    an input run   a Bash command that runs the harness or a verdict tool:
                   any of `run_patterns` (the host passes its harness name and
                   tools; the defaults cover cc-fuzzer's and libFuzzer's)
    reading        Read, Grep, Glob, NotebookRead; Bash whose first program
                   reads or searches (cat, head, tail, sed, grep, rg, find, ls,
                   awk, wc, nl, less, more, file, strings, xxd, ctags, cscope)
                   or a static query (crs-trace, crs-codeql, cull, semgrep)
    anything else  neutral (writing a candidate input is preparation)

State is one small JSON file per session under the hygiene state directory.
The core returns text; wiring it to a host's hook is the adapter's job.

CLI: `cc-fuzzer governor observe --session S [--threshold N] [--run REGEX]...`
(the PostToolBatch hook input JSON on stdin) prints {"nudge": "..."|""}.
"""
from __future__ import annotations

import json
import re
import sys
from pathlib import Path

from cc_fuzzer_core import hygiene

THRESHOLD = 30
READ_TOOLS = {"Read", "Grep", "Glob", "NotebookRead", "LSP"}
READ_PROGRAMS = {"cat", "head", "tail", "sed", "grep", "egrep", "fgrep", "rg", "ag", "find", "ls",
                 "awk", "gawk", "wc", "nl", "less", "more", "file", "strings", "xxd", "hexdump",
                 "od", "ctags", "cscope", "tree", "diff", "git", "crs-trace", "crs-codeql",
                 "cull", "semgrep", "codeql", "objdump", "readelf", "nm", "sort", "uniq", "cut",
                 "tr", "column", "basename", "dirname", "realpath", "stat", "du", "which",
                 "crc-known-bugs"}
# shell filler that neither reads nor runs anything
NEUTRAL_PROGRAMS = {"echo", "printf", "true", "false", "test", "[", "[[", "set", "export",
                    "cd", "sleep", "wait", ":", "done", "do", "then", "fi", "else", "for",
                    "while", "if", "local", "read"}
# the verdict tools and fuzzer drivers a crafted input goes through
DEFAULT_RUN_PATTERNS = (r"\bcrc-promote-pov\b", r"\bcrs-fuzz\s+(run|start|add-seeds)\b",
                        r"\brun-pov\b", r"\bcc-fuzzer\s+(crash|triage|replay)\b",
                        r"(^|\s)-runs=\d", r"(^|[\s;&|(])gdb\s")


def _shell_text(command: str) -> str:
    """The command line without heredoc bodies and quoted strings: what is left
    names the programs."""
    lines, out, end = (command or "").splitlines(), [], None
    for ln in lines:
        if end is not None:
            if ln.strip() == end:
                end = None
            continue
        out.append(ln)
        m = re.search(r"<<-?\s*['\"]?(\w+)['\"]?", ln)
        if m:
            end = m.group(1)
    text = "\n".join(out)
    return re.sub(r"'[^']*'|\"(?:\\.|[^\"\\])*\"", "Q", text)


def _programs(command: str) -> list:
    """The program names a shell command line runs (first word of each stage)."""
    out = []
    for stage in re.split(r"\|\||&&|[|;\n]", _shell_text(command)):
        words = [w for w in stage.strip().split() if "=" not in w.split("/")[0]] or [""]
        w = words[0]
        if w in ("sudo", "time", "timeout", "nice", "env", "xargs", "cd") and len(words) > 1:
            w = words[1] if w != "timeout" or len(words) < 3 else words[2]
        out.append(Path(w).name)
    return out


def classify(call: dict, run_patterns=DEFAULT_RUN_PATTERNS) -> str:
    """'run', 'read' or 'other' for one tool call."""
    tool = call.get("tool_name") or ""
    inp = call.get("tool_input") or {}
    if tool in READ_TOOLS:
        return "read"
    if tool == "Bash":
        cmd = str(inp.get("command") or "")
        if any(re.search(p, cmd) for p in run_patterns):
            return "run"
        progs = [p for p in _programs(cmd) if p and p not in NEUTRAL_PROGRAMS]
        if progs and all(p in READ_PROGRAMS for p in progs):
            return "read"
    return "other"


def _state(session: str) -> Path:
    safe = re.sub(r"[^A-Za-z0-9_.-]", "_", session or "nosession")[:80]
    return hygiene.state_dir() / f"governor-{safe}.json"


HOW = "write it to a file and run the harness binary on it"


def nudge_text(reads: int, how: str = HOW) -> str:
    """The nudge; `how` is the host's way to run an input (its verdict tool)."""
    return (f"{reads} reading and search calls since an input last went through the harness. "
            f"Turn your current hypothesis into an input and run it now ({how}): a crash or a "
            "clean run answers the question faster than more reading. If you cannot build an "
            "input yet, write down exactly what you still need to know and ask only that.")


def observe(session: str, calls: list, *, threshold: int = THRESHOLD,
            run_patterns=DEFAULT_RUN_PATTERNS, how: str = HOW) -> str | None:
    """Account one finished batch; a nudge when reading has gone on too long."""
    if threshold <= 0:
        return None
    path = _state(session)
    try:
        doc = json.loads(path.read_text())
    except (OSError, ValueError):
        doc = {}
    reads, since_nudge = int(doc.get("reads", 0)), int(doc.get("since_nudge", 0))
    nudges = int(doc.get("nudges", 0))
    for c in calls or []:
        kind = classify(c, run_patterns)
        if kind == "run":
            reads, since_nudge = 0, 0
        elif kind == "read":
            reads += 1
            since_nudge += 1
    text = None
    if reads >= threshold and since_nudge >= threshold:
        text, since_nudge, nudges = nudge_text(reads, how), 0, nudges + 1
    tmp = path.with_suffix(".tmp")
    tmp.write_text(json.dumps({"reads": reads, "since_nudge": since_nudge, "nudges": nudges}))
    tmp.replace(path)
    return text


def _cmd_observe(a):
    """Never fails on its own error: bad input or state says nothing."""
    try:
        raw = sys.stdin.read()
        doc = json.loads(raw) if raw.strip() else {}
        patterns = tuple(DEFAULT_RUN_PATTERNS) + tuple(a.run or ())
        text = observe(a.session or doc.get("session_id") or "", doc.get("tool_calls") or [],
                       threshold=a.threshold, run_patterns=patterns, how=a.how or HOW)
    except Exception:  # noqa: BLE001 - a broken governor must not disturb work
        text = None
    print(json.dumps({"nudge": text or ""}))
    return 0


def register_cli(subparsers):
    from cc_fuzzer_core.cli import add_subsystem
    _p, verbs = add_subsystem(subparsers, "governor",
                              "nudge toward running inputs after long reading streaks")
    v = verbs.add_parser("observe", help="account one batch (hook input JSON on stdin)")
    v.add_argument("--session", default="")
    v.add_argument("--threshold", type=int, default=THRESHOLD)
    v.add_argument("--run", action="append", help="extra regex for an input-run command")
    v.add_argument("--how", default="", help="how this host runs an input (named in the nudge)")
    v.set_defaults(func=_cmd_observe)
