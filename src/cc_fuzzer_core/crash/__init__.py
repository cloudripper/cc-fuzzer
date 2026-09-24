"""Crash classification and detection (UPDATE_ROADMAP.md §2 row 4).

    classify.classify(text, exit_code) -> Classification   (was is-crash.sh)
    detect.detect(campaign) -> DetectResult                  (was detect-crashes.sh)

CLI: `cc-fuzzer crash classify [--exit-code N] [<file>]` (is-crash.sh's output
line and exit codes: 0 crash, 1 no crash, 2 usage) and `cc-fuzzer crash detect
[--json] [--missing-ok]`. The plugin's detect-crashes.sh hook runs `crash
detect` and turns the result into Claude Code hook output; the core never does.
"""
from __future__ import annotations

import json
import sys

from cc_fuzzer_core.paths import CampaignError, campaign as _campaign

_CLASSIFY_HELP = """\
cc-fuzzer crash classify - classify sanitizer output as a crash or not.

Reads captured output (stdin, or the one file given) and prints one JSON line:
  {"is_crash":<bool>,"category":"<...|none>","summary_line":"...",
   "top_frame":"<function @ file:line or empty>","exit_code":<int or null>}

Usage: cc-fuzzer crash classify [--exit-code N] [<file>]

--exit-code N  the process's exit status; lets a crash with no sanitizer output
               (raw SIGSEGV, SIGABRT, ...) be classified.
Exit status: 0 crash, 1 no crash, 2 usage error.
"""


def _write(text: str, stream=None):
    stream = stream or sys.stdout
    stream.flush()
    stream.buffer.write(text.encode("utf-8", "surrogateescape"))
    stream.buffer.flush()


def _cmd_classify(a):
    from cc_fuzzer_core.crash.classify import classify

    exit_code, path, args = None, None, list(a.args)
    while args:
        arg = args.pop(0)
        if arg == "--exit-code":
            if not args:
                sys.stderr.write("is-crash.sh: --exit-code needs a value\n")
                return 2
            exit_code = args.pop(0)
        elif arg in ("--help", "-h"):
            sys.stdout.write(_CLASSIFY_HELP)
            return 0
        elif arg.startswith("-"):
            sys.stderr.write(f"is-crash.sh: unknown flag: {arg}\n")
            return 2
        elif path is not None:
            sys.stderr.write("is-crash.sh: only one input path allowed\n")
            return 2
        else:
            path = arg
    if path is not None:
        try:
            with open(path, "rb") as f:
                raw = f.read()
        except OSError:
            sys.stderr.write(f"is-crash.sh: cannot read {path}\n")
            return 2
    else:
        raw = sys.stdin.buffer.read()
    r = classify(raw.decode("utf-8", "surrogateescape"), exit_code)
    _write(r.to_json() + "\n")
    return 0 if r.is_crash else 1


def _cmd_detect(a):
    from cc_fuzzer_core.crash.detect import detect
    try:
        c = _campaign()
    except CampaignError as e:
        if a.missing_ok and "not inside a cc-fuzzer project" in str(e):
            return 0
        sys.stderr.write(f"{e}\n")
        return e.code
    r = detect(c)
    if a.json:
        print(json.dumps(r.to_dict()))
    elif r.count:
        print(f"queued {r.count} new crash file(s) into {r.new_dir}/")
    return 0


def register_cli(subparsers):
    from cc_fuzzer_core.cli import add_raw_verb, add_subsystem

    _p, verbs = add_subsystem(subparsers, "crash", "crash classification and detection")
    add_raw_verb(verbs, "crash", "classify", _cmd_classify,
                 "classify sanitizer output (port of is-crash.sh); --help for usage")
    v = verbs.add_parser("detect", help="queue recent crash files into crashes/new/ (port of detect-crashes.sh)")
    v.add_argument("--json", action="store_true",
                   help='print {"alive", "new_dir", "queued", "files"} (default: a summary line when queued)')
    v.add_argument("--missing-ok", action="store_true", help="no project found => exit 0 silently")
    v.set_defaults(func=_cmd_detect)
