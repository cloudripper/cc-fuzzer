"""Argparse dispatcher for `cc-fuzzer <subsystem> <verb> [args]`.

Registration pattern: every subsystem module listed in SUBSYSTEMS exposes

    def register_cli(subparsers) -> None

which adds ONE subparser named after the subsystem (e.g. "manifest") with its
own verb subparsers. Each verb sets `func=<handler>` via set_defaults; the
handler takes the parsed argparse.Namespace and returns an int exit code (None
is treated as 0). Later stages add their module to SUBSYSTEMS and nothing else.

Modules are imported lazily, only to build the parser, so importing
cc_fuzzer_core itself stays cheap.
"""
from __future__ import annotations

import argparse
import importlib
import sys

from cc_fuzzer_core import __version__

# Order is the order subsystems appear in `cc-fuzzer --help`.
SUBSYSTEMS = (
    "cc_fuzzer_core.paths",
    "cc_fuzzer_core.enums",
    "cc_fuzzer_core.config",
    "cc_fuzzer_core.schema",
    "cc_fuzzer_core.manifest",
)


def add_subsystem(subparsers, name, help_text):
    """Helper for register_cli(): add the subsystem parser and return
    (subsystem_parser, verb_subparsers). A subsystem invoked without a verb
    prints its own help and exits 2."""
    p = subparsers.add_parser(name, help=help_text, description=help_text)
    verbs = p.add_subparsers(dest="verb", metavar="<verb>")
    p.set_defaults(func=lambda _a, _p=p: (_p.print_help(sys.stderr), 2)[1])
    return p, verbs


def build_parser():
    parser = argparse.ArgumentParser(
        prog="cc-fuzzer",
        description="cc-fuzzer core command line (cc-fuzzer <subsystem> <verb>).",
    )
    parser.add_argument("--version", action="version", version=f"cc-fuzzer {__version__}")
    subparsers = parser.add_subparsers(dest="subsystem", metavar="<subsystem>")
    for modname in SUBSYSTEMS:
        importlib.import_module(modname).register_cli(subparsers)
    return parser


def main(argv):
    parser = build_parser()
    args = parser.parse_args(argv)
    func = getattr(args, "func", None)
    if func is None:
        parser.print_help(sys.stderr)
        return 2
    try:
        rc = func(args)
    except BrokenPipeError:  # e.g. `cc-fuzzer ... | head`
        return 0
    return 0 if rc is None else int(rc)
