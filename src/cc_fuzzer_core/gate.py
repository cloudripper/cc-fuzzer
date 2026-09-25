"""Refusals the core owns, so a hook and the API cannot disagree (§11, §12).

The plugin states a rule once in a prompt, and prose has already failed here:
enforce-readonly.sh exists because the plugin-read-only rule was broken four
times across documented campaigns, each caught after the fact. So a rule that
matters is enforced twice, and BOTH layers ask the same code:

  - the core refuses the action at its API. Authoritative, and present in
    every host.
  - a PreToolUse hook refuses it earlier, with a reason the model can act on
    and the exact command to run instead. The hook only translates; the
    decision is `cc-fuzzer gate ...`, so the two can never drift apart.

This module holds §12's half: which binary an action may run on. A crash
reproduced on a cmplog, symcc or coverage binary is not evidence -- it is a
statement about the instrumentation -- and under time pressure a triager
reaches for whichever binary is already built. classify_command() reads a
shell command the model is about to run and says whether it crosses that line.

CLI: `cc-fuzzer gate classify-command` (stdin or --command), exit 0 allow,
1 deny; `--json` for the hook.
"""
from __future__ import annotations

import json
import os
import re
import shlex
import sys
from dataclasses import dataclass, field

from cc_fuzzer_core import variants as _variants

ALLOW, DENY = "allow", "deny"

# Binaries that must never be executed by hand. The suffixes come from the
# variant declarations, so adding a variant cannot leave a hole here.
_INSTRUMENTED = {_variants.BINARY_SUFFIX[n]: n
                 for n in _variants.forbidden_for_evidence()
                 if _variants.BINARY_SUFFIX.get(n)}

# The launcher entry points that ARE allowed to run an instrumented binary.
LAUNCHERS = ("launch-fuzzer-slot.sh", "run-concolic.sh", "cc-fuzzer slots",
             "cc_fuzzer_core slots", "run-fuzzer.sh")

# A crash input: what the campaign calls one on disk.
_CRASH_PATH_RE = re.compile(r"(crashes/(new|known|flaky)/|/repro/|\breproducer\b)")


@dataclass(frozen=True)
class Verdict:
    decision: str
    reason: str = ""
    suggestion: str = ""
    binary: str = ""
    variant: str = ""
    matched: tuple = field(default=())

    @property
    def allowed(self) -> bool:
        return self.decision == ALLOW

    def as_dict(self) -> dict:
        return {"decision": self.decision, "reason": self.reason,
                "suggestion": self.suggestion, "binary": self.binary,
                "variant": self.variant, "matched": list(self.matched)}


def _tokens(command: str) -> list:
    try:
        return shlex.split(command, comments=True)
    except ValueError:
        return command.split()


def variant_of(path: str) -> str:
    """The variant a binary path names, by its suffix ('' when it is not an
    instrumented one)."""
    base = os.path.basename(path)
    for suffix, name in _INSTRUMENTED.items():
        if base.endswith(suffix):
            return name
    return ""


def is_launcher(command: str) -> bool:
    return any(l in command for l in LAUNCHERS)


def classify_command(command: str, *, record=None, harness: str = "") -> Verdict:
    """Whether this shell command may run as written.

    Two refusals, both §12:
      1. executing a cmplog / symcc / coverage binary outside the launcher
      2. running a crash input against a binary that is not the one `replay`
         would select
    """
    if not command or not command.strip():
        return Verdict(ALLOW)
    if is_launcher(command):
        return Verdict(ALLOW, "the slot launcher may use instrumented binaries")

    toks = _tokens(command)
    instrumented = [(t, variant_of(t)) for t in toks if variant_of(t)]
    if instrumented:
        path, name = instrumented[0]
        return Verdict(
            DENY,
            f"{os.path.basename(path)} is the {name} binary; it is built to feed the "
            f"fuzzer, not to be run by hand. A crash that reproduces on it is evidence "
            f"about the instrumentation, not about the target.",
            suggestion=("cc-fuzzer crash replay <file>"
                        if _CRASH_PATH_RE.search(command)
                        else "cc-fuzzer variants select --action <action> --harness <name>"),
            binary=path, variant=name, matched=(path,))

    if record is None or not _CRASH_PATH_RE.search(command):
        return Verdict(ALLOW)

    # A crash input is being fed to something. It must be the replay binary.
    try:
        sel = _variants.select(record, _variants.A_REPLAY, harness=harness)
    except _variants.SelectionError:
        return Verdict(ALLOW, "no replay binary recorded; nothing to compare against")
    known = {os.path.realpath(str(record.get(f) or ""))
             for f in _variants.BINARY_FIELD.values() if record.get(f)}
    for t in toks:
        real = os.path.realpath(t)
        if real in known and real != os.path.realpath(sel.binary):
            return Verdict(
                DENY,
                f"a crash input may only be replayed on {sel.variant} "
                f"({sel.binary}); {t} is a different build of the harness",
                suggestion="cc-fuzzer crash replay <file>",
                binary=sel.binary, variant=sel.variant, matched=(t,))
    return Verdict(ALLOW)


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def _record(a):
    if getattr(a, "harness", ""):
        try:
            return _variants.harness_record(harness=a.harness)
        except Exception:
            return None
    try:
        return _variants.harness_record()
    except Exception:
        return None


def _cmd_classify(a):
    command = a.command if a.command is not None else sys.stdin.read()
    v = classify_command(command, record=_record(a), harness=a.harness)
    if a.json:
        print(json.dumps(v.as_dict(), indent=2))
    elif not v.allowed:
        print(v.reason, file=sys.stderr)
        if v.suggestion:
            print(f"run instead: {v.suggestion}", file=sys.stderr)
    return 0 if v.allowed else 1


def register_cli(subparsers):
    from cc_fuzzer_core.cli import add_subsystem
    _p, verbs = add_subsystem(subparsers, "gate",
                              "Refusals shared by the core API and the plugin hooks.")

    v = verbs.add_parser("classify-command",
                         help="may this shell command run? (exit 1 = deny)")
    v.add_argument("--command", help="the command (default: stdin)")
    v.add_argument("--harness", default="")
    v.add_argument("--json", action="store_true")
    v.set_defaults(func=_cmd_classify)
