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

EXIT CONTRACT, and it is total: **0 means allowed, and any non-zero means NOT
allowed** -- denied, or the gate could not reach a decision. There is
deliberately no exit code that means "the tool broke, carry on": a gate whose
failure is distinguishable from a refusal invites `gate ... || allow`, which
turns every refusal into a silent permit. That is the one bug a gate must not
have, and it is the bug the first version of this project's own PreToolUse
hook shipped with.

So the only correct shell idiom is the natural one:

    if ! cc-fuzzer gate classify-command --command "$CMD"; then refuse; fi

A caller that wants to distinguish the two reads `decision` from `--json`
("deny" vs "error"), which is explicit rather than incidental.
"""
from __future__ import annotations

import json
import os
import re
import shlex
import sys
from dataclasses import dataclass, field
from typing import Mapping

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
# §11: nothing enters fuzz/findings/ except through the promote path
# ---------------------------------------------------------------------------

FINDINGS_DIR = "findings"
PROMOTE_COMMAND = "cc-fuzzer findings promote <id>"
# The commands that ARE the promote path, and may therefore write there.
PROMOTE_COMMANDS = ("cc-fuzzer findings promote", "findings.sh promote")

# A Bash command that writes into a path: redirections and the usual movers.
_WRITE_RE = re.compile(
    r"(>>?|\b(?:cp|mv|mkdir|tee|install|rsync|touch|ln|dd)\b|\brm\b)")


def protected(config=None) -> tuple:
    """(dirs, allowed commands) the write gate enforces.

    `dirs` are path SUFFIXES: "findings" protects fuzz/findings/ (the plugin
    default); a CRS whose submission directory is watched by the framework
    protects it the same way:

        {"gate": {"protected_dirs": ["findings", "/artifacts/povs"],
                  "allow_commands": ["crs-promote-pov"]}}

    `allow_commands` ADD to the promote path's own commands: a command that
    contains one of them is the sanctioned writer and may write there.
    """
    block = (config or {}).get("gate") or {}
    if not isinstance(block, Mapping):
        block = {}
    dirs = block.get("protected_dirs") or (FINDINGS_DIR,)
    if isinstance(dirs, str):
        dirs = (dirs,)
    dirs = tuple(d.strip().strip("/") for d in dirs if isinstance(d, str) and d.strip().strip("/"))
    allow = block.get("allow_commands") or ()
    if isinstance(allow, str):
        allow = (allow,)
    return dirs or (FINDINGS_DIR,), PROMOTE_COMMANDS + tuple(a for a in allow if isinstance(a, str) and a)


def check_finding_dir(path) -> Verdict:
    """Whether a finding directory carries a valid verification marker (§11)."""
    from cc_fuzzer_core.crash import pipeline
    problems = pipeline.marker_problems(path)
    if not problems:
        return Verdict(ALLOW, f"{path} is verified")
    return Verdict(DENY, "; ".join(problems),
                   suggestion=f"promote it through {PROMOTE_COMMAND}")


def _dir_re(d: str):
    return re.compile(rf"(^|/){re.escape(d)}(/|$)")


def _touches(command: str, dirs) -> tuple:
    """Tokens in `command` that point inside a protected directory."""
    hits = []
    pats = [_dir_re(d) for d in dirs]
    for tok in _tokens(command):
        cleaned = tok.lstrip("<>")
        if any(p.search(cleaned) for p in pats):
            hits.append(tok)
    if not hits:
        for d in dirs:
            if re.search(rf"\b{re.escape(d)}/", command):
                hits.append(d + "/")
                break
    return tuple(hits)


def _touches_findings(command: str) -> tuple:
    return _touches(command, (FINDINGS_DIR,))


def _where(d: str) -> str:
    return f"fuzz/{d}/" if d == FINDINGS_DIR else f"{d}/"


def classify_finding_write(command: str, *, tool: str = "Bash",
                           path: str = "", config=None) -> Verdict:
    """Refuse a write under a protected directory (default fuzz/findings/)
    that does not go through the promote path.

    The rule is not "be careful writing there": a finding directory IS the
    claim that something was verified, so creating one by hand asserts a
    verification that never happened. The same holds for any directory a
    framework submits from; `config` names those (see protected()).
    """
    dirs, allow = protected(config)
    if tool in ("Write", "Edit", "MultiEdit"):
        target = path or ""
        hit = next((d for d in dirs if _dir_re(d).search(target)), None)
        if hit is None:
            return Verdict(ALLOW)
        return Verdict(DENY,
                       f"{target} is under {_where(hit)}. A finding directory is the "
                       f"claim that a crash was verified, so it is created only by the "
                       f"promote path, which writes a verification marker after a verifier "
                       f"confirms the crash.",
                       suggestion=PROMOTE_COMMAND, matched=(target,))

    if not command:
        return Verdict(ALLOW)
    if any(a in command for a in allow):
        return Verdict(ALLOW, "the promote path may write findings")
    hits = _touches(command, dirs)
    if not hits or not _WRITE_RE.search(command):
        return Verdict(ALLOW)
    hit = next((d for d in dirs if any(_dir_re(d).search(h.lstrip("<>")) or h == d + "/"
                                       for h in hits)), dirs[0])
    return Verdict(DENY,
                   f"this command writes under {_where(hit)} ({hits[0]}). A finding "
                   f"directory is the claim that a crash was verified; it is created only "
                   f"by the promote path, which writes a verification marker after a "
                   f"verifier confirms the crash.",
                   suggestion=PROMOTE_COMMAND, matched=hits)


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


def _guard(fn):
    """Any failure to reach a verdict exits as a REFUSAL, not as an error the
    caller might read as success. See the exit contract in the module doc."""
    def wrapper(a):
        try:
            return fn(a)
        except Exception as e:  # noqa: BLE001 - a gate never fails open
            v = Verdict(DENY, f"gate could not classify this: {type(e).__name__}: {e}")
            if getattr(a, "json", False):
                print(json.dumps({**v.as_dict(), "decision": DENY, "error": True}, indent=2))
            else:
                print(v.reason, file=sys.stderr)
            return 1
    return wrapper


def _cmd_check_finding(a):
    v = check_finding_dir(a.path)
    if a.json:
        print(json.dumps(v.as_dict(), indent=2))
    elif not v.allowed:
        print(v.reason, file=sys.stderr)
    return 0 if v.allowed else 1


def _gate_config(a):
    """--config, else the campaign's fuzz-config.json, else the defaults."""
    if getattr(a, "config", None):
        with open(a.config) as f:
            return json.load(f)
    try:
        from cc_fuzzer_core import config as _config
        from cc_fuzzer_core.paths import campaign
        return _config.load(campaign(strict=False))
    except Exception:  # noqa: BLE001 - no campaign: the defaults still protect
        return {}


def _cmd_classify_write(a):
    command = a.command if a.command is not None else (sys.stdin.read() if not a.path else "")
    v = classify_finding_write(command, tool=a.tool, path=a.path or "", config=_gate_config(a))
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
    v.set_defaults(func=_guard(_cmd_classify))

    v = verbs.add_parser("check-finding",
                         help="does this finding dir carry a valid verification marker?")
    v.add_argument("path")
    v.add_argument("--json", action="store_true")
    v.set_defaults(func=_guard(_cmd_check_finding))

    v = verbs.add_parser("classify-write",
                         help="may this write under a protected dir (default fuzz/findings/) "
                              "proceed? (exit 1 = deny)")
    v.add_argument("--command", help="a Bash command (default: stdin)")
    v.add_argument("--config", help="fuzz-config.json with a gate block "
                                    "(default: the campaign's)")
    v.add_argument("--tool", default="Bash")
    v.add_argument("--path", default="", help="the target path, for Write/Edit")
    v.add_argument("--json", action="store_true")
    v.set_defaults(func=_guard(_cmd_classify_write))
