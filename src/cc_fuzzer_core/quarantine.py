"""Corpus quarantine and seed safety (ports of scripts/corpus-quarantine.sh and
scripts/check-seed-safety.sh).

quarantine(campaign, harness, inputs=None) -> QuarantineResult. Every new corpus
input (seed-generator, concolic-executor, CVE PoCs) lands in
fuzz/harnesses/<h>/corpus-quarantine/ first; this promotes the safe ones into the
live corpus so a crashing seed can't kill the fuzzer at startup:

  destructive payload (seed_safety)  -> corpus-quarantine/rejected/
  harness exits 0 / 1                -> corpus/
  timeout (10 s, SIGKILL 2 s later)  -> crashes/flaky/
  any other exit                     -> hard-linked to crashes/new/<h>__<sha16>.bin,
                                        original to crashes/flaky/

seed_safety(path) flags only unambiguous destructive shell payloads (rm -rf /,
fork bombs, mkfs / dd / shred on a real block device, chmod on /, writes to a
block device or /proc/sysrq-trigger) in a file's first 64 KiB, line by line like
grep. CCFUZZ_ALLOW_DESTRUCTIVE_SEEDS=1 bypasses the check.

corpus-quarantine.sh toggled `set +e` / `set -e` around the harness run, which
switched errexit ON for the rest of a script that never asked for it: the first
failing mv (e.g. an unwritable corpus dir) aborted the run without a summary.
Here a failed move is reported on stderr, the run carries on, and the exit
status is 1 (not every input was classified).
"""
from __future__ import annotations

import hashlib
import json
import os
import re
import shutil
import signal
import subprocess
import sys
from dataclasses import dataclass, field
from pathlib import Path

from cc_fuzzer_core.paths import Campaign, CampaignError, HarnessLayout, _field_text, campaign as _campaign

ALLOW_ENV = "CCFUZZ_ALLOW_DESTRUCTIVE_SEEDS"
SCAN_BYTES = 65536
RUN_TIMEOUT_S = 10
KILL_AFTER_S = 2
_BLOCK = rb"(sd[a-z]|nvme[0-9]|hd[a-z]|mmcblk[0-9]|vd[a-z]|xvd[a-z])"

# (pattern, reason), matched per line; [[:space:]] == \s (ASCII) here.
SEED_SAFETY_PATTERNS = [
    (rb"\brm\s+-[a-zA-Z]*[rR][a-zA-Z]*[fF][a-zA-Z]*\s+/[^\"']", "rm -rf with absolute-path target"),
    (rb"\brm\s+-[a-zA-Z]*[fF][a-zA-Z]*[rR][a-zA-Z]*\s+/[^\"']", "rm -fr with absolute-path target"),
    (rb"\bmkfs(\.[a-z0-9]+)?\s+/dev/" + _BLOCK, "mkfs on a real block device"),
    (rb"\bdd\s[^|]*\bof=/dev/" + _BLOCK, "dd writing to a real block device"),
    (rb":\s*\(\s*\)\s*\{\s*:\s*\|\s*:\s*&\s*\}\s*;\s*:", "fork bomb signature"),
    (rb"\bshred\s[^|]*\s/dev/(sd[a-z]|nvme[0-9]|hd[a-z])", "shred on a real block device"),
    (rb"\bchmod\s+(--no-preserve-root|-R\s+777)\s+/", "chmod on / (root recursive)"),
    (rb">\s*/dev/(sd[a-z]|nvme[0-9]|hd[a-z]|mmcblk[0-9])[0-9]*\s*$", "stdout redirect into a real block device"),
    (rb">\s*/proc/sysrq-trigger", "write to /proc/sysrq-trigger (kernel control)"),
]
_COMPILED = [(re.compile(p), r) for p, r in SEED_SAFETY_PATTERNS]


def seed_safety(path) -> str | None:
    """The reason a file is unsafe to run, or None."""
    try:
        with open(path, "rb") as f:
            head = f.read(SCAN_BYTES)
    except OSError:
        return None
    lines = head.split(b"\n")
    for pat, reason in _COMPILED:
        if any(pat.search(ln) for ln in lines):
            return reason
    return None


@dataclass
class QuarantineResult:
    code: int = 0
    promoted: int = 0
    crashed: int = 0
    hung: int = 0
    rejected: int = 0
    lines: list = field(default_factory=list)     # stdout lines (REJECTED: ..., summary)
    errors: list = field(default_factory=list)    # stderr lines

    @property
    def summary(self) -> str:
        return (f"promoted={self.promoted}   crashed={self.crashed} (-> crashes/new/)   "
                f"hung={self.hung} (-> flaky/)   rejected={self.rejected} (-> corpus-quarantine/rejected/)")


def run_input(binary: str, path: str, cwd, *, timeout: float = RUN_TIMEOUT_S,
              kill_after: float = KILL_AFTER_S) -> int:
    """Run `binary path` like `timeout --kill-after=2 10 ...`: its exit status,
    124 on timeout (137 if it had to be SIGKILLed), 128+N when killed by N."""
    try:
        p = subprocess.Popen([binary, path], cwd=cwd, stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                             stderr=subprocess.DEVNULL, start_new_session=True)
    except OSError:
        return 126
    try:
        rc = p.wait(timeout)
    except subprocess.TimeoutExpired:
        _signal_group(p, signal.SIGTERM)
        try:
            p.wait(kill_after)
            return 124
        except subprocess.TimeoutExpired:
            _signal_group(p, signal.SIGKILL)
            p.wait()
            return 137
    return 128 - rc if rc < 0 else rc


def _signal_group(p, sig):
    try:
        os.killpg(p.pid, sig)
    except OSError:
        try:
            p.send_signal(sig)
        except OSError:
            pass


def _active_harness(state_dir: Path) -> str:
    try:
        with open(state_dir / "current.json") as f:
            return str(json.load(f).get("active_harness", "") or "")
    except Exception:
        return ""


def quarantine(c: Campaign, harness: str = "", inputs=None, *, env=None) -> QuarantineResult:
    """Classify quarantined inputs (see module docstring). `inputs` default to
    every file directly in the harness's corpus-quarantine/; relative paths
    resolve against the project root and are reported as given."""
    env = os.environ if env is None else env
    res = QuarantineResult()
    root = c.project_root
    lay = c.layout()
    harness = harness or _active_harness(c.state_dir)
    if not harness:
        res.errors.append("ERROR: --harness <name> not provided and current.json has no active_harness")
        res.code = 1
        return res
    if not lay.is_known_harness(harness):
        res.errors.append(f"ERROR: harness '{harness}' is not declared in fuzz-config.json:harnesses[]")
        res.code = 1
        return res

    corpus, quar = lay.corpus_dir(harness), lay.quarantine_dir(harness)
    rejected, crashes_new, flaky = quar / "rejected", c.crashes_dir / "new", c.crashes_dir / "flaky"
    for d in (corpus, quar, rejected, crashes_new, flaky):
        d.mkdir(parents=True, exist_ok=True)

    binary = _field_text(lay.harness_binary(harness)) or ""
    bin_io = binary if os.path.isabs(binary) else os.path.join(root, binary)
    if not binary or not (os.path.isfile(bin_io) and os.access(bin_io, os.X_OK)):
        res.errors.append(f"ERROR: harness binary missing or not executable: {binary}")
        res.code = 1
        return res

    if inputs:
        todo = list(inputs)
    else:
        try:
            todo = [e.path for e in os.scandir(quar) if e.is_file(follow_symlinks=False)]
        except OSError:
            todo = []
    if not todo:
        res.lines.append("(no inputs to quarantine)")
        return res

    allow = env.get(ALLOW_ENV, "0") == "1"
    for given in todo:
        f = given if os.path.isabs(given) else os.path.join(root, given)
        if not os.path.isfile(f):
            continue
        base = os.path.basename(f)
        reason = None if allow else seed_safety(f)
        try:
            if reason:
                shutil.move(f, rejected / base)
                res.lines.append(f"REJECTED: UNSAFE {given}: {reason}")
                res.rejected += 1
                continue
            rc = run_input(bin_io, f, root)
            if rc in (0, 1):
                shutil.move(f, corpus / base)
                res.promoted += 1
            elif rc in (124, 137):
                shutil.move(f, flaky / base)
                res.hung += 1
            else:
                with open(f, "rb") as fh:
                    digest = hashlib.sha256(fh.read()).hexdigest()[:16]
                target = crashes_new / HarnessLayout.crash_filename(harness, digest)
                if not target.is_file():
                    try:
                        os.link(f, target)
                    except OSError:
                        shutil.copy(f, target)
                shutil.move(f, flaky / base)  # the original goes to flaky as a duplicate
                res.crashed += 1
        except OSError as e:
            res.errors.append(f"WARN: {given}: {e.strerror or e}; left in place")
            res.code = 1
    res.lines.append(res.summary)
    return res


# ---------------------------------------------------------------------------
# CLI: cc-fuzzer quarantine run | safety
# ---------------------------------------------------------------------------

def _campaign_or_error():
    try:
        return _campaign(), None
    except CampaignError as e:
        sys.stderr.write(f"{e}\n")
        return None, e.code


def _cmd_run(a):
    harness, inputs, args = "", [], list(a.args)
    while args:
        arg = args.pop(0)
        if arg == "--harness":
            harness = args.pop(0) if args else ""
        elif arg in ("-h", "--help"):
            sys.stdout.write(__doc__.split("\n\n")[1] + "\n\nUsage: cc-fuzzer quarantine run "
                             "[--harness <name>] [<file>...]\n")
            return 0
        else:
            inputs.append(arg)
    c, code = _campaign_or_error()
    if c is None:
        return code
    r = quarantine(c, harness, inputs)
    for ln in r.lines:
        sys.stdout.write(ln + "\n")
    for ln in r.errors:
        sys.stderr.write(ln + "\n")
    return r.code


def _cmd_safety(a):
    c, code = _campaign_or_error()
    if c is None:
        return code
    if os.environ.get(ALLOW_ENV, "0") == "1":
        sys.stderr.write(f"check-seed-safety.sh: {ALLOW_ENV}=1 — safety check bypassed\n")
        return 0
    inputs = list(a.args)
    if not inputs:
        if sys.stdin.isatty():
            sys.stderr.write("ERROR: no files given and stdin is a terminal\n"
                             "Usage: cc-fuzzer quarantine safety <file> [<file> ...]   OR   "
                             "ls files | cc-fuzzer quarantine safety\n")
            return 2
        inputs = [ln for ln in sys.stdin.read().split("\n") if ln]
    unsafe = False
    for given in inputs:
        f = given if os.path.isabs(given) else os.path.join(c.project_root, given)
        if not os.path.isfile(f):
            continue
        reason = seed_safety(f)
        if reason:
            print(f"UNSAFE {given}: {reason}")
            unsafe = True
    return 3 if unsafe else 0


def register_cli(subparsers):
    from cc_fuzzer_core.cli import add_raw_verb, add_subsystem

    _p, verbs = add_subsystem(subparsers, "quarantine", "corpus quarantine and seed safety")
    add_raw_verb(verbs, "quarantine", "run", _cmd_run,
                 "promote / reject quarantined corpus inputs (port of corpus-quarantine.sh)")
    add_raw_verb(verbs, "quarantine", "safety", _cmd_safety,
                 "flag destructive seed payloads, exit 3 if any (port of check-seed-safety.sh)")
