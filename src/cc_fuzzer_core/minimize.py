"""Reduce a crashing input to the smallest one that still causes THE SAME bug.

A fuzzer's reproducer is whatever random buffer happened to trip the bug, so a
four-kilobyte input often has eight bytes that matter. The long form is
usually accepted, but the short one is worth more than convenience:

  - it is what makes the essential cause legible, to a reviewer and to whoever
    has to write the patch;
  - two long inputs that look like different findings frequently minimize to
    the same few bytes, so dedup gets better;
  - a submission carrying 4KB of noise invites the question of whether the
    submitter knows which part is the bug.

The whole difficulty is the invariant. Delta debugging will happily shrink an
input until it crashes *somewhere else* -- a buffer that no longer reaches the
parser but now trips an assertion in the header check is a smaller input and a
DIFFERENT finding, and a minimizer that accepts it has silently swapped the
bug out from under the report. So every candidate must reproduce with the same
stack hash as the original, not merely crash:

    crash != crash-with-the-same-cause

The reduction is ddmin (Zeller & Hildebrandt). It is deterministic: the same
input and binary give the same result, so a minimized PoV is reproducible
evidence rather than an artefact of when you ran it.

The binary comes from variants.select(..., "replay") (§12), because a crash
minimized against an instrumented build is minimized against the
instrumentation.

CLI: `cc-fuzzer minimize <file> [--harness NAME] [-o OUT] [--json]`.
"""
from __future__ import annotations

import json
import os
import sys
import time
from dataclasses import dataclass, field
from pathlib import Path

from cc_fuzzer_core import variants as _v
from cc_fuzzer_core.crash import replay as _replay

MINIMIZED_SCHEMA = "minimized-input/v1"

# Bounds. Minimization is a search, and an unbounded search in a scored run is
# a way to spend the budget on a finding you already have.
MAX_ROUNDS = 40
MAX_PROBES = 400
DEFAULT_TIMEOUT_S = 10
# One attempt per candidate: a flaky reproducer is not a minimization problem,
# and re-running every candidate three times multiplies the search by three.
PROBE_ATTEMPTS = 1


class MinimizeError(RuntimeError):
    pass


@dataclass(frozen=True)
class Minimized:
    data: bytes = b""
    original_size: int = 0
    size: int = 0
    stack_hash: str = ""
    category: str = ""
    binary: str = ""
    variant: str = ""
    evidence_grade: str = ""
    rounds: int = 0
    probes: int = 0
    seconds: float = 0.0
    reason: str = ""
    path: str = ""
    preserved: bool = True

    @property
    def ratio(self) -> float:
        return (self.size / self.original_size) if self.original_size else 1.0

    def as_dict(self) -> dict:
        return {"schema": MINIMIZED_SCHEMA, "original_size": self.original_size,
                "size": self.size, "ratio": round(self.ratio, 4),
                "stack_hash": self.stack_hash, "category": self.category,
                "binary": self.binary, "variant": self.variant,
                "evidence_grade": self.evidence_grade, "rounds": self.rounds,
                "probes": self.probes, "seconds": round(self.seconds, 3),
                "reason": self.reason, "path": self.path,
                "preserved": self.preserved}


# ---------------------------------------------------------------------------
# the oracle: does this candidate reproduce the SAME bug?
# ---------------------------------------------------------------------------

class _Probe:
    """Runs a candidate and answers only: same bug, yes or no."""

    def __init__(self, binary: str, want_hash: str, *, timeout: int, workdir: Path,
                 max_probes: int = MAX_PROBES):
        self.binary, self.want = binary, want_hash
        self.timeout, self.workdir = timeout, workdir
        self.max_probes, self.count = max_probes, 0

    @property
    def exhausted(self) -> bool:
        return self.count >= self.max_probes

    def __call__(self, data: bytes) -> bool:
        if not data or self.exhausted:
            return False
        self.count += 1
        p = self.workdir / "candidate.bin"
        p.write_bytes(data)
        rc, out = _replay.run_once(self.binary, str(p), timeout=self.timeout)
        from cc_fuzzer_core.crash import classify as _classify
        cl = _classify.classify(out, rc)
        if not cl.is_crash:
            return False
        # The invariant: a crash somewhere else is a different finding, and
        # accepting it would swap the bug out from under the report.
        return _replay.stack_hash(out, category=cl.category) == self.want


# ---------------------------------------------------------------------------
# ddmin
# ---------------------------------------------------------------------------

def ddmin(data: bytes, still_fails, *, max_rounds: int = MAX_ROUNDS) -> tuple:
    """Classic delta debugging. Returns (reduced, rounds)."""
    n, rounds = 2, 0
    while len(data) >= 2 and rounds < max_rounds:
        rounds += 1
        chunk = max(1, len(data) // n)
        chunks = [data[i:i + chunk] for i in range(0, len(data), chunk)]
        # First try each single chunk (a big win when one survives alone).
        for c in chunks:
            if len(c) < len(data) and still_fails(c):
                data, n = c, 2
                break
        else:
            # Then try removing one chunk at a time.
            for i in range(len(chunks)):
                complement = b"".join(chunks[:i] + chunks[i + 1:])
                if complement and len(complement) < len(data) and still_fails(complement):
                    data = complement
                    n = max(n - 1, 2)
                    break
            else:
                if n >= len(data):
                    break
                n = min(n * 2, len(data))
    return data, rounds


def minimize(record, reproducer: str, *, harness: str = "", stack_hash: str = "",
             timeout: int = DEFAULT_TIMEOUT_S, max_rounds: int = MAX_ROUNDS,
             max_probes: int = MAX_PROBES, workdir=None) -> Minimized:
    """Smallest input that still reproduces the SAME crash.

    `stack_hash` pins which bug must be preserved; without one it is taken
    from the original input's own replay.
    """
    src = Path(reproducer)
    if not src.is_file():
        raise MinimizeError(f"no such reproducer: {reproducer}")
    data = src.read_bytes()
    if not data:
        raise MinimizeError("reproducer is empty")

    t0 = time.monotonic()
    base = _replay.replay(record, reproducer, harness=harness, attempts=1,
                          timeout=timeout)
    if base.verdict == _replay.NO_CRASH:
        raise MinimizeError(
            f"the input does not reproduce on {base.variant} -- nothing to minimize")
    want = stack_hash or base.stack_hash
    if not want:
        raise MinimizeError("no stack hash to preserve; refusing to minimize blind")

    import tempfile
    tmp = tempfile.TemporaryDirectory() if workdir is None else None
    wd = Path(workdir or tmp.name)
    try:
        probe = _Probe(base.binary, want, timeout=timeout, workdir=wd,
                       max_probes=max_probes)
        reduced, rounds = ddmin(data, probe, max_rounds=max_rounds)
        # Never return something that does not reproduce: if the search ran out
        # of budget mid-step, fall back to the original rather than shipping a
        # smaller input nobody checked.
        limit = ""
        if probe.exhausted:
            limit = f"probe budget ({max_probes}) reached"
        elif rounds >= max_rounds:
            limit = f"round budget ({max_rounds}) reached"

        if reduced != data and not probe(reduced):
            # Ran out mid-step. Shipping a smaller input nobody checked is the
            # one outcome worse than not minimizing at all.
            reduced = data
            note = ((limit + "; ") if limit else "") + \
                "search ended on an unverified candidate, so the original was kept"
        elif limit:
            note = limit + "; this is the smallest verified input found so far"
        else:
            note = ""
    finally:
        if tmp is not None:
            tmp.cleanup()

    return Minimized(
        data=reduced, original_size=len(data), size=len(reduced),
        stack_hash=want, category=base.category, binary=base.binary,
        variant=base.variant, evidence_grade=base.evidence_grade,
        rounds=rounds, probes=probe.count, seconds=time.monotonic() - t0,
        reason=note, preserved=True)


def write(result: Minimized, path) -> Path:
    p = Path(path)
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_bytes(result.data)
    return p


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def _cmd_minimize(a):
    from cc_fuzzer_core.variants import harness_record
    try:
        record = harness_record(harness=a.harness)
        r = minimize(record, a.file, harness=a.harness, stack_hash=a.stack_hash,
                     timeout=a.timeout, max_rounds=a.max_rounds,
                     max_probes=a.max_probes)
    except (MinimizeError, _v.SelectionError, _replay.ReplayError) as e:
        print(f"error: {e}", file=sys.stderr)
        return 2
    out = a.output or (a.file + ".min")
    write(r, out)
    from dataclasses import replace as _replace
    r = _replace(r, path=str(out))
    if a.json:
        print(json.dumps(r.as_dict(), indent=2))
    else:
        pct = 100 * (1 - r.ratio)
        print(f"{r.original_size} -> {r.size} bytes ({pct:.0f}% smaller), "
              f"same bug {r.stack_hash} -> {out}")
        if r.reason:
            print(r.reason)
    return 0


def register_cli(subparsers):
    from cc_fuzzer_core.cli import add_subsystem
    _p, verbs = add_subsystem(subparsers, "minimize",
                              "Reduce a crash input, preserving the same bug.")
    v = verbs.add_parser("run", help="minimize a reproducer")
    v.add_argument("file")
    v.add_argument("--harness", default="")
    v.add_argument("--stack-hash", default="", help="the bug to preserve (default: the input's own)")
    v.add_argument("-o", "--output")
    v.add_argument("--timeout", type=int, default=DEFAULT_TIMEOUT_S)
    v.add_argument("--max-rounds", type=int, default=MAX_ROUNDS)
    v.add_argument("--max-probes", type=int, default=MAX_PROBES)
    v.add_argument("--json", action="store_true")
    v.set_defaults(func=_cmd_minimize)
