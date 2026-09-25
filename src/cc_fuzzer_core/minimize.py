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

CLI: `cc-fuzzer minimize run <file> [--harness NAME] [-o OUT] [--json]`, and
`cc-fuzzer minimize sensitivity <file>` for the byte map (see sensitivity()).
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


# probe outcomes
SAME, NONE, OTHER = "same", "none", "other"


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

    def outcome(self, data: bytes) -> tuple:
        """Run a candidate: (SAME|NONE|OTHER, stack_hash, category).

        Returns (None, "", "") without running anything when the budget is
        spent, so callers can tell "not probed" from "probed, no crash".
        """
        if self.exhausted:
            return None, "", ""
        if not data:
            return NONE, "", ""
        self.count += 1
        p = self.workdir / "candidate.bin"
        p.write_bytes(data)
        rc, out = _replay.run_once(self.binary, str(p), timeout=self.timeout)
        from cc_fuzzer_core.crash import classify as _classify
        cl = _classify.classify(out, rc)
        if not cl.is_crash:
            return NONE, "", ""
        h = _replay.stack_hash(out, category=cl.category)
        return (SAME if h == self.want else OTHER), h, cl.category

    def __call__(self, data: bytes) -> bool:
        # The invariant: a crash somewhere else is a different finding, and
        # accepting it would swap the bug out from under the report.
        return self.outcome(data)[0] == SAME


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
# sensitivity: which of the remaining bytes actually decide the bug?
# ---------------------------------------------------------------------------
#
# ddmin answers "what is the shortest input that still shows this bug". It
# does not answer "which of those bytes matter". A 12-byte PoV is typically a
# few bytes of framing the parser needs to get anywhere, and a few bytes that
# decide the faulting operand. Whoever writes the patch needs the second set:
# it is the value the missing check should have rejected.
#
# So, after minimizing, mutate each byte in place and ask the same question
# the minimizer asks -- same bug, yes or no -- and classify the byte by how
# many mutations it survives. Length is left alone: ddmin already settled it.
#
# Two mutations per byte, chosen so they always differ from the original:
#   b ^ 0xFF  a large change: any exact-value check (magic, tag, opcode) fails
#   b ^ 0x01  a one-bit change: survives a range check (a length that only has
#             to exceed a bound), which is what separates `#` from `~`
#
# A mutation that crashes ELSEWHERE is not noise: it is a neighbouring bug on
# the same path, reported with the offsets that reach it.

SENSITIVITY_SCHEMA = "input-sensitivity/v1"
MUTATIONS = (0xFF, 0x01)
# Two probes per byte, so this covers a 512-byte input. Anything longer should
# be minimized first; the bytes past the budget are reported as unknown rather
# than guessed.
SENSITIVITY_MAX_PROBES = 1024

LOAD_BEARING, CONSTRAINED, FREE, UNKNOWN = "load_bearing", "constrained", "free", "unknown"
MARK = {LOAD_BEARING: "#", CONSTRAINED: "~", FREE: ".", UNKNOWN: "?"}


@dataclass(frozen=True)
class Span:
    start: int
    end: int            # exclusive
    cls: str
    hex: str

    def as_dict(self) -> dict:
        return {"start": self.start, "end": self.end, "class": self.cls,
                "mark": MARK[self.cls], "hex": self.hex}


@dataclass(frozen=True)
class Sensitivity:
    size: int = 0
    stack_hash: str = ""
    category: str = ""
    binary: str = ""
    variant: str = ""
    evidence_grade: str = ""
    mask: str = ""      # one mark per byte, see MARK
    spans: tuple = ()
    neighbours: tuple = ()
    probes: int = 0
    seconds: float = 0.0
    reason: str = ""

    @property
    def complete(self) -> bool:
        return MARK[UNKNOWN] not in self.mask

    def offsets(self, cls: str) -> list:
        return [i for i, m in enumerate(self.mask) if m == MARK[cls]]

    def counts(self) -> dict:
        return {c: self.mask.count(MARK[c]) for c in MARK}

    def as_dict(self) -> dict:
        return {"schema": SENSITIVITY_SCHEMA, "size": self.size,
                "stack_hash": self.stack_hash, "category": self.category,
                "binary": self.binary, "variant": self.variant,
                "evidence_grade": self.evidence_grade,
                "mutations": [f"xor 0x{m:02x}" for m in MUTATIONS],
                "mask": self.mask, "legend": {v: k for k, v in MARK.items()},
                "counts": self.counts(), "complete": self.complete,
                "spans": [sp.as_dict() for sp in self.spans],
                "neighbours": list(self.neighbours),
                "probes": self.probes, "seconds": round(self.seconds, 3),
                "reason": self.reason}


def classify_byte(outcomes) -> str:
    """Outcomes of every mutation of one byte -> its class.

    A crash elsewhere counts as losing the bug: the byte still decided which
    bug this input shows.
    """
    if not outcomes or any(o is None for o in outcomes):
        return UNKNOWN
    kept = sum(1 for o in outcomes if o == SAME)
    if kept == len(outcomes):
        return FREE
    return LOAD_BEARING if kept == 0 else CONSTRAINED


def _spans(data: bytes, classes) -> tuple:
    out, start = [], 0
    for i in range(1, len(classes) + 1):
        if i == len(classes) or classes[i] != classes[start]:
            out.append(Span(start, i, classes[start], data[start:i].hex()))
            start = i
    return tuple(out)


def sensitivity(record, reproducer: str, *, harness: str = "", stack_hash: str = "",
                timeout: int = DEFAULT_TIMEOUT_S,
                max_probes: int = SENSITIVITY_MAX_PROBES, workdir=None) -> Sensitivity:
    """Map which bytes of a (minimized) reproducer decide THE SAME bug.

    Deterministic, like minimize(): same input and binary, same map.
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
            f"the input does not reproduce on {base.variant} -- nothing to map")
    want = stack_hash or base.stack_hash
    if not want:
        raise MinimizeError("no stack hash to preserve; refusing to map blind")
    if base.stack_hash and base.stack_hash != want:
        raise MinimizeError(
            f"the input shows bug {base.stack_hash}, not the pinned {want}")

    import tempfile
    tmp = tempfile.TemporaryDirectory() if workdir is None else None
    wd = Path(workdir or tmp.name)
    classes, others = [], {}
    try:
        probe = _Probe(base.binary, want, timeout=timeout, workdir=wd,
                       max_probes=max_probes)
        buf = bytearray(data)
        for i, b in enumerate(data):
            outcomes = []
            for m in MUTATIONS:
                buf[i] = b ^ m
                kind, h, cat = probe.outcome(bytes(buf))
                outcomes.append(kind)
                if kind == OTHER:
                    n = others.setdefault(h, {"stack_hash": h, "category": cat,
                                              "offsets": []})
                    if i not in n["offsets"]:
                        n["offsets"].append(i)
            buf[i] = b
            classes.append(classify_byte(outcomes))
    finally:
        if tmp is not None:
            tmp.cleanup()

    reason = ""
    if UNKNOWN in classes:
        first = classes.index(UNKNOWN)
        reason = (f"probe budget ({max_probes}) reached at offset {first} of "
                  f"{len(data)}; minimize first, or raise the budget")
    return Sensitivity(
        size=len(data), stack_hash=want, category=base.category,
        binary=base.binary, variant=base.variant,
        evidence_grade=base.evidence_grade,
        mask="".join(MARK[c] for c in classes), spans=_spans(data, classes),
        neighbours=tuple(sorted(others.values(), key=lambda n: n["offsets"][0])),
        probes=probe.count, seconds=time.monotonic() - t0, reason=reason)


def render(s: Sensitivity, data: bytes, width: int = 16) -> str:
    """Hex dump with the mask underneath, for a human reading a PoV."""
    lines = []
    for off in range(0, len(data), width):
        row = data[off:off + width]
        lines.append(f"{off:08x}  {' '.join(f'{c:02x}' for c in row)}")
        lines.append(f"{'':8}  {' '.join(f' {m}' for m in s.mask[off:off + width])}")
    return "\n".join(lines)


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


def _cmd_sensitivity(a):
    from cc_fuzzer_core.variants import harness_record
    try:
        record = harness_record(harness=a.harness)
        r = sensitivity(record, a.file, harness=a.harness, stack_hash=a.stack_hash,
                        timeout=a.timeout, max_probes=a.max_probes)
    except (MinimizeError, _v.SelectionError, _replay.ReplayError) as e:
        print(f"error: {e}", file=sys.stderr)
        return 2
    if a.json:
        print(json.dumps(r.as_dict(), indent=2))
    else:
        c = r.counts()
        print(f"bug {r.stack_hash}: {c[LOAD_BEARING]} load-bearing, "
              f"{c[CONSTRAINED]} constrained, {c[FREE]} free, {c[UNKNOWN]} unknown "
              f"of {r.size} bytes ({r.probes} probes)")
        print(render(r, Path(a.file).read_bytes()))
        for n in r.neighbours:
            print(f"neighbour {n['stack_hash']} ({n['category']}) via offsets {n['offsets']}")
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

    s = verbs.add_parser("sensitivity",
                         help="map which bytes of a PoV decide the bug")
    s.add_argument("file")
    s.add_argument("--harness", default="")
    s.add_argument("--stack-hash", default="", help="the bug to map (default: the input's own)")
    s.add_argument("--timeout", type=int, default=DEFAULT_TIMEOUT_S)
    s.add_argument("--max-probes", type=int, default=SENSITIVITY_MAX_PROBES)
    s.add_argument("--json", action="store_true")
    s.set_defaults(func=_cmd_sensitivity)
