"""Deterministic crash replay (§4 stage 2).

The triager used to do this by hand: export the right ASAN_OPTIONS, run the
reproducer three times, read the output, and type the stack hash into a shell
command as `echo "<frames>" | sha256sum | cut -c1-16`. Three things could go
wrong in that, and did: the wrong binary (§12), a different sanitizer
configuration between runs, and a stack hash that depends on which frames the
model chose to type.

replay() does all three deterministically:

  - the binary comes from variants.select(..., "replay"), never from the
    caller. A crash "reproduced" on a cmplog or coverage binary is a statement
    about the instrumentation; when no verify binary was built, the fallback
    to the fuzzing binary is recorded as evidence_grade="weak" rather than
    passed off as the same thing.
  - every attempt runs with the same sanitizer options.
  - the stack hash is computed from the classified frames, so the same crash
    hashes the same whoever is looking at it.

Determinism is the verdict: a crash that fires on some attempts and not others
is `flaky`, which is a different answer from `not a crash`.

CLI: `cc-fuzzer crash replay <file> [--harness NAME] [--json]`.
"""
from __future__ import annotations

import hashlib
import json
import os
import sys
from dataclasses import dataclass, field

from cc_fuzzer_core import variants as _v
from cc_fuzzer_core.crash import classify as _classify

REPLAY_SCHEMA = "crash-replay/v1"
ATTEMPTS = 3
TIMEOUT_S = 30
STACK_HASH_LEN = 16
# Frames that go into the stack hash. Enough to tell two bugs apart, few
# enough that an unrelated caller does not change the hash.
HASH_FRAMES = 3

# Every attempt runs with these, so two attempts cannot differ because of the
# environment they inherited.
ASAN_OPTIONS = ("symbolize=1:abort_on_error=1:halt_on_error=1"
                ":print_stacktrace=1:detect_leaks=1")
UBSAN_OPTIONS = "halt_on_error=1:print_stacktrace=1:abort_on_error=1"

# verdicts
CRASH, FLAKY, NO_CRASH = "crash", "flaky", "no-crash"


class ReplayError(RuntimeError):
    pass


@dataclass(frozen=True)
class Attempt:
    n: int
    exit_code: int
    is_crash: bool
    category: str
    top_frame: str
    summary_line: str = ""

    def as_dict(self) -> dict:
        return {"attempt": self.n, "exit_code": self.exit_code, "is_crash": self.is_crash,
                "category": self.category, "top_frame": self.top_frame,
                "summary_line": self.summary_line}


@dataclass(frozen=True)
class Replay:
    verdict: str
    crashes: int
    attempts: int
    binary: str
    variant: str
    evidence_grade: str
    stack_hash: str = ""
    category: str = "none"
    top_frame: str = ""
    summary_line: str = ""
    reason: str = ""
    runs: tuple = field(default=())

    @property
    def deterministic(self) -> bool:
        return self.verdict == CRASH

    def as_dict(self) -> dict:
        return {
            "schema": REPLAY_SCHEMA,
            "verdict": self.verdict,
            "crashes": self.crashes,
            "attempts": self.attempts,
            "deterministic": self.deterministic,
            "binary": self.binary,
            "variant": self.variant,
            "evidence_grade": self.evidence_grade,
            "stack_hash": self.stack_hash,
            "category": self.category,
            "top_frame": self.top_frame,
            "summary_line": self.summary_line,
            "reason": self.reason,
            "runs": [r.as_dict() for r in self.runs],
        }


# ---------------------------------------------------------------------------
# stack hash
# ---------------------------------------------------------------------------

def frames(text: str, limit: int = HASH_FRAMES) -> list:
    """The first `limit` non-infrastructure frames, as classify sees them."""
    out = []
    for line in (text or "").splitlines():
        frame = _classify.top_frame([line])
        if frame and frame not in out:
            out.append(frame)
            if len(out) >= limit:
                break
    return out


def stack_hash(text: str, *, category: str = "") -> str:
    """A stable hash of the crash site. Computed, never typed: the triager
    used to pipe frames it had chosen by hand into sha256sum."""
    parts = frames(text)
    if not parts:
        parts = [category or "unknown"]
    joined = " ".join(parts)
    return hashlib.sha256(joined.encode("utf-8", "surrogateescape")).hexdigest()[:STACK_HASH_LEN]


# ---------------------------------------------------------------------------
# running
# ---------------------------------------------------------------------------

def run_once(binary: str, reproducer: str, *, timeout: int = TIMEOUT_S, env=None):
    """One attempt. Returns (exit_code, combined output)."""
    import subprocess
    run_env = dict(os.environ if env is None else env)
    run_env["ASAN_OPTIONS"] = ASAN_OPTIONS
    run_env["UBSAN_OPTIONS"] = UBSAN_OPTIONS
    try:
        p = subprocess.run([binary, reproducer], capture_output=True, timeout=timeout,
                           env=run_env)
    except subprocess.TimeoutExpired:
        return 124, f"TIMEOUT after {timeout}s"
    except OSError as e:
        raise ReplayError(f"cannot run {binary}: {e}") from None
    out = (p.stdout or b"") + (p.stderr or b"")
    return p.returncode, out.decode("utf-8", "surrogateescape")


def replay(record, reproducer: str, *, harness: str = "", attempts: int = ATTEMPTS,
           timeout: int = TIMEOUT_S, env=None) -> Replay:
    """Replay `reproducer` on the binary §12 selects for the replay action."""
    if not os.path.isfile(reproducer):
        raise ReplayError(f"no such reproducer: {reproducer}")
    sel = _v.select(record or {}, _v.A_REPLAY, harness=harness)
    if not os.access(sel.binary, os.X_OK):
        raise ReplayError(f"{sel.variant} binary is not executable: {sel.binary}")

    runs, crashes, last = [], 0, None
    for i in range(1, attempts + 1):
        rc, out = run_once(sel.binary, reproducer, timeout=timeout, env=env)
        cl = _classify.classify(out, rc)
        runs.append(Attempt(i, rc, cl.is_crash, cl.category, cl.top_frame, cl.summary_line))
        if cl.is_crash:
            crashes += 1
            last = (cl, out)

    if crashes == attempts:
        verdict, reason = CRASH, f"crashed on all {attempts} attempts"
    elif crashes:
        # Not the same as "no crash": the bug is real but the reproducer is
        # unreliable, and that is what routes it to crashes/flaky/.
        verdict, reason = FLAKY, f"crashed on {crashes} of {attempts} attempts"
    else:
        verdict, reason = NO_CRASH, f"did not crash in {attempts} attempts"

    cl, out = last if last else (None, "")
    return Replay(
        verdict=verdict, crashes=crashes, attempts=attempts,
        binary=sel.binary, variant=sel.variant, evidence_grade=sel.evidence_grade,
        stack_hash=stack_hash(out, category=cl.category if cl else "") if cl else "",
        category=cl.category if cl else "none",
        top_frame=cl.top_frame if cl else "",
        summary_line=cl.summary_line if cl else "",
        reason=reason if sel.evidence_grade == _v.STRONG else f"{reason}; {sel.reason}",
        runs=tuple(runs),
    )


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def _cmd_replay(a):
    from cc_fuzzer_core.variants import harness_record
    try:
        record = harness_record(harness=a.harness)
    except Exception as e:
        print(f"error: {e}", file=sys.stderr)
        return 2
    if a.binary:
        # §12: naming a binary is allowed only when it is the selected one.
        try:
            _v.check_binary(record, _v.A_REPLAY, a.binary, harness=a.harness)
        except _v.SelectionError as e:
            print(f"error: {e}", file=sys.stderr)
            return 2
    try:
        r = replay(record, a.file, harness=a.harness, attempts=a.attempts,
                   timeout=a.timeout)
    except (ReplayError, _v.SelectionError) as e:
        print(f"error: {e}", file=sys.stderr)
        return 2
    if a.json:
        print(json.dumps(r.as_dict(), indent=2))
    else:
        print(f"{r.verdict} ({r.crashes}/{r.attempts}) on {r.variant} [{r.evidence_grade}]")
        if r.stack_hash:
            print(f"stack_hash {r.stack_hash}  {r.category}  {r.top_frame}")
    return 0 if r.deterministic else 1


def register_verb(verbs):
    v = verbs.add_parser("replay", help="replay a crash on the binary §12 selects")
    v.add_argument("file", help="the reproducer")
    v.add_argument("--harness", default="")
    v.add_argument("--binary", help="refused unless it is the selected binary")
    v.add_argument("--attempts", type=int, default=ATTEMPTS)
    v.add_argument("--timeout", type=int, default=TIMEOUT_S)
    v.add_argument("--json", action="store_true")
    v.set_defaults(func=_cmd_replay)
