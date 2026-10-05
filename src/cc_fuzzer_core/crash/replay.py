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

screen= is the fast path for a fuzzer's raw artifacts: the first attempt's
cause (classify.cause) must be one the caller wants, or replay stops there
with verdict "screened" (or "no-crash"). A harness that calls exit() then
costs one run, not three plus minimization.

Determinism is the verdict: a crash that fires on some attempts and not others
is `flaky`, which is a different answer from `not a crash`.

CLI: `cc-fuzzer crash replay <file> [--harness NAME] [--json]`.
"""
from __future__ import annotations

import hashlib
import json
import os
import re
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
# Frames REPORTED (not hashed): enough for a patch author to see the path in.
REPORT_FRAMES = 12
# The sanitizer report handed downstream is bounded: it goes into JSON records
# and prompts, and the useful part is the head of the report.
EXCERPT_MAX_LINES = 60
EXCERPT_MAX_CHARS = 6000

# Every attempt runs with these, so two attempts cannot differ because of the
# environment they inherited. handle_sigill=1 as in OSS-Fuzz's runner: a trap
# (ud2) is reported as "AddressSanitizer: ILL", the signature a benchmark's
# oracle expects (AIxCC faad2's cpv_1); without it libFuzzer's fallback handler
# printed only "deadly signal" and the crash read as not_a_crash.
ASAN_OPTIONS = ("symbolize=1:abort_on_error=1:halt_on_error=1"
                ":print_stacktrace=1:detect_leaks=1:handle_sigill=1")
# silence_unsigned_overflow=1 as OSS-Fuzz and its scorers run UBSan builds:
# unsigned wrap-around is not undefined behaviour, and without it a replay
# stops at the first harmless wrap (then minimizes toward it) instead of
# the signed overflow the fuzzer found.
UBSAN_OPTIONS = ("halt_on_error=1:print_stacktrace=1:abort_on_error=1:"
                 "silence_unsigned_overflow=1")

# verdicts
CRASH, FLAKY, NO_CRASH, SCREENED = "crash", "flaky", "no-crash", "screened"


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
    frames: tuple = field(default=())   # up to REPORT_FRAMES, top first
    excerpt: str = ""                   # the sanitizer report, bounded
    sanitizer: str = ""                 # which detector reported it (sanitizer_of)
    cause: str = ""                     # classify.cause of the first run

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
            "frames": list(self.frames),
            "excerpt": self.excerpt,
            "sanitizer": self.sanitizer,
            "cause": self.cause,
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


_REPORT_START = re.compile(
    r"==\d+==\s*ERROR:|runtime error:|^\s*(?:WARNING|ERROR): \w+Sanitizer|"
    r"==\d+== ?ERROR: libFuzzer|^SUMMARY:", re.M)


def excerpt(text: str, *, max_lines: int = EXCERPT_MAX_LINES,
            max_chars: int = EXCERPT_MAX_CHARS) -> str:
    """The sanitizer report out of a run's output: from the first report line
    through SUMMARY, bounded. Falls back to the tail when there is no report
    header (a bare abort, a timeout)."""
    lines = (text or "").splitlines()
    start = next((i for i, ln in enumerate(lines) if _REPORT_START.search(ln)), None)
    if start is None:
        body = lines[-min(len(lines), 20):]
    else:
        body = []
        for ln in lines[start:]:
            body.append(ln)
            if ln.startswith("SUMMARY:") and len(body) > 1:
                break
    out = "\n".join(body[:max_lines])
    return out[:max_chars]


# The detector that reported a crash, by the first name in the report.
_SANITIZERS = (("AddressSanitizer", "address"), ("MemorySanitizer", "memory"),
               ("LeakSanitizer", "leak"), ("ThreadSanitizer", "thread"),
               ("UndefinedBehaviorSanitizer", "undefined"), (": runtime error: ", "undefined"),
               ("libFuzzer: timeout", "libfuzzer"), ("libFuzzer: out-of-memory", "libfuzzer"),
               ("libFuzzer: deadly signal", "libfuzzer"))


def sanitizer_of(text: str) -> str:
    """"address" | "memory" | "leak" | "thread" | "undefined" | "libfuzzer" | ""
    -- whichever detector's name appears FIRST (a leak report ends with an
    AddressSanitizer SUMMARY line; its header names LeakSanitizer)."""
    best, pos = "", None
    for needle, name in _SANITIZERS:
        i = (text or "").find(needle)
        if i >= 0 and (pos is None or i < pos):
            best, pos = name, i
    return best


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

_LOADER_ERROR = re.compile(r"error while loading shared libraries: [^\n]*")


def run_once(binary: str, reproducer: str, *, timeout: int = TIMEOUT_S, env=None):
    """One attempt. Returns (exit_code, combined output)."""
    import subprocess
    run_env = dict(os.environ if env is None else env)
    run_env["ASAN_OPTIONS"] = ASAN_OPTIONS
    run_env["UBSAN_OPTIONS"] = UBSAN_OPTIONS
    try:
        p = subprocess.run([binary, reproducer], capture_output=True, timeout=timeout,
                           env=run_env, stdin=subprocess.DEVNULL)
    except subprocess.TimeoutExpired as e:
        # The target can print a complete sanitizer report and then hang in its
        # crash handler instead of aborting (an ASan self-re-exec deadlock seen
        # when the binary is run directly on some kernels/containers). Discarding
        # the output here made a real crash read as not_a_crash. Keep whatever was
        # captured before the kill so classify() can still see the report; a
        # genuine no-output timeout still classifies as not-a-crash.
        partial = (e.stdout or b"") + (e.stderr or b"")
        text = partial.decode("utf-8", "surrogateescape")
        return 124, text if text.strip() else f"TIMEOUT after {timeout}s"
    except OSError as e:
        raise ReplayError(f"cannot run {binary}: {e}") from None
    out = (p.stdout or b"") + (p.stderr or b"")
    text = out.decode("utf-8", "surrogateescape")
    if p.returncode == 127 and _LOADER_ERROR.search(text):
        # The binary never started (a shared library this host lacks): that
        # says nothing about the input. Reported as "did not crash" it hid a
        # runtime image built on the wrong OS for the target (libssl.so.1.1).
        raise ReplayError(f"{binary} cannot run here: {_LOADER_ERROR.search(text).group(0)}")
    return p.returncode, text


def replay(record, reproducer: str, *, harness: str = "", attempts: int = ATTEMPTS,
           timeout: int = TIMEOUT_S, env=None, screen=None) -> Replay:
    """Replay `reproducer` on the binary §12 selects for the replay action.
    `screen`, when given, is the causes worth more than one run (module
    docstring)."""
    if not os.path.isfile(reproducer):
        raise ReplayError(f"no such reproducer: {reproducer}")
    if screen is not None:
        unknown = sorted(set(screen) - set(_classify.CAUSES))
        if unknown:
            raise ReplayError(f"unknown screen cause(s): {', '.join(unknown)} "
                              f"(known: {', '.join(_classify.CAUSES)})")
    sel = _v.select(record or {}, _v.A_REPLAY, harness=harness)
    if not os.access(sel.binary, os.X_OK):
        raise ReplayError(f"{sel.variant} binary is not executable: {sel.binary}")

    runs, crashes, last, first_cause, screened = [], 0, None, "", False
    for i in range(1, attempts + 1):
        rc, out = run_once(sel.binary, reproducer, timeout=timeout, env=env)
        cl = _classify.classify(out, rc)
        runs.append(Attempt(i, rc, cl.is_crash, cl.category, cl.top_frame, cl.summary_line))
        if cl.is_crash:
            crashes += 1
            last = (cl, out)
        if i == 1:
            first_cause = _classify.cause(out, rc)
            if screen is not None and first_cause not in screen:
                attempts, screened = 1, True
                break

    if screened:
        verdict = SCREENED if crashes else NO_CRASH
        reason = f"screened out after one run: {first_cause} (screen keeps {', '.join(screen) or 'nothing'})"
    elif crashes == attempts:
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
        frames=tuple(frames(out, limit=REPORT_FRAMES)) if cl else (),
        excerpt=excerpt(out) if cl else "",
        sanitizer=sanitizer_of(out) if cl else "",
        cause=first_cause,
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
