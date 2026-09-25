"""The swappable last step of crash verification (§4 stage 3).

The first two pipeline stages are fixed and portable: the artifact filter, and
the deterministic replay (crash/replay.py). What counts as FINAL confirmation
is not universal, so it is chosen by `fuzz-config.json`:

    "verification": {"final_step": "poc-realism", "timeout_s": 600}

  poc-realism              the default and what the plugin has always done: a
                           mechanical reproducer, a verifier that exits 0 only
                           when a trust boundary is crossed, and the realism
                           statements. Agent-backed, so the loop dispatches
                           poc-builder to produce it; the core checks it.
  command:<path>           an external executable. It is handed a
                           verify-request/v1 on stdin and must answer with a
                           verify-verdict/v1 on stdout. This is how a
                           downstream harness plugs its own oracle in without
                           the core knowing anything about it.
  python:<module>:<call>   an in-process callable, for a host that already has
                           its oracle as a Python function.

An oracle can also be declared AUTHORITATIVE:

    "verification": {"final_step": "command:/opt/run-pov-oracle", "authoritative": true}

That is the host saying "my oracle reproduces on the reference build, so its
confirmation is submission-grade evidence on its own". It matters when every
binary the core can see is a fuzzing build (OSS-CRS ships libFuzzer builds
only): local replay then grades `weak`, and without this nothing could ever be
submittable even though the scoring oracle itself confirmed it. It is ignored
for poc-realism, which is the core checking an agent's work, not an oracle.

A Verdict is confirmed | rejected | inconclusive. `inconclusive` is a real
answer, deliberately not folded into `rejected`: "the oracle could not decide"
and "the oracle says no" lead to different next actions, and collapsing them
turns every timeout into a dismissal.
"""
from __future__ import annotations

import json
from dataclasses import dataclass, field
from typing import Mapping

REQUEST_SCHEMA = "verify-request/v1"
VERDICT_SCHEMA = "verify-verdict/v1"

CONFIRMED, REJECTED, INCONCLUSIVE = "confirmed", "rejected", "inconclusive"
STATUSES = (CONFIRMED, REJECTED, INCONCLUSIVE)

DEFAULT_STEP = "poc-realism"
DEFAULT_TIMEOUT_S = 600
ENTRY_POINT_GROUP = "cc_fuzzer.verifiers"


class VerifierError(RuntimeError):
    pass


@dataclass(frozen=True)
class Verdict:
    status: str
    reason: str = ""
    evidence: tuple = field(default=())
    attestation: dict = field(default_factory=dict)
    step: str = ""

    def __post_init__(self):
        if self.status not in STATUSES:
            raise VerifierError(
                f"verdict status {self.status!r} is not one of {', '.join(STATUSES)}")

    @property
    def confirmed(self) -> bool:
        return self.status == CONFIRMED

    def as_dict(self) -> dict:
        return {"schema": VERDICT_SCHEMA, "status": self.status, "reason": self.reason,
                "evidence": list(self.evidence), "attestation": dict(self.attestation),
                "step": self.step}

    @classmethod
    def from_dict(cls, doc: Mapping, *, step: str = "") -> "Verdict":
        if not isinstance(doc, Mapping):
            raise VerifierError(f"expected a {VERDICT_SCHEMA} object, got {type(doc).__name__}")
        schema = doc.get("schema")
        if schema and schema != VERDICT_SCHEMA:
            raise VerifierError(f"expected {VERDICT_SCHEMA}, got {schema!r}")
        status = doc.get("status")
        if status not in STATUSES:
            raise VerifierError(
                f"verdict status {status!r} is not one of {', '.join(STATUSES)}")
        ev = doc.get("evidence") or []
        if not isinstance(ev, (list, tuple)):
            raise VerifierError("verdict evidence must be a list of paths")
        att = doc.get("attestation") or {}
        if not isinstance(att, Mapping):
            raise VerifierError("verdict attestation must be an object")
        return cls(status, doc.get("reason") or "", tuple(str(e) for e in ev),
                   dict(att), step or str(doc.get("step") or ""))


def request(finding: Mapping, ctx: Mapping) -> dict:
    """The verify-request/v1 an external verifier is handed."""
    return {
        "schema": REQUEST_SCHEMA,
        "finding": dict(finding or {}),
        "harness": ctx.get("harness", ""),
        "reproducer": ctx.get("reproducer", ""),
        "binaries": dict(ctx.get("binaries") or {}),
        "replay": dict(ctx.get("replay") or {}),
        "project_root": ctx.get("project_root", ""),
        "timeout_s": ctx.get("timeout_s", DEFAULT_TIMEOUT_S),
    }


# ---------------------------------------------------------------------------
# choosing one
# ---------------------------------------------------------------------------

def step_of(config: Mapping | None) -> str:
    block = (config or {}).get("verification") or {}
    if not isinstance(block, Mapping):
        raise VerifierError("fuzz-config.json: verification must be an object")
    return str(block.get("final_step") or DEFAULT_STEP)


def timeout_of(config: Mapping | None) -> int:
    block = (config or {}).get("verification") or {}
    if not isinstance(block, Mapping):
        return DEFAULT_TIMEOUT_S
    try:
        return max(1, int(block.get("timeout_s", DEFAULT_TIMEOUT_S)))
    except (TypeError, ValueError):
        return DEFAULT_TIMEOUT_S


def authoritative(config: Mapping | None) -> bool:
    """True when the configured final step is an oracle whose confirmation is
    submission-grade evidence by itself (see module docstring)."""
    block = (config or {}).get("verification") or {}
    if not isinstance(block, Mapping) or block.get("authoritative") is not True:
        return False
    return not is_agent_backed(step_of(config))


# where a finding's evidence grade came from
SOURCE_REPLAY, SOURCE_ORACLE = "replay", "oracle"


def evidence(replay_grade: str, verdict: "Verdict", config: Mapping | None) -> tuple:
    """(grade, source) for a verdict on top of a local replay.

    Only an authoritative oracle's CONFIRMATION upgrades the grade. A local
    replay's `strong` is never downgraded, and an oracle that rejects or
    cannot decide adds nothing.
    """
    from cc_fuzzer_core import variants as _v
    if verdict.status == CONFIRMED and authoritative(config) and replay_grade != _v.STRONG:
        return _v.STRONG, SOURCE_ORACLE
    return replay_grade, SOURCE_REPLAY


def is_agent_backed(step: str) -> bool:
    """True when the verdict needs an agent to produce the evidence first, so
    the loop must dispatch one rather than call the verifier inline."""
    return step == DEFAULT_STEP


def resolve(step: str):
    """The verifier callable for `step`: verify(finding, ctx) -> Verdict."""
    step = (step or DEFAULT_STEP).strip()
    if step == DEFAULT_STEP:
        from cc_fuzzer_core.crash.verifiers import realism
        return realism.verify
    if step.startswith("command:"):
        from cc_fuzzer_core.crash.verifiers import command
        return command.make(step[len("command:"):])
    if step.startswith("python:"):
        return _python_verifier(step[len("python:"):])
    fn = _entry_point(step)
    if fn is not None:
        return fn
    raise VerifierError(
        f"unknown verification.final_step {step!r}: expected '{DEFAULT_STEP}', "
        f"'command:<path>', 'python:<module>:<callable>', or a name registered "
        f"under the {ENTRY_POINT_GROUP} entry point group")


def _python_verifier(spec: str):
    mod, sep, attr = spec.partition(":")
    if not sep or not mod or not attr:
        raise VerifierError(f"python verifier must be 'module:callable', got {spec!r}")
    from importlib import import_module
    try:
        target = import_module(mod)
    except ImportError as e:
        raise VerifierError(f"cannot import verifier module {mod!r}: {e}") from None
    for part in attr.split("."):
        target = getattr(target, part, None)
        if target is None:
            raise VerifierError(f"{mod} has no attribute {attr!r}")
    if not callable(target):
        raise VerifierError(f"{spec} is not callable")
    return target


def _entry_point(name: str):
    try:
        from importlib.metadata import entry_points
    except ImportError:  # pragma: no cover
        return None
    try:
        eps = entry_points()
        group = eps.select(group=ENTRY_POINT_GROUP) if hasattr(eps, "select") \
            else eps.get(ENTRY_POINT_GROUP, [])
        for ep in group:
            if ep.name == name:
                return ep.load()
    except Exception:
        return None
    return None


def verify(finding: Mapping, ctx: Mapping, *, config: Mapping | None = None) -> Verdict:
    """Run the configured final step."""
    step = ctx.get("step") or step_of(config)
    fn = resolve(step)
    ctx = {**ctx, "step": step, "timeout_s": ctx.get("timeout_s") or timeout_of(config)}
    out = fn(finding, ctx)
    if isinstance(out, Verdict):
        return out if out.step else Verdict(out.status, out.reason, out.evidence,
                                            out.attestation, step)
    if isinstance(out, Mapping):
        return Verdict.from_dict(out, step=step)
    raise VerifierError(f"verifier {step!r} returned {type(out).__name__}, not a verdict")
