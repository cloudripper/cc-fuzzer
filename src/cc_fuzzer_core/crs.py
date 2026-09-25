"""The surface a CRS actually needs, and nothing else.

A CRS already owns the things cc-fuzzer's plugin has to provide for itself: a
scheduler, fuzzer lifecycle, corpus sync across harnesses, and a listener that
hears about crashes as they happen. It does not need `loop.step()`, and
driving one campaign a tick at a time is the wrong shape for a system running
many harnesses under its own orchestration.

What is worth importing is the judgement that sits either side of the fuzzer,
in two request/response seams:

    triage(record, crash)      a crash arrived. Is it real, which bug is it,
                               what is the smallest input that shows it, and
                               does the oracle confirm it?
    check_patch(record, ...)   a patch was written. Does it stop the PoV
                               without breaking the program?

Both exist because the expensive mistake in a scored run is submitting
something that is not true. Triage protects the finding; check_patch protects
the fix. Neither takes a tick, a current.json, or a scheduler -- `triage`
needs one dict describing where the binaries are.

    from cc_fuzzer_core import crs

    r = crs.triage({"verify_binary": "/out/parser_verify"}, "/crashes/x.bin",
                   harness="parser", config=cfg)
    if r.submittable:
        submit(r.pov, r.stack_hash)      # r.pov is the MINIMIZED input
        hand_to_patcher(r.sensitivity)   # which of its bytes decide the bug

The corpus helpers are the other half: quarantine before promoting a seed,
harvest a dictionary, find the delta targets a diff implies. They are
deliberately thin -- generating seeds and harnesses is a model's job, and the
core supplies the prompts for that (see cc_fuzzer_core.prompts), not a
service that pretends to do it deterministically.
"""
from __future__ import annotations

import json
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Mapping

from cc_fuzzer_core import minimize as _minimize
from cc_fuzzer_core import patch as _patch
from cc_fuzzer_core import variants as _v
from cc_fuzzer_core.crash import pipeline as _pipeline
from cc_fuzzer_core.crash import replay as _replay
from cc_fuzzer_core.crash import verifiers as _verifiers

TRIAGE_SCHEMA = "triage-result/v1"

# outcomes
CONFIRMED, REJECTED, INCONCLUSIVE, NOT_A_CRASH, FLAKY = (
    "confirmed", "rejected", "inconclusive", "not_a_crash", "flaky")


@dataclass(frozen=True)
class TriageResult:
    status: str
    reason: str = ""
    pov: str = ""                 # the MINIMIZED reproducer, when there is one
    original_pov: str = ""
    stack_hash: str = ""
    category: str = ""
    top_frame: str = ""
    binary: str = ""
    variant: str = ""
    evidence_grade: str = ""      # after the oracle: see evidence_source
    evidence_source: str = ""     # "replay" or "oracle" (an authoritative one)
    replay_grade: str = ""        # what local replay alone established
    verdict_step: str = ""
    original_size: int = 0
    size: int = 0
    marker: str = ""
    directory: str = ""
    replay: dict = field(default_factory=dict)
    minimized: dict = field(default_factory=dict)
    sensitivity: dict = field(default_factory=dict)

    @property
    def submittable(self) -> bool:
        """Confirmed by the configured oracle AND resting on real evidence.

        `weak` means the crash was only shown on the fuzzing binary because no
        verify binary was built -- usable for triage, not for a submission --
        unless an oracle declared `authoritative` confirmed it, which upgrades
        the grade (evidence_source="oracle").
        """
        return self.status == CONFIRMED and self.evidence_grade == _v.STRONG

    def as_dict(self) -> dict:
        return {"schema": TRIAGE_SCHEMA, "status": self.status,
                "submittable": self.submittable, "reason": self.reason,
                "pov": self.pov, "original_pov": self.original_pov,
                "stack_hash": self.stack_hash, "category": self.category,
                "top_frame": self.top_frame, "binary": self.binary,
                "variant": self.variant, "evidence_grade": self.evidence_grade,
                "evidence_source": self.evidence_source,
                "replay_grade": self.replay_grade,
                "verdict_step": self.verdict_step,
                "original_size": self.original_size, "size": self.size,
                "marker": self.marker, "directory": self.directory,
                "replay": self.replay, "minimized": self.minimized,
                "sensitivity": self.sensitivity}


# ---------------------------------------------------------------------------
# the crash seam
# ---------------------------------------------------------------------------

def triage(record: Mapping, crash: str, *, harness: str = "",
           config: Mapping | None = None, campaign=None, finding_id: str = "",
           finding: Mapping | None = None, do_minimize: bool = True,
           attempts: int = _replay.ATTEMPTS, timeout: int = _replay.TIMEOUT_S,
           minimize_probes: int = _minimize.MAX_PROBES,
           do_sensitivity: bool = True,
           sensitivity_probes: int = _minimize.SENSITIVITY_MAX_PROBES) -> TriageResult:
    """A crash arrived. Decide what it is, in one call.

      1. replay it deterministically on the binary §12 selects
      2. reduce it to the smallest input showing THE SAME bug
      3. hand it to the configured final verifier (your oracle)
      4. if confirmed, map which of its bytes decide the bug (sensitivity)
      5. if confirmed and a campaign was given, write the finding marker

    Step 4 runs only on confirmed bugs: it costs two probes per byte and its
    reader is whoever writes the patch, so there is nobody to spend it on for
    a rejected crash.

    A flaky reproducer stops at step 1: it is a real bug with an unreliable
    trigger, which is a different thing from a finding, and minimizing it
    would be measuring noise.
    """
    r = _replay.replay(record, crash, harness=harness, attempts=attempts,
                       timeout=timeout)
    base = {"replay": r.as_dict(), "original_pov": crash,
            "stack_hash": r.stack_hash, "category": r.category,
            "top_frame": r.top_frame, "binary": r.binary, "variant": r.variant,
            "evidence_grade": r.evidence_grade, "replay_grade": r.evidence_grade,
            "evidence_source": _verifiers.SOURCE_REPLAY,
            "original_size": Path(crash).stat().st_size if Path(crash).is_file() else 0}

    if r.verdict == _replay.NO_CRASH:
        return TriageResult(NOT_A_CRASH, r.reason, pov=crash, size=base["original_size"], **base)
    if r.verdict == _replay.FLAKY:
        return TriageResult(FLAKY, r.reason + "; an unreliable trigger is not yet a finding",
                            pov=crash, size=base["original_size"], **base)

    pov, mini = crash, {}
    if do_minimize:
        try:
            m = _minimize.minimize(record, crash, harness=harness,
                                   stack_hash=r.stack_hash, timeout=timeout,
                                   max_probes=minimize_probes)
            out = Path(crash).with_suffix(Path(crash).suffix + ".min")
            _minimize.write(m, out)
            pov, mini = str(out), m.as_dict()
        except _minimize.MinimizeError:
            # Minimization is an improvement, never a gate: a crash that
            # cannot be reduced is still a crash.
            mini = {}

    ctx = {"harness": harness, "reproducer": pov,
           "binaries": {f: record.get(f) for f in _v.BINARY_FIELD.values() if record.get(f)},
           "replay": r.as_dict(), "config": config,
           "project_root": str(getattr(campaign, "project_root", "") or "")}
    v = _verifiers.verify(finding or {"stack_hash": r.stack_hash}, ctx, config=config)

    size = Path(pov).stat().st_size if Path(pov).is_file() else base["original_size"]
    common = {**base, "pov": pov, "size": size, "minimized": mini,
              "verdict_step": v.step}
    if v.status != _verifiers.CONFIRMED:
        status = REJECTED if v.status == _verifiers.REJECTED else INCONCLUSIVE
        return TriageResult(status, v.reason, **common)

    common["evidence_grade"], common["evidence_source"] = _verifiers.evidence(
        r.evidence_grade, v, config)

    sens = {}
    if do_sensitivity:
        try:
            sens = _minimize.sensitivity(record, pov, harness=harness,
                                         stack_hash=r.stack_hash, timeout=timeout,
                                         max_probes=sensitivity_probes).as_dict()
        except _minimize.MinimizeError:
            # Like minimization: an improvement to the evidence, never a gate.
            sens = {}
    common["sensitivity"] = sens

    marker = directory = ""
    if campaign is not None and finding_id:
        f = _pipeline.finalize(campaign, finding_id,
                               finding or {"id": finding_id, "stack_hash": r.stack_hash},
                               record=record, reproducer=pov, config=config,
                               harness=harness, replay_result=r.as_dict(),
                               # the oracle already answered; do not ask twice
                               verify_fn=lambda _f, _c: v)
        marker, directory = f.marker, f.directory
    return TriageResult(CONFIRMED, v.reason, marker=marker, directory=directory, **common)


# ---------------------------------------------------------------------------
# the patch seam
# ---------------------------------------------------------------------------

def check_patch(record: Mapping, patch_file: str, pov, *, project_root,
                config: Mapping | None = None, harness: str = "",
                stack_hash: str = "") -> _patch.PatchVerdict:
    """Does this patch stop the PoV without breaking the program?

    `pov` is one path or a list: every variant of the bug the patch is meant
    to fix. With `patch.pov` / `patch.pov_after` configured, the PoV runs
    through the host's runner (e.g. `libCRS run-pov --rebuild-id {build}`)
    instead of the local binary.

    Thin on purpose: the gates and their order live in cc_fuzzer_core.patch,
    and the order is the point (the PoV must crash BEFORE the patch, or
    everything after it measures nothing).
    """
    return _patch.validate(record, patch_file, pov, project_root=project_root,
                           config=config, harness=harness, stack_hash=stack_hash)


# ---------------------------------------------------------------------------
# the corpus seam (thin, and honest about it)
# ---------------------------------------------------------------------------

def safe_seeds(campaign, harness: str = "", inputs=None):
    """Promote quarantined inputs that are safe to keep, reject the rest.

    Worth calling before anything a model produced enters a corpus: the
    rejects are inputs that would damage the machine running them (fork bombs,
    writes to a block device), not merely useless ones.
    """
    from cc_fuzzer_core import quarantine
    return quarantine.quarantine(campaign, harness, inputs)


def dictionary(campaign, *, harness: str = "", output: str = ""):
    """Harvest comparison operands the fuzzer has already seen into a
    dictionary (AFL++ cmplog)."""
    from cc_fuzzer_core import cmplog
    return cmplog.extract(campaign, harness=harness, output=output)


def delta_targets(campaign, range_: str | None = None):
    """The functions a diff touches -- where to aim when the job is a known
    change rather than open exploration, which is the usual CRS shape."""
    from cc_fuzzer_core import delta
    return delta.find_targets(campaign, range_)


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def _cmd_triage(a):
    from cc_fuzzer_core import config as _config
    from cc_fuzzer_core.paths import campaign as _campaign
    from cc_fuzzer_core.variants import harness_record
    try:
        c = _campaign(strict=False)
    except Exception:
        c = None
    try:
        cfg = json.load(open(a.config)) if a.config else (_config.load(c) if c else {})
        record = harness_record(campaign=c, harness=a.harness) if not a.verify_binary \
            else {"verify_binary": a.verify_binary}
        r = triage(record, a.crash, harness=a.harness, config=cfg, campaign=c,
                   finding_id=a.finding_id, do_minimize=not a.no_minimize,
                   do_sensitivity=not a.no_sensitivity)
    except Exception as e:  # noqa: BLE001 - the CLI reports, it does not raise
        print(f"error: {type(e).__name__}: {e}", file=sys.stderr)
        return 2
    print(json.dumps(r.as_dict(), indent=2) if a.json else
          f"{r.status}: {r.reason}\n  pov {r.pov} ({r.original_size} -> {r.size} bytes)\n"
          f"  bug {r.stack_hash} {r.category} [{r.evidence_grade} via {r.evidence_source}]\n"
          f"  submittable: {r.submittable}"
          + (f"\n  bytes {r.sensitivity['mask']}  (# load-bearing, ~ constrained, . free)"
             if r.sensitivity else ""))
    return 0 if r.submittable else 1


def register_cli(subparsers):
    from cc_fuzzer_core.cli import add_subsystem
    _p, verbs = add_subsystem(subparsers, "crs",
                              "The request/response surface for a CRS (no loop).")
    v = verbs.add_parser("triage", help="replay + minimize + verify one crash")
    v.add_argument("crash")
    v.add_argument("--harness", default="")
    v.add_argument("--verify-binary", default="", help="skip the harness record")
    v.add_argument("--finding-id", default="", help="also write the finding marker")
    v.add_argument("--no-minimize", action="store_true")
    v.add_argument("--no-sensitivity", action="store_true")
    v.add_argument("--config")
    v.add_argument("--json", action="store_true")
    v.set_defaults(func=_cmd_triage)
