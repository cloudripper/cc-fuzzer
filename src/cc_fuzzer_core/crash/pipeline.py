"""The crash pipeline, and the only door into fuzz/findings/ (§4, §11).

Three named stages, whose verdicts are recorded on the finding:

  1. filter       portable pre-checks plus the triager's four-principle
                  verdicts (recorded through `findings filter-verdict`)
  2. replay       deterministic, in the core (crash/replay.py)
  3. final_verify swappable (crash/verifiers/), chosen by
                  fuzz-config.json: verification.final_step

§11 is the rule that makes the third stage mean something: NOTHING enters
fuzz/findings/ unless this module put it there, and it only does that after a
verifier confirmed it. finalize() is the only code that creates
fuzz/findings/<id>/, and the last thing it writes is `<id>/.verified` -- a
verification-marker/v1 recording what was verified and against which binary.

The marker is written LAST and atomically on purpose: a directory that exists
without a valid marker is an interrupted or a hand-made promotion, and both
should read as unverified rather than as a finding. Downstream this is the
never-submit-an-unverified-PoV rule, where a false submission costs the
accuracy multiplier directly.
"""
from __future__ import annotations

import hashlib
import json
import os
import tempfile
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Mapping

from cc_fuzzer_core import variants as _v
from cc_fuzzer_core.crash import verifiers as _verifiers

MARKER_SCHEMA = "verification-marker/v1"
MARKER_NAME = ".verified"

STAGE_FILTER, STAGE_REPLAY, STAGE_FINAL = "filter", "replay", "final_verify"
STAGES = (STAGE_FILTER, STAGE_REPLAY, STAGE_FINAL)


class PipelineError(RuntimeError):
    pass


def sha256_file(path) -> str:
    h = hashlib.sha256()
    try:
        with open(path, "rb") as f:
            for chunk in iter(lambda: f.read(1 << 16), b""):
                h.update(chunk)
    except OSError:
        return ""
    return h.hexdigest()


@dataclass(frozen=True)
class Marker:
    finding_id: str
    reproducer: str
    reproducer_sha256: str
    binary: str
    binary_sha256: str
    variant: str
    evidence_grade: str
    classify_verdict: str
    stack_hash: str
    step: str
    status: str
    at: str
    evidence: tuple = field(default=())
    evidence_source: str = "replay"

    def as_dict(self) -> dict:
        return {"schema": MARKER_SCHEMA, "finding_id": self.finding_id,
                "reproducer": self.reproducer, "reproducer_sha256": self.reproducer_sha256,
                "binary": self.binary, "binary_sha256": self.binary_sha256,
                "variant": self.variant, "evidence_grade": self.evidence_grade,
                "evidence_source": self.evidence_source,
                "classify_verdict": self.classify_verdict, "stack_hash": self.stack_hash,
                "step": self.step, "status": self.status, "at": self.at,
                "evidence": list(self.evidence)}


def write_marker(finding_dir, marker: Marker) -> Path:
    """Write the marker atomically, as the last act of a promotion."""
    d = Path(finding_dir)
    d.mkdir(parents=True, exist_ok=True)
    target = d / MARKER_NAME
    fd, tmp = tempfile.mkstemp(dir=str(d), prefix=".verified.")
    try:
        with os.fdopen(fd, "w") as f:
            json.dump(marker.as_dict(), f, indent=2, sort_keys=True)
            f.write("\n")
            f.flush()
            os.fsync(f.fileno())
        os.replace(tmp, target)
    except BaseException:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise
    return target


def read_marker(finding_dir):
    p = Path(finding_dir) / MARKER_NAME
    try:
        doc = json.loads(p.read_text())
    except (OSError, ValueError):
        return None
    return doc if isinstance(doc, dict) else None


def marker_problems(finding_dir, *, check_files: bool = True) -> list:
    """Why this finding directory is not verified ([] when it is)."""
    d = Path(finding_dir)
    doc = read_marker(d)
    if doc is None:
        return [f"{d}: no {MARKER_NAME} marker (nothing verified this finding)"]
    out = []
    if doc.get("schema") != MARKER_SCHEMA:
        out.append(f"{d}: marker schema is {doc.get('schema')!r}, expected {MARKER_SCHEMA}")
    if doc.get("status") != _verifiers.CONFIRMED:
        out.append(f"{d}: marker status is {doc.get('status')!r}, not {_verifiers.CONFIRMED}")
    if check_files:
        for key, sha_key in (("reproducer", "reproducer_sha256"), ("binary", "binary_sha256")):
            path, want = doc.get(key) or "", doc.get(sha_key) or ""
            if not path or not want:
                out.append(f"{d}: marker is missing {key}")
                continue
            got = sha256_file(path)
            if not got:
                out.append(f"{d}: marker names a {key} that is gone: {path}")
            elif got != want:
                out.append(f"{d}: {key} changed since verification ({path})")
    return out


def verified(finding_dir, **kw) -> bool:
    return not marker_problems(finding_dir, **kw)


# ---------------------------------------------------------------------------
# finalize: the only creator of fuzz/findings/<id>/
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class Finalized:
    finding_id: str
    status: str
    step: str
    directory: str = ""
    marker: str = ""
    reason: str = ""
    evidence: tuple = field(default=())

    @property
    def confirmed(self) -> bool:
        return self.status == _verifiers.CONFIRMED

    def as_dict(self) -> dict:
        return {"finding_id": self.finding_id, "status": self.status, "step": self.step,
                "directory": self.directory, "marker": self.marker,
                "reason": self.reason, "evidence": list(self.evidence)}


def finalize(campaign, fid: str, finding: Mapping, *, record: Mapping,
             reproducer: str, config: Mapping | None = None, harness: str = "",
             replay_result: Mapping | None = None, verify_fn=None) -> Finalized:
    """Run the configured final step and, only if it confirms, create the
    finding directory and write its marker.

    A rejected or inconclusive verdict creates NOTHING: there is no half-made
    finding directory to mistake for a real one later.
    """
    step = _verifiers.step_of(config)
    ctx = {
        "harness": harness,
        "reproducer": reproducer,
        "binaries": {f: record.get(f) for f in _v.BINARY_FIELD.values() if record.get(f)},
        "replay": dict(replay_result or {}),
        "project_root": str(getattr(campaign, "project_root", "") or ""),
        "config": config,
        "step": step,
        "timeout_s": _verifiers.timeout_of(config),
    }
    fn = verify_fn or (lambda f, c: _verifiers.verify(f, c, config=config))
    verdict = fn(finding, ctx)

    if verdict.status != _verifiers.CONFIRMED:
        return Finalized(fid, verdict.status, step, reason=verdict.reason,
                         evidence=verdict.evidence)

    sel = _v.select(record, _v.A_VERIFY if not replay_result else _v.A_REPLAY,
                    harness=harness)
    grade, source = _verifiers.evidence(sel.evidence_grade, verdict, config)
    findings_dir = Path(getattr(campaign, "fuzz_root", ".")) / "findings" / fid
    marker = Marker(
        finding_id=fid,
        reproducer=reproducer,
        reproducer_sha256=sha256_file(reproducer),
        binary=sel.binary,
        binary_sha256=sha256_file(sel.binary),
        variant=sel.variant,
        evidence_grade=grade,
        evidence_source=source,
        classify_verdict=str((replay_result or {}).get("verdict") or ""),
        stack_hash=str((replay_result or {}).get("stack_hash")
                       or (finding or {}).get("stack_hash") or ""),
        step=step,
        status=verdict.status,
        at=time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        evidence=tuple(verdict.evidence),
    )
    path = write_marker(findings_dir, marker)
    return Finalized(fid, verdict.status, step, str(findings_dir), str(path),
                     verdict.reason, verdict.evidence)
