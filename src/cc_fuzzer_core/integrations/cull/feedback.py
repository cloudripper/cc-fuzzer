"""Triage outcomes back to cull as cull-feedback/v1 (recommendation 8).

Written now, read by cull once its rerank takes feedback. The file
<state>/cull/feedback.jsonl is APPEND-ONLY: a row, once written, is never
edited; a later outcome for the same candidate is a new row.

Matching a crash to a candidate is deterministic, from a triage export's
frames ("fn @ file:line", top first):

    strong   a top-5 frame is the candidate's function, in its file, within
             +-5 lines of the sink
    weak     a top-5 frame is the candidate's function, in its file
    none     otherwise

Outcomes:

    confirmed     the triage result is submittable AND the match is strong
    refuted       only with evidence, one of:
                    coverage: the sink lines ran at least cull.refute_min_execs
                              times with no matching crash
                    targeted: a dispatch aimed at this candidate spent its
                              budget with no matching crash
    inconclusive  a weak match; no row at all for none
"""
from __future__ import annotations

import json
import re
import time
from pathlib import Path
from typing import Iterable, Mapping

from cc_fuzzer_core.integrations.cull import settings

SCHEMA = "cull-feedback/v1"
STRONG, WEAK, NONE = "strong", "weak", "none"
CONFIRMED, REFUTED, INCONCLUSIVE = "confirmed", "refuted", "inconclusive"
TOP_FRAMES = 5
LINE_SLACK = 5

_FRAME = re.compile(r"^(?P<fn>.*?) @ (?P<file>.+?)(?::(?P<line>\d+))?$")


class FeedbackError(ValueError):
    pass


def path(state_dir) -> Path:
    return Path(state_dir) / "cull" / "feedback.jsonl"


def _same_file(frame_file: str, cand_file: str) -> bool:
    f = frame_file.replace("\\", "/").split("/")
    d = [x for x in (cand_file or "").replace("\\", "/").split("/") if x not in ("", ".")]
    return bool(d) and len(f) >= len(d) and f[-len(d):] == d


def match(candidate: Mapping, frames: Iterable[str]) -> str:
    best = NONE
    for fr in list(frames or ())[:TOP_FRAMES]:
        m = _FRAME.match(fr or "")
        if not m or m.group("fn") != candidate.get("function"):
            continue
        if not _same_file(m.group("file"), candidate.get("path") or ""):
            continue
        line = m.group("line")
        if line is not None and abs(int(line) - int(candidate.get("line") or 0)) <= LINE_SLACK:
            return STRONG
        best = WEAK
    return best


def best_match(candidates: Iterable[Mapping], frames) -> tuple:
    """(candidate, strength) for the best-matching candidate, strong first,
    then rank order; (None, "none") when nothing matches."""
    frames = list(frames or ())
    found = None
    for c in sorted(candidates, key=lambda c: c.get("position") or 10**9):
        s = match(c, frames)
        if s == STRONG:
            return c, STRONG
        if s == WEAK and found is None:
            found = c
    return (found, WEAK) if found else (None, NONE)


def matcher(intake_doc: Mapping):
    """A crs.triage candidate_matcher: the strongly matched candidate's id."""
    cands = list(intake_doc.get("candidates") or [])

    def fn(result: Mapping) -> str:
        c, s = best_match(cands, result.get("frames") or [])
        return c["candidate_id"] if c and s == STRONG else ""
    return fn


def append(state_dir, row: Mapping) -> dict:
    p = path(state_dir)
    p.parent.mkdir(parents=True, exist_ok=True)
    doc = {"schema": SCHEMA, "ts": int(time.time()), **row}
    with open(p, "a", encoding="utf-8") as f:
        f.write(json.dumps(doc, sort_keys=True) + "\n")
    return doc


def from_triage(state_dir, intake_doc: Mapping, triage: Mapping) -> dict | None:
    """Record what one triage export says about the candidates; the row, or
    None when the crash matches no candidate."""
    c, strength = best_match(intake_doc.get("candidates") or [], triage.get("frames") or [])
    if c is None:
        return None
    outcome = CONFIRMED if strength == STRONG and triage.get("submittable") else INCONCLUSIVE
    return append(state_dir, {
        "candidate_id": c["candidate_id"], "outcome": outcome, "match": strength,
        "stack_hash": triage.get("stack_hash") or "",
        "category": triage.get("category") or "",
        "evidence": {"kind": "triage", "status": triage.get("status"),
                     "submittable": bool(triage.get("submittable")),
                     "pov_sha256": triage.get("pov_sha256") or ""},
        "cull_run": (intake_doc.get("provenance") or {}).get("cull_run"),
    })


def refute(state_dir, intake_doc: Mapping, candidate_id: str, *,
           sink_execs: int | None = None, targeted: Mapping | None = None,
           config: Mapping | None = None) -> dict:
    """A refutation, which must carry its evidence (see module docstring)."""
    cfg = settings(config)
    ids = {c["candidate_id"] for c in intake_doc.get("candidates") or []}
    if candidate_id not in ids:
        raise FeedbackError(f"no candidate {candidate_id} in the intake")
    if sink_execs is not None and sink_execs >= int(cfg["refute_min_execs"]):
        ev = {"kind": "coverage", "sink_execs": int(sink_execs),
              "min_execs": int(cfg["refute_min_execs"])}
    elif targeted and targeted.get("dispatch_id") and targeted.get("budget_exhausted") is True:
        ev = {"kind": "targeted", "dispatch_id": str(targeted["dispatch_id"]),
              "budget_exhausted": True}
    else:
        raise FeedbackError(
            "a refutation needs evidence: sink_execs >= cull.refute_min_execs "
            f"({cfg['refute_min_execs']}), or a targeted dispatch that exhausted its budget")
    return append(state_dir, {"candidate_id": candidate_id, "outcome": REFUTED,
                              "match": NONE, "evidence": ev,
                              "cull_run": (intake_doc.get("provenance") or {}).get("cull_run")})


def read(state_dir) -> list:
    p = path(state_dir)
    if not p.is_file():
        return []
    return [json.loads(ln) for ln in p.read_text().splitlines() if ln.strip()]
