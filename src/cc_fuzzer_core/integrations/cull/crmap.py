"""cull candidates as a code-review/v1 snapshot (recommendation 2).

cull no longer exports a code-review format (it was consumer-specific), so
the mapping lives here, on the consumer's side, and `findings import-cr`
and the promote gate work unchanged. import-cr imports only `high` and
`medium` confidence: the confidence is cull's when it ships one, else the
configurable `cull.confidence_map` (see intake.local_confidence).

    cr_hash         candidate_id
    id              cr<NNN>, the position in rank order (code-review/v1 ids
                    must match ^cr[0-9]{3,}$); `cull_id` keeps cull-<rank>
    file, function, line_range   the sink; [line, line]
    pattern         from the family / sink class (intake.pattern_of)
    confidence      cull's, else the local map
    evidence        cull's sentence, then the call chain joined with " -> "
    precondition    "input reaches <fn> via <chain>", else "reachability: <tier>"
    oracle_kind     memory
    tier_classified cull
"""
from __future__ import annotations

import time
from typing import Mapping

from cc_fuzzer_core.integrations.cull import settings

ARROW = " → "


def finding(c: Mapping) -> dict:
    chain = list(c.get("call_chain") or [])
    evidence = (c.get("why") or "").strip()
    if chain:
        evidence = (evidence + " | chain: " if evidence else "chain: ") + ARROW.join(chain)
    pre = (f"input reaches {c.get('function')} via {ARROW.join(chain)}" if chain
           else f"reachability: {c.get('reach_tier')}")
    line = int(c.get("line") or 0)
    d = {
        "id": f"cr{int(c.get('position') or 0):03d}",
        "cull_id": f"cull-{c.get('position')}",
        "cr_hash": c["candidate_id"],
        "status": "candidate",
        "file": c.get("path") or "",
        "function": c.get("function") or "",
        "line_range": [line, line],
        "pattern": c.get("pattern") or "other",
        "confidence": c.get("confidence") or "low",
        "tier_classified": "cull",
        "evidence": evidence[:2000],
        "oracle_kind": "memory",
        "precondition": pre[:500],
    }
    if c.get("tier"):
        d["exploitability_hint"] = f"cull tier {c['tier']} (verdict {c.get('verdict')})"
    return d


def snapshot(intake_doc: Mapping, *, config: Mapping | None = None,
             target: str = "", now: float | None = None) -> dict:
    """A code-review/v1 document. Candidates of class `other` are left out
    unless cull.import_other is true."""
    cfg = settings(config)
    cands = [c for c in intake_doc.get("candidates") or []
             if c.get("pattern") != "other" or cfg["import_other"]]
    fns = {(c.get("path"), c.get("function")) for c in cands}
    return {
        "schema": "code-review/v1",
        "ts": int(time.time() if now is None else now),
        "target": target or "cull",
        "scope": {
            "files_scanned": len({c.get("path") for c in cands}),
            "functions_inventoried": len(fns),
            "loc_total": 0,
            "candidates_reviewed": len(cands),
            "not_reviewed": 0,
            # a static ranking, not a review of every function
            "coverage_complete": False,
            "mode": "capped",
            "excluded_paths": [],
        },
        "tiers_run": ["cull"],
        "findings": [finding(c) for c in cands],
        "focus_areas": [],
        "cull_run": (intake_doc.get("provenance") or {}).get("cull_run"),
    }
