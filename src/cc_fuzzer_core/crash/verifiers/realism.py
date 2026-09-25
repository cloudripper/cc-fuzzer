"""The `poc-realism` verifier: the plugin's own gate, as a verifier (§4).

This is what cc-fuzzer has always required before a crash becomes a finding: a
mechanical reproducer (driver), a verifier script that exits 0 only when a
trust boundary is actually crossed, and the three realism statements. The work
is agent-backed -- poc-builder produces the bundle -- so this verifier does not
create evidence, it CHECKS it. The loop dispatches the agent; the core decides
whether what came back is enough.

With impact_tiering off (§9) the boundary/precondition/projected statements
are not required, matching the promote gate.
"""
from __future__ import annotations

import os
from typing import Mapping

from cc_fuzzer_core import features
from cc_fuzzer_core.crash.verifiers import (CONFIRMED, INCONCLUSIVE, REJECTED,
                                            Verdict)

REQUIRED = ("driver", "verifier")
STATEMENTS = ("boundary", "precondition", "projected_vs_demonstrated")


def _path(ctx: Mapping, p: str) -> str:
    root = ctx.get("project_root") or ""
    return p if os.path.isabs(p) or not root else os.path.join(root, p)


def verify(finding: Mapping, ctx: Mapping) -> Verdict:
    step = ctx.get("step") or "poc-realism"
    att = (finding or {}).get("realism_attestation") or {}
    if not att:
        # Not a rejection: the PoC bundle has not been produced yet, and the
        # loop's answer to that is to dispatch poc-builder, not to drop the
        # finding.
        return Verdict(INCONCLUSIVE,
                       "no realism_attestation yet; dispatch poc-builder to produce "
                       "the reproducer and verifier", step=step)

    missing = [k for k in REQUIRED if not att.get(k)]
    if features.enabled(features.IMPACT_TIERING, ctx.get("config")):
        missing += [k for k in STATEMENTS if not att.get(k)]
    if missing:
        return Verdict(REJECTED,
                       "realism attestation is incomplete: missing " + ", ".join(missing),
                       step=step)

    evidence = []
    for key in REQUIRED:
        p = _path(ctx, str(att[key]))
        if not os.path.isfile(p):
            return Verdict(REJECTED, f"attested {key} does not exist: {att[key]}", step=step)
        evidence.append(att[key])

    return Verdict(CONFIRMED, "realism gate satisfied", tuple(evidence), dict(att), step)
