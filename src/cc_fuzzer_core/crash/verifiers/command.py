"""The `command:<path>` verifier: an external oracle (§4).

The downstream harness has its own notion of a confirmed finding -- an
evaluator's oracle, a reproducer runner, a scoring script -- and the core must
not need to know anything about it. So the contract is two JSON documents and
an exit code:

    stdin   verify-request/v1   the finding, the reproducer, the binaries,
                                what replay already established
    stdout  verify-verdict/v1   {"status": "confirmed"|"rejected"|"inconclusive",
                                 "reason": ..., "evidence": [...], "attestation": {...}}

Everything that can go wrong on the way to a verdict is `inconclusive`, never
`rejected`: a timeout, a crash in the oracle, unparseable output, a missing
executable. Treating those as rejection would silently discard real findings
whenever the oracle has a bad day, and the whole point of this stage is that
a false submission costs more than a missed one.
"""
from __future__ import annotations

import json
import os
import shlex
import subprocess
from typing import Mapping

from cc_fuzzer_core.crash.verifiers import (INCONCLUSIVE, Verdict, VerifierError,
                                            request)


def make(spec: str):
    """A verifier that runs `spec` (a path, optionally with arguments)."""
    spec = (spec or "").strip()
    if not spec:
        raise VerifierError("command verifier needs a path: 'command:<path>'")
    argv = shlex.split(spec)

    def verify(finding: Mapping, ctx: Mapping) -> Verdict:
        return run(argv, finding, ctx)

    verify.argv = argv
    return verify


def run(argv: list, finding: Mapping, ctx: Mapping) -> Verdict:
    step = ctx.get("step") or f"command:{' '.join(argv)}"
    timeout = ctx.get("timeout_s") or 600
    payload = json.dumps(request(finding, ctx))
    cwd = ctx.get("project_root") or None
    try:
        p = subprocess.run(argv, input=payload, capture_output=True, text=True,
                           timeout=timeout, cwd=cwd)
    except subprocess.TimeoutExpired:
        return Verdict(INCONCLUSIVE, f"verifier timed out after {timeout}s", step=step)
    except OSError as e:
        return Verdict(INCONCLUSIVE, f"cannot run verifier {argv[0]}: {e}", step=step)

    out = (p.stdout or "").strip()
    if not out:
        tail = " | ".join((p.stderr or "").strip().splitlines()[-3:])
        return Verdict(INCONCLUSIVE,
                       f"verifier exited {p.returncode} with no verdict on stdout"
                       + (f": {tail}" if tail else ""), step=step)
    try:
        doc = json.loads(out)
    except ValueError as e:
        return Verdict(INCONCLUSIVE, f"verifier output is not JSON ({e})", step=step)
    try:
        return Verdict.from_dict(doc, step=step)
    except VerifierError as e:
        return Verdict(INCONCLUSIVE, f"verifier returned an invalid verdict: {e}", step=step)
