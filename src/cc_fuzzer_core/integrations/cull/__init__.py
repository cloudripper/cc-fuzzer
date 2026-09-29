"""cull integration: cull's ranked bug candidates as cc-fuzzer inputs.

cull (github.com/cloudripper/cull) narrows a C/C++ project to the writes,
reads, frees and dereferences worth a fuzzer's time and hands them over as
bug-candidate SARIF (`cull scan --format sarif-bug-candidates`), each result
carrying cull's evidence record (`cull.evidence`) and a `cull/v1` bag. This
package reads that and nothing else; it never imports or runs cull except
through the query-engine command a host configures.

    cull SARIF
       └─ intake            validate, normalize, keep the cull/v1 bag   (intake.py)
            ├─ code-review/v1  -> findings import-cr -> candidate ledger (crmap.py)
            ├─ sast-signal/v1  -> prescan suspicion by function          (intake.py)
            ├─ cards           -> model context, token-bounded           (cards.py)
            ├─ queue           -> reached tiers before none-found        (queue.py)
            └─ feedback        <- triage outcomes, cull-feedback/v1      (feedback.py)
       input hints -> harness dictionary                                  (hints.py)

Gated by three flags, all OFF by default (cc_fuzzer_core.features):
cull_intake, cull_feedback, cull_query_engine. Configuration lives in the
fuzz-config.json `cull` block (DEFAULTS below).

Fields cull does not ship yet degrade, never fail: a missing candidate_id is
computed with cull's own formula, a missing confidence is derived from the
rank and reachability, a missing reach tier maps from cull's reachability
label (or is `unknown`), and every derivation is marked `*_source: "local"`.

CLI: `cc-fuzzer intake cull <sarif>`, `cc-fuzzer cull queue|cards|feedback|hints|diff|engine`.
"""
from __future__ import annotations

from typing import Mapping

DEFAULTS = {
    # accept a SARIF whose run says it is degraded (a partial ranking beats none)
    "accept_degraded": True,
    # import candidates whose class maps to no cc-fuzzer pattern
    "import_other": False,
    # cull's reachability label -> reach tier (before cull ships reach_tier)
    "reach_map": {"input": "harness", "harness": "harness", "entry-point": "indirect",
                  "none": "none-found"},
    # local confidence, used only when cull gives none
    "confidence_map": {"high": {"max_rank": 5, "reach_tiers": ["harness"]},
                       "medium": {"max_rank": 20, "reach_tiers": ["harness", "indirect"]}},
    # the queue admits none-found candidates only with this much budget left
    "none_found_budget_floor": 0.3,
    # prompt cards
    "cards_top_k": 10,
    "card_max_tokens": 300,
    "cards_max_tokens": 2000,
    # prescan weight per reach tier (a semgrep `high` hit weighs 9)
    "signal_weights": {"harness": 15, "indirect": 12, "unknown": 11, "none-found": 10},
    # feedback: a refutation from coverage needs this many executions of the sink
    "refute_min_execs": 10000,
}


def settings(config: Mapping | None) -> dict:
    """The `cull` block with DEFAULTS filled in (one level of dict merge)."""
    block = (config or {}).get("cull") or {}
    if not isinstance(block, Mapping):
        block = {}
    out = {}
    for k, v in DEFAULTS.items():
        got = block.get(k, v)
        out[k] = {**v, **got} if isinstance(v, dict) and isinstance(got, Mapping) else got
    for k, v in block.items():
        out.setdefault(k, v)
    return out


def register_cli(subparsers):
    from cc_fuzzer_core.integrations.cull import cli
    cli.register(subparsers)
