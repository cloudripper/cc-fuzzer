"""CLI for the cull integration.

    cc-fuzzer intake cull <sarif> [--diff D] [--import]    (needs cull_intake)
    cc-fuzzer cull queue [--done ID ...] [--budget-remaining F] [--delta]
    cc-fuzzer cull cards [--top-k N] [--delta]
    cc-fuzzer cull feedback triage <triage-export.json>     (needs cull_feedback)
    cc-fuzzer cull feedback refute <id> (--sink-execs N | --dispatch-id D)
    cc-fuzzer cull hints --dict <harness.dict>
    cc-fuzzer cull diff <old-intake> <new-intake>
    cc-fuzzer cull engine                                   (needs cull_query_engine)

A command whose flag is off exits 2 and says which flag; the core never
runs any of this on its own.
"""
from __future__ import annotations

import json
import shutil
import sys
from pathlib import Path

from cc_fuzzer_core import features as _features

ENGINE_COMMAND = ("command:cull query --db {db} --template {template} --params {params} "
                  "--max-hits {max_hits} --timeout {timeout} --json")


def _campaign():
    from cc_fuzzer_core.paths import campaign
    return campaign()


def _config(a, c):
    if getattr(a, "config", None):
        return json.load(open(a.config))
    from cc_fuzzer_core import config as _c
    try:
        return _c.load(c)
    except Exception:
        return {}


def _gate(flag: str, cfg) -> bool:
    if _features.load(cfg).enabled(flag):
        return True
    print(f"cull: the {flag} feature is off (enable it in fuzz-config.json features, "
          f"or CC_FUZZER_FEATURES=+{flag})", file=sys.stderr)
    return False


def _intake_or_die(c):
    from cc_fuzzer_core.integrations.cull import intake
    doc = intake.latest(c.state_dir)
    if doc is None:
        print("cull: no intake yet; run `cc-fuzzer intake cull <sarif>`", file=sys.stderr)
        raise SystemExit(2)
    return doc


def _cmd_intake(a):
    from cc_fuzzer_core.integrations.cull import intake
    c = _campaign()
    cfg = _config(a, c)
    if not _gate(_features.CULL_INTAKE, cfg):
        return 2
    try:
        doc = intake.intake(a.sarif, config=cfg, diff=a.diff or None)
    except (intake.IntakeError, OSError) as e:
        print(f"error: {e}", file=sys.stderr)
        return 2
    paths = intake.write(doc, c.state_dir, config=cfg)
    out = {"paths": paths, "counts": doc["counts"], "degraded_fields": doc["degraded_fields"],
           "cull_run": doc["provenance"]["cull_run"]}
    if a.do_import:
        from cc_fuzzer_core import findings
        r = findings.import_cr(c, paths["code_review"])
        out["imported"] = len(r.imported)
        out["skipped"] = r.skipped
    if a.json:
        print(json.dumps(out, indent=2))
    else:
        n = doc["counts"]
        print(f"cull: {n['candidates']} candidate(s); reach {n['by_reach_tier']}; "
              f"confidence {n['by_confidence']}")
        if doc["degraded_fields"]:
            print("derived locally (older cull): " + ", ".join(doc["degraded_fields"]))
        for k, v in paths.items():
            print(f"  {k}: {v}")
        if a.do_import:
            print(f"  import-cr: imported {out['imported']}, skipped {out['skipped']}")
    return 0


def _cmd_queue(a):
    from cc_fuzzer_core.integrations.cull import queue
    c = _campaign()
    r = queue.order(_intake_or_die(c)["candidates"], done=a.done,
                    budget_remaining=a.budget_remaining, config=_config(a, c),
                    delta=a.delta)
    if a.json:
        print(json.dumps({"queue": [q["candidate_id"] for q in r["queue"]],
                          "held": [q["candidate_id"] for q in r["held"]],
                          "reason": r["reason"]}, indent=2))
    else:
        for q in r["queue"]:
            near = f" [{queue.proximity(q)}]" if a.delta and queue.proximity(q) else ""
            print(f"{q['candidate_id']}  {q['reach_tier']:<10} #{q['position']:<4} "
                  f"{q['function']} ({q['path']}:{q['line']}){near}")
        print(r["reason"])
    return 0


def _cmd_cards(a):
    from cc_fuzzer_core.integrations.cull import cards, queue
    c = _campaign()
    cfg = _config(a, c)
    q = queue.order(_intake_or_die(c)["candidates"], config=cfg, delta=a.delta)["queue"]
    sys.stdout.write(cards.render(q, config=cfg, top_k=a.top_k)["text"])
    return 0


def _cmd_feedback(a):
    from cc_fuzzer_core.integrations.cull import feedback
    c = _campaign()
    cfg = _config(a, c)
    if not _gate(_features.CULL_FEEDBACK, cfg):
        return 2
    doc = _intake_or_die(c)
    try:
        if a.fb_verb == "triage":
            row = feedback.from_triage(c.state_dir, doc, json.load(open(a.export)))
        else:
            targeted = {"dispatch_id": a.dispatch_id, "budget_exhausted": True} \
                if a.dispatch_id else None
            row = feedback.refute(c.state_dir, doc, a.candidate_id, sink_execs=a.sink_execs,
                                  targeted=targeted, config=cfg)
    except feedback.FeedbackError as e:
        print(f"error: {e}", file=sys.stderr)
        return 2
    print(json.dumps(row) if row else "no candidate matches this crash; nothing written")
    return 0


def _cmd_hints(a):
    from cc_fuzzer_core.integrations.cull import hints
    c = _campaign()
    r = hints.merge(_intake_or_die(c)["candidates"], a.dict)
    print(json.dumps(r))
    return 0


def _cmd_diff(a):
    from cc_fuzzer_core.integrations.cull import intake
    print(json.dumps(intake.compare(json.load(open(a.old)), json.load(open(a.new))), indent=2))
    return 0


def engine_available() -> bool:
    """Does the installed cull have engine mode (`cull query`, cull 0.3.0)?
    An older cull does not: look before configuring it."""
    import subprocess
    exe = shutil.which("cull")
    if not exe:
        return False
    try:
        p = subprocess.run([exe, "query", "--help"], capture_output=True, text=True, timeout=30)
    except (OSError, subprocess.TimeoutExpired):
        return False
    return p.returncode == 0


def _cmd_engine(a):
    c = _campaign()
    cfg = _config(a, c)
    if not _gate(_features.CULL_QUERY_ENGINE, cfg):
        return 2
    ok = engine_available()
    print(json.dumps({"available": ok,
                      "query": {"engines": ["semgrep", "codeql"],
                                "codeql_engine": ENGINE_COMMAND} if ok else
                      {"engines": ["semgrep"], "codeql_direct": False},
                      "note": "" if ok else "no cull with a `query` engine mode (cull >= 0.3.0) on PATH; "
                              "codeql stays unavailable rather than running agent-written QL"},
                     indent=2))
    return 0 if ok else 1


def register(subparsers):
    from cc_fuzzer_core.cli import add_subsystem
    _p, verbs = add_subsystem(subparsers, "intake", "Read another tool's output (optional integrations).")
    v = verbs.add_parser("cull", help="read cull's bug-candidate SARIF (needs cull_intake)")
    v.add_argument("sarif")
    v.add_argument("--diff", default="", help="a diff, for candidates cull scanned without one")
    v.add_argument("--import", dest="do_import", action="store_true",
                   help="also import the high/medium candidates (findings import-cr)")
    v.add_argument("--config")
    v.add_argument("--json", action="store_true")
    v.set_defaults(func=_cmd_intake)

    _p, verbs = add_subsystem(subparsers, "cull", "The cull integration (optional).")
    v = verbs.add_parser("queue", help="the model's candidate order (reached tiers first)")
    v.add_argument("--done", action="append", default=[], metavar="ID")
    v.add_argument("--budget-remaining", type=float, default=None, metavar="FRACTION")
    v.add_argument("--delta", action="store_true",
                   help="nearest the diff first within each tier; admit none-found in the diff")
    v.add_argument("--config")
    v.add_argument("--json", action="store_true")
    v.set_defaults(func=_cmd_queue)
    v = verbs.add_parser("cards", help="token-bounded candidate cards for a prompt")
    v.add_argument("--top-k", type=int, default=None)
    v.add_argument("--delta", action="store_true", help="order as `cull queue --delta`")
    v.add_argument("--config")
    v.set_defaults(func=_cmd_cards)
    v = verbs.add_parser("feedback", help="write cull-feedback/v1 (needs cull_feedback)")
    fv = v.add_subparsers(dest="fb_verb", required=True)
    x = fv.add_parser("triage", help="a triage export's outcome")
    x.add_argument("export")
    x.add_argument("--config")
    x.set_defaults(func=_cmd_feedback)
    x = fv.add_parser("refute", help="a candidate refuted, with evidence")
    x.add_argument("candidate_id")
    g = x.add_mutually_exclusive_group(required=True)
    g.add_argument("--sink-execs", type=int, default=None)
    g.add_argument("--dispatch-id", default="")
    x.add_argument("--config")
    x.set_defaults(func=_cmd_feedback)
    v = verbs.add_parser("hints", help="merge cull's input hints into a dictionary")
    v.add_argument("--dict", required=True)
    v.set_defaults(func=_cmd_hints)
    v = verbs.add_parser("diff", help="compare two intakes, provenance first")
    v.add_argument("old")
    v.add_argument("new")
    v.set_defaults(func=_cmd_diff)
    v = verbs.add_parser("engine", help="the query-engine config for cull (needs cull_query_engine)")
    v.add_argument("--config")
    v.set_defaults(func=_cmd_engine)
