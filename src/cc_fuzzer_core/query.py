"""Self-authored queries: the loop asks a question instead of re-reading (§5).

When coverage plateaus, every existing branch re-examines what the campaign
already has: re-analyze the gaps, generate more seeds, mutate harder. None of
them can answer "is this function reachable from a public entry point at all?"
or "does any caller pass an attacker-controlled length here?" -- questions
whose answers live in the code, not in the coverage.

The `query` branch lets the loop write a FRESH semgrep rule (or a CodeQL query
where a database exists), run it, and triage the hits into gap annotations,
code-review candidates or seed hints. The hypothesis is recorded with the
result, because a query whose question nobody wrote down cannot be judged
later -- the hits alone do not say what was being asked.

Every run is bounded and recorded:

  fuzz/state/queries.jsonl        one query-run/v1 per run: engine, rule,
                                  hypothesis, hits, disposition, seconds
  snapshots/query-result-<ts>.json  the full result for the tick

Budget lives in fuzz-config.json and is enforced HERE, not in the prompt:

  "query": {"enabled": true, "per_query_timeout_s": 120,
            "max_queries_per_dispatch": 3, "max_dispatches_per_campaign": 20,
            "max_hits": 200, "engines": ["semgrep", "codeql"],
            "codeql_db": "/out/codeql/db"}

CodeQL runs only against a database the HOST built (frameworks increasingly
build it as a target-build step); the core never builds one. Without
`codeql_db`, or without codeql on PATH, a CodeQL query is `unavailable`.

Queries come from a shipped pack of parametric templates (rules/query-pack):
the agent fills in function and sink names rather than writing QL, which
models do unreliably, and the same template with the same names is the same
query on a rerun. `cc-fuzzer query template list|fill`.

CLI: `cc-fuzzer query run --engine semgrep --rule <file> --hypothesis "..."`,
`cc-fuzzer query budget`, `cc-fuzzer query log`, `cc-fuzzer query template`.
"""
from __future__ import annotations

import json
import os
import sys
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Mapping

RUN_SCHEMA = "query-run/v1"
RESULT_SCHEMA = "query-result/v1"
LOG_NAME = "queries.jsonl"
SNAPSHOT_PREFIX = "query-result"

SEMGREP, CODEQL = "semgrep", "codeql"
ENGINES = (SEMGREP, CODEQL)

# Dispositions a hit set can be triaged into. `none` is a real outcome: a
# hypothesis that was tested and found wrong is worth recording, or the loop
# will keep asking it.
D_GAP, D_CANDIDATE, D_SEED, D_NONE = "gap", "cr_candidate", "seed_hint", "none"
DISPOSITIONS = (D_GAP, D_CANDIDATE, D_SEED, D_NONE)

DEFAULTS = {
    "enabled": True,
    "per_query_timeout_s": 120,
    "max_queries_per_dispatch": 3,
    "max_dispatches_per_campaign": 20,
    "max_hits": 200,
    "engines": list(ENGINES),
    "codeql_db": "",
}


class QueryError(RuntimeError):
    pass


class BudgetExhausted(QueryError):
    """Raised rather than silently running anyway: the point of a budget is
    that the loop cannot spend past it by deciding to."""


# ---------------------------------------------------------------------------
# budget
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class Budget:
    enabled: bool = True
    per_query_timeout_s: int = 120
    max_queries_per_dispatch: int = 3
    max_dispatches_per_campaign: int = 20
    max_hits: int = 200
    engines: tuple = field(default=ENGINES)
    codeql_db: str = ""

    def allows(self, engine: str) -> bool:
        return self.enabled and engine in self.engines

    def as_dict(self) -> dict:
        return {"enabled": self.enabled,
                "per_query_timeout_s": self.per_query_timeout_s,
                "max_queries_per_dispatch": self.max_queries_per_dispatch,
                "max_dispatches_per_campaign": self.max_dispatches_per_campaign,
                "max_hits": self.max_hits, "engines": list(self.engines),
                "codeql_db": self.codeql_db}


def budget(config: Mapping | None = None) -> Budget:
    block = (config or {}).get("query")
    d = dict(DEFAULTS)
    if isinstance(block, Mapping):
        for k, v in block.items():
            if k in d:
                d[k] = v
    def _int(key):
        try:
            return max(1, int(d[key]))
        except (TypeError, ValueError):
            return DEFAULTS[key]
    engines = d["engines"] if isinstance(d["engines"], (list, tuple)) else ENGINES
    return Budget(bool(d["enabled"]), _int("per_query_timeout_s"),
                  _int("max_queries_per_dispatch"), _int("max_dispatches_per_campaign"),
                  _int("max_hits"),
                  tuple(e for e in engines if e in ENGINES),
                  str(d.get("codeql_db") or ""))


# ---------------------------------------------------------------------------
# the log
# ---------------------------------------------------------------------------

def log_path(c) -> Path:
    return Path(c.state_dir) / LOG_NAME


def runs(c) -> list:
    out = []
    p = log_path(c)
    if not p.is_file():
        return out
    for line in p.read_text(errors="replace").splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            doc = json.loads(line)
        except ValueError:
            continue
        if isinstance(doc, dict):
            out.append(doc)
    return out


def dispatches(c) -> int:
    """How many distinct dispatches have spent query budget."""
    return len({r.get("dispatch_id") for r in runs(c) if r.get("dispatch_id")})


def runs_in_dispatch(c, dispatch_id: str) -> int:
    return sum(1 for r in runs(c) if r.get("dispatch_id") == dispatch_id)


def spent(c, config: Mapping | None = None) -> dict:
    b = budget(config)
    used = dispatches(c)
    return {"dispatches": used, "max_dispatches_per_campaign": b.max_dispatches_per_campaign,
            "remaining": max(0, b.max_dispatches_per_campaign - used),
            "queries": len(runs(c)), "enabled": b.enabled}


def exhausted(c, config: Mapping | None = None) -> bool:
    """True when the lever should go quiet (yolo_evaluate consults this)."""
    s = spent(c, config)
    return not s["enabled"] or s["remaining"] <= 0


def append_run(c, doc: Mapping) -> Path:
    p = log_path(c)
    p.parent.mkdir(parents=True, exist_ok=True)
    with open(p, "a", encoding="utf-8") as f:
        f.write(json.dumps(doc, sort_keys=True) + "\n")
    return p


# ---------------------------------------------------------------------------
# running one query
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class QueryRun:
    engine: str
    rule: str
    hypothesis: str
    hits: tuple = field(default=())
    status: str = "ok"
    reason: str = ""
    seconds: float = 0.0
    disposition: str = D_NONE
    capped: bool = False
    dispatch_id: str = ""
    at: str = ""

    def as_dict(self) -> dict:
        return {"schema": RUN_SCHEMA, "engine": self.engine, "rule": self.rule,
                "hypothesis": self.hypothesis, "hit_count": len(self.hits),
                "hits": list(self.hits), "status": self.status, "reason": self.reason,
                "seconds": round(self.seconds, 3), "disposition": self.disposition,
                "capped": self.capped, "dispatch_id": self.dispatch_id, "at": self.at}


def _semgrep_hits(target_root: Path, rule: str, timeout: int, max_hits: int):
    """Run one semgrep rule through the same invocation the prescan uses."""
    from cc_fuzzer_core.prescan import sast_scan
    status, findings = sast_scan.run_semgrep_config(Path(target_root), rule, [], timeout)
    hits = []
    for f in findings or []:
        if isinstance(f, Mapping):
            hits.append({"file": f.get("path") or f.get("file") or "",
                         "line": f.get("line") or f.get("start_line") or 0,
                         "message": (f.get("message") or "")[:400],
                         "rule_id": f.get("check_id") or f.get("rule_id") or ""})
        else:
            hits.append({"message": str(f)[:400]})
    return status, hits


def _codeql_hits(target_root: Path, rule: str, timeout: int, max_hits: int, db=None):
    """Run one query against a HOST-built database; ("unavailable", []) when
    there is no codeql or no database. The core only runs queries."""
    import subprocess
    import tempfile
    from cc_fuzzer_core import tools
    from cc_fuzzer_core.prescan import sast_scan
    codeql = tools.which(CODEQL)
    if not codeql or not db or not Path(db).is_dir():
        return "unavailable", []
    with tempfile.TemporaryDirectory() as td:
        out = Path(td) / "q.sarif"
        p = subprocess.run([codeql, "database", "analyze", str(db), rule,
                            "--format=sarifv2.1.0", f"--output={out}", "--rerun"],
                           timeout=timeout, capture_output=True, text=True)
        if p.returncode != 0 or not out.is_file():
            tail = ((p.stderr or "").strip().splitlines() or [f"exit {p.returncode}"])[-1]
            return f"error: {tail}", []
        findings = sast_scan.normalize_sarif(out, Path(target_root))
    hits = [{"file": f["path"], "line": f["line"], "message": f["message"][:400],
             "rule_id": f["rule_id"]} for f in findings]
    return "ok", hits[:max_hits + 1]   # one over the cap, so run() can see it was capped


def run(c, *, engine: str, rule: str, hypothesis: str, config: Mapping | None = None,
        dispatch_id: str = "", disposition: str = D_NONE, target_root=None) -> QueryRun:
    """Run one query, enforcing the budget, and record it."""
    b = budget(config)
    if not b.enabled:
        raise BudgetExhausted("query.enabled is false")
    if engine not in ENGINES:
        raise QueryError(f"unknown engine '{engine}' (known: {', '.join(ENGINES)})")
    if engine not in b.engines:
        raise BudgetExhausted(f"engine '{engine}' is not in query.engines")
    if disposition not in DISPOSITIONS:
        raise QueryError(f"unknown disposition '{disposition}' "
                         f"(known: {', '.join(DISPOSITIONS)})")
    if not hypothesis.strip():
        raise QueryError("a query needs a --hypothesis: the hits alone do not "
                         "record what was being asked")
    if not os.path.isfile(rule):
        raise QueryError(f"no such rule file: {rule}")

    if dispatches(c) >= b.max_dispatches_per_campaign and \
            (not dispatch_id or runs_in_dispatch(c, dispatch_id) == 0):
        raise BudgetExhausted(
            f"query budget spent: {b.max_dispatches_per_campaign} dispatches used")
    if dispatch_id and runs_in_dispatch(c, dispatch_id) >= b.max_queries_per_dispatch:
        raise BudgetExhausted(
            f"dispatch {dispatch_id} already ran {b.max_queries_per_dispatch} queries")

    root = Path(target_root or getattr(c, "project_root", "."))
    t0 = time.monotonic()
    try:
        if engine == SEMGREP:
            status, hits = _semgrep_hits(root, rule, b.per_query_timeout_s, b.max_hits)
        else:
            status, hits = _codeql_hits(root, rule, b.per_query_timeout_s, b.max_hits,
                                        db=b.codeql_db or None)
        reason = "" if status == "ok" else f"engine status: {status}"
    except Exception as e:  # noqa: BLE001 - a failed query is a result, not a crash
        status, hits, reason = "error", [], f"{type(e).__name__}: {e}"
    seconds = time.monotonic() - t0

    capped = len(hits) > b.max_hits
    r = QueryRun(engine=engine, rule=rule, hypothesis=hypothesis.strip(),
                 hits=tuple(hits[:b.max_hits]), status=status, reason=reason,
                 seconds=seconds, disposition=disposition, capped=capped,
                 dispatch_id=dispatch_id,
                 at=time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()))
    append_run(c, r.as_dict())
    return r


# ---------------------------------------------------------------------------
# the query pack: parametric templates, filled not written
# ---------------------------------------------------------------------------

_PARAM_RE = __import__("re").compile(r"{{\s*([a-z_]+)\s*}}")
_IDENT_RE = __import__("re").compile(r"^[A-Za-z_][A-Za-z0-9_]*(::[A-Za-z_][A-Za-z0-9_]*)*$")
_TEMPLATE_EXT = {SEMGREP: ".yaml.tmpl", CODEQL: ".ql.tmpl"}


def pack_dir() -> Path:
    from cc_fuzzer_core import paths
    return paths.data("rules", "query-pack")


def templates() -> list:
    """[{engine, name, params, path}] for every template in the pack."""
    out = []
    for engine, ext in _TEMPLATE_EXT.items():
        d = pack_dir() / engine
        for p in sorted(d.glob(f"*{ext}")) if d.is_dir() else []:
            params = sorted(set(_PARAM_RE.findall(p.read_text())))
            out.append({"engine": engine, "name": p.name[:-len(ext)], "params": params,
                        "path": str(p)})
    return out


def fill(name: str, *, engine: str = SEMGREP, **params) -> str:
    """The template `name` with every {{param}} replaced. Values must be
    identifiers, so a filled template cannot carry injected query text."""
    if engine not in _TEMPLATE_EXT:
        raise QueryError(f"unknown engine '{engine}' (known: {', '.join(ENGINES)})")
    p = pack_dir() / engine / f"{name}{_TEMPLATE_EXT[engine]}"
    if not p.is_file():
        known = ", ".join(t["name"] for t in templates() if t["engine"] == engine)
        raise QueryError(f"no {engine} template '{name}' (known: {known})")
    text = p.read_text()
    wanted = set(_PARAM_RE.findall(text))
    missing = sorted(wanted - set(params))
    extra = sorted(set(params) - wanted)
    if missing or extra:
        raise QueryError(f"template {engine}/{name} takes {', '.join(sorted(wanted))}"
                         + (f"; missing {', '.join(missing)}" if missing else "")
                         + (f"; unknown {', '.join(extra)}" if extra else ""))
    for k, v in params.items():
        if not isinstance(v, str) or not _IDENT_RE.match(v):
            raise QueryError(f"{k}={v!r} is not an identifier")
    return _PARAM_RE.sub(lambda m: params[m.group(1)], text)


def write_snapshot(c, result: QueryRun, *, now=None) -> Path:
    ts = int(now if now is not None else time.time())
    d = Path(c.state_dir) / "snapshots"
    d.mkdir(parents=True, exist_ok=True)
    p = d / f"{SNAPSHOT_PREFIX}-{ts}.json"
    # the spread carries the RUN schema, so set the snapshot's own last
    doc = {**result.as_dict(), "schema": RESULT_SCHEMA, "run_schema": RUN_SCHEMA, "ts": ts}
    p.write_text(json.dumps(doc, indent=2, sort_keys=True) + "\n")
    return p


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def _campaign():
    from cc_fuzzer_core.paths import campaign
    return campaign()


def _config(a):
    from cc_fuzzer_core import config as _c
    if getattr(a, "config", None):
        with open(a.config) as f:
            return json.load(f)
    try:
        return _c.load()
    except Exception:
        return {}


def _cmd_run(a):
    c = _campaign()
    try:
        r = run(c, engine=a.engine, rule=a.rule, hypothesis=a.hypothesis,
                config=_config(a), dispatch_id=a.dispatch_id,
                disposition=a.disposition)
    except BudgetExhausted as e:
        print(f"query budget: {e}", file=sys.stderr)
        return 3
    except QueryError as e:
        print(f"error: {e}", file=sys.stderr)
        return 2
    snap = write_snapshot(c, r)
    if a.json:
        print(json.dumps({**r.as_dict(), "snapshot": str(snap)}, indent=2))
    else:
        print(f"{r.status}: {len(r.hits)} hit(s) in {r.seconds:.1f}s -> {snap}")
    return 0


def _cmd_budget(a):
    print(json.dumps({**spent(_campaign(), _config(a)),
                      "budget": budget(_config(a)).as_dict()}, indent=2))
    return 0


def _cmd_log(a):
    for doc in runs(_campaign()):
        if a.json:
            print(json.dumps(doc, sort_keys=True))
        else:
            print(f"{doc.get('at','')}  {doc.get('engine',''):<8} "
                  f"hits={doc.get('hit_count',0):<4} {doc.get('disposition',''):<12} "
                  f"{doc.get('hypothesis','')[:60]}")
    return 0


def _cmd_template_list(a):
    ts = templates()
    if a.json:
        print(json.dumps(ts, indent=2))
    else:
        for t in ts:
            print(f"{t['engine']:<8} {t['name']:<20} {', '.join(t['params'])}")
    return 0


def _cmd_template_fill(a):
    params = {}
    for kv in a.param:
        k, sep, v = kv.partition("=")
        if not sep:
            print(f"error: --param expects KEY=VALUE, got {kv!r}", file=sys.stderr)
            return 2
        params[k] = v
    try:
        text = fill(a.name, engine=a.engine, **params)
    except QueryError as e:
        print(f"error: {e}", file=sys.stderr)
        return 2
    if a.output:
        Path(a.output).parent.mkdir(parents=True, exist_ok=True)
        Path(a.output).write_text(text)
        print(a.output)
    else:
        sys.stdout.write(text)
    return 0


def register_cli(subparsers):
    from cc_fuzzer_core.cli import add_subsystem
    _p, verbs = add_subsystem(subparsers, "query",
                              "Self-authored semgrep/CodeQL queries (§5).")

    v = verbs.add_parser("run", help="run one query and record it")
    v.add_argument("--engine", default=SEMGREP, choices=ENGINES)
    v.add_argument("--rule", required=True, help="the rule/query file")
    v.add_argument("--hypothesis", required=True,
                   help="what this query is testing (recorded with the result)")
    v.add_argument("--disposition", default=D_NONE, choices=DISPOSITIONS)
    v.add_argument("--dispatch-id", default="", help="groups queries from one dispatch")
    v.add_argument("--config")
    v.add_argument("--json", action="store_true")
    v.set_defaults(func=_cmd_run)

    v = verbs.add_parser("budget", help="what the query lever has left")
    v.add_argument("--config")
    v.set_defaults(func=_cmd_budget)

    t = verbs.add_parser("template", help="the parametric query pack (list | fill)")
    tv = t.add_subparsers(dest="template_verb", required=True)
    x = tv.add_parser("list", help="templates and their params")
    x.add_argument("--json", action="store_true")
    x.set_defaults(func=_cmd_template_list)
    x = tv.add_parser("fill", help="fill one template's names; prints or writes it")
    x.add_argument("name")
    x.add_argument("--engine", default=SEMGREP, choices=ENGINES)
    x.add_argument("--param", action="append", default=[], metavar="KEY=VALUE")
    x.add_argument("-o", "--output")
    x.set_defaults(func=_cmd_template_fill)

    v = verbs.add_parser("log", help="the recorded query runs")
    v.add_argument("--json", action="store_true")
    v.set_defaults(func=_cmd_log)
