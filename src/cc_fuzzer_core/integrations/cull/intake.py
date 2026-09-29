"""Read cull's bug-candidate SARIF into cull-intake/v1 (recommendation 1).

Tolerant, not lax: an invalid file is an error, never an empty intake. What
counts as invalid is what the CRS framework's SARIF validator asks of every
result (cull's own `check_bug_candidates`) plus the evidence contract: every
result carries a `cull.evidence` record of a major version this reader knows.

From evidence 1.7.0 cull decides reach_tier, confidence, sink_class, access,
call_chain, why and position itself (`properties["cull/v1"]`), and a
1.7.0 intake has no local derivation at all. Its `reach_tier: null` ("no
entry point in the database") and `call_chain: null` ("no path") are
answers, read as `unknown` and `[]`, never as gaps.

Inside a known major version, a field an older cull did not ship DEGRADES:

    candidate_id   computed with cull's formula; id_source "local"
    confidence     derived from rank and reach tier; confidence_source "local"
    reach_tier     mapped from cull's reachability label (reach_map); "unknown"
                   when the record predates reachability
    call_chain     from flow_steps; [] when there are none
    provenance     null fields; a rerun is compared on cull's version and the
                   SARIF file's sha256 instead

and each degradation is listed once in the intake's `degraded_fields`.
"""
from __future__ import annotations

import hashlib
import json
import time
from pathlib import Path
from typing import Mapping

from cc_fuzzer_core.integrations.cull import settings

INTAKE_SCHEMA = "cull-intake/v1"
SIGNAL_SCHEMA = "sast-signal/v1"
EVIDENCE_SCHEMA = "cull.evidence"
EVIDENCE_MAJOR = 1
# The evidence version each field arrived in (cull's evidence_record.py).
SINCE = {"diff_proximity": (1, 1), "flow_steps": (1, 2), "alert": (1, 4),
         "null": (1, 5), "integer": (1, 5), "candidate_id": (1, 6),
         "why": (1, 7), "reach_tier": (1, 7), "call_chain": (1, 7),
         "sink_class": (1, 7), "access": (1, 7)}

TIERS = ("harness", "indirect", "unknown", "none-found")
UNKNOWN = "unknown"

# cc-fuzzer code-review/v1 `pattern` for each cull family (enums.CR_TO_CATEGORY)
_FAMILY_PATTERN = {"CWE-787": "oob_write", "CWE-125": "oob_read", "CWE-416": "uaf",
                   "CWE-415": "double_free", "CWE-476": "null_deref", "CWE-690": "null_deref"}
# ASan's vocabulary, for when cull names a sink class (a later cull wave)
_SINK_PATTERN = {"heap-buffer-overflow": "oob", "stack-buffer-overflow": "oob",
                 "global-buffer-overflow": "oob", "heap-use-after-free": "uaf",
                 "double-free": "double_free", "segv": "null_deref", "null": "null_deref",
                 "null-deref": "null_deref"}
_ALERT_CWE = {**{c: "oob_write" for c in ("787", "788", "120", "121", "122", "131", "805")},
              **{c: "oob_read" for c in ("125", "126", "127")},
              "416": "uaf", "415": "double_free", "476": "null_deref", "690": "null_deref"}
_SINK_CLASS = {"oob_write": "out-of-bounds-write", "oob_read": "out-of-bounds-read",
               "uaf": "heap-use-after-free", "double_free": "double-free",
               "null_deref": "segv", "int_overflow": "integer-overflow"}


class IntakeError(ValueError):
    pass


# ---------------------------------------------------------------------------
# validation
# ---------------------------------------------------------------------------

def _version(v) -> tuple:
    try:
        return tuple(int(x) for x in str(v).split(".")[:3])
    except ValueError:
        return ()


def validate(doc) -> list:
    """Problems with a bug-candidate SARIF (empty = accepted)."""
    bad = []
    if not isinstance(doc, Mapping) or doc.get("version") != "2.1.0":
        return ["version: not SARIF 2.1.0"]
    runs = doc.get("runs") or []
    if not runs:
        bad.append("runs: none")
    for i, run in enumerate(runs):
        if not ((run.get("tool") or {}).get("driver") or {}).get("name"):
            bad.append(f"runs[{i}].tool.driver.name")
        for j, res in enumerate(run.get("results") or []):
            at = f"runs[{i}].results[{j}]"
            if not (res.get("message") or {}).get("text"):
                bad.append(at + ".message.text")
            locs = res.get("locations") or []
            if not locs:
                bad.append(at + ".locations")
                continue
            phys = locs[0].get("physicalLocation") or {}
            if not (phys.get("artifactLocation") or {}).get("uri"):
                bad.append(at + ".artifactLocation.uri")
            line = (phys.get("region") or {}).get("startLine")
            if not isinstance(line, int) or isinstance(line, bool):
                bad.append(at + ".region.startLine")
            if not any(l.get("name") for l in locs[0].get("logicalLocations") or []):
                bad.append(at + ".logicalLocations")
            ev = (res.get("properties") or {}).get("evidence")
            if not isinstance(ev, Mapping) or ev.get("schema") != EVIDENCE_SCHEMA:
                bad.append(at + ".properties.evidence: no cull.evidence record")
                continue
            ver = _version(ev.get("version"))
            if not ver or ver[0] != EVIDENCE_MAJOR:
                bad.append(f"{at}.properties.evidence.version {ev.get('version')!r}: "
                           f"this reader knows major {EVIDENCE_MAJOR}")
            if not isinstance((ev.get("location") or {}).get("line"), int):
                bad.append(at + ".properties.evidence.location.line")
    return bad


# ---------------------------------------------------------------------------
# derivations (each used only when cull did not supply the field)
# ---------------------------------------------------------------------------

def rule_id(ev: Mapping) -> str:
    """cull's rule: `cull/<family>`, or another query set's rule id."""
    alert = ev.get("alert") or {}
    return str(alert.get("rule")) if alert.get("rule") else f"cull/{ev.get('family') or 'CWE-787'}"


def candidate_id(ev: Mapping) -> str:
    """cull's formula: sha256(rule | path | line | function)[:16]."""
    loc = ev.get("location") or {}
    key = "|".join(str(x) for x in (rule_id(ev), loc.get("path") or "", loc.get("line") or 0,
                                    loc.get("function") or ""))
    return hashlib.sha256(key.encode("utf-8")).hexdigest()[:16]


def pattern_of(ev: Mapping, bag: Mapping) -> str:
    """The code-review/v1 pattern, or `other`."""
    access = bag.get("access") or ev.get("access") or \
        ((ev.get("write") or {}).get("access") or "write")
    sink = str(bag.get("sink_class") or "").lower()
    if sink:
        p = _SINK_PATTERN.get(sink)
        if p == "oob":
            return "oob_read" if access == "read" else "oob_write"
        return p or "other"
    alert = ev.get("alert") or {}
    if alert:
        for cwe in alert.get("cwes") or []:
            p = _ALERT_CWE.get(str(cwe).split("-")[-1])
            if p:
                return p
        return "other"
    fam = ev.get("family") or ""
    if fam in ("CWE-190", "CWE-191"):
        # an overflow is a memory bug only where its result decides memory
        return "int_overflow" if (ev.get("integer") or {}).get("feeds") else "other"
    p = _FAMILY_PATTERN.get(fam, "other")
    if p == "oob_write" and access == "read":
        return "oob_read"
    return p


def reach_tier(ev: Mapping, bag: Mapping, cfg: Mapping) -> tuple:
    """(tier, source): cull's own reach_tier when it ships one, else mapped.

    From evidence 1.7.0 cull decides it; its `null` means "no entry point in
    the database" -- an answer, not a missing field -- and reads as `unknown`
    (ordered by rank, like any tier nothing ranks below)."""
    for src in (bag, ev):
        if "reach_tier" in src:
            t = src.get("reach_tier")
            return (t if t in TIERS else UNKNOWN), "cull"
    if "reachability" not in ev:
        return UNKNOWN, "local"
    label = ev.get("reachability") or "none"
    return cfg["reach_map"].get(label, UNKNOWN), "local"


def call_chain(ev: Mapping) -> list:
    """The first (best) flow path, source first, then the sink's function."""
    paths = ev.get("flow_steps") or []
    chain = []
    if paths:
        for s in paths[0].get("steps") or []:
            where = f"{s.get('path')}:{s.get('line')}"
            chain.append(f"{s['message']} @ {where}" if s.get("message") else where)
    fn = (ev.get("location") or {}).get("function")
    if chain and fn:
        chain.append(f"{fn}()")
    return chain


def local_confidence(position: int, tier: str, verdict: str, cfg: Mapping) -> str:
    if verdict == "REPORT":
        return "high"          # cull's arithmetic proved it
    for level in ("high", "medium"):
        rule = (cfg["confidence_map"] or {}).get(level) or {}
        if position <= int(rule.get("max_rank", 0)) and tier in (rule.get("reach_tiers") or []):
            return level
    return "low"


# ---------------------------------------------------------------------------
# intake
# ---------------------------------------------------------------------------

def _load(sarif) -> tuple:
    if isinstance(sarif, Mapping):
        return dict(sarif), None
    p = Path(sarif)
    data = p.read_bytes()
    try:
        return json.loads(data), hashlib.sha256(data).hexdigest()
    except ValueError as e:
        raise IntakeError(f"{p}: not JSON ({e})") from None


def _degraded(run: Mapping) -> bool:
    props = run.get("properties") or {}
    prov = props.get("cull/v1:provenance") or {}
    return bool(prov.get("degraded") or (props.get("analysis") or {}).get("degraded")
                or (props.get("budget") or {}).get("degraded"))


def intake(sarif, *, config: Mapping | None = None, diff=None, now: float | None = None) -> dict:
    """cull-intake/v1 from a bug-candidate SARIF (a path or a parsed dict)."""
    from cc_fuzzer_core.prescan import sast_scan
    cfg = settings(config)
    doc, file_sha = _load(sarif)
    problems = validate(doc)
    if problems:
        raise IntakeError("not a cull bug-candidate SARIF this reader accepts: "
                          + "; ".join(problems[:8])
                          + (f" (+{len(problems) - 8} more)" if len(problems) > 8 else ""))
    run = doc["runs"][0]
    driver = (run.get("tool") or {}).get("driver") or {}
    degraded = _degraded(run)
    if degraded and not cfg["accept_degraded"]:
        raise IntakeError("the cull run is degraded and cull.accept_degraded is false")

    prov = (run.get("properties") or {}).get("cull/v1:provenance")
    notes = set()
    if not prov:
        notes.add("provenance")
    provenance = {
        "cull_version": (prov or {}).get("cull_version") or driver.get("version"),
        "db_sha256": (prov or {}).get("db_sha256"),
        "pack_sha256": (prov or {}).get("pack_sha256"),
        "diff_sha256": (prov or {}).get("diff_sha256"),
        "codeql_version": (prov or {}).get("codeql_version"),
        "evidence_version": (prov or {}).get("evidence_version"),
        "sarif_sha256": file_sha,
        "degraded": degraded,
        "raw": prov,
    }
    provenance["cull_run"] = provenance["db_sha256"] or file_sha

    found = sast_scan.normalize_sarif(doc, Path("/"), keep_properties=True)
    # cull's own order when it gives one (evidence 1.7.0: proofs first, then
    # triage, diff bands before score; `rank` is a score, not the order);
    # before that, rank order with the file's order breaking ties
    def _given(i):
        pos = ((found[i].get("properties") or {}).get("cull/v1") or {}).get("position")
        return pos if isinstance(pos, int) and not isinstance(pos, bool) else None
    if all(_given(i) is not None for i in range(len(found))):
        order = sorted(range(len(found)), key=lambda i: (_given(i), i))
    else:
        order = sorted(range(len(found)), key=lambda i: (-(found[i].get("rank") or 0.0), i))
        if found:
            notes.add("position")
    targets = None
    if diff is not None:
        from cc_fuzzer_core import delta
        targets = delta.targets_of(diff)

    cands = []
    for pos, i in enumerate(order, 1):
        f = found[i]
        props = f.get("properties") or {}
        ev = props.get("evidence") or {}
        bag = props.get("cull/v1") or {}
        ver = _version(ev.get("version"))
        for field, since in SINCE.items():
            if ver < since and field not in ev:
                notes.add(f"evidence.{field}")
        loc = ev.get("location") or {}
        cid = ev.get("candidate_id") or bag.get("candidate_id")
        id_source = "cull"
        if not cid:
            cid, id_source = candidate_id(ev), "local"
            notes.add("candidate_id")
        tier, tier_source = reach_tier(ev, bag, cfg)
        if tier_source == "local":
            notes.add("reach_tier")
        conf = bag.get("confidence")
        conf_source = "cull"
        if conf not in ("high", "medium", "low"):
            conf, conf_source = local_confidence(pos, tier, ev.get("verdict") or "", cfg), "local"
            notes.add("confidence")
        pattern = pattern_of(ev, bag)
        if "call_chain" in bag or "call_chain" in ev:
            # cull's call path (null for none-found and null tiers: no path)
            chain = bag.get("call_chain") if "call_chain" in bag else ev.get("call_chain")
            chain = list(chain) if isinstance(chain, list) else []
        else:
            chain = call_chain(ev)      # data flow, the pre-1.7 stand-in
            notes.add("call_chain")
        prox = ev.get("diff_proximity")
        if prox is None and targets is not None:
            from cc_fuzzer_core import delta
            rel = delta.relevance([f"{loc.get('function')} @ {loc.get('path')}:{loc.get('line')}"],
                                  targets)
            prox = {"label": "in-diff" if rel["frames_in_diff"] else
                    "changed-function" if rel["functions_in_diff"] else None,
                    "source": "local"}
        cands.append({
            "candidate_id": cid, "id_source": id_source,
            "position": pos, "rank": f.get("rank"),
            "rule_id": rule_id(ev), "family": ev.get("family"),
            "verdict": ev.get("verdict"), "tier": ev.get("tier"),
            "reachability": ev.get("reachability"),
            "reach_tier": tier, "reach_source": tier_source,
            "confidence": conf, "confidence_source": conf_source,
            "pattern": pattern, "sink_class": bag.get("sink_class") or _SINK_CLASS.get(pattern),
            "path": loc.get("path") or f.get("path"), "line": loc.get("line"),
            "column": loc.get("column"), "function": loc.get("function") or f.get("function"),
            "function_span": loc.get("function_span"),
            "why": ev.get("why") if "why" in ev and ev.get("why") else (f.get("message") or ""),
            "call_chain": list(chain or []),
            "guards": list(ev.get("guards") or []),
            "refusal": list(ev.get("refusal") or []),
            "diff_proximity": prox,
            "input_hints": list(bag.get("input_hints") or bag.get("hints") or []),
            "evidence_version": ev.get("version"),
            "evidence": ev,
            "cull_v1": bag,
        })
    return {
        "schema": INTAKE_SCHEMA,
        "ts": int(time.time() if now is None else now),
        "source": str(sarif) if not isinstance(sarif, Mapping) else "<dict>",
        "producer": {"name": driver.get("name"), "version": driver.get("version")},
        "provenance": provenance,
        "degraded_fields": sorted(notes),
        "counts": {"candidates": len(cands),
                   "by_reach_tier": {t: sum(1 for c in cands if c["reach_tier"] == t)
                                     for t in TIERS},
                   "by_confidence": {c: sum(1 for x in cands if x["confidence"] == c)
                                     for c in ("high", "medium", "low")},
                   "proven_fits_omitted": (run.get("properties") or {}).get("provenFitsOmitted")},
        "candidates": cands,
    }


def signal(intake_doc: Mapping, config: Mapping | None = None) -> dict:
    """sast-signal/v1 for the prescan: one finding per candidate, weighted by
    reach tier so cull outweighs a semgrep hit, which outweighs a heuristic."""
    w = settings(config)["signal_weights"]
    sev = {"high": "high", "medium": "medium", "low": "low"}
    findings = [{"tool": "cull", "rule_id": c["rule_id"],
                 "severity": sev.get(c["confidence"], "low"),
                 "weight": int(w.get(c["reach_tier"], w.get(UNKNOWN, 10))),
                 "cwe": [c["family"]] if str(c.get("family") or "").startswith("CWE-") else [],
                 "path": c["path"], "line": c["line"] or 0,
                 "message": f"[cull {c['tier'] or c['verdict']}; reach {c['reach_tier']}] {c['why']}"[:500],
                 "candidate_id": c["candidate_id"]}
                for c in intake_doc.get("candidates") or []]
    return {"schema": SIGNAL_SCHEMA, "tool": "cull",
            "cull_run": (intake_doc.get("provenance") or {}).get("cull_run"),
            "findings": findings}


def write(intake_doc: Mapping, state_dir, *, config: Mapping | None = None) -> dict:
    """Write the intake, the prescan signal and the code-review/v1 snapshot.

    <state>/cull/intake-<ts>.json, <state>/signals/cull.json (the prescan reads
    every file there) and <state>/cull/code-review-<ts>.json (import-cr takes
    it by path: it is kept out of snapshots/ so it never shadows a model
    review as the "latest" snapshot).
    """
    from cc_fuzzer_core.integrations.cull import crmap
    sd = Path(state_dir)
    ts = intake_doc["ts"]
    out = {}
    for key, rel, doc in (
            ("intake", f"cull/intake-{ts}.json", intake_doc),
            ("signal", "signals/cull.json", signal(intake_doc, config)),
            ("code_review", f"cull/code-review-{ts}.json",
             crmap.snapshot(intake_doc, config=config))):
        p = sd / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        tmp = p.with_suffix(p.suffix + ".tmp")
        tmp.write_text(json.dumps(doc, indent=2, sort_keys=True) + "\n")
        tmp.replace(p)
        out[key] = str(p)
    return out


def latest(state_dir) -> dict | None:
    """The newest intake under <state>/cull/, or None."""
    d = Path(state_dir) / "cull"
    files = sorted(d.glob("intake-*.json"), key=lambda p: (int(p.stem.split("-")[-1])
                                                           if p.stem.split("-")[-1].isdigit()
                                                           else 0, p.name))
    return json.loads(files[-1].read_text()) if files else None


def compare(old: Mapping, new: Mapping) -> dict:
    """Two intakes, provenance first (recommendation 10): a changed db_sha256
    or pack explains a changed candidate list before anything else is read."""
    keys = ("cull_version", "codeql_version", "pack_sha256", "db_sha256", "diff_sha256",
            "evidence_version", "degraded")
    po, pn = old.get("provenance") or {}, new.get("provenance") or {}
    changed = {k: [po.get(k), pn.get(k)] for k in keys if po.get(k) != pn.get(k)}
    a = {c["candidate_id"] for c in old.get("candidates") or []}
    b = {c["candidate_id"] for c in new.get("candidates") or []}
    if not changed:
        why = "same provenance: any difference is cull's, not the input's"
    elif "db_sha256" in changed:
        why = "the database changed: a different candidate list is expected"
    else:
        why = "provenance changed: " + ", ".join(sorted(changed))
    return {"provenance_changed": changed, "explanation": why,
            "added": sorted(b - a), "removed": sorted(a - b), "kept": len(a & b)}
