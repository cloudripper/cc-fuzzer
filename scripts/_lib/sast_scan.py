#!/usr/bin/env python3
"""sast_scan.py — deterministic SAST signal for Tier-1 of the code-review pipeline.

This module shells out to external static analyzers (semgrep, optionally CodeQL),
normalizes their output to a common finding shape, and attributes each finding to
an inventoried function so the prescan can fold a *real-tool* signal into the
suspicion score. It does NO LLM calls.

It is intentionally additive and graceful, mirroring how the plugin treats
cmplog / SymCC: when a tool is missing the scan is skipped with a loud reason
string and the campaign continues on the grep-heuristic signal alone. A semgrep
hit is a stronger signal than a coarse `strcpy` grep, so attributed findings get
a heavier score bump than the PATTERN_RULES weights — but they never gate the
review; Tier-2 (Sonnet) still confirms.

Public surface (imported by code_review_prescan.py):

    detect_tools()                       -> {"semgrep": bool, "codeql": bool}
    run_sast(target_root, *, ...)        -> SastResult
    attribute(findings, functions)       -> mutates FunctionEntry-likes in place,
                                            returns (attributed, unattributed)

`run_sast` returns a SastResult dataclass carrying per-tool status, the
normalized findings, and a machine-readable `to_dict()` for the prescan JSON's
`sast` block.

Common normalized finding shape (one dict per finding):

    {
      "tool":      "semgrep" | "codeql",
      "rule_id":   "toctou-access-open",
      "severity":  "high" | "medium" | "low" | "info",
      "cwe":       ["CWE-367"],            # may be empty
      "path":      "src/file.c",           # relative to target_root
      "line":      142,
      "end_line":  146,
      "message":   "access() check followed by open() — TOCTOU race",
    }

CLI (for manual runs / debugging, NOT used by the pipeline):

    sast_scan.py --target-root <dir> [--rules <dir,dir>] [--tool semgrep]
                 [--timeout 300] [--json]
"""
from __future__ import annotations

import argparse
import json
import os
import re
import shutil
import subprocess
import sys
import time
from dataclasses import dataclass, field, asdict
from pathlib import Path
from typing import Dict, List, Optional, Tuple, Iterable


# ---------------------------------------------------------------------------
# Severity model
# ---------------------------------------------------------------------------

# Normalized severity -> suspicion-score bump applied to the function the
# finding lands in. Deliberately heavier than a single grep PATTERN_RULES hit
# (max 8) because a SAST rule encodes a real check/use relationship, not just
# the presence of a dangerous token. Capped so a noisy ruleset can't swamp the
# CVE-hotspot signal (max +10).
SEVERITY_WEIGHT: Dict[str, int] = {
    "high": 9,
    "medium": 5,
    "low": 2,
    "info": 1,
}

# semgrep emits ERROR / WARNING / INFO in `extra.severity`; map to ours.
_SEMGREP_SEVERITY = {
    "ERROR": "high",
    "WARNING": "medium",
    "INFO": "low",
}

# CodeQL SARIF levels.
_SARIF_LEVEL = {
    "error": "high",
    "warning": "medium",
    "note": "low",
    "none": "info",
}


# ---------------------------------------------------------------------------
# Result container
# ---------------------------------------------------------------------------

@dataclass
class ToolRun:
    tool: str
    status: str               # "ok" | "skipped: <reason>" | "error: <reason>"
    findings_count: int = 0
    duration_s: float = 0.0
    rules_source: List[str] = field(default_factory=list)


@dataclass
class SastResult:
    enabled: bool
    runs: List[ToolRun] = field(default_factory=list)
    findings: List[dict] = field(default_factory=list)
    # findings that could not be attributed to any inventoried function
    # (header-only, macro bodies, file-level rules). Surfaced so the reviewer
    # can still see them.
    unattributed: List[dict] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "enabled": self.enabled,
            "tools": [asdict(r) for r in self.runs],
            "findings_total": len(self.findings),
            "attributed": len(self.findings) - len(self.unattributed),
            "unattributed": self.unattributed,
        }


# ---------------------------------------------------------------------------
# Tool detection
# ---------------------------------------------------------------------------

def detect_tools() -> Dict[str, bool]:
    """Return which supported analyzers are on PATH."""
    return {
        "semgrep": shutil.which("semgrep") is not None,
        "codeql": shutil.which("codeql") is not None,
    }


# ---------------------------------------------------------------------------
# semgrep
# ---------------------------------------------------------------------------

def _semgrep_severity(raw: str) -> str:
    return _SEMGREP_SEVERITY.get((raw or "").upper(), "low")


def _extract_cwe(extra_meta: dict) -> List[str]:
    """semgrep stuffs CWE under extra.metadata.cwe as a str or list of strs."""
    cwe = (extra_meta or {}).get("cwe")
    if not cwe:
        return []
    if isinstance(cwe, str):
        cwe = [cwe]
    out = []
    for c in cwe:
        # entries look like "CWE-367: Time-of-check Time-of-use ..." — keep the id
        c = str(c).strip()
        if c.upper().startswith("CWE-"):
            out.append(c.split(":", 1)[0].strip())
        elif c:
            out.append(c)
    return out


def _has_rule_file(d: Path) -> bool:
    """True when `d` (recursively) contains at least one .yml/.yaml file."""
    try:
        return any(d.rglob("*.yml")) or any(d.rglob("*.yaml"))
    except Exception:  # noqa: BLE001
        return False


def _expand_rule_dirs(rule_dirs: List[Path]) -> List[Path]:
    """Map each requested LOCAL rule dir to the config path(s) safe to hand
    semgrep. (Registry refs like `p/trailofbits` / `auto` never reach here —
    run_semgrep routes those verbatim; this is local-dir handling only.)

    A rule-pack checkout can carry non-rule YAML in dot-directories (e.g. a
    `.github/workflows/*.yml`) that semgrep tries to load as a rule and then
    aborts the entire scan on. semgrep's `--exclude` filters TARGET paths, not
    config paths, so the only reliable fix is to never point a `--config` at a
    tree containing that cruft. Strategy, generic (no hardcoded pack name):
      * dir has NO dot-subdirectory  -> use the dir as-is (covers rules/semgrep)
      * dir HAS a dot-subdirectory   -> expand to its non-dot immediate child
                                        dirs that hold rule files, plus any
                                        top-level rule files in the dir itself
    De-duplicated, order-stable."""
    out: List[Path] = []
    seen = set()

    def _add(p: Path) -> None:
        key = str(p)
        if key not in seen:
            seen.add(key)
            out.append(p)

    for d in rule_dirs:
        try:
            children = list(d.iterdir())
        except Exception:  # noqa: BLE001
            _add(d)
            continue
        has_dot_subdir = any(c.is_dir() and c.name.startswith(".") for c in children)
        if not has_dot_subdir:
            _add(d)
            continue
        # Pack with dot-dir cruft: take clean (non-dot) child rule dirs
        # individually. (Not the dir itself — that would recurse into the cruft.)
        expanded_any = False
        for c in sorted(children):
            if c.is_dir() and not c.name.startswith(".") and _has_rule_file(c):
                _add(c)
                expanded_any = True
        # Top-level rule files in the dir root: pass them by explicit file path
        # so semgrep loads them without re-descending into the dot-dirs.
        for c in sorted(children):
            if c.is_file() and c.suffix in (".yml", ".yaml"):
                _add(c)
                expanded_any = True
        # Degenerate: a dir whose ONLY rule content is under dot-dirs. Skip it
        # rather than poison the run (semgrep would abort on the dot-dir YAML).
        _ = expanded_any
    return out


# A semgrep registry shorthand: `p/<pack>`, `r/<rule>`, `s/<snippet>`, etc.
# (single lowercase letter, slash, more). http(s) URLs are handled separately.
# Used to pass on-demand registry refs straight through to semgrep.
_REGISTRY_REF_RE = re.compile(r"^[a-z]/")

# PRIVACY DEFAULT: `--config auto` is metrics-gated by semgrep ("Cannot create
# auto config when metrics are off"), and this plugin never enables telemetry,
# so `auto` is unsupported. We skip it with this explanation rather than sending
# it (which would just fail) or enabling metrics (a telemetry leak).
_AUTO_SKIP_NOTE = ("auto skipped: requires semgrep telemetry (--metrics on), "
                   "which is disabled for privacy — use an explicit registry "
                   "pack such as p/trailofbits")


def _classify_rule_specs(rule_specs) -> Tuple[List[Path], List[str], List[str]]:
    """Split mixed rule specs into (local_dirs, registry_tokens, skipped).

    Each spec is a Path (auto-discovered local pack) or a str (user-supplied via
    --sast-rules). Classification:
      * existing local directory  -> local_dirs (Path)        (auto-expanded)
      * registry shorthand `^[a-z]/…` (p/…, r/…, s/…)  -> registry_tokens (verbatim)
      * http(s):// URL             -> registry_tokens          (verbatim)
      * `auto`                     -> skipped (UNSUPPORTED: needs telemetry)
      * anything else (typo'd path / unreachable) -> skipped (recorded, no crash)

    `skipped` entries are human-readable notes surfaced in the ToolRun status —
    never sent to semgrep. NB: `auto` is matched BEFORE the registry regex so it
    can never leak into an invocation."""
    local_dirs: List[Path] = []
    registry: List[str] = []
    skipped: List[str] = []
    for spec in rule_specs:
        if isinstance(spec, Path):
            if spec.is_dir():
                local_dirs.append(spec)
            else:
                skipped.append(str(spec))
            continue
        s = str(spec).strip()
        if not s:
            continue
        if s == "auto":
            # Never reaches semgrep — telemetry-gated, disabled for privacy.
            skipped.append(_AUTO_SKIP_NOTE)
            continue
        p = Path(s)
        if p.is_dir():
            local_dirs.append(p)
        elif _REGISTRY_REF_RE.match(s) or s.startswith(("http://", "https://")):
            registry.append(s)
        else:
            skipped.append(s)
    return local_dirs, registry, skipped


def run_semgrep(target_root: Path, rules_dirs, excludes: List[str],
                timeout: int) -> Tuple[ToolRun, List[dict]]:
    """Run semgrep over target_root with the given rule specs. `rules_dirs` is a
    mixed list of Path (auto-discovered local packs) and/or str (user-supplied
    --sast-rules: local dirs, semgrep registry refs like `p/trailofbits`, or
    http(s) URLs). `auto` is unsupported (telemetry-gated; disabled for privacy)
    and is skipped with a note. Returns (ToolRun, normalized findings). Never
    raises for the common failure modes — a missing binary, a bad ruleset, a
    bad registry token, or a timeout all become a ToolRun status string."""
    t0 = time.time()
    if shutil.which("semgrep") is None:
        return ToolRun("semgrep", "skipped: semgrep not on PATH"), []

    local_dirs, registry_tokens, skipped = _classify_rule_specs(rules_dirs)
    if not local_dirs and not registry_tokens:
        # Nothing runnable. Surface why — including the explanatory note for an
        # unsupported `auto` spec — instead of a bare "no rule dirs".
        if skipped:
            reason = f"no usable rule sources ({'; '.join(skipped[:3])})"
        else:
            reason = "no rule dirs found"
        return ToolRun("semgrep", f"skipped: {reason}"), []

    # Local dirs: expand each into the actual config paths to hand semgrep,
    # pruning non-rule cruft that aborts a scan (a pack dir may carry dot-dirs
    # like .github/workflows/*.yml that semgrep tries to load as rules and then
    # aborts the WHOLE run on). Registry tokens are passed VERBATIM as their own
    # config (no existence check, no expansion) — semgrep fetches them on demand.
    config_specs = [str(p) for p in _expand_rule_dirs(local_dirs)] + list(registry_tokens)
    if not config_specs:
        return ToolRun("semgrep", "skipped: no rule dirs found"), []

    # Run each config spec in its OWN semgrep invocation and union the findings.
    # Rationale: semgrep aborts the ENTIRE run (scans zero files) if ANY config
    # it is handed is invalid. Feeding all packs to one process would let a
    # single bad config (or unreachable registry token) zero out every other
    # pack's findings. Isolating per-spec means a bad spec only loses itself;
    # every valid pack still produces results.
    all_findings: List[dict] = []
    per_dir_status: List[str] = []
    had_success = False
    for spec in config_specs:
        fr, fnd = _run_semgrep_one(target_root, spec, excludes, timeout)
        per_dir_status.append(fr)
        if fnd or fr == "ok" or fr.startswith("ok "):
            had_success = True
        all_findings.extend(fnd)

    # Aggregate per-spec statuses into a single ToolRun status. "ok" overall when
    # at least one spec scanned cleanly; otherwise surface the failure detail.
    if had_success:
        bad = [s for s in per_dir_status if not (s == "ok" or s.startswith("ok "))]
        noisy = [s for s in per_dir_status if s.startswith("ok (")]
        status = "ok"
        notes = []
        if noisy:
            notes.append(f"{len(noisy)} pack(s) with ignored rule-load errors")
        if bad:
            notes.append(f"{len(bad)} pack(s) failed: {'; '.join(bad[:3])}")
        if skipped:
            notes.append(f"{len(skipped)} spec(s) skipped (unresolved): {', '.join(skipped[:3])}")
        if notes:
            status = "ok (" + "; ".join(notes) + ")"
    else:
        # Every spec failed — surface the first concrete reason.
        status = next((s for s in per_dir_status if s != "ok"), "error: no results")

    run = ToolRun("semgrep", status, findings_count=len(all_findings),
                  duration_s=round(time.time() - t0, 2), rules_source=config_specs)
    return run, all_findings


def _run_semgrep_one(target_root: Path, rule_dir: str, excludes: List[str],
                     timeout: int) -> Tuple[str, List[dict]]:
    """Run semgrep for a SINGLE config spec (local path or registry ref).
    Returns (status_string, findings). Never raises. Status is "ok" /
    "ok (N rule-load errors ignored)" / "error: <reason>"."""
    # PRIVACY DEFAULT: semgrep ALWAYS runs with --metrics=off. No invocation may
    # enable telemetry. (`--config auto` would need metrics on, so it never
    # reaches here — _classify_rule_specs skips it with an explanation upstream.)
    cmd = ["semgrep", "--json", "--quiet", "--disable-version-check",
           "--metrics=off", "--timeout", str(max(5, timeout // 4)),
           "--config", rule_dir]
    for ex in excludes:
        frag = ex.strip().strip("/")
        if frag:
            cmd += ["--exclude", frag]
    cmd.append(str(target_root))

    try:
        proc = subprocess.run(
            cmd, capture_output=True, text=True, timeout=timeout,
            cwd=str(target_root),
        )
    except subprocess.TimeoutExpired:
        return f"error: timeout after {timeout}s", []
    except Exception as e:  # noqa: BLE001 — defensive, never crash the prescan
        return f"error: {type(e).__name__}: {e}", []

    # semgrep exit codes: 0 = no findings, 1 = findings present, >=2 = error.
    # BUT semgrep still emits a complete results JSON on stdout in many >=2
    # cases — notably when a rule dir contains a non-rule YAML it can't parse
    # (e.g. a pack's .github/workflows/*.yml → exit 7), or a registry pack ships
    # a rule semgrep version-skews on. When semgrep DID scan, those rule-load
    # errors land in the JSON `errors` array while the
    # `results` are intact. So decide SUCCESS by the PRESENCE of a parseable
    # results list, NOT by the exit code: parse stdout first, and only hard-fail
    # when there is no usable results JSON (bad invocation / crash / OOM / timeout).
    try:
        doc = json.loads(proc.stdout or "")
    except (json.JSONDecodeError, ValueError):
        doc = None
    if not isinstance(doc, dict) or not isinstance(doc.get("results"), list):
        # No usable results JSON => a real failure. Surface the best message.
        msg = (proc.stderr or "").strip().splitlines()
        tail = msg[-1] if msg else f"exit {proc.returncode}"
        if proc.returncode == 0:
            tail = "unparseable JSON output"
        return f"error: {tail}", []

    findings: List[dict] = []
    for res in doc.get("results") or []:
        extra = res.get("extra") or {}
        meta = extra.get("metadata") or {}
        path = res.get("path") or ""
        # semgrep paths are relative to cwd (== target_root here) already, but
        # normalize defensively.
        try:
            path = str(Path(path).resolve().relative_to(target_root))
        except Exception:
            path = os.path.relpath(path, str(target_root)) if path else path
        start = (res.get("start") or {}).get("line") or 0
        end = (res.get("end") or {}).get("line") or start
        findings.append({
            "tool": "semgrep",
            "rule_id": res.get("check_id") or "semgrep.unknown",
            "severity": _semgrep_severity(extra.get("severity")),
            "cwe": _extract_cwe(meta),
            "path": path,
            "line": int(start),
            "end_line": int(end),
            "message": (extra.get("message") or meta.get("message") or "").strip()[:500],
        })

    # Reflect any rule-load errors (e.g. a non-rule YAML in a rule dir) in the
    # status so config noise is VISIBLE but never discards the findings.
    load_errors = doc.get("errors") or []
    if load_errors:
        return f"ok ({len(load_errors)} rule-load errors ignored)", findings
    return "ok", findings


# ---------------------------------------------------------------------------
# CodeQL (opt-in: needs a prebuilt database)
# ---------------------------------------------------------------------------

def run_codeql(target_root: Path, db_path: Optional[Path], query_suite: str,
               timeout: int) -> Tuple[ToolRun, List[dict]]:
    """Analyze a *prebuilt* CodeQL database and normalize the SARIF results.

    Building a CodeQL DB requires the project's compile command and is slow, so
    this module does NOT build one implicitly. The caller supplies a db_path
    (from config `code_review.sast.codeql_db`); absent that, CodeQL is skipped.
    This keeps the prescan's "free, ~seconds" contract intact — DB construction
    is a separate, explicit step."""
    t0 = time.time()
    if shutil.which("codeql") is None:
        return ToolRun("codeql", "skipped: codeql not on PATH"), []
    if not db_path:
        return ToolRun("codeql", "skipped: no codeql_db configured"), []
    db_path = Path(db_path)
    if not db_path.exists():
        return ToolRun("codeql", f"skipped: db not found ({db_path})"), []

    sarif_out = db_path.parent / f"codeql-results-{int(time.time())}.sarif"
    cmd = ["codeql", "database", "analyze", str(db_path), query_suite,
           "--format=sarifv2.1.0", f"--output={sarif_out}",
           "--threads=0", "--rerun"]
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
    except subprocess.TimeoutExpired:
        return ToolRun("codeql", f"error: timeout after {timeout}s"), []
    except Exception as e:  # noqa: BLE001
        return ToolRun("codeql", f"error: {type(e).__name__}: {e}"), []

    if proc.returncode != 0 or not sarif_out.exists():
        msg = (proc.stderr or "").strip().splitlines()
        tail = msg[-1] if msg else f"exit {proc.returncode}"
        return ToolRun("codeql", f"error: {tail}"), []

    findings = _parse_sarif(sarif_out, target_root)
    run = ToolRun("codeql", "ok", findings_count=len(findings),
                  duration_s=round(time.time() - t0, 2),
                  rules_source=[query_suite])
    return run, findings


def _parse_sarif(sarif_path: Path, target_root: Path) -> List[dict]:
    try:
        doc = json.loads(sarif_path.read_text())
    except Exception:
        return []
    findings: List[dict] = []
    for run in doc.get("runs") or []:
        # rule -> cwe / default severity lookup
        rule_meta: Dict[str, dict] = {}
        driver = (run.get("tool") or {}).get("driver") or {}
        for rule in driver.get("rules") or []:
            rid = rule.get("id") or ""
            tags = ((rule.get("properties") or {}).get("tags") or [])
            cwes = [t.replace("external/cwe/", "").upper().replace("CWE-", "CWE-")
                    for t in tags if "cwe" in t.lower()]
            # normalize "external/cwe/cwe-367" -> "CWE-367"
            cwes = [("CWE-" + c.split("-")[-1]) for c in cwes if c]
            rule_meta[rid] = {
                "cwe": cwes,
                "severity": _SARIF_LEVEL.get(
                    ((rule.get("defaultConfiguration") or {}).get("level") or "warning"),
                    "medium"),
            }
        for res in run.get("results") or []:
            rid = res.get("ruleId") or "codeql.unknown"
            level = res.get("level")
            sev = _SARIF_LEVEL.get(level, rule_meta.get(rid, {}).get("severity", "medium"))
            locs = res.get("locations") or []
            if not locs:
                continue
            phys = (locs[0].get("physicalLocation") or {})
            uri = ((phys.get("artifactLocation") or {}).get("uri") or "")
            region = phys.get("region") or {}
            start = region.get("startLine") or 0
            end = region.get("endLine") or start
            try:
                path = str(Path(uri).resolve().relative_to(target_root))
            except Exception:
                path = uri
            findings.append({
                "tool": "codeql",
                "rule_id": rid,
                "severity": sev,
                "cwe": rule_meta.get(rid, {}).get("cwe", []),
                "path": path,
                "line": int(start),
                "end_line": int(end),
                "message": ((res.get("message") or {}).get("text") or "").strip()[:500],
            })
    return findings


# ---------------------------------------------------------------------------
# Attribution: map a finding to the function it lands in
# ---------------------------------------------------------------------------

def _norm(path: str) -> str:
    return path.replace("\\", "/").lstrip("./")


def attribute(findings: List[dict], functions: Iterable) -> Tuple[int, List[dict]]:
    """Attach each finding to the inventoried function whose [line_start,
    line_end] range contains the finding's line in the same file, and bump that
    function's suspicion score.

    `functions` is an iterable of objects exposing `.file`, `.line_start`,
    `.line_end`, `.suspicion_score`, `.score_breakdown` (dict), and a
    `.sast_hits` list (created here if missing). Paths are compared by suffix so
    target-root-relative vs absolute differences don't break matching.

    Returns (attributed_count, unattributed_findings)."""
    # Index functions by normalized file path for cheap lookup.
    by_file: Dict[str, List] = {}
    for fn in functions:
        if not hasattr(fn, "sast_hits") or fn.sast_hits is None:
            try:
                fn.sast_hits = []
            except Exception:
                continue
        by_file.setdefault(_norm(fn.file), []).append(fn)

    attributed = 0
    unattributed: List[dict] = []
    for f in findings:
        fpath = _norm(f.get("path") or "")
        line = int(f.get("line") or 0)
        # Candidate function lists: exact path, or any indexed path that is a
        # suffix of the finding path (or vice versa) — handles rel/abs mismatch.
        cands = by_file.get(fpath)
        if cands is None:
            cands = []
            for k, v in by_file.items():
                if k.endswith(fpath) or fpath.endswith(k):
                    cands.extend(v)
        target = None
        for fn in cands:
            if fn.line_start <= line <= fn.line_end:
                # Prefer the tightest enclosing function on overlap.
                if target is None or (fn.line_end - fn.line_start) < (target.line_end - target.line_start):
                    target = fn
        if target is None:
            unattributed.append(f)
            continue

        sev = f.get("severity", "low")
        bump = SEVERITY_WEIGHT.get(sev, 1)
        target.suspicion_score += bump
        key = f"sast_{f.get('tool', 'sast')}_{sev}"
        target.score_breakdown[key] = target.score_breakdown.get(key, 0) + bump
        target.sast_hits.append({
            "tool": f.get("tool"),
            "rule_id": f.get("rule_id"),
            "severity": sev,
            "cwe": f.get("cwe", []),
            "line": line,
            "message": f.get("message", ""),
        })
        attributed += 1
    return attributed, unattributed


# ---------------------------------------------------------------------------
# Top-level driver
# ---------------------------------------------------------------------------

def run_sast(target_root: Path, *, mode: str, rules_dirs,
             excludes: List[str], timeout: int,
             codeql_db: Optional[Path] = None,
             codeql_suite: str = "cpp-security-and-quality.qls") -> SastResult:
    """Run the configured analyzers. `mode` is one of:
        "off"  -> do nothing (enabled=False)
        "auto" -> run whichever of semgrep/codeql is available (default)
        "on"   -> run; if nothing available, the per-tool status records why
    `rules_dirs` is a mixed list of Path (local packs) and/or str (local dirs,
    semgrep registry refs like `p/trailofbits` / `auto`, or http(s) URLs); see
    run_semgrep for the routing. Findings are returned un-attributed; the caller
    invokes attribute()."""
    if mode == "off":
        return SastResult(enabled=False,
                          runs=[ToolRun("sast", "skipped: disabled (mode=off)")])

    result = SastResult(enabled=True)

    sg_run, sg_findings = run_semgrep(target_root, rules_dirs, excludes, timeout)
    result.runs.append(sg_run)
    result.findings.extend(sg_findings)

    # CodeQL only when a DB is configured (auto and on both honor this; without
    # a DB it self-skips cheaply).
    cq_run, cq_findings = run_codeql(target_root, codeql_db, codeql_suite, timeout)
    result.runs.append(cq_run)
    result.findings.extend(cq_findings)

    return result


# ---------------------------------------------------------------------------
# CLI (debugging only)
# ---------------------------------------------------------------------------

def main() -> int:
    ap = argparse.ArgumentParser(description="Standalone SAST scan (debug).")
    ap.add_argument("--target-root", required=True)
    ap.add_argument("--rules", default="",
                    help="comma-separated rule sources: local dirs and/or explicit "
                         "semgrep registry refs (p/trailofbits, http(s):// URLs). "
                         "'auto' is unsupported (needs telemetry, disabled for privacy).")
    ap.add_argument("--mode", default="auto", choices=["off", "auto", "on"])
    ap.add_argument("--timeout", type=int, default=300)
    ap.add_argument("--excluded-paths", default="")
    ap.add_argument("--codeql-db", default="")
    ap.add_argument("--json", action="store_true", help="dump findings as JSON")
    args = ap.parse_args()

    # Raw strings so run_sast can classify local dirs vs registry refs (`auto`,
    # `p/…`, URLs); wrapping in Path() would mangle URLs and hide registry refs.
    rules = [p.strip() for p in args.rules.split(",") if p.strip()]
    excludes = [e for e in args.excluded_paths.split(",") if e.strip()]
    res = run_sast(Path(args.target_root).resolve(), mode=args.mode,
                   rules_dirs=rules, excludes=excludes, timeout=args.timeout,
                   codeql_db=Path(args.codeql_db) if args.codeql_db else None)
    if args.json:
        print(json.dumps({"summary": res.to_dict(), "findings": res.findings},
                         indent=2))
    else:
        for r in res.runs:
            print(f"[{r.tool}] {r.status} "
                  f"({r.findings_count} findings, {r.duration_s}s)", file=sys.stderr)
        for f in res.findings:
            print(f"{f['severity']:6} {f['path']}:{f['line']} "
                  f"{f['rule_id']} {f.get('cwe')}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
