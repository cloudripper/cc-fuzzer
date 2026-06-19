#!/usr/bin/env python3
"""code_review_merge.py — combine code-review window partials into the canonical snapshot.

Tier-2 of the sweep flow writes one PARTIAL snapshot per window
(`code-review-<ts>-w<NN>.json`, each scoped to `top_candidates[start:start+count]`).
This helper merges them into the single canonical `code-review-<ts>.json` the rest
of the campaign reads, and writes the consolidated `code-review.md` with a LOUD
coverage header so a capped review can never read as a complete audit.

What it does (the merge half of the windowing contract):
  - Reads the prescan artifact (for `scope.functions_inventoried` + `scope.mode`,
    the authoritative totals — a window partial only knows its own slice).
  - Reads every window partial.
  - Dedups findings by `cr_hash` (first writer wins on conflicting fields; the
    *status* is upgraded to the most-advanced one seen across partials so a
    later window that confirmed a bug isn't reset by an earlier candidate).
  - Reassigns stable `cr<NNN>` ids in `cr_hash` sort order (deterministic).
  - AGGREGATES scope: functions_inventoried (from prescan),
    candidates_reviewed = sum of per-window reviewed, not_reviewed =
    functions_inventoried - candidates_reviewed,
    coverage_complete = (mode == "sweep" and not_reviewed == 0).
  - Writes the canonical JSON + the markdown report with the loud header.

Single-window (capped) mode passes through trivially: one partial in, one
canonical out, with the same loud disclosure.

CLI:
    code_review_merge.py \\
        --prescan  fuzz/state/snapshots/code-review-prescan-<ts>.json \\
        --out      fuzz/state/snapshots/code-review-<ts>.json \\
        --md       fuzz/state/code-review.md \\
        --target   <name> \\
        partial1.json partial2.json ...
"""
from __future__ import annotations
import argparse
import json
import sys
import time
from pathlib import Path

# CR status lifecycle, most-advanced last. Used to pick the winning status when
# the same cr_hash appears in more than one window partial.
_STATUS_RANK = {"candidate": 0, "triaging": 1, "confirmed": 2, "poc": 3,
                "dismissed": 1}  # dismissed ~ triaging precedence: a later confirm beats it


def _load(path):
    with open(path) as f:
        return json.load(f)


def _atomic_write_json(path, obj):
    p = Path(path)
    p.parent.mkdir(parents=True, exist_ok=True)
    tmp = p.with_suffix(p.suffix + ".tmp")
    with tmp.open("w") as f:
        json.dump(obj, f, indent=2)
        f.write("\n")
    tmp.replace(p)


def _atomic_write_text(path, text):
    p = Path(path)
    p.parent.mkdir(parents=True, exist_ok=True)
    tmp = p.with_suffix(p.suffix + ".tmp")
    tmp.write_text(text, encoding="utf-8")
    tmp.replace(p)


def _coverage_header(mode, reviewed, inventoried, not_reviewed, complete):
    """The LOUD coverage disclosure line. Identical contract to the agent text."""
    if complete:
        return f"✓ COVERAGE: swept all {inventoried} functions."
    pct = (100.0 * reviewed / inventoried) if inventoried else 0.0
    return (
        f"⚠ COVERAGE: reviewed {reviewed} of {inventoried} functions "
        f"({pct:.0f}%). {not_reviewed} functions were NOT reviewed. This is a "
        f"capped starting map, not a complete audit — re-run "
        f"`/cc-fuzzer:fuzz-review --sweep` for full coverage."
    )


def _render_markdown(doc, header_line):
    scope = doc.get("scope") or {}
    findings = doc.get("findings") or []
    focus = doc.get("focus_areas") or []
    target = doc.get("target") or "(target)"
    ts_iso = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(doc.get("ts") or time.time()))

    lines = []
    lines.append(f"# Code review for `{target}`")
    lines.append("")
    # The loud header is the FIRST content line so it can never be missed.
    lines.append(header_line)
    lines.append("")
    lines.append(
        f"Generated {ts_iso}. Scope: {scope.get('files_scanned', '?')} files, "
        f"{scope.get('functions_inventoried', '?')} functions, "
        f"{scope.get('loc_total', '?')} LOC. Reviewed "
        f"{scope.get('candidates_reviewed', '?')} candidates "
        f"(mode: {scope.get('mode', '?')}). Tiers run: {doc.get('tiers_run')}."
    )
    lines.append("")
    lines.append("## Purpose")
    lines.append("")
    lines.append(
        "This document identifies vulnerable PATTERNS in the target source that "
        "the campaign should investigate. It is INPUT for the fuzzer, not a "
        "security audit and not a list of bugs to verify. It's a starting map."
    )
    lines.append("")

    # Focus areas
    lines.append("## Top focus areas")
    lines.append("")
    if focus:
        for fa in sorted(focus, key=lambda a: a.get("rank", 99)):
            scope_name = fa.get("scope", "?")
            lines.append(f"### {fa.get('rank', '?')}. `{scope_name}`")
            lines.append(f"**Rationale**: {fa.get('rationale', '')}")
            lines.append(f"**Fuzzing recommendation**: {fa.get('fuzzing_recommendation', '')}")
            lines.append("")
    else:
        lines.append("(none)")
        lines.append("")

    # Top findings (high/medium + needs_deep_pass), capped at 20.
    def _rank(f):
        return {"high": 0, "medium": 1, "low": 2}.get(f.get("confidence"), 3)
    shown = [f for f in findings
             if f.get("confidence") in ("high", "medium") or f.get("needs_deep_pass")]
    shown.sort(key=lambda f: (_rank(f), f.get("file", ""), f.get("id", "")))
    lines.append("## Top findings (high, medium, and any flagged needs_deep_pass)")
    lines.append("")
    for f in shown[:20]:
        lr = f.get("line_range") or [f.get("line_start", "?")]
        lines.append(
            f"### `{f.get('id')}` — `{f.get('pattern')}` in "
            f"`{f.get('file')}:{lr[0]}` (`{f.get('confidence')}`, "
            f"`{f.get('oracle_kind', 'memory')}`)"
        )
        lines.append(f"- **Status**: `{f.get('status')}` (cr_hash `{f.get('cr_hash')}`)")
        lines.append(f"- **Function**: `{f.get('function')}`")
        if f.get("oracle_kind") and f.get("oracle_kind") != "memory":
            lines.append(f"- **Trust boundary**: `{f.get('trust_boundary_crossed', '')}`")
            lines.append(f"- **Precondition**: {f.get('precondition', '')}")
        lines.append(f"- **Evidence**: {f.get('evidence', '')}")
        if f.get("exploitability_hint"):
            lines.append(f"- **Exploitability**: {f.get('exploitability_hint')}")
        if f.get("fuzzing_recommendation"):
            lines.append(f"- **Fuzzing**: {f.get('fuzzing_recommendation')}")
        if f.get("needs_deep_pass"):
            lines.append(f"- **Needs deep pass**: `true` — {f.get('deep_pass_question', '')}")
        lines.append("")
    if len(shown) > 20:
        lines.append(f"See `{Path(doc.get('_artifact', 'code-review-<ts>.json')).name}` for the full set.")
        lines.append("")

    lines.append("## Consumers")
    lines.append("")
    lines.append(
        "`campaign-planner` reads the focus areas to populate `## Coverage "
        "Targets`. `harness-writer` biases entry-point selection. "
        "`seed-generator` pulls each finding's `fuzzing_recommendation`."
    )
    lines.append("")
    return "\n".join(lines)


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("--prescan", required=True, help="prescan artifact (scope totals + mode).")
    ap.add_argument("--out", required=True, help="canonical code-review-<ts>.json output path.")
    ap.add_argument("--md", required=True, help="code-review.md output path.")
    ap.add_argument("--target", default="", help="target name for the snapshot/markdown.")
    ap.add_argument("partials", nargs="+", help="window partial JSON paths.")
    args = ap.parse_args()

    try:
        prescan = _load(args.prescan)
    except Exception as e:
        print(f"ERROR: cannot read prescan {args.prescan}: {e}", file=sys.stderr)
        return 2
    pscope = prescan.get("scope") or {}
    inventoried = int(pscope.get("functions_inventoried") or 0)
    mode = pscope.get("mode") or "capped"

    # Merge findings across partials, dedup by cr_hash.
    by_hash = {}
    reviewed_total = 0
    tiers = set()
    target = args.target or ""
    files_scanned = pscope.get("files_scanned")
    loc_total = pscope.get("loc_total")
    revisit_passes = []
    model_costs = {}

    for pp in args.partials:
        try:
            d = _load(pp)
        except Exception as e:
            print(f"ERROR: cannot read partial {pp}: {e}", file=sys.stderr)
            return 2
        wscope = d.get("scope") or {}
        reviewed_total += int(wscope.get("candidates_reviewed") or 0)
        for t in (d.get("tiers_run") or []):
            tiers.add(t)
        if not target:
            target = d.get("target") or ""
        if files_scanned is None:
            files_scanned = wscope.get("files_scanned")
        if loc_total is None:
            loc_total = wscope.get("loc_total")
        for rp in (d.get("revisit_passes") or []):
            revisit_passes.append(rp)
        # Accumulate model costs additively (token counts sum across windows).
        for k, v in (d.get("model_costs") or {}).items():
            if isinstance(v, (int, float)):
                model_costs[k] = model_costs.get(k, 0) + v
        for f in (d.get("findings") or []):
            h = f.get("cr_hash")
            if not h:
                # No hash → keep by a synthetic key so it isn't silently dropped.
                h = f"__nohash__{len(by_hash)}"
                by_hash[h] = dict(f)
                continue
            if h not in by_hash:
                by_hash[h] = dict(f)
            else:
                # Upgrade status to the most-advanced lifecycle seen; opus tier wins.
                cur = by_hash[h]
                if _STATUS_RANK.get(f.get("status"), 0) > _STATUS_RANK.get(cur.get("status"), 0):
                    cur["status"] = f.get("status")
                if f.get("tier_classified") == "opus":
                    cur["tier_classified"] = "opus"

    # Stable cr id reassignment in cr_hash sort order.
    merged = [by_hash[h] for h in sorted(by_hash)]
    for i, f in enumerate(merged, 1):
        f["id"] = f"cr{i:03d}"

    # Collect focus areas from partials (concatenate, dedup by scope, re-rank).
    fa_by_scope = {}
    for pp in args.partials:
        try:
            d = _load(pp)
        except Exception:
            continue
        for fa in (d.get("focus_areas") or []):
            sc = fa.get("scope")
            if sc and sc not in fa_by_scope:
                fa_by_scope[sc] = dict(fa)
    focus_areas = sorted(fa_by_scope.values(), key=lambda a: a.get("rank", 99))
    for i, fa in enumerate(focus_areas, 1):
        fa["rank"] = i

    not_reviewed = max(0, inventoried - reviewed_total)
    coverage_complete = (mode == "sweep" and not_reviewed == 0)

    doc = {
        "schema": "code-review/v1",
        "ts": prescan.get("ts") or int(time.time()),
        "target": target,
        "scope": {
            "files_scanned": files_scanned,
            "functions_inventoried": inventoried,
            "loc_total": loc_total,
            "candidates_reviewed": reviewed_total,
            "not_reviewed": not_reviewed,
            "coverage_complete": coverage_complete,
            "mode": mode,
            "excluded_paths": pscope.get("excluded_paths") or [],
        },
        "tiers_run": sorted(tiers) if tiers else ["prescan", "sonnet"],
        "findings": merged,
        "focus_areas": focus_areas,
    }
    if revisit_passes:
        doc["revisit_passes"] = revisit_passes
    if model_costs:
        doc["model_costs"] = model_costs

    doc["_artifact"] = str(args.out)
    header = _coverage_header(mode, reviewed_total, inventoried, not_reviewed, coverage_complete)
    md = _render_markdown(doc, header)
    del doc["_artifact"]

    _atomic_write_json(args.out, doc)
    _atomic_write_text(args.md, md)

    print(header)
    print(args.out)
    return 0


if __name__ == "__main__":
    sys.exit(main())
