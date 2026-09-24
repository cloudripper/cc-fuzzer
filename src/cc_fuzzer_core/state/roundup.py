"""Tick-coverage roundup (port of tick-coverage-roundup.sh's heredoc).

Aggregates the newest per-harness coverage-<harness>-<ts>.json snapshots into
one tick-coverage-<ts>.json (schema tick-coverage/v1) — the aggregate the
orchestrator reads at the top of every WARM tick instead of re-deriving
coverage from individual snapshots. Harnesses whose newest snapshot is older
than stale_threshold seconds (or that have none) are flagged stale, which
surfaces silent-zero instrumentation problems.
"""
from __future__ import annotations

import glob
import json
import os
import re
import time
from dataclasses import dataclass
from pathlib import Path

from cc_fuzzer_core.paths import Campaign

DEFAULT_STALE_THRESHOLD_SECONDS = 600
_COV_NAME_RE = re.compile(r"^coverage-([a-z0-9][a-z0-9_-]{0,31})-\d+\.json$")


@dataclass(frozen=True)
class RoundupResult:
    path: Path
    doc: dict


def _harness_of(path, doc):
    """Harness from the filename prefix, else an explicit `harness` field."""
    m = _COV_NAME_RE.match(os.path.basename(path))
    if m:
        return m.group(1)
    return doc.get("harness") or None


def compute(c: Campaign, *, now: int | None = None,
            stale_threshold: int = DEFAULT_STALE_THRESHOLD_SECONDS) -> dict:
    ts = int(time.time()) if now is None else int(now)
    snaps = str(c.snapshots_dir)
    declared = c.layout().declared_harnesses()

    # Load every coverage-*.json once; select the newest per harness.
    newest = {}
    for path in glob.glob(os.path.join(glob.escape(snaps), "coverage-*.json")):
        try:
            with open(path) as f:
                doc = json.load(f)
        except Exception:
            continue
        if doc.get("schema") != "coverage-snapshot/v2":
            continue
        h = _harness_of(path, doc)
        if h is None or (declared and h not in declared):
            continue  # orphaned / undeclared harness (the validator reports these)
        snap_ts = int(doc.get("timestamp", 0))
        cur = newest.get(h)
        if cur is None or snap_ts > cur[2]:
            newest[h] = (path, doc, snap_ts)

    # The previous roundup (for per-harness deltas).
    prev = None
    for p in reversed(sorted(glob.glob(os.path.join(glob.escape(snaps), "tick-coverage-*.json")))):
        try:
            with open(p) as f:
                prev = json.load(f)
            break
        except Exception:
            continue

    def prev_lines_covered(name):
        if not prev:
            return None
        for h in prev.get("harnesses", []):
            if h.get("name") == name:
                return h.get("lines_covered", 0)
        return None

    rows, stale_harnesses = [], []
    overall_covered = overall_total = 0
    for name in declared:
        triple = newest.get(name)
        if triple is None:
            rows.append({
                "name": name, "lines_covered": 0, "lines_total": 0, "pct": 0.0,
                "delta_since_last_tick": 0, "first_seen": True, "instrumentation_ok": False,
                "snapshot_file": None, "snapshot_ts": 0, "snapshot_age_seconds": None, "stale": True,
            })
            stale_harnesses.append(name)
            continue
        path, doc, snap_ts = triple
        cov = doc.get("coverage", {})
        lines_covered = int(cov.get("lines_covered", 0))
        lines_total = int(cov.get("lines_total", 0))
        age = ts - snap_ts
        stale = age > stale_threshold
        prev_lc = prev_lines_covered(name)
        first_seen = prev_lc is None
        if stale:
            stale_harnesses.append(name)
        overall_covered += lines_covered
        overall_total += lines_total
        rows.append({
            "name": name,
            "lines_covered": lines_covered,
            "lines_total": lines_total,
            "pct": round((lines_covered / lines_total * 100.0), 2) if lines_total else 0.0,
            "delta_since_last_tick": 0 if first_seen else (lines_covered - int(prev_lc)),
            "first_seen": first_seen,
            "instrumentation_ok": bool(doc.get("instrumentation", {}).get("ok", False)),
            "snapshot_file": os.path.relpath(path, c.project_root),
            "snapshot_ts": snap_ts,
            "snapshot_age_seconds": age,
            "stale": stale,
        })

    return {
        "schema": "tick-coverage/v1",
        "timestamp": ts,
        "mode": "multi",
        "harnesses": rows,
        "overall": {
            "lines_covered": overall_covered,
            "lines_total": overall_total,
            "weighted_pct": round((overall_covered / overall_total * 100.0), 2) if overall_total else 0.0,
        },
        "stale_harnesses": stale_harnesses,
        "stale_threshold_seconds": stale_threshold,
    }


def roundup(c: Campaign, *, now: int | None = None,
            stale_threshold: int = DEFAULT_STALE_THRESHOLD_SECONDS) -> RoundupResult:
    """Compute and write snapshots/tick-coverage-<now>.json."""
    doc = compute(c, now=now, stale_threshold=stale_threshold)
    c.snapshots_dir.mkdir(parents=True, exist_ok=True)
    out = c.snapshots_dir / f"tick-coverage-{doc['timestamp']}.json"
    with open(out, "w") as f:
        json.dump(doc, f, indent=2)
        f.write("\n")
    return RoundupResult(out, doc)
