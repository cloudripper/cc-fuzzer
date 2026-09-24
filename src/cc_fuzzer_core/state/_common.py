"""Small readers shared by the state-machine modules (each _lib module used to
carry its own copy)."""
from __future__ import annotations

import datetime
import glob
import json
import os


def load_json(path):
    """Parsed JSON, or None on any problem."""
    try:
        with open(path) as f:
            return json.load(f)
    except Exception:
        return None


def load_jsonl(path):
    """Every parseable non-blank line of a .jsonl file ([] when missing)."""
    rows = []
    if not os.path.exists(path):
        return rows
    try:
        with open(path) as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    rows.append(json.loads(line))
                except Exception:
                    pass
    except Exception:
        pass
    return rows


def roundup_series(snaps_dir, since_ts):
    """(ts, weighted_pct) for tick-coverage roundups since since_ts, in order."""
    series = []
    for p in sorted(glob.glob(os.path.join(snaps_dir, "tick-coverage-*.json"))):
        d = load_json(p)
        if not d:
            continue
        ts = int(d.get("timestamp") or 0)
        if ts < since_ts:
            continue
        pct = (d.get("overall") or {}).get("weighted_pct")
        if pct is not None:
            series.append((ts, float(pct)))
    return series


def last_gain_ts(series, floor_ts):
    """Timestamp of the most recent roundup that improved on the prior one."""
    gain_ts = floor_ts
    for i in range(1, len(series)):
        if series[i][1] > series[i - 1][1]:
            gain_ts = series[i][0]
    return gain_ts


def ticks_since(series, ts):
    return sum(1 for t, _ in series if t > ts)


def iso_to_ts(s):
    """'YYYY-MM-DDTHH:MM:SSZ' -> epoch (naive, local-time interpretation as
    before); 0 when unparseable."""
    try:
        if s.endswith("Z"):
            return int(datetime.datetime.strptime(s, "%Y-%m-%dT%H:%M:%SZ").timestamp())
    except Exception:
        pass
    return 0
