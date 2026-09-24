"""Append to the campaign event log (events.jsonl, schema event/v1).

The same line format scripts/events.sh writes: {"schema", "ts", "tick",
"event", ...fields}, compact separators, `tick` = the number of "tick" events
already in the log. Core subsystems that record events (slot liveness) use
append(); events.sh stays the writer for the orchestrator's own events.
"""
from __future__ import annotations

import json
import time
from pathlib import Path

SCHEMA = "event/v1"


def tick_count(path: Path) -> int:
    n = 0
    try:
        with open(path) as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    if json.loads(line).get("event") == "tick":
                        n += 1
                except Exception:
                    pass
    except OSError:
        pass
    return n


def append(state_dir: Path, event: str, **fields) -> dict:
    """Append one event to <state_dir>/events.jsonl and return it."""
    state_dir = Path(state_dir)
    state_dir.mkdir(parents=True, exist_ok=True)
    path = state_dir / "events.jsonl"
    row = {"schema": SCHEMA, "ts": int(time.time()), "tick": tick_count(path), "event": event}
    row.update(fields)
    with open(path, "a") as f:
        f.write(json.dumps(row, separators=(",", ":")) + "\n")
    return row
