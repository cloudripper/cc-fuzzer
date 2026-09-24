"""The campaign event log (events.jsonl, schema event/v1) and its one writer.

Line format: {"schema", "ts", "tick", "event", ...fields}, compact
separators, `tick` = the number of "tick" events already in the log. Every
append holds an exclusive lock on the log while it counts ticks and writes, so
concurrent writers (the orchestrator's events.sh, a host SubagentStop hook, a
core subsystem) can't interleave or double-write a row.

agent_call rows are the spend ledger (UPDATE_ROADMAP.md §10): append() hands
them to cc_fuzzer_core.ledger, which adds `source` (and `call_id`) and is the
one reader of spend. Everything else is written here directly.

CLI: `cc-fuzzer events <cmd> [args]` is the port of scripts/events.sh (now a
shim), same commands, same rows, same help text:

    tick <branch> <reason> <duration_ms> [agent]
    agent_call <agent> <tokens_in> <tokens_out>     (source=orchestrator)
    campaign_start | campaign_resume | campaign_stop
    corpus_quarantine <count> <details>
    error <message>
"""
from __future__ import annotations

import contextlib
import json
import sys
import time
from pathlib import Path

try:
    import fcntl
except ImportError:  # non-POSIX: appends are still atomic enough for one writer
    fcntl = None

SCHEMA = "event/v1"
LOG = "events.jsonl"


def _rows(text: str) -> list[dict]:
    out = []
    for line in text.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            d = json.loads(line)
        except Exception:
            continue
        if isinstance(d, dict):
            out.append(d)
    return out


def _ticks(rows) -> int:
    return sum(1 for d in rows if d.get("event") == "tick")


def tick_count(path: Path) -> int:
    try:
        with open(path) as f:
            return _ticks(_rows(f.read()))
    except OSError:
        return 0


def read(state_dir) -> list[dict]:
    """Every parseable event row of <state_dir>/events.jsonl ([] if missing)."""
    try:
        with open(Path(state_dir) / LOG) as f:
            return _rows(f.read())
    except OSError:
        return []


class Log:
    """An events.jsonl held under an exclusive lock (see locked())."""

    def __init__(self, f, rows):
        self._f = f
        self.rows = rows

    def append(self, event: str, fields: dict, *, now: float | None = None) -> dict:
        row = {"schema": SCHEMA, "ts": int(time.time() if now is None else now),
               "tick": _ticks(self.rows), "event": event}
        row.update(fields)
        self._f.write(json.dumps(row, separators=(",", ":")) + "\n")
        self._f.flush()
        self.rows.append(row)
        return row


@contextlib.contextmanager
def locked(state_dir):
    """Lock <state_dir>/events.jsonl (created if missing) and yield a Log
    holding the rows already in it."""
    state_dir = Path(state_dir)
    state_dir.mkdir(parents=True, exist_ok=True)
    with open(state_dir / LOG, "a+") as f:
        if fcntl is not None:
            fcntl.flock(f.fileno(), fcntl.LOCK_EX)
        try:
            f.seek(0)
            rows = _rows(f.read())
            f.seek(0, 2)
            yield Log(f, rows)
        finally:
            if fcntl is not None:
                fcntl.flock(f.fileno(), fcntl.LOCK_UN)


def append(state_dir, event: str, **fields) -> dict:
    """Append one event to <state_dir>/events.jsonl and return it. An
    agent_call goes through the ledger (source defaults to orchestrator)."""
    if event == "agent_call":
        from cc_fuzzer_core import ledger
        return ledger.append_fields(state_dir, **fields).row
    with locked(state_dir) as log:
        return log.append(event, fields)


# ---------------------------------------------------------------------------
# CLI: cc-fuzzer events <cmd> (port of scripts/events.sh)
# ---------------------------------------------------------------------------

PROG = "events.sh"
COMMANDS = ("tick", "agent_call", "campaign_start", "campaign_resume", "campaign_stop",
            "corpus_quarantine", "error", "help")


def _help(events_path: str) -> str:
    return f"""{PROG} - the canonical writer for {events_path}

Commands:
  tick <branch> <reason> <duration_ms> [agent]
  agent_call <agent> <tokens_in> <tokens_out>
  campaign_start | campaign_resume | campaign_stop
  corpus_quarantine <count> <details>
  error <message>

Per STATE_SCHEMA.md, this is the ONLY tool that should write to events.jsonl.
Always sets schema: event/v1.
"""


class _BadInt(Exception):
    pass


def _int(v: str) -> int:
    try:
        return int(v)
    except ValueError as e:
        # events.sh built its fields in a `python3 <<PY` heredoc: a bad number
        # printed this traceback and the row was written without the fields.
        sys.stderr.write('Traceback (most recent call last):\n'
                         '  File "<stdin>", line 2, in <module>\n'
                         f"ValueError: {e}\n")
        raise _BadInt()


def _arg(args, i, default=None, required=None):
    v = args[i] if len(args) > i else ""
    if v == "" and required:
        sys.stderr.write(f"{PROG}: {i + 1}: {required}\n")
        raise SystemExit(1)
    return v if v != "" else default


def _run_cmd(cmd: str, args: list) -> int:
    from cc_fuzzer_core.paths import CampaignError, campaign, state_dir_text
    try:
        c = campaign()
    except CampaignError as e:
        sys.stderr.write(f"{e}\n")
        return e.code
    c.state_dir.mkdir(parents=True, exist_ok=True)
    if cmd not in COMMANDS or cmd == "help":
        sys.stdout.write(_help(f"{state_dir_text(c)}/{LOG}"))
        return 0
    try:
        if cmd == "tick":
            branch = _arg(args, 0, required="branch required")
            reason, duration, agent = _arg(args, 1, ""), _arg(args, 2, "0"), _arg(args, 3, "")
            try:
                fields = {"branch": branch, "reason": reason, "duration_ms": _int(duration)}
                if agent:
                    fields["agent_called"] = agent
            except _BadInt:
                fields = {}
        elif cmd == "agent_call":
            agent = _arg(args, 0, required="agent name required")
            try:
                ti, to = _int(_arg(args, 1, "0")), _int(_arg(args, 2, "0"))
            except _BadInt:
                # No fields: not a ledger row (no agent, no tokens), kept for parity.
                with locked(c.state_dir) as log:
                    log.append(cmd, {})
                return 0
            from cc_fuzzer_core import ledger
            ledger.append(c, agent=agent, usage=ledger.Usage(ti, to), source=ledger.ORCHESTRATOR)
            return 0
        elif cmd == "corpus_quarantine":
            try:
                fields = {"count": _int(_arg(args, 0, "0")), "details": _arg(args, 1, "")}
            except _BadInt:
                fields = {}
        elif cmd == "error":
            fields = {"error_message": _arg(args, 0, required="error message required")}
        else:
            fields = {}
    except SystemExit as e:
        return int(e.code)
    with locked(c.state_dir) as log:
        log.append(cmd, fields)
    return 0


def register_cli(subparsers):
    from cc_fuzzer_core.cli import add_raw_verb, add_subsystem

    _p, verbs = add_subsystem(subparsers, "events", "append to events.jsonl (port of events.sh)")
    for cmd in COMMANDS:
        add_raw_verb(verbs, "events", cmd, lambda a, _c=cmd: _run_cmd(_c, a.args),
                     "print the commands" if cmd == "help" else f"append a `{cmd}` event")
