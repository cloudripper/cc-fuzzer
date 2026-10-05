"""Tool-call hygiene: one response asks for the same call only once.

Some models put the same tool call into one response twice or more. The host
runs every copy (in parallel: a repeat-read check that only sees finished
reads cannot catch them), and every copy's result enters the context and is
re-sent with each later request. On the qualification runs 406 of 1,270
Read calls (2.2M characters) and 925 of 3,267 Bash calls (2.3M characters,
harness runs among them) were such duplicates. A repeat in a LATER response
is not this module's business.

    call(session, prompt, call_id, tool, tool_input)  a deny reason when this
        call repeats one already in the session's current batch, else None
    batch_end(session)  every call of the response has finished: clear it

Calls of one response are checked concurrently, so the batch is a small JSON
file per session under a lock. If the host never reports a batch end, an
entry expires after MAX_AGE_S, and a call denied once is allowed when asked
for again, so a deliberate repeat is never blocked twice.

The core returns decisions; turning a host's hook input and output into
these calls is the host adapter's job.

CLI: `cc-fuzzer hygiene call --session S --prompt P --id ID --tool T` (the
tool input JSON on stdin) prints {"decision": "allow"|"deny", "reason"};
`cc-fuzzer hygiene batch-end --session S`.
"""
from __future__ import annotations

import fcntl
import hashlib
import json
import os
import re
import sys
import tempfile
import time
from contextlib import contextmanager
from pathlib import Path

MAX_AGE_S = 300
STATE_ENV = "CC_FUZZER_HOOK_STATE"


def state_dir() -> Path:
    d = Path(os.environ.get(STATE_ENV) or Path(tempfile.gettempdir()) / "cc-fuzzer-hooks")
    d.mkdir(parents=True, exist_ok=True)
    return d


def _key(tool: str, tool_input) -> str:
    blob = json.dumps({"t": tool, "i": tool_input}, sort_keys=True, default=str)
    return hashlib.sha256(blob.encode()).hexdigest()[:24]


@contextmanager
def _batch(session: str):
    """The session's batch document, read and written under an exclusive lock."""
    safe = re.sub(r"[^A-Za-z0-9_.-]", "_", session or "nosession")[:80]
    path = state_dir() / f"batch-{safe}.json"
    with open(path.with_suffix(".lock"), "a+") as lk:
        fcntl.flock(lk, fcntl.LOCK_EX)
        try:
            try:
                doc = json.loads(path.read_text())
            except (OSError, ValueError):
                doc = {}
            doc.setdefault("calls", {})
            doc.setdefault("denied", [])
            yield doc
            tmp = path.with_suffix(".tmp")
            tmp.write_text(json.dumps(doc))
            os.replace(tmp, path)
        finally:
            fcntl.flock(lk, fcntl.LOCK_UN)


def call(session: str, prompt: str, call_id: str, tool: str, tool_input, *,
         now: float | None = None) -> str | None:
    """A deny reason when this call duplicates one already in the response."""
    now = time.time() if now is None else now
    key = _key(tool, tool_input)
    with _batch(session or "") as doc:
        if doc.get("prompt_id") != prompt:
            doc.update(prompt_id=prompt, calls={}, denied=[])
        calls = {k: v for k, v in doc["calls"].items() if now - v["ts"] <= MAX_AGE_S}
        doc["calls"] = calls
        first = calls.get(key)
        if first and first["id"] != call_id and key not in doc["denied"]:
            doc["denied"].append(key)
            return (f"Duplicate: this exact {tool} call is already in this response "
                    f"({first['id']}). It runs once; use that result. To run it again on "
                    f"purpose, ask for it in your next response.")
        if key in doc["denied"]:
            doc["denied"].remove(key)             # asked again after a denial: allow
        calls[key] = {"id": call_id, "ts": now}
    return None


def batch_end(session: str) -> None:
    with _batch(session or "") as doc:
        doc["calls"], doc["denied"] = {}, []


def _cmd_call(a):
    """Never fails on its own error: bad input or state allows."""
    try:
        raw = sys.stdin.read()
        reason = call(a.session, a.prompt, a.id, a.tool, json.loads(raw) if raw.strip() else None)
    except Exception:  # noqa: BLE001 - a broken check must not block work
        reason = None
    print(json.dumps({"decision": "deny" if reason else "allow", "reason": reason or ""}))
    return 0


def _cmd_batch_end(a):
    try:
        batch_end(a.session)
    except Exception:  # noqa: BLE001
        pass
    return 0


def register_cli(subparsers):
    from cc_fuzzer_core.cli import add_subsystem
    _p, verbs = add_subsystem(subparsers, "hygiene",
                              "tool-call hygiene (a call repeated within one response)")
    v = verbs.add_parser("call", help="allow or deny one tool call (its input JSON on stdin)")
    for f in ("--session", "--prompt", "--id", "--tool"):
        v.add_argument(f, default="")
    v.set_defaults(func=_cmd_call)
    v = verbs.add_parser("batch-end", help="every call of the response has finished")
    v.add_argument("--session", default="")
    v.set_defaults(func=_cmd_batch_end)
