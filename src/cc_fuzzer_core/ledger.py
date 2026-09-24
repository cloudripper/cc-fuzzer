"""The agent_call spend ledger (UPDATE_ROADMAP.md §10).

Spend used to be exactly as complete as the orchestrator's memory: it was
supposed to call `events.sh agent_call` after every dispatch, and the YOLO
evaluator also billed the tokens on `tick` rows (a double count). Now:

  append(campaign, *, agent, usage, source, call_id, transcript)
      writes one `agent_call` event (event/v1 plus `source`, `call_id`, and
      the cache/model/transcript fields when known). Per call_id the ledger
      keeps the report with the largest total tokens: a transcript sum only
      grows (a blocked subagent continues; the async transcript flush catches
      up), so a later, larger report for the same call appends a row that
      replaces the earlier one, and an equal or smaller one (a re-fired hook,
      a driver echoing the hook) is a no-op. Append-only: nothing is rewritten.
  reconcile(campaign) re-reads the transcripts of the host-hook calls and
      appends a replacing row where the total grew (run it at tick start).
  spend(campaign, *, since_ts) -> Spend{usd, calls, tokens, by_agent,
      by_model, by_source}, priced by cc_fuzzer_core.models. The ONE spend
      reader: the YOLO evaluator's cost posture and the hard cost cap
      (state.derive_tick) both go through it. Only agent_call rows count;
      a row with no tokens at all is a dispatch marker, not a billable call.

Sources (enums.LEDGER_SOURCE):
  orchestrator  the model's own `events.sh agent_call` (advisory). Rows written
                before §10 carry no `source` and are read as orchestrator.
  host-hook     the host measured it (the plugin's SubagentStop hook, from the
                subagent transcript's per-message usage).
  driver        the §7 loop driver, from its AgentResult.

Precedence: when a host-sourced row (host-hook / driver) exists for an agent
and tick, the orchestrator rows for that same agent and tick are superseded
(ignored by spend) -- the measurement wins over the declaration.

usage_from_transcript(path) sums a JSONL transcript's assistant-message usage
(each message id once: streaming writes one line per content block, repeating
the same usage). It knows the transcript shape, not the host: the host adapter
only hands over a path.

CLI: cc-fuzzer ledger append|spend|show|reconcile [--json]
"""
from __future__ import annotations

import json
import os
import sys
from dataclasses import dataclass, field
from pathlib import Path

from cc_fuzzer_core import events
from cc_fuzzer_core.enums import LEDGER_HOST_SOURCES, LEDGER_SOURCE

ORCHESTRATOR, HOST_HOOK, DRIVER = "orchestrator", "host-hook", "driver"
HOST_SOURCES = LEDGER_HOST_SOURCES
EVENT = "agent_call"


class LedgerError(ValueError):
    pass


@dataclass(frozen=True)
class Usage:
    tokens_in: int = 0
    tokens_out: int = 0
    cache_read: int = 0
    cache_write: int = 0
    model: str | None = None

    @property
    def total(self) -> int:
        return self.tokens_in + self.tokens_out + self.cache_read + self.cache_write

    @property
    def billable(self) -> bool:
        return bool(self.tokens_in or self.tokens_out or self.cache_read or self.cache_write)

    @classmethod
    def of_row(cls, row: dict) -> "Usage":
        def n(k):
            try:
                return int(row.get(k) or 0)
            except (TypeError, ValueError):
                return 0
        return cls(n("tokens_in"), n("tokens_out"), n("cache_read"), n("cache_write"), row.get("model") or None)


@dataclass(frozen=True)
class Appended:
    row: dict
    appended: bool   # False: call_id already recorded with >= tokens; `row` is that report


def _state_dir(campaign) -> Path:
    return Path(getattr(campaign, "state_dir", campaign))


def source_of(row: dict) -> str:
    return row.get("source") or ORCHESTRATOR


def agent_of(row: dict) -> str:
    return row.get("agent_called") or row.get("agent") or ""


def _fields(agent: str, usage: Usage, source: str, call_id: str | None, transcript: str | None) -> dict:
    d = {"agent_called": agent, "tokens_in": int(usage.tokens_in), "tokens_out": int(usage.tokens_out)}
    if usage.cache_read:
        d["cache_read"] = int(usage.cache_read)
    if usage.cache_write:
        d["cache_write"] = int(usage.cache_write)
    if usage.model:
        d["model"] = usage.model
    d["source"] = source
    if call_id:
        d["call_id"] = call_id
    if transcript:
        d["transcript"] = str(transcript)
    return d


def _best(rows):
    """The report spend counts among one call_id's rows: the largest total,
    the earliest on a tie."""
    best = None
    for r in rows:
        if best is None or Usage.of_row(r).total > Usage.of_row(best).total:
            best = r
    return best


def append(campaign, *, agent: str, usage: Usage, source: str, call_id: str | None = None,
           transcript: str | None = None, now: float | None = None) -> Appended:
    """Record one agent call. `campaign` is a Campaign or a state dir.
    Host sources must name the call (call_id); an orchestrator row need not.
    A call_id already recorded with at least this many total tokens is a
    no-op; a larger report appends a replacing row carrying the call's
    original tick (the tick the call ran in, which precedence keys on)."""
    if source not in LEDGER_SOURCE:
        raise LedgerError(f"unknown source {source!r} (one of {', '.join(sorted(LEDGER_SOURCE))})")
    if not agent:
        raise LedgerError("agent required")
    if source in HOST_SOURCES and not call_id:
        raise LedgerError(f"source {source} requires a call_id")
    with events.locked(_state_dir(campaign)) as log:
        tick = None
        if call_id:
            same = [r for r in log.rows if r.get("event") == EVENT and r.get("call_id") == call_id]
            if same:
                best = _best(same)
                if usage.total <= Usage.of_row(best).total:
                    return Appended(best, False)
                tick = same[0].get("tick")
        row = log.append(EVENT, _fields(agent, usage, source, call_id, transcript), now=now, tick=tick)
        return Appended(row, True)


def append_fields(campaign, *, agent_called: str = "", tokens_in=0, tokens_out=0, cache_read=0,
                  cache_write=0, model=None, source: str = ORCHESTRATOR, call_id=None, transcript=None,
                  **_ignored) -> Appended:
    """append() from raw event fields (events.append("agent_call", ...))."""
    return append(campaign, agent=agent_called,
                  usage=Usage(int(tokens_in or 0), int(tokens_out or 0), int(cache_read or 0),
                              int(cache_write or 0), model),
                  source=source, call_id=call_id, transcript=transcript)


# ---------------------------------------------------------------------------
# reading: precedence + spend
# ---------------------------------------------------------------------------

REPLACED, SUPERSEDED, COUNTED = "replaced", "superseded", "counted"


def _by_call_id(calls) -> dict:
    groups: dict = {}
    for r in calls:
        cid = r.get("call_id")
        if cid:
            groups.setdefault(cid, []).append(r)
    return groups


def classify(rows) -> list[tuple[dict, str]]:
    """[(agent_call row, status)] in log order: `replaced` (another report of
    the same call_id carries more tokens), `superseded` (an orchestrator row
    for an agent+tick that has a host-sourced row) or `counted`.
    Non-agent_call rows are skipped."""
    calls = [r for r in rows if isinstance(r, dict) and r.get("event") == EVENT]
    dup = set()
    for same in _by_call_id(calls).values():
        best = _best(same)
        dup.update(id(r) for r in same if r is not best)
    hosted = {(agent_of(r), r.get("tick")) for r in calls
              if id(r) not in dup and source_of(r) in HOST_SOURCES}
    out = []
    for r in calls:
        if id(r) in dup:
            out.append((r, REPLACED))
        elif source_of(r) not in HOST_SOURCES and (agent_of(r), r.get("tick")) in hosted:
            out.append((r, SUPERSEDED))
        else:
            out.append((r, COUNTED))
    return out


def dropped(rows) -> set:
    """id()s of the agent_call rows spend ignores (replaced, superseded) --
    for readers that count dispatches from the same row list."""
    return {id(r) for r, st in classify(rows) if st != COUNTED}


def _bucket():
    return {"calls": 0, "tokens_in": 0, "tokens_out": 0, "cache_read": 0, "cache_write": 0, "usd": 0.0}


def _add(b: dict, u: Usage, usd: float):
    b["calls"] += 1
    b["tokens_in"] += u.tokens_in
    b["tokens_out"] += u.tokens_out
    b["cache_read"] += u.cache_read
    b["cache_write"] += u.cache_write
    b["usd"] += usd


@dataclass
class Spend:
    usd: float = 0.0
    calls: int = 0
    tokens: dict = field(default_factory=_bucket)       # the totals bucket (calls/usd included)
    by_agent: dict = field(default_factory=dict)
    by_model: dict = field(default_factory=dict)
    by_source: dict = field(default_factory=dict)
    superseded: int = 0
    replaced: int = 0
    # (agent, usd) per counted call, in log order, so subtotals sum in the
    # same order the old per-event loops did.
    items: list = field(default_factory=list, repr=False)

    def usd_for(self, agents) -> float:
        total = 0.0
        for a, usd in self.items:
            if a in agents:
                total += usd
        return total

    def calls_for(self, agents) -> int:
        return sum(1 for a, _ in self.items if a in agents)

    def as_dict(self) -> dict:
        r4 = lambda b: {**b, "usd": round(b["usd"], 6)}
        return {
            "usd": round(self.usd, 6), "calls": self.calls,
            "tokens": {k: v for k, v in self.tokens.items() if k not in ("calls", "usd")},
            "by_agent": {k: r4(v) for k, v in sorted(self.by_agent.items())},
            "by_model": {k: r4(v) for k, v in sorted(self.by_model.items())},
            "by_source": {k: r4(v) for k, v in sorted(self.by_source.items())},
            "superseded": self.superseded, "replaced": self.replaced,
        }


def spend(campaign, *, since_ts: int = 0, model_map=None, rows=None) -> Spend:
    """Priced spend over the counted agent_call rows with ts >= since_ts.
    `campaign` is a Campaign or a state dir; `model_map` defaults to
    models.load(state dir); `rows` (the parsed log) skips re-reading it."""
    from cc_fuzzer_core import models
    sd = _state_dir(campaign)
    mm = model_map if model_map is not None else models.load(sd)
    rows = events.read(sd) if rows is None else rows
    sp = Spend()
    for r, status in classify(rows):
        try:
            ts = int(r.get("ts") or 0)
        except (TypeError, ValueError):
            ts = 0
        if ts < since_ts:
            continue
        if status == REPLACED:
            sp.replaced += 1
            continue
        if status == SUPERSEDED:
            sp.superseded += 1
            continue
        u = Usage.of_row(r)
        if not u.billable:
            continue
        agent = agent_of(r)
        usd = mm.cost(u.tokens_in, u.tokens_out, agent=agent, model=u.model,
                      cache_read=u.cache_read, cache_write=u.cache_write)
        model = u.model or mm.resolve(agent)
        sp.usd += usd
        sp.calls += 1
        _add(sp.tokens, u, usd)
        _add(sp.by_agent.setdefault(agent, _bucket()), u, usd)
        _add(sp.by_model.setdefault(model, _bucket()), u, usd)
        _add(sp.by_source.setdefault(source_of(r), _bucket()), u, usd)
        sp.items.append((agent, usd))
    return sp


# ---------------------------------------------------------------------------
# transcripts
# ---------------------------------------------------------------------------

SYNTHETIC_MODEL = "<synthetic>"   # a host-generated message (no API call, no usage)


def transcript_messages(path) -> list[Usage]:
    """One Usage per assistant message in a JSONL transcript, in first-seen
    order. Lines sharing a message id are one message (a streamed response
    writes a line per content block, each repeating the usage); its usage is
    the per-field max over those lines. Unparseable lines (e.g. a partial
    last line still being written) are skipped."""
    by_id: dict = {}
    order: list = []
    with open(path, errors="replace") as f:
        for n, line in enumerate(f):
            line = line.strip()
            if not line:
                continue
            try:
                d = json.loads(line)
            except Exception:
                continue
            if not isinstance(d, dict) or d.get("type") != "assistant":
                continue
            msg = d.get("message")
            if not isinstance(msg, dict) or msg.get("model") == SYNTHETIC_MODEL:
                continue
            usage = msg.get("usage")
            if not isinstance(usage, dict):
                continue

            def n_(k):
                try:
                    return int(usage.get(k) or 0)
                except (TypeError, ValueError):
                    return 0
            u = Usage(n_("input_tokens"), n_("output_tokens"), n_("cache_read_input_tokens"),
                      n_("cache_creation_input_tokens"), msg.get("model") or None)
            key = msg.get("id") or f"line:{n}"
            prev = by_id.get(key)
            if prev is None:
                order.append(key)
                by_id[key] = u
            else:
                by_id[key] = Usage(max(prev.tokens_in, u.tokens_in), max(prev.tokens_out, u.tokens_out),
                                   max(prev.cache_read, u.cache_read), max(prev.cache_write, u.cache_write),
                                   prev.model or u.model)
    return [by_id[k] for k in order]


def usage_from_transcript(path) -> Usage:
    """Summed usage of a transcript's assistant messages; `model` is the one
    that carried the most tokens (ties: the later one)."""
    msgs = transcript_messages(path)
    weight, last = {}, {}
    for i, u in enumerate(msgs):
        if u.model:
            weight[u.model] = weight.get(u.model, 0) + u.tokens_in + u.tokens_out + u.cache_read + u.cache_write
            last[u.model] = i
    model = max(weight, key=lambda m: (weight[m], last[m])) if weight else None
    return Usage(sum(u.tokens_in for u in msgs), sum(u.tokens_out for u in msgs),
                 sum(u.cache_read for u in msgs), sum(u.cache_write for u in msgs), model)


# ---------------------------------------------------------------------------
# reconcile: catch up on transcripts that grew after their hook fired
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class Reconciled:
    call_id: str
    before: int              # total tokens of the counted report
    after: int               # total tokens in the transcript now
    row: dict | None         # the replacing row (None when nothing grew)
    error: str | None = None


def reconcile(campaign, *, now: float | None = None) -> list[Reconciled]:
    """For every call_id whose counted report carries a `transcript` path,
    re-read the transcript; where its total grew, append a replacing row
    (same agent, source, call_id). The transcript is written asynchronously,
    so a hook can fire before the subagent's last turn is flushed; calling
    this at tick start folds the late usage in. Missing or unreadable
    transcripts are reported, never fatal."""
    sd = _state_dir(campaign)
    calls = [r for r in events.read(sd) if r.get("event") == EVENT]
    out = []
    for cid, same in _by_call_id(calls).items():
        best = _best(same)
        path = next((r.get("transcript") for r in reversed(same) if r.get("transcript")), None)
        if not path:
            continue
        before = Usage.of_row(best).total
        try:
            u = usage_from_transcript(path)
        except OSError as e:
            out.append(Reconciled(cid, before, before, None, f"{path}: {e.strerror or e}"))
            continue
        if u.total <= before:
            out.append(Reconciled(cid, before, u.total, None))
            continue
        if not u.model:
            u = Usage(u.tokens_in, u.tokens_out, u.cache_read, u.cache_write, best.get("model"))
        r = append(sd, agent=agent_of(best), usage=u, source=source_of(best), call_id=cid,
                   transcript=path, now=now)
        out.append(Reconciled(cid, before, u.total, r.row if r.appended else None))
    return out


# ---------------------------------------------------------------------------
# CLI: cc-fuzzer ledger append | spend | show | reconcile
# ---------------------------------------------------------------------------

def _campaign():
    from cc_fuzzer_core.paths import CampaignError, campaign
    try:
        return campaign(), 0
    except CampaignError as e:
        sys.stderr.write(f"{e}\n")
        return None, e.code


def _cmd_append(a):
    c, code = _campaign()
    if c is None:
        return code
    try:
        if a.transcript:
            u = usage_from_transcript(a.transcript)
            if a.model:
                u = Usage(u.tokens_in, u.tokens_out, u.cache_read, u.cache_write, a.model)
        else:
            u = Usage(a.tokens_in, a.tokens_out, a.cache_read, a.cache_write, a.model)
        r = append(c, agent=a.agent, usage=u, source=a.source, call_id=a.call_id,
                   transcript=os.path.abspath(a.transcript) if a.transcript else None)
    except (LedgerError, OSError) as e:
        sys.stderr.write(f"ledger: {e}\n")
        return 2
    if a.json:
        print(json.dumps({"appended": r.appended, "row": r.row}, separators=(",", ":")))
    elif r.appended:
        print(f"ledger: recorded {r.row['agent_called']} tick {r.row['tick']} "
              f"({r.row['tokens_in']} in / {r.row['tokens_out']} out, source {r.row['source']})")
    else:
        print(f"ledger: call_id {a.call_id} already recorded with as many tokens "
              f"(tick {r.row.get('tick')}); nothing written")
    return 0


def _money(x):
    return f"${x:.4f}"


def _cmd_spend(a):
    c, code = _campaign()
    if c is None:
        return code
    from cc_fuzzer_core import models
    try:
        sp = spend(c, since_ts=a.since)
    except models.ModelsError as e:
        sys.stderr.write(f"ledger: {e}\n")
        return 2
    if a.json:
        print(json.dumps(sp.as_dict(), indent=2))
        return 0
    t = sp.tokens
    print(f"spend: {_money(sp.usd)} over {sp.calls} call(s); tokens in {t['tokens_in']} out {t['tokens_out']} "
          f"cache read {t['cache_read']} write {t['cache_write']}")
    if sp.superseded or sp.replaced:
        print(f"ignored: {sp.superseded} superseded orchestrator row(s), {sp.replaced} replaced call_id report(s)")
    for title, table in (("agent", sp.by_agent), ("model", sp.by_model), ("source", sp.by_source)):
        for k, b in sorted(table.items()):
            print(f"  {title:<6} {k:<22} {b['calls']:>4} call(s) {_money(b['usd']):>10}")
    return 0


def _cmd_reconcile(a):
    c, code = _campaign()
    if c is None:
        return code
    res = reconcile(c)
    if a.json:
        print(json.dumps([{"call_id": r.call_id, "before": r.before, "after": r.after,
                           "appended": r.row is not None, "error": r.error} for r in res], indent=2))
        return 0
    grew = [r for r in res if r.row is not None]
    for r in res:
        if r.error:
            print(f"ledger: {r.call_id}: {r.error}")
        elif r.row is not None:
            print(f"ledger: {r.call_id}: {r.before} -> {r.after} tokens; replacing row appended")
    print(f"ledger: reconciled {len(res)} call(s), {len(grew)} grew")
    return 0


def _ts(r) -> int:
    try:
        return int(r.get("ts") or 0)
    except (TypeError, ValueError):
        return 0


def _cmd_show(a):
    c, code = _campaign()
    if c is None:
        return code
    rows = [(r, st) for r, st in classify(events.read(c.state_dir))
            if _ts(r) >= a.since and (not a.counted or st == COUNTED)]
    if a.json:
        print(json.dumps([{**r, "status": st, "source": source_of(r)} for r, st in rows], indent=2))
        return 0
    for r, st in rows:
        extra = f" call_id={r['call_id']}" if r.get("call_id") else ""
        model = f" model={r['model']}" if r.get("model") else ""
        print(f"tick {r.get('tick')} ts {r.get('ts')} {agent_of(r) or '-':<20} {source_of(r):<12} {st:<10} "
              f"in={r.get('tokens_in', 0)} out={r.get('tokens_out', 0)} "
              f"cache_read={r.get('cache_read', 0)} cache_write={r.get('cache_write', 0)}{model}{extra}")
    return 0


def register_cli(subparsers):
    from cc_fuzzer_core.cli import add_subsystem

    _p, verbs = add_subsystem(subparsers, "ledger", "agent_call spend ledger (host-written, §10)")
    v = verbs.add_parser("append", help="record one agent call (per --call-id the largest report counts)")
    v.add_argument("--agent", required=True)
    v.add_argument("--source", required=True, choices=sorted(LEDGER_SOURCE))
    v.add_argument("--call-id", default=None)
    v.add_argument("--tokens-in", type=int, default=0)
    v.add_argument("--tokens-out", type=int, default=0)
    v.add_argument("--cache-read", type=int, default=0)
    v.add_argument("--cache-write", type=int, default=0)
    v.add_argument("--model", default=None)
    v.add_argument("--transcript", default=None,
                   help="sum the usage of this JSONL transcript instead of the --tokens-* flags")
    v.add_argument("--json", action="store_true")
    v.set_defaults(func=_cmd_append)
    v = verbs.add_parser("spend", help="priced spend over the counted agent_call rows")
    v.add_argument("--since", type=int, default=0, help="only rows with ts >= this epoch")
    v.add_argument("--json", action="store_true")
    v.set_defaults(func=_cmd_spend)
    v = verbs.add_parser("show", help="every agent_call row and whether spend counts it")
    v.add_argument("--since", type=int, default=0, help="only rows with ts >= this epoch")
    v.add_argument("--counted", action="store_true", help="only the rows spend counts")
    v.add_argument("--json", action="store_true")
    v.set_defaults(func=_cmd_show)
    v = verbs.add_parser("reconcile", help="re-read host-hook transcripts; append a replacing row where usage grew")
    v.add_argument("--json", action="store_true")
    v.set_defaults(func=_cmd_reconcile)
