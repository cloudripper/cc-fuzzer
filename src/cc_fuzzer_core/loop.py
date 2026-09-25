"""The loop, with no scheduler in it (§7).

The plugin drives the campaign by re-firing itself: the tick skill reads the
orchestrator's `YOLO_NEXT:` line and turns a `schedule` directive into a
Claude Code `ScheduleWakeup`. A container has no such thing, and should not
need one -- it has its own loop already.

So `step()` advances the campaign by EXACTLY ONE TICK and returns. It never
sleeps, never schedules, and never expects to be woken. A `wait` directive
carries `delay_hint_s`, and what the caller does about it -- sleep, return to
a queue, schedule a wakeup, ignore it -- is the caller's business.

What the driver does itself, in process, because none of it is a judgement
call (this is also where the orphaned yolo-route.sh logic finally lives):

    1. campaign state          none | running | stopped | stale | corrupted
    2. COLD/RESUME routing     the setup chain is fully determined by which
                               artifacts exist, so it never costs a dispatch
    3. liveness                are the slots actually running?
    4. crash detect            queue new crash files
    5. coverage snapshot       (when a fuzzer is live)
    6. update_current
    7. derive + evaluate
    8. halts                   cost cap, tick cap, halt flags

Only when the next move needs judgement does it call the model, through an
AgentRunner the host supplies. The driver parses the `YOLO_NEXT:` line out of
whatever comes back.

Token accounting stops being a declaration. The runner returns real token
counts, the driver writes them to the ledger (§10), and `cost_cap` becomes a
measurement rather than a promise -- the orchestrator was never obliged to
report its own spend.

CLI: `cc-fuzzer tick --once --json` (no runner: returns the deterministic
directive, or `orchestrator` when a decision is needed).
"""
from __future__ import annotations

import json
import re
import sys
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Mapping, Protocol

from cc_fuzzer_core import ledger as _ledger
from cc_fuzzer_core import models as _models

TICK_SCHEMA = "tick-result/v1"

# Directive kinds. `orchestrator` is not a move: it says the next move needs a
# decision, which is what makes it the one case that costs a dispatch.
DISPATCH, RUN, WAIT, HALT, DONE, INACTIVE, ORCHESTRATOR = (
    "dispatch", "run", "wait", "halt", "done", "inactive", "orchestrator")
KINDS = (DISPATCH, RUN, WAIT, HALT, DONE, INACTIVE, ORCHESTRATOR)

# Campaign states, as check-campaign-state.sh reports them.
S_NONE, S_RUNNING, S_STOPPED, S_STALE, S_CORRUPTED = (
    "none", "running", "stopped", "stale", "corrupted")

DEFAULT_DELAY_S = 300
MIN_DELAY_S = 60
MAX_DELAY_S = 3600

_DIRECTIVE_RE = re.compile(r"^\s*YOLO_NEXT:\s*(\w+)\s*(.*)$")
_KV_RE = re.compile(r'(\w+)=(?:"([^"]*)"|(\S+))')


class LoopError(RuntimeError):
    pass


# ---------------------------------------------------------------------------
# the directive
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class Directive:
    kind: str
    reason: str = ""
    agent: str = ""
    args: str = ""
    script: str = ""
    delay_hint_s: int = 0
    prompt: str = ""

    def __post_init__(self):
        if self.kind not in KINDS:
            raise LoopError(f"unknown directive {self.kind!r} (known: {', '.join(KINDS)})")

    def as_dict(self) -> dict:
        d = {"kind": self.kind, "reason": self.reason}
        for k in ("agent", "args", "script", "prompt"):
            if getattr(self, k):
                d[k] = getattr(self, k)
        if self.kind == WAIT:
            d["delay_hint_s"] = self.delay_hint_s
        return d

    def as_line(self) -> str:
        """The `YOLO_NEXT:` line, the vocabulary the plugin already speaks."""
        kind = "schedule" if self.kind == WAIT else self.kind
        parts = [f"YOLO_NEXT: {kind}"]
        if self.agent:
            parts.append(f'agent={self.agent}')
        if self.args:
            parts.append(f'args="{self.args}"')
        if self.script:
            parts.append(f'script="{self.script}"')
        if self.kind == WAIT:
            parts.append(f"delay={self.delay_hint_s}")
            if self.prompt:
                parts.append(f"prompt={self.prompt}")
        if self.reason:
            parts.append(f'reason="{self.reason}"')
        return " ".join(parts)


def clamp_delay(seconds) -> int:
    try:
        n = int(seconds)
    except (TypeError, ValueError):
        n = DEFAULT_DELAY_S
    return max(MIN_DELAY_S, min(MAX_DELAY_S, n))


def parse_directive(text: str) -> Directive | None:
    """The LAST `YOLO_NEXT:` line in `text`, or None.

    The last one, not the first: the contract has always been that the
    directive is the final non-blank line, and a model that reasons out loud
    may well mention the vocabulary on the way there.
    """
    found = None
    for line in (text or "").splitlines():
        m = _DIRECTIVE_RE.match(line)
        if m:
            found = m
    if not found:
        return None
    kind, rest = found.group(1).strip(), found.group(2)
    kv = {k: (q or bare) for k, q, bare in _KV_RE.findall(rest)}
    if kind == "schedule":
        kind = WAIT
    if kind not in KINDS:
        return None
    return Directive(
        kind=kind,
        reason=kv.get("reason", ""),
        agent=kv.get("agent", ""),
        args=kv.get("args", ""),
        script=kv.get("script", ""),
        delay_hint_s=clamp_delay(kv.get("delay", DEFAULT_DELAY_S)) if kind == WAIT else 0,
        prompt=kv.get("prompt", ""),
    )


# ---------------------------------------------------------------------------
# the agent runner (the host's half)
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class AgentResult:
    text: str
    tokens_in: int = 0
    tokens_out: int = 0
    cache_read: int = 0
    cache_write: int = 0
    model: str = ""


class AgentRunner(Protocol):
    def run(self, agent: str, inputs: Mapping, *, model: str = "",
            budget: Mapping | None = None) -> AgentResult:
        ...


# ---------------------------------------------------------------------------
# routing (the port of yolo-route.sh)
# ---------------------------------------------------------------------------

def has_plan(c) -> bool:
    return (Path(c.state_dir) / "plan.md").is_file() and \
        (Path(c.state_dir) / "plan.md").stat().st_size > 0


def has_harness(c) -> bool:
    return (Path(c.state_dir) / "harness-built.json").is_file()


def has_corpus(c) -> bool:
    for d in sorted(Path(c.fuzz_root).glob("harnesses/*/corpus")):
        if d.is_dir() and any(p.is_file() for p in d.iterdir()):
            return True
    return False


def campaign_state(c) -> str:
    """none | running | stopped | stale | corrupted."""
    state = Path(c.state_dir)
    if not state.is_dir():
        return S_NONE
    try:
        from cc_fuzzer_core.crash.detect import any_slot_alive
        if any_slot_alive(c):
            return S_RUNNING
    except Exception:
        pass
    if not (state / "current.json").is_file():
        return S_NONE if not has_harness(c) else S_STOPPED
    return S_STOPPED


def route(c, state: str = "") -> Directive:
    """The deterministic next move, or `orchestrator` when it needs judgement.

    The COLD/RESUME chain is decided by which artifacts exist, so it never
    costs a dispatch and cannot be stranded by a truncated model reply.
    """
    state = state or campaign_state(c)
    if state == S_RUNNING:
        return Directive(ORCHESTRATOR,
                         "warm tick - coverage/triage/escalation judgment")
    if state in (S_STALE, S_CORRUPTED):
        return Directive(ORCHESTRATOR, f"state {state} - needs assessment")
    if state in (S_NONE, S_STOPPED):
        if not has_plan(c):
            return Directive(DISPATCH, "no plan yet - cold start",
                             agent="campaign-planner", args="--mode fresh")
        if not has_harness(c):
            return Directive(DISPATCH, "plan ready, need harness", agent="harness-writer")
        if not has_corpus(c):
            return Directive(DISPATCH, "harness ready, need seed corpus",
                             agent="seed-generator")
        return Directive(RUN, "harness + corpus ready, (re)launch fuzzing",
                         script="run-fuzzer.sh")
    return Directive(ORCHESTRATOR, f"mode unresolved ({state or 'empty'}) - needs assessment")


# ---------------------------------------------------------------------------
# one tick
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class TickResult:
    directive: Directive
    state: str = ""
    events: tuple = field(default=())
    halted_reason: str = ""
    state_digest: dict = field(default_factory=dict)
    phases: tuple = field(default=())
    agent: str = ""

    @property
    def halted(self) -> bool:
        return self.directive.kind in (HALT, DONE, INACTIVE)

    def as_dict(self) -> dict:
        return {"schema": TICK_SCHEMA, "directive": self.directive.as_dict(),
                "line": self.directive.as_line(), "state": self.state,
                "events": list(self.events), "halted": self.halted,
                "halted_reason": self.halted_reason,
                "state_digest": self.state_digest, "phases": list(self.phases),
                "agent": self.agent}


def _phase(name, fn, events, phases):
    """Run one deterministic phase. A phase that fails records itself and the
    tick continues: a coverage snapshot that cannot run is not a reason to
    stop the campaign."""
    try:
        out = fn()
        phases.append({"phase": name, "ok": True})
        return out
    except Exception as e:  # noqa: BLE001 - a phase must not end the tick
        phases.append({"phase": name, "ok": False, "error": f"{type(e).__name__}: {e}"})
        events.append({"event": "phase_failed", "phase": name, "error": str(e)})
        return None


def prepare(c, *, now=None) -> dict:
    """The deterministic half of a tick: everything before a decision.

    Split out so the plugin's tick skill runs exactly the same phases the
    container does, instead of a second implementation in prose.
    """
    events, phases = [], []
    state = _phase("campaign_state", lambda: campaign_state(c), events, phases) or S_NONE

    if state == S_RUNNING:
        from cc_fuzzer_core.slots import liveness as _liveness
        _phase("liveness", lambda: _liveness.check(c), events, phases)

    from cc_fuzzer_core.crash import detect as _detect
    det = _phase("crash_detect", lambda: _detect.detect(c), events, phases)
    queued = getattr(det, "queued", 0) or 0
    if queued:
        events.append({"event": "crashes_queued", "count": queued})

    if state == S_RUNNING:
        from cc_fuzzer_core import coverage as _coverage
        _phase("coverage_snapshot", lambda: _coverage.snapshot(c), events, phases)

    from cc_fuzzer_core import state as _state
    _phase("update_current", lambda: _state.update_current(c), events, phases)

    digest = _phase("evaluate", lambda: _evaluate(c), events, phases) or {}
    return {"state": state, "events": events, "phases": phases, "digest": digest}


def _evaluate(c) -> dict:
    """The advisory evaluation block for the tick that was just composed."""
    from cc_fuzzer_core.state import yolo_evaluate
    current = Path(c.state_dir) / "current.json"
    if not current.is_file():
        return {}
    doc = yolo_evaluate.evaluate_from_current(str(current))
    if hasattr(doc, "as_dict"):
        doc = doc.as_dict()
    return doc if isinstance(doc, dict) else {}


def halt_directive(digest: Mapping) -> Directive | None:
    """A halt the state already decided, before anything is dispatched."""
    y = (digest or {}).get("yolo_state") or digest or {}
    if y.get("active") is False:
        return Directive(INACTIVE, "yolo is off")
    if y.get("halt_triggered") or y.get("halted"):
        return Directive(HALT, str(y.get("halt_reason") or "halt flag set"))
    return None


def step(c, runner: AgentRunner | None = None, *, now=None,
         config: Mapping | None = None, source: str = "driver") -> TickResult:
    """Advance the campaign exactly one tick.

    Returns the directive the caller should act on. Nothing here sleeps or
    schedules: a `wait` carries a hint and the caller decides what to do with
    it.
    """
    pre = prepare(c, now=now)
    events, phases, digest = pre["events"], pre["phases"], pre["digest"]

    halt = halt_directive(digest)
    if halt is not None:
        return TickResult(halt, pre["state"], tuple(events), halt.reason, digest,
                          tuple(phases))

    directive = route(c, pre["state"])
    if directive.kind != ORCHESTRATOR:
        return TickResult(directive, pre["state"], tuple(events), "", digest, tuple(phases))

    if runner is None:
        # No way to ask: report that a decision is needed rather than guessing
        # one. `cc-fuzzer tick` uses this, and so does the plugin, whose main
        # thread does the dispatching itself.
        return TickResult(directive, pre["state"], tuple(events), "", digest,
                          tuple(phases), agent="fuzz-orchestrator")

    agent = "fuzz-orchestrator"
    model = _models.resolve(agent, config)
    result = runner.run(agent, {"state": pre["state"], "digest": digest},
                        model=model, budget=(digest or {}).get("budget"))
    _record(c, agent, result, source=source, events=events)

    decided = parse_directive(getattr(result, "text", "") or "")
    if decided is None:
        # A reply with no directive is not a halt and not a guess: say so, and
        # let the caller re-enter. Re-dispatching on the spot is what the old
        # loop did, and it paid for a second Opus call to recover one line.
        events.append({"event": "no_directive", "agent": agent})
        decided = Directive(WAIT, "orchestrator returned no directive",
                            delay_hint_s=MIN_DELAY_S)
    return TickResult(decided, pre["state"], tuple(events), decided.reason
                      if decided.kind in (HALT, DONE, INACTIVE) else "",
                      digest, tuple(phases), agent=agent)


def _record(c, agent: str, result, *, source: str, events: list) -> None:
    """Write the model's MEASURED usage to the ledger (§10)."""
    usage = _ledger.Usage(
        tokens_in=getattr(result, "tokens_in", 0) or 0,
        tokens_out=getattr(result, "tokens_out", 0) or 0,
        cache_read=getattr(result, "cache_read", 0) or 0,
        cache_write=getattr(result, "cache_write", 0) or 0,
        model=getattr(result, "model", "") or "",
    )
    call_id = f"{agent}-{int(time.time() * 1000)}"
    try:
        _ledger.append(c, agent=agent, usage=usage, source=source, call_id=call_id)
        events.append({"event": "agent_call", "agent": agent, "call_id": call_id,
                       "tokens_in": usage.tokens_in, "tokens_out": usage.tokens_out})
    except Exception as e:  # noqa: BLE001 - accounting must not end a tick
        events.append({"event": "ledger_failed", "agent": agent, "error": str(e)})


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def _campaign():
    from cc_fuzzer_core.paths import campaign
    return campaign()


def _cmd_tick(a):
    c = _campaign()
    if a.prepare:
        pre = prepare(c)
        print(json.dumps({"state": pre["state"], "events": pre["events"],
                          "phases": pre["phases"], "state_digest": pre["digest"]}, indent=2))
        return 0
    r = step(c)
    if a.json:
        print(json.dumps(r.as_dict(), indent=2))
    else:
        print(r.directive.as_line())
    return 0


def _cmd_route(a):
    print(route(_campaign()).as_line())
    return 0


def _cmd_parse(a):
    text = a.text if a.text is not None else sys.stdin.read()
    d = parse_directive(text)
    if d is None:
        print("no YOLO_NEXT directive found", file=sys.stderr)
        return 1
    print(json.dumps(d.as_dict(), indent=2) if a.json else d.as_line())
    return 0


def register_cli(subparsers):
    from cc_fuzzer_core.cli import add_subsystem
    _p, verbs = add_subsystem(subparsers, "tick",
                              "Advance the campaign one tick (no scheduler).")

    v = verbs.add_parser("run", help="one tick; prints the next directive")
    v.add_argument("--once", action="store_true", help="accepted for symmetry; a tick is always one")
    v.add_argument("--prepare", action="store_true",
                   help="only the deterministic phases, for a host that dispatches itself")
    v.add_argument("--json", action="store_true")
    v.set_defaults(func=_cmd_tick)

    v = verbs.add_parser("route", help="the deterministic directive for the current state")
    v.set_defaults(func=_cmd_route)

    v = verbs.add_parser("parse", help="read a YOLO_NEXT directive out of text")
    v.add_argument("--text", help="default: stdin")
    v.add_argument("--json", action="store_true")
    v.set_defaults(func=_cmd_parse)
