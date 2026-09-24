"""Per-slot liveness check and auto-restart (port of scripts/check-slot-liveness.sh).

check(campaign, dry_run=False) -> LivenessResult. Walks the slots declared in
fuzz-config.json:fuzzer_slots (or, when none are declared, the ones in
fuzzers.json) against the live manifest. A dead declared slot is relaunched
through slots.launcher (restart_count +1); anti-flap refuses a slot restarted
3+ times in the last 60 s ("deadlocked", error event, left dead). With no
fuzzers.json nothing is checked: that is the post-stop / pre-launch state and
auto-restart must not fight a deliberate stop.

One output line per slot:
  slot=<name> engine=<eng> state=<alive|restarted|deadlocked|dead> [info]

After any restart the campaign's current.json is refreshed
(state.update_current) so the orchestrator sees the new liveness.

Events: a deadlocked slot records `error` {error_message}, a restart records
`agent_call` {agent_called: check-slot-liveness, tokens 0/0}. (The script
passed these to events.sh as --error-message / --agent-called flags, which
events.sh takes positionally, so it logged the literal "--error-message" and a
field-less agent_call.)
"""
from __future__ import annotations

import contextlib
import io
import json
import os
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone

from cc_fuzzer_core import events
from cc_fuzzer_core.paths import Campaign, _field_text
from cc_fuzzer_core.slots.launcher import SlotRequest, launch

THROTTLE_RESTARTS = 3
THROTTLE_WINDOW_S = 60


@dataclass
class SlotPlan:
    slot: str
    engine: str
    role: str
    schedule: str
    libfuzzer_forks: str
    pid: str
    restart_count: str
    last_restart_at: str
    harness: str
    timeout_ms: str


@dataclass
class LivenessResult:
    lines: list = field(default_factory=list)
    restarted: list = field(default_factory=list)   # slot names

    @property
    def text(self) -> str:
        return "".join(f"{ln}\n" for ln in self.lines)


def _load(path):
    with open(path) as f:
        return json.load(f)


def _opt(v) -> str:
    return "" if v is None else str(v)


def plan(c: Campaign) -> list[SlotPlan]:
    """The union of declared and live slots, one row per declared slot."""
    declared = []
    try:
        declared = _load(c.state_dir / "fuzz-config.json").get("fuzzer_slots") or []
    except Exception:
        pass
    live = {}
    try:
        for s in _load(c.state_dir / "fuzzers.json").get("slots", []):
            live[s["slot"]] = s
    except Exception:
        pass
    if not declared:
        declared = [{"slot": s["slot"], "engine": s["engine"], "role": s.get("role"),
                     "afl_power_schedule": s.get("afl_power_schedule"),
                     "timeout_ms": s.get("timeout_ms"), "harness": s.get("harness", "")}
                    for s in live.values()]
    rows = []
    for d in declared:
        name = d.get("slot", "main")
        cur = live.get(name, {})
        rows.append(SlotPlan(
            slot=name,
            engine=d.get("engine", "auto"),
            role=d.get("role") or "",
            schedule=d.get("afl_power_schedule") or "",
            libfuzzer_forks=_opt(d.get("libfuzzer_forks")),
            pid=str(cur.get("pid", "") or ""),
            restart_count=str(cur.get("restart_count", 0) or 0),
            last_restart_at=str(cur.get("last_restart_at") or ""),
            harness=d.get("harness", "") or "",
            timeout_ms=_opt(d.get("timeout_ms")),
        ))
    return rows


def _alive(pid: str) -> bool:
    try:
        n = int(pid)
        if n <= 0:
            return False
        os.kill(n, 0)
        return True
    except (ValueError, OSError):
        return False


def throttled(restart_count: str, last_restart_at: str, *, now: float | None = None) -> bool:
    """3+ restarts, the last one under 60 s ago."""
    try:
        cnt = int(restart_count or 0)
        if cnt < THROTTLE_RESTARTS or not last_restart_at:
            return False
        dt = datetime.fromisoformat(last_restart_at.replace("Z", "+00:00"))
        now_dt = datetime.fromtimestamp(time.time() if now is None else now, timezone.utc)
        return (now_dt - dt).total_seconds() < THROTTLE_WINDOW_S
    except Exception:
        return False


def check(c: Campaign, *, dry_run: bool = False, refresh_current: bool = True) -> LivenessResult:
    """Check every slot and relaunch the dead ones (see module docstring)."""
    res = LivenessResult()
    if not (c.state_dir / "fuzzers.json").is_file():
        res.lines.append("(no fuzzers.json — nothing to check)")
        return res
    root = c.project_root
    for p in plan(c):
        if not p.slot:
            continue
        h = f" harness={p.harness}" if p.harness else ""
        head = f"slot={p.slot} engine={p.engine}"
        if p.pid and _alive(p.pid):
            res.lines.append(f"{head} state=alive pid={p.pid}{h}")
            continue
        if throttled(p.restart_count, p.last_restart_at):
            res.lines.append(f"{head} state=deadlocked restart_count={p.restart_count} "
                             f"(3+ restarts in <60s — leaving dead)")
            events.append(c.state_dir, "error",
                          error_message=f"slot {p.slot} deadlocked: {p.restart_count} restarts in <60s")
            continue
        if dry_run:
            res.lines.append(f"{head} state=dead would_restart=1 restart_count={p.restart_count}{h}")
            continue
        if not p.harness:
            res.lines.append(f"{head} state=dead launch_failed=no-harness-binding (slot has no harness)")
            continue
        binary = _field_text(c.layout().harness_binary(p.harness)) or ""
        bin_io = binary if os.path.isabs(binary) else os.path.join(root, binary)
        if not binary or not (os.path.isfile(bin_io) and os.access(bin_io, os.X_OK)):
            res.lines.append(f"{head} harness={p.harness} state=dead launch_failed=no-binary-for-harness")
            continue
        r = launch(c, SlotRequest(slot=p.slot, engine=p.engine, harness=p.harness, binary=binary,
                                  role=p.role, power_schedule=p.schedule,
                                  libfuzzer_forks=p.libfuzzer_forks, timeout_ms=p.timeout_ms,
                                  restart_of=p.slot))
        if r.code == 0:
            try:
                new_pid = (c.state_dir / f"fuzzer-{p.slot}.pid").read_text().rstrip("\n")
            except OSError:
                new_pid = "?"
            res.lines.append(f"{head} state=restarted pid={new_pid} prior_restart_count={p.restart_count}{h}")
            res.restarted.append(p.slot)
            events.append(c.state_dir, "agent_call", agent_called="check-slot-liveness",
                          tokens_in=0, tokens_out=0)
        else:
            res.lines.append(f"{head} state=dead launch_failed=1 restart_count={p.restart_count}{h}")
    if res.restarted and refresh_current:
        from cc_fuzzer_core.state import update_current
        with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
            try:
                update_current(c)
            except Exception:
                pass
    return res
