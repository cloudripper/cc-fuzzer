"""YOLO configuration + the yolo-state.sh verbs (enable/disable/status/check-halt/next-tick).

ONE place for the YOLO defaults. They used to be restated in yolo-state.sh
(enable), derive-tick-state.py (the halt gate), yolo_evaluate.py (the advisory
block), ceiling_probe.py / toolbox_eval.py (their CLIs) and the status printer,
and had drifted (status showed `balanced` for a guided config; the evaluator
ignored the aggressive soft-cost default enable documents). Every reader now
goes through YoloSettings.

YoloSettings reads lazily: a field is only cast when a consumer asks for it, so
a bad value in one field fails only the computation that needs it (the halt
gate keeps working when, say, redundancy_threshold is garbage), exactly as the
per-call `.get(key, default)` reads did. `.get(key, default)` — NOT
`or default` — so user-set zeros (max_ticks=0 disables the cap) survive.
"""
from __future__ import annotations

import json
import sys
import time
from dataclasses import dataclass
from pathlib import Path

from cc_fuzzer_core import config as _config
from cc_fuzzer_core.paths import Campaign, CampaignError, campaign as _campaign

MODES = ("guided", "hybrid", "self_loop")
POSTURES = ("conservative", "balanced", "aggressive")
# Default aggressiveness posture per mode (when the block has no explicit
# `aggressiveness`): self_loop ships aggressive, hybrid balanced, guided
# conservative.
MODE_POSTURE = {"guided": "conservative", "hybrid": "balanced", "self_loop": "aggressive"}

YOLO_DEFAULTS = {
    "mode": "hybrid",
    "interval_seconds": 1800,             # 30 min
    "max_ticks": 24,
    "max_cost_usd": 10.0,
    "cost_cap_enabled": True,             # --no-cap: no soft throttle AND no hard cost halt
    "stop_on_no_progress_ticks": 30,
    # self_loop: flat ticks before the reshape -> consult -> halt ladder
    # begins; enable clamps it below stop_on_no_progress_ticks.
    "plateau_escalate_ticks": 8,
    "crash_storm_threshold": 10,
    "redundancy_threshold": 2,
    "soft_cost_fraction": 0.6,            # AGGRESSIVE_SOFT_COST_FRACTION when aggressive
    "max_backoff_multiplier": 4,
    "enabled_at_ts": 0,
    "enabled_at_tick": 0,
}
# Aggressive posture throttles deep-tier agents later.
AGGRESSIVE_SOFT_COST_FRACTION = 0.8


class YoloSettings:
    """Effective values of a fuzz-config.json `yolo` block (see module doc)."""

    def __init__(self, block: dict | None):
        self.block = block if isinstance(block, dict) else {}

    @classmethod
    def load(cls, c) -> "YoloSettings":
        return cls(_config.block(c, "yolo"))

    # -- raw access ----------------------------------------------------------
    def default(self, key: str):
        if key == "soft_cost_fraction" and self.aggressiveness == "aggressive":
            return AGGRESSIVE_SOFT_COST_FRACTION
        return YOLO_DEFAULTS[key]

    def raw(self, key: str):
        """The configured value (uncast), else the default."""
        return self.block[key] if key in self.block else self.default(key)

    def int(self, key: str) -> int:
        return int(self.raw(key))

    def float(self, key: str) -> float:
        return float(self.raw(key))

    def bool(self, key: str) -> bool:
        return bool(self.raw(key))

    # -- derived -------------------------------------------------------------
    @property
    def enabled(self) -> bool:
        return bool(self.block.get("enabled"))

    @property
    def mode(self) -> str:
        m = self.block.get("mode", YOLO_DEFAULTS["mode"])
        return m if m in MODES else YOLO_DEFAULTS["mode"]

    @property
    def aggressiveness(self) -> str:
        """An explicit valid `aggressiveness` wins; else derived from the mode."""
        a = self.block.get("aggressiveness")
        if a in POSTURES:
            return a
        return MODE_POSTURE.get(self.mode, "balanced")

    def resolved(self) -> dict:
        """Every effective value (casts everything; raises on a bad field)."""
        out = {"enabled": self.enabled, "mode": self.mode, "aggressiveness": self.aggressiveness}
        for k, v in YOLO_DEFAULTS.items():
            if k == "mode":
                continue
            cast = {bool: bool, int: int, float: float}[type(v)]
            out[k] = cast(self.raw(k))
        return out


# ---------------------------------------------------------------------------
# enable / disable / status / check-halt / next-tick
# ---------------------------------------------------------------------------

@dataclass
class YoloResult:
    """What a verb did: exit code, stdout/stderr text, and the yolo block after."""
    code: int = 0
    out: str = ""
    err: str = ""
    block: dict | None = None


def _usage_error(msg) -> YoloResult:
    return YoloResult(2, "", f"ERROR: {msg}\n")


def _cfg(c: Campaign) -> Path:
    return _config.config_path(c)


def _current_tick(c: Campaign) -> int:
    try:
        with open(c.state_dir / "current.json") as f:
            return int(json.load(f).get("tick_number", 0))
    except Exception:
        return 0


ENABLE_FLAGS = {
    "--mode": "mode", "--aggressiveness": "aggressiveness", "--interval": "interval_seconds",
    "--max-ticks": "max_ticks", "--max-cost": "max_cost_usd",
    "--stop-on-no-progress": "stop_on_no_progress_ticks",
    "--crash-storm-threshold": "crash_storm_threshold",
    "--redundancy-threshold": "redundancy_threshold", "--soft-cost-fraction": "soft_cost_fraction",
    "--max-backoff-multiplier": "max_backoff_multiplier",
    "--plateau-escalate-ticks": "plateau_escalate_ticks",
}


def parse_enable_args(argv) -> tuple[dict | None, YoloResult | None]:
    """yolo-state.sh enable's flag parser: {field: raw string} (+ cost_cap)."""
    opts: dict = {}
    i = 0
    while i < len(argv):
        a = argv[i]
        if a == "--no-cap":
            opts["cost_cap_enabled"] = "false"
            i += 1
        elif a == "--cap":
            opts["cost_cap_enabled"] = "true"
            i += 1
        elif a in ENABLE_FLAGS:
            opts[ENABLE_FLAGS[a]] = argv[i + 1] if i + 1 < len(argv) else ""
            i += 2
        else:
            return None, _usage_error(f"enable: unknown arg '{a}'")
    if opts.get("mode", "") not in ("",) + MODES:
        return None, _usage_error(f"--mode must be guided, hybrid, or self_loop (got '{opts['mode']}')")
    if opts.get("aggressiveness", "") not in ("",) + POSTURES:
        return None, _usage_error("--aggressiveness must be conservative, balanced, or aggressive "
                                  f"(got '{opts['aggressiveness']}')")
    return opts, None


_PRECAMPAIGN_CONFIG = '{\n  "fuzz_forks": 2\n}\n'


def enable(c: Campaign, opts: dict | None = None, *, now: int | None = None) -> YoloResult:
    """Set yolo.enabled=true: explicit options win, existing values are kept,
    genuinely-missing fields get the defaults. Records enabled_at_ts/_tick.
    Creates a minimal pre-campaign fuzz-config.json when there is none (YOLO
    can be switched on before the COLD start)."""
    opts = dict(opts or {})
    res = YoloResult()
    cfg_path = _cfg(c)
    if not cfg_path.is_file():
        cfg_path.parent.mkdir(parents=True, exist_ok=True)
        cfg_path.write_text(_PRECAMPAIGN_CONFIG)
        res.err = (f"note: no campaign yet — created {cfg_path} to hold the YOLO config.\n"
                   "      The next /cc-fuzzer:campaign (COLD) reads yolo.enabled and starts the "
                   "self-loop automatically.\n")
    now = int(time.time()) if now is None else now
    tick = _current_tick(c)

    with open(cfg_path) as f:
        cfg = json.load(f)
    yolo = cfg.get("yolo") or {}

    def override(fld, cast, default=None):
        v = opts.get(fld, "")
        if v:
            try:
                yolo[fld] = cast(v)
                return
            except Exception:
                pass
        if fld not in yolo:
            yolo[fld] = cast(YOLO_DEFAULTS[fld] if default is None else default)

    override("mode", str)
    # aggressiveness: explicit wins; else keep an existing value; else derive
    # from the (now-resolved) mode.
    if opts.get("aggressiveness") in POSTURES:
        yolo["aggressiveness"] = opts["aggressiveness"]
    elif "aggressiveness" not in yolo:
        yolo["aggressiveness"] = MODE_POSTURE.get(yolo.get("mode", YOLO_DEFAULTS["mode"]), "balanced")
    soft_default = YoloSettings(yolo).default("soft_cost_fraction")
    cap = opts.get("cost_cap_enabled") or ""
    if cap == "false":
        yolo["cost_cap_enabled"] = False
    elif cap == "true":
        yolo["cost_cap_enabled"] = True
    elif "cost_cap_enabled" not in yolo:
        yolo["cost_cap_enabled"] = YOLO_DEFAULTS["cost_cap_enabled"]
    override("interval_seconds", int)
    override("max_ticks", int)
    override("max_cost_usd", float)
    override("stop_on_no_progress_ticks", int)
    override("crash_storm_threshold", int)
    override("redundancy_threshold", int)
    override("soft_cost_fraction", float, soft_default)
    override("max_backoff_multiplier", int)
    override("plateau_escalate_ticks", int)
    if yolo["plateau_escalate_ticks"] >= yolo["stop_on_no_progress_ticks"]:
        yolo["plateau_escalate_ticks"] = max(1, yolo["stop_on_no_progress_ticks"] - 1)

    yolo["enabled"] = True
    yolo["enabled_at_ts"] = int(now)
    yolo["enabled_at_tick"] = int(tick)
    yolo["last_halt_reason"] = None
    cfg["yolo"] = yolo
    _config.write(cfg_path, cfg)

    res.block = yolo
    res.out = (f"yolo enabled mode={yolo['mode']} aggressiveness={yolo['aggressiveness']} "
               f"at tick={yolo['enabled_at_tick']} "
               f"interval={yolo['interval_seconds']}s "
               f"max_ticks={yolo['max_ticks']} "
               f"max_cost=${yolo['max_cost_usd']:.2f} "
               f"stop_on_no_progress={yolo['stop_on_no_progress_ticks']} "
               f"plateau_escalate={yolo['plateau_escalate_ticks']} "
               f"redundancy={yolo['redundancy_threshold']} "
               f"soft_cost={yolo['soft_cost_fraction']} "
               f"cost_cap={'on' if yolo['cost_cap_enabled'] else 'OFF'}\n")
    return res


def _no_config(c) -> YoloResult:
    return YoloResult(2, "", f"ERROR: {_cfg(c)} not found. Initialize the campaign first.\n")


def disable(c: Campaign, reason: str = "") -> YoloResult:
    """Set yolo.enabled=false; a non-empty reason becomes last_halt_reason."""
    if not _cfg(c).is_file():
        return _no_config(c)
    with open(_cfg(c)) as f:
        cfg = json.load(f)
    yolo = cfg.get("yolo") or {}
    was_enabled = bool(yolo.get("enabled"))
    yolo["enabled"] = False
    if reason:
        yolo["last_halt_reason"] = reason
    cfg["yolo"] = yolo
    _config.write(_cfg(c), cfg)
    out = (f"yolo disabled{' (was: enabled)' if was_enabled else ' (was: already disabled)'}"
           + (f" reason: {reason}" if reason else "") + "\n")
    return YoloResult(0, out, "", yolo)


def status(c: Campaign) -> YoloResult:
    if not _cfg(c).is_file():
        return YoloResult(0, "yolo: not configured (no fuzz-config.json)\n")
    with open(_cfg(c)) as f:
        cfg = json.load(f)
    y = cfg.get("yolo") or {}
    if not y:
        return YoloResult(0, "yolo: not configured\n")
    s = YoloSettings(y)
    lines = [f"yolo: {'ENABLED' if y.get('enabled') else 'disabled'}"]
    if y.get("enabled"):
        cap = s.raw("cost_cap_enabled")
        lines += [
            f"  mode:                     {y.get('mode', YOLO_DEFAULTS['mode'])}",
            f"  aggressiveness:           {y.get('aggressiveness', s.aggressiveness)}",
            f"  interval:                 {s.raw('interval_seconds')}s",
            f"  max_ticks:                {s.raw('max_ticks')}",
            f"  max_cost_usd:             ${s.raw('max_cost_usd'):.2f}",
            f"  stop_on_no_progress:      {s.raw('stop_on_no_progress_ticks')} ticks",
            f"  plateau_escalate:         {s.raw('plateau_escalate_ticks')} ticks "
            "(self_loop reshape→consult→halt ladder)",
            f"  crash_storm_threshold:    {s.raw('crash_storm_threshold')} findings/tick",
            f"  redundancy_threshold:     {s.raw('redundancy_threshold')} unproductive dispatches",
            f"  soft_cost_fraction:       {s.raw('soft_cost_fraction')} of max_cost (throttle Opus)"
            + ("" if cap else " [DISABLED via --no-cap]"),
            f"  cost_cap:                 {'on' if cap else 'OFF (--no-cap: no soft throttle and no hard max_cost halt; other halts still apply)'}",
            # "?" = never recorded (enable always records both)
            f"  enabled_at_tick:          {y['enabled_at_tick'] if 'enabled_at_tick' in y else '?'}",
            f"  enabled_at_ts:            {y['enabled_at_ts'] if 'enabled_at_ts' in y else '?'}",
        ]
    if y.get("last_halt_reason"):
        lines.append(f"  last_halt_reason:         {y['last_halt_reason']}")
    return YoloResult(0, "\n".join(lines) + "\n")


def _yolo_state(c: Campaign) -> dict | None:
    """current.json's yolo_state ({} when absent); None when there is no current.json."""
    p = c.state_dir / "current.json"
    if not p.is_file():
        return None
    with open(p) as f:
        return json.load(f).get("yolo_state") or {}


def check_halt(c: Campaign) -> YoloResult:
    """Exit 0 = continue (or not active), exit 1 = halt due. The orchestrator
    must `disable --reason ...` and not schedule the next wake on 1."""
    ys = _yolo_state(c)
    if ys is None:
        return YoloResult(1, "no current.json — halt (cannot evaluate)\n")
    if not ys.get("active"):
        return YoloResult(0, "not_active\n")
    if ys.get("halt_triggered"):
        return YoloResult(1, (ys.get("halt_reason") or "halt_triggered_no_reason") + "\n")
    used = ys.get("tick_quota_used", 0)
    est = ys.get("estimated_cost_usd", 0)
    return YoloResult(0, f"continue tick={ys.get('tick_quota_used', '?')}/{used + ys.get('tick_quota_remaining', 0)} "
                         f"cost=${est:.2f}/${est + ys.get('cost_quota_remaining_usd', 0):.2f}\n")


def next_tick(c: Campaign) -> YoloResult:
    """The YOLO_NEXT: directive derived from current.json:yolo_state — the tick
    skill's fallback when the orchestrator omitted its own. On halt it also
    disables YOLO so the halt sticks. Always exit 0, exactly one line."""
    ys = _yolo_state(c)
    if ys is None or not ys.get("active"):
        return YoloResult(0, "YOLO_NEXT: inactive\n")
    if ys.get("halt_triggered"):
        r = (ys.get("halt_reason") or "halt_triggered_no_reason").replace('"', "'")
        try:
            disable(c, r)
        except Exception:
            pass
        return YoloResult(0, f'YOLO_NEXT: halt reason="{r}"\n')
    # Conservative recovery: base interval, no disposition-aware backoff.
    delay = ys.get("interval_seconds") or YOLO_DEFAULTS["interval_seconds"]
    used = ys.get("tick_quota_used", 0)
    total = used + ys.get("tick_quota_remaining", 0)
    return YoloResult(0, f'YOLO_NEXT: schedule delay={delay} prompt=/cc-fuzzer:tick '
                         f'reason="yolo tick {used + 1}/{total} (recovered: orchestrator omitted YOLO_NEXT)"\n')


# ---------------------------------------------------------------------------
# CLI: cc-fuzzer yolo <verb> [args]   (yolo-state.sh is a shim onto this)
# ---------------------------------------------------------------------------

VERBS = "enable | disable | status | check-halt | next-tick"


def run(c: Campaign, argv) -> YoloResult:
    cmd, rest = (argv[0], list(argv[1:])) if argv else ("help", [])
    if cmd == "enable":
        opts, err = parse_enable_args(rest)
        return err or enable(c, opts)
    if cmd == "disable":
        reason = ""
        i = 0
        while i < len(rest):
            if rest[i] == "--reason":
                reason = rest[i + 1] if i + 1 < len(rest) else ""
                i += 2
            else:
                return _usage_error(f"disable: unknown arg '{rest[i]}'")
        return disable(c, reason)
    if cmd == "status":
        return status(c)
    if cmd == "check-halt":
        return check_halt(c)
    if cmd == "next-tick":
        return next_tick(c)
    if cmd in ("help", "-h", "--help"):
        return YoloResult(0, f"usage: cc-fuzzer yolo <{VERBS}> [args]\n"
                             "  (scripts/yolo-state.sh help documents every flag)\n")
    return _usage_error(f"unknown subcommand '{cmd}' (try: {VERBS})")


def _cli(a):
    try:
        c = _campaign()
    except CampaignError as e:
        sys.stderr.write(f"{e}\n")
        return e.code
    r = run(c, a.args)
    sys.stdout.write(r.out)
    sys.stderr.write(r.err)
    return r.code


def register_cli(subparsers):
    import argparse

    p = subparsers.add_parser("yolo", help="YOLO self-loop state (port of yolo-state.sh)",
                              description=f"cc-fuzzer yolo <{VERBS}> [args] (see scripts/yolo-state.sh)",
                              add_help=False)
    p.add_argument("args", nargs=argparse.REMAINDER)
    p.set_defaults(func=_cli)
