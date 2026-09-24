"""The per-tick state machine (UPDATE_ROADMAP.md §2 row 3).

    update_current(campaign) -> UpdateResult       roundup + build + derive (update-current.sh)
    roundup.roundup(campaign) -> RoundupResult     tick-coverage-<ts>.json
    build_current.build(campaign, now) -> dict     cc-fuzzer-current/v2
    derive_tick.derive(current.json) -> DeriveResult   tick_coverage / consult_state / yolo_state
    yolo_evaluate.evaluate(...)                    the advisory dynamic-YOLO block
    toolbox.compute(...)                           the lever board
    ceiling.compute(...) / ceiling.probe(campaign) the plateau / structural-ceiling probe
    yolo_state                                     YOLO defaults (YoloSettings) + enable/disable/...

CLI: `cc-fuzzer state update-current|roundup|build-current|derive|evaluate|
toolbox|ceiling-probe` and `cc-fuzzer yolo <verb>`. The scripts
(update-current.sh, tick-coverage-roundup.sh, ceiling-probe.sh,
yolo-state.sh, _lib/derive-tick-state.py, ...) are shims onto these.
"""
from __future__ import annotations

import json
import os
import sys
import time
import traceback
from dataclasses import dataclass
from pathlib import Path

from cc_fuzzer_core.paths import Campaign, CampaignError, campaign as _campaign


@dataclass(frozen=True)
class UpdateResult:
    path: Path          # state_dir/current.json
    display: str        # the path as update-current.sh prints it (project-relative)
    code: int           # 0 = current.json written
    doc: dict | None


def update_current(c: Campaign, *, now: int | None = None) -> UpdateResult:
    """Refresh the tick-coverage roundup, compose current.json, then merge the
    derived blocks. The roundup and the derive pass are best-effort (they never
    wedge a tick); a failure composing current.json is reported via `code`."""
    from cc_fuzzer_core.state import build_current, derive_tick, roundup

    c.snapshots_dir.mkdir(parents=True, exist_ok=True)
    try:
        roundup.roundup(c, stale_threshold=_stale_threshold())
    except Exception:
        pass
    now = int(time.time()) if now is None else now
    out = c.state_dir / "current.json"
    display = os.path.join(build_current.display_dir(c, c.state_dir), "current.json")
    try:
        doc = build_current.build(c, now)
        build_current.write(c, doc)
    except Exception:
        traceback.print_exc()
        return UpdateResult(out, display, 1, None)
    try:
        doc = derive_tick.derive(out, fuzz_dir=c.fuzz_root).doc or doc
    except Exception:
        pass
    return UpdateResult(out, display, 0, doc)


def _stale_threshold() -> int:
    from cc_fuzzer_core.state.roundup import DEFAULT_STALE_THRESHOLD_SECONDS
    return int(os.environ.get("STALE_THRESHOLD_SECONDS") or DEFAULT_STALE_THRESHOLD_SECONDS)


# ---------------------------------------------------------------------------
# CLI: cc-fuzzer state <verb>
# ---------------------------------------------------------------------------

def _with_campaign(fn):
    def run(a):
        try:
            c = _campaign()
        except CampaignError as e:
            sys.stderr.write(f"{e}\n")
            return e.code
        return fn(c, a)
    return run


def _cmd_update_current(c, _a):
    r = update_current(c)
    if r.code == 0:
        print(r.display)
    return r.code


def _cmd_roundup(c, _a):
    from cc_fuzzer_core.state import roundup
    print(roundup.roundup(c, stale_threshold=_stale_threshold()).path)
    return 0


def _cmd_build_current(c, a):
    from cc_fuzzer_core.state import build_current
    now = int(time.time())
    doc = build_current.build(c, now)
    if a.write:
        print(build_current.write(c, doc))
    else:
        print(json.dumps(doc, indent=2))
    return 0


def _cmd_derive(a):
    from cc_fuzzer_core.state import derive_tick
    if a.current:
        derive_tick.derive(a.current)
        return 0
    try:
        c = _campaign()
    except CampaignError as e:
        sys.stderr.write(f"{e}\n")
        return e.code
    derive_tick.derive(c.state_dir / "current.json", fuzz_dir=c.fuzz_root)
    return 0


def _cmd_evaluate(a):
    from cc_fuzzer_core.state import yolo_evaluate
    print(json.dumps(yolo_evaluate.evaluate_from_current(a.current), indent=2))
    return 0


def _cmd_toolbox(a):
    from cc_fuzzer_core.state import toolbox
    print(json.dumps(toolbox.compute_from_current(a.current), indent=2))
    return 0


def _cmd_ceiling(c, _a):
    from cc_fuzzer_core.state import ceiling
    try:
        r = ceiling.probe(c)
    except FileNotFoundError as e:
        sys.stderr.write(f"ceiling-probe: no current.json at {e.args[0]} — run a tick first.\n")
        return 1
    print(json.dumps(r.block, indent=2))
    sys.stderr.write(f"\nceiling-probe: stage {r.block['ladder_stage']} | {r.block['summary']}\n  → {r.path}\n")
    return 0


def register_cli(subparsers):
    from cc_fuzzer_core.cli import add_subsystem
    from cc_fuzzer_core.state import yolo_state

    _p, verbs = add_subsystem(subparsers, "state", "per-tick state machine (current.json and its derived blocks)")
    v = verbs.add_parser("update-current", help="roundup + compose current.json + derived blocks")
    v.set_defaults(func=_with_campaign(_cmd_update_current))
    v = verbs.add_parser("roundup", help="write snapshots/tick-coverage-<ts>.json "
                                          "(STALE_THRESHOLD_SECONDS, default 600)")
    v.set_defaults(func=_with_campaign(_cmd_roundup))
    v = verbs.add_parser("build-current", help="compose current.json (print it; --write to store)")
    v.add_argument("--write", action="store_true")
    v.set_defaults(func=_with_campaign(_cmd_build_current))
    v = verbs.add_parser("derive", help="merge tick_coverage/consult_state/yolo_state into current.json")
    v.add_argument("current", nargs="?", help="path to current.json (default: the campaign's)")
    v.set_defaults(func=_cmd_derive)
    v = verbs.add_parser("evaluate", help="print the advisory YOLO evaluation block for a current.json")
    v.add_argument("current")
    v.set_defaults(func=_cmd_evaluate)
    v = verbs.add_parser("toolbox", help="print the lever board for a current.json")
    v.add_argument("current")
    v.set_defaults(func=_cmd_toolbox)
    v = verbs.add_parser("ceiling-probe", help="write a ceiling-probe/v1 snapshot and print it")
    v.set_defaults(func=_with_campaign(_cmd_ceiling))

    yolo_state.register_cli(subparsers)
