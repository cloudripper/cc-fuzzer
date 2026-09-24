"""Fuzzer slots: launch and liveness (UPDATE_ROADMAP.md §2 row 5).

    launcher.launch(campaign, SlotRequest) -> LaunchResult   (was launch-fuzzer-slot.sh + _lib/launch_slot.py)
    liveness.check(campaign, dry_run) -> LivenessResult      (was check-slot-liveness.sh)

CLI: `cc-fuzzer slots launch [--slot S] [--engine E] [--harness H] ...` (the
script's flags, messages and exit codes) and `cc-fuzzer slots liveness
[--dry-run]`. The scripts are shims onto these.
"""
from __future__ import annotations

import sys

from cc_fuzzer_core.paths import CampaignError, campaign as _campaign

_LAUNCH_FLAGS = {
    "--slot": "slot", "--engine": "engine", "--harness": "harness", "--binary": "binary",
    "--corpus": "corpus", "--role": "role", "--power-schedule": "power_schedule",
    "--libfuzzer-forks": "libfuzzer_forks", "--timeout-ms": "timeout_ms", "--restart-of": "restart_of",
}

LAUNCH_HELP = """\
cc-fuzzer slots launch - launch one fuzzer slot in the background.

  --slot <name>              (default: main; ^[a-z0-9-]+$, max 32 chars)
  --engine libfuzzer|aflpp   (default: auto)
  --harness <name>           (default: the first declared harness)
  --binary <path>            (default: the harness record's harness_binary)
  --corpus <dir>             (default: fuzz/harnesses/<harness>/corpus)
  --role master|secondary    (AFL++ only)
  --power-schedule <name>    (AFL++ only)
  --libfuzzer-forks <N>      (libFuzzer only; overrides fuzz_forks)
  --timeout-ms <N>           (per-input timeout, >= 100)
  --restart-of <slot>        (internal: a liveness restart)

Writes <state>/fuzzer-<slot>.{pid,engine,log} and the slot's fuzzers.json entry.
Exit: 0 launched, 1 engine/tool unavailable, 2 bad arguments / unsafe env, 3 already running.
"""


def _campaign_or_error():
    try:
        return _campaign(), None
    except CampaignError as e:
        sys.stderr.write(f"{e}\n")
        return None, e.code


def _cmd_launch(a):
    from cc_fuzzer_core.slots.launcher import SlotRequest, launch

    req, args = SlotRequest(), list(a.args)
    while args:
        arg = args.pop(0)
        if arg in _LAUNCH_FLAGS:
            setattr(req, _LAUNCH_FLAGS[arg], args.pop(0) if args else "")
        elif arg in ("-h", "--help"):
            sys.stdout.write(LAUNCH_HELP)
            return 0
        else:
            sys.stderr.write(f"ERROR: unknown arg '{arg}'\n")
            return 2
    c, code = _campaign_or_error()
    if c is None:
        return code
    r = launch(c, req)
    sys.stderr.write(r.err)
    sys.stdout.write(r.out)
    return r.code


def _cmd_liveness(a):
    from cc_fuzzer_core.slots.liveness import check

    c, code = _campaign_or_error()
    if c is None:
        return code
    # Like the script: only a leading --dry-run means anything.
    r = check(c, dry_run=bool(a.args) and a.args[0] == "--dry-run")
    sys.stdout.write(r.text)
    return 0


def register_cli(subparsers):
    from cc_fuzzer_core.cli import add_raw_verb, add_subsystem

    _p, verbs = add_subsystem(subparsers, "slots", "fuzzer slot launch and liveness")
    add_raw_verb(verbs, "slots", "launch", _cmd_launch,
                 "launch one fuzzer slot (port of launch-fuzzer-slot.sh); --help for flags")
    add_raw_verb(verbs, "slots", "liveness", _cmd_liveness,
                 "report slots and relaunch dead ones ([--dry-run]; port of check-slot-liveness.sh)")
