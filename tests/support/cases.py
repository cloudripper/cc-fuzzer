"""Shared golden cases for the §2 ports (UPDATE_ROADMAP.md table rows 1-8).

Each Case names ONE golden (tests/golden/<name>.json), the fixture + setup it
runs on, the bash entry point that recorded it (`bash_argv`) and the core CLI
command that must reproduce it (`core_argv`, None when the case only exercises
bash-side behaviour such as the shim's own help text).

tests/test_golden_bash.py asserts every bash_argv against its golden (the
contract, recorded from the pre-port bash/python implementation);
tests/test_core_*.py assert every core_argv against the SAME golden, so a port
can only land if it reproduces the old behaviour exactly.
"""
from __future__ import annotations

import json
import os
import shutil
import subprocess
import time
from dataclasses import dataclass, field
from typing import Callable

from tests.support.golden import FROZEN_NOW, SUPPORT_BIN, TESTS, bash, core, python_script

N = FROZEN_NOW


@dataclass
class Case:
    name: str
    fixture: str | None
    bash_argv: list
    core_argv: list | None
    setup: Callable | None = None
    env: dict = field(default_factory=dict)
    cwd: str | None = None
    stdin: str | None = None
    # live=True: run_case starts a real `sleep` process first and exposes its
    # pid as sb.live_pid (for slot-liveness checks); setup writes it where needed.
    live: bool = False
    # real_now=True: the sandbox clock is the real wall clock (for code that
    # compares mtimes with the real clock, e.g. find -mmin).
    real_now: bool = False
    # Capture fields the core run is not compared on (e.g. the bash side prints
    # plugin hook JSON where the core prints data): ("stdout",).
    core_ignore: tuple = ()


def run_case(test, case: Case, argv):
    """Sandbox the case's fixture, apply its setup, run argv, return the capture."""
    sb = test.sandbox(case.fixture, **({"now": int(time.time())} if case.real_now else {}))
    if case.fixture is None:
        (sb.project / "fuzz").mkdir()
    if case.live:
        proc = subprocess.Popen(["sleep", "300"])
        test.addCleanup(proc.wait)
        test.addCleanup(proc.kill)
        sb.live_pid = proc.pid
    if case.setup:
        case.setup(sb)
    return sb.run(argv, env=case.env or None, cwd=case.cwd, stdin=case.stdin)


def assert_core_case(test, case: Case):
    """Run case.core_argv and assert it against the case's golden."""
    test.assertGolden(case.name, run_case(test, case, case.core_argv), ignore=case.core_ignore)


# ---------------------------------------------------------------------------
# helpers
# ---------------------------------------------------------------------------

def _jsonl_append(sb, rel, *rows):
    with open(sb.path(rel), "a") as f:
        for r in rows:
            f.write((r if isinstance(r, str) else json.dumps(r)) + "\n")


def _cap_regex(sb):
    # fuzz_forks is capped at nproc-1: keep goldens machine-independent.
    sb.add_regex(r"nproc-1=\d+\); using \d+", "nproc-1=<CAP>); using <CAP>")
    sb.add_regex(r"(cap \(nproc-1\): +)\d+", r"\1<CAP>")
    sb.add_regex(r"(Resolved fuzz_forks: )\d+", r"\1<CAP>")


def _capped_stdout(sb):
    _cap_regex(sb)
    sb.add_regex(r"(?m)\A\d+$", "<CAP>")


def _yolo(sb, **fields):
    def f(doc):
        y = doc.setdefault("yolo", {})
        y.update(fields)
    sb.edit_json("fuzz/state/fuzz-config.json", f)


def _strip_derived(sb):
    sb.edit_json("fuzz/state/current.json",
                 lambda d: [d.pop(k, None) for k in ("tick_coverage", "consult_state", "yolo_state")] and None)


# ---------------------------------------------------------------------------
# row 1: fuzz-config.sh / enums.py
# ---------------------------------------------------------------------------

FC = "scripts/_lib/fuzz-config.sh"


def _set_in_empty_project(sb):
    pass  # run_case already made fuzz/; the state dir is created by `set`


CONFIG_CASES = [
    Case("fuzz-config/get-forks-env", "campaign-warm", bash(FC, "get", "fuzz_forks"),
         core("config", "get", "fuzz_forks"), env={"FUZZ_FORKS": "1"}),
    Case("fuzz-config/get-forks-override-zero", "campaign-warm", bash(FC, "get", "fuzz_forks"),
         core("config", "get", "fuzz_forks"), env={"FUZZ_FORKS_OVERRIDE": "0"}),
    Case("fuzz-config/get-forks-garbage", "campaign-warm", bash(FC, "get", "fuzz_forks"),
         core("config", "get", "fuzz_forks"), setup=_capped_stdout, env={"FUZZ_FORKS": "lots"}),
    Case("fuzz-config/get-forks-capped", "campaign-warm", bash(FC, "get", "fuzz_forks"),
         core("config", "get", "fuzz_forks"), setup=_capped_stdout, env={"FUZZ_FORKS": "999"}),
    Case("fuzz-config/get-key", "campaign-warm", bash(FC, "get", "schema"),
         core("config", "get", "schema")),
    Case("fuzz-config/get-missing-key", "campaign-warm", bash(FC, "get", "nope"),
         core("config", "get", "nope")),
    Case("fuzz-config/get-no-file", "campaign-cold", bash(FC, "get", "schema"),
         core("config", "get", "schema"),
         setup=lambda sb: sb.path("fuzz/state/fuzz-config.json").unlink()),
    Case("fuzz-config/set-int", "campaign-cold", bash(FC, "set", "fuzz_forks", "4"),
         core("config", "set", "fuzz_forks", "4")),
    Case("fuzz-config/set-string", "campaign-warm", bash(FC, "set", "note", "hello world"),
         core("config", "set", "note", "hello world")),
    Case("fuzz-config/set-creates-file", None, bash(FC, "set", "fuzz_forks", "3"),
         core("config", "set", "fuzz_forks", "3"), setup=_set_in_empty_project),
    Case("fuzz-config/show", "campaign-warm", bash(FC, "show"), core("config", "show"),
         setup=_cap_regex),
    Case("fuzz-config/help", "campaign-warm", bash(FC, "help"), core("config", "help")),
]

EN = "scripts/_lib/enums.py"

ENUMS_CASES = [
    Case("enums/print-categories", None, python_script(EN, "print", "categories"),
         core("enums", "print", "categories")),
    Case("enums/print-sep", None, python_script(EN, "print", "REC_BRANCHES", "--sep", ","),
         core("enums", "print", "REC_BRANCHES", "--sep", ",")),
    Case("enums/check-member", None, python_script(EN, "check", "engines", "aflpp"),
         core("enums", "check", "engines", "aflpp")),
    Case("enums/check-nonmember", None, python_script(EN, "check", "engines", "honggfuzz"),
         core("enums", "check", "engines", "honggfuzz")),
    Case("enums/unknown-enum", None, python_script(EN, "print", "bogus"),
         core("enums", "print", "bogus")),
    Case("enums/doc-drift", None, python_script(EN, "doc-drift"), core("enums", "doc-drift")),
    Case("enums/usage", None, python_script(EN, "print"), None),
    Case("enums/unknown-command", None, python_script(EN, "frob", "engines"), None),
]


# ---------------------------------------------------------------------------
# row 2: validate-state.sh
# ---------------------------------------------------------------------------

VS = bash("scripts/validate-state.sh")
VC = core("schema", "validate")


def _vs(name, fixture, setup=None, env=None, cwd=None):
    return Case(f"validate-state/{name}", fixture, VS, VC, setup=setup, env=env or {}, cwd=cwd)


def _break_deep(sb):
    """campaign-warm with one of (almost) every content/layout problem."""
    sb.path("fuzz/harness").mkdir()                        # retired singular path
    sb.path("fuzz/state/crashes").mkdir()                  # forbidden legacy path
    sb.path("out/default/crashes").mkdir(parents=True)     # forbidden (project-relative)
    shutil.rmtree(sb.path("fuzz/harnesses/encoder/corpus"))
    sb.path("fuzz/harnesses/encoder/harness/encoder_fuzzer").chmod(0o644)
    sb.path("fuzz/state/FINDINGS-REPORT-fixture.md").unlink()

    def hb(d):
        d["coverage_binary"] = None
        d["cmplog_enabled"] = True
        d["fuzzing_mode"] = "hybrid"
        d["target_source_hash"] = "TODO"
        d["extra_field"] = 1
    sb.edit_json("fuzz/state/harness-built.json", hb)

    def hs(d):
        d["harnesses"][1]["schema"] = "harness-built/v6"
        d["harnesses"][1].pop("built_at", None)
        d["harnesses"].append({"schema": "harness-built/v7", "name": "Bad Name"})
    sb.edit_json("fuzz/state/harnesses.json", hs)

    def cur(d):
        d["recommendation"]["branch"] = "dance"
        d["recommendation"]["harness"] = "ghost"
    sb.edit_json("fuzz/state/current.json", cur)
    sb.edit_json("fuzz/state/budget.json", lambda d: d.update(bonus=1))

    def cfg(d):
        d["fuzzer_slots"].append({"slot": "parser-main", "harness": "ghost", "engine": "honggfuzz",
                                  "role": "boss", "afl_power_schedule": "slow"})
        d["fuzzer_slots"].append({"slot": "BAD SLOT", "engine": "libfuzzer"})
        d["mystery"] = True
    sb.edit_json("fuzz/state/fuzz-config.json", cfg)

    def man(d):
        del d["slots"][0]["pgid"]
        d["slots"][1]["harness"] = "ghost"
    sb.edit_json("fuzz/state/fuzzers.json", man)

    _jsonl_append(sb, "fuzz/state/events.jsonl", "not json",
                  {"schema": "event/v0", "ts": 1}, {"schema": "event/v1", "ts": 1})
    snaps = "fuzz/state/snapshots"
    sb.write(f"{snaps}/coverage-999.json", "{}\n")
    sb.write(f"{snaps}/coverage-ghost-1789990000.json", json.dumps(
        {"schema": "coverage-snapshot/v2", "timestamp": 1, "engine": "libfuzzer", "fuzzer_stats": {},
         "coverage": {}, "instrumentation": {}, "harness": "ghost"}) + "\n")
    sb.edit_json(f"{snaps}/gaps-parser-1789998250.json", lambda d: d.update(notes="x"))
    sb.edit_json(f"{snaps}/coverage-encoder-1789998300.json", lambda d: d.update(harness="parser"))
    sb.write(f"{snaps}/gaps-encoder-1789990000.json", json.dumps(
        {"schema": "gaps-report/v1", "timestamp": 1, "snapshot_file": "x", "gaps": []}) + "\n")
    sb.write(f"{snaps}/tick-briefing-1789999000.json", json.dumps(
        {"schema": "tick-briefing/v1", "ts": 1}) + "\n")
    sb.write(f"{snaps}/planner-consult-1789999000.json", "{not json\n")
    sb.write(f"{snaps}/ceiling-probe-1789999000.json", json.dumps(
        {"schema": "ceiling-probe/v1", "ladder_stage": 0, "is_real_ceiling": False,
         "structural_candidates": [], "engine_fit": {}, "summary": "", "surprise": 1}) + "\n")
    sb.write(f"{snaps}/cve-context-1789999000.json", json.dumps(["not", "an", "object"]) + "\n")
    sb.write(f"{snaps}/code-review-prescan-1789999000.json", json.dumps(
        {"schema": "code-review-prescan/v1", "ts": 1, "target_root": "src", "scope": {},
         "top_candidates": []}) + "\n")
    sb.write(f"{snaps}/code-review-1789999000.json", json.dumps({
        "schema": "code-review/v1", "ts": 1, "target": "t", "tiers_run": ["sonnet"],
        "focus_areas": [], "scope": {"mode": "yolo", "functions_inventoried": "3",
                                     "coverage_complete": "yes"},
        "findings": [
            {"id": "cr1", "cr_hash": "xyz", "status": "open", "file": "a.c", "function": "f",
             "line_range": [1, 2], "pattern": "oob_read", "confidence": "certain",
             "tier_classified": "haiku", "evidence": "e", "oracle_kind": "fun",
             "needs_deep_pass": "no"},
            "not-an-object",
            {"id": "cr002"},
        ]}) + "\n")
    sb.write(f"{snaps}/code-review-1789999000-w01.json", json.dumps({
        "schema": "code-review/v1", "ts": 1, "scope": {}, "findings": {"not": "a list"}}) + "\n")
    sb.write(f"{snaps}/delta-1789999000.json", "{}\n")
    sb.write("fuzz/crashes/new/parser__nothex.bin", b"x")
    sb.write("fuzz/crashes/new/README", "stray\n")
    sb.write("fuzz/state/nix-environment-issues.json", json.dumps({"issues": [
        {"severity": "error", "code": "E1", "summary": "store path gone",
         "remediation": {"human_message": "rebuild"}},
        {"severity": "warning", "code": "W1", "summary": "profile drift"},
        "junk",
    ]}) + "\n")


def _break_logs(sb):
    """campaign-crashes: every jsonl ledger with bad lines."""
    _jsonl_append(sb, "fuzz/state/findings.jsonl",
                  "{broken",
                  {"schema": "finding/v1", "id": "f009"},
                  {"schema": "finding/v2", "id": "f001", "stack_hash": "a1b2c3d4e5f60718",
                   "harnesses": ["ghost"], "category": "rainbow", "location": "x",
                   "exploitability": "sure", "root_cause": "r",
                   "reproducer": "fuzz/crashes/known/f009/repro.bin", "first_seen": "a",
                   "last_seen": "b", "dedup_count": 1, "status": "finding", "wat": 1},
                  {"schema": "finding/v2", "id": "f010", "source": "code_review", "cr_ref": "cr001",
                   "harnesses": ["parser"], "category": "ubsan-shift", "location": "x",
                   "exploitability": "unlikely", "root_cause": "r", "first_seen": "a",
                   "last_seen": "b", "dedup_count": 1, "status": "stale",
                   "reproducer": "fuzz/crashes/stale/f010/repro.bin"},
                  "",
                  {"schema": "finding/v2", "id": "f011", "stack_hash": "0f1e2d3c4b5a6978",
                   "harnesses": [], "category": "oom", "location": "x",
                   "exploitability": "likely", "root_cause": "r", "reproducer": "",
                   "first_seen": "a", "last_seen": "b", "dedup_count": 1})
    _jsonl_append(sb, "fuzz/state/harness-corrections.jsonl",
                  "nope",
                  {"schema": "harness-correction/v0"},
                  {"schema": "harness-correction/v1", "ts": 1, "principle": "vibes"})
    _jsonl_append(sb, "fuzz/state/dropped_crashes.jsonl",
                  "[1,",
                  {"schema": "dropped/v0"},
                  {"schema": "dropped-crash/v1", "ts": "t", "crash_file": "c", "stage": "artifact_filter",
                   "reason": "r"},
                  {"schema": "dropped-crash/v1", "ts": "t", "crash_file": "c", "stage": "gut_feeling",
                   "reason": "r", "principle": "vibes"},
                  {"schema": "dropped-crash/v1", "stage": "deterministic_replay", "principle": "null"})
    sb.write("fuzz/crashes/known/f003/harnesses.txt", "parser\n")
    sb.write("fuzz/crashes/known/f12/repro.bin", b"x")


def _missing_dirs(sb):
    for d in ("fuzz/state/snapshots", "fuzz/crashes/flaky", "fuzz/crashes/known"):
        shutil.rmtree(sb.path(d))
    sb.write("fuzz/state/schema-version", "  v12  \nextra line\n")
    sb.write("fuzz/state/nix-environment-issues.json", "not json\n")


def _no_config(sb):
    sb.path("fuzz/state/fuzz-config.json").unlink()
    sb.path("fuzz/state/schema-version").unlink()


def _no_harnesses(sb):
    sb.edit_json("fuzz/state/fuzz-config.json", lambda d: d.update(harnesses=[]))
    sb.edit_json("fuzz/state/harness-built.json", lambda d: d.update(coverage_tracking=False))


def _hb_unparseable(sb):
    sb.write("fuzz/state/harness-built.json", "{oops\n")


VALIDATE_CASES = [
    _vs("broken-deep", "campaign-warm", _break_deep),
    _vs("broken-logs", "campaign-crashes", _break_logs),
    _vs("missing-dirs", "campaign-cold", _missing_dirs),
    _vs("no-config", "campaign-cold", _no_config),
    _vs("no-harnesses", "campaign-cold", _no_harnesses),
    _vs("harness-built-unparseable", "campaign-cold", _hb_unparseable),
    _vs("warm-from-subdir", "campaign-warm", cwd="src"),
    _vs("project-root-env", "campaign-warm", env={"PROJECT_ROOT": "."}, cwd=None),
]


# ---------------------------------------------------------------------------
# row 3: yolo-state.sh, tick-coverage-roundup.sh, ceiling-probe.sh,
#        derive-tick-state.py, update-current.sh
# ---------------------------------------------------------------------------

YS = "scripts/yolo-state.sh"


def _ys(name, fixture, *args, setup=None, env=None, core_args=True):
    return Case(f"yolo-state/{name}", fixture, bash(YS, *args),
                core("yolo", *args) if core_args else None, setup=setup, env=env or {})


def _halted(sb):
    def h(doc):
        doc["yolo_state"]["halt_triggered"] = True
        doc["yolo_state"]["halt_reason"] = "tick cap reached (24/24)"
    sb.edit_json("fuzz/state/current.json", h)


def _yolo_disabled_with_reason(sb):
    _yolo(sb, enabled=False, last_halt_reason="operator stop")


def _yolo_partial(sb):
    # An enabled block missing most fields (hand-edited config).
    sb.edit_json("fuzz/state/fuzz-config.json",
                 lambda d: d.update(yolo={"enabled": True, "mode": "guided", "max_ticks": 3}))


YOLO_CASES = [
    _ys("enable-defaults", "campaign-warm", "enable"),
    _ys("enable-self-loop", "campaign-warm", "enable", "--mode", "self_loop", "--no-cap",
        "--max-ticks", "5", "--stop-on-no-progress", "4", "--plateau-escalate-ticks", "9",
        "--interval", "600", "--max-cost", "2.5"),
    _ys("enable-keeps-existing", "campaign-plateau", "enable", "--aggressiveness", "balanced",
        "--cap", "--soft-cost-fraction", "0.7", "--redundancy-threshold", "3",
        "--crash-storm-threshold", "4", "--max-backoff-multiplier", "2"),
    _ys("enable-bad-number", "campaign-warm", "enable", "--max-ticks", "many"),
    _ys("enable-bad-mode", "campaign-warm", "enable", "--mode", "wild"),
    _ys("enable-bad-aggressiveness", "campaign-warm", "enable", "--aggressiveness", "max"),
    _ys("enable-unknown-arg", "campaign-warm", "enable", "--turbo"),
    _ys("enable-precampaign", None, "enable", "--mode", "guided"),
    _ys("disable", "campaign-plateau", "disable"),
    _ys("disable-reason", "campaign-plateau", "disable", "--reason", "done for today"),
    _ys("disable-already", "campaign-warm", "disable"),
    _ys("disable-no-config", None, "disable"),
    _ys("disable-unknown-arg", "campaign-plateau", "disable", "--now"),
    _ys("status-enabled", "campaign-plateau", "status"),
    _ys("status-not-configured", "campaign-warm", "status"),
    _ys("status-no-config", None, "status"),
    _ys("status-disabled-reason", "campaign-plateau", "status", setup=_yolo_disabled_with_reason),
    _ys("status-partial", "campaign-warm", "status", setup=_yolo_partial),
    _ys("check-halt-no-current", "campaign-cold", "check-halt"),
    _ys("check-halt-inactive", "campaign-warm", "check-halt"),
    _ys("check-halt-continue", "campaign-plateau", "check-halt"),
    _ys("check-halt-halted", "campaign-plateau", "check-halt", setup=_halted),
    _ys("unknown-subcommand", "campaign-warm", "frob"),
    _ys("help", "campaign-warm", "help", core_args=False),
]

RU = "scripts/tick-coverage-roundup.sh"
ROUNDUP_CASES = [
    Case("tick-coverage-roundup/warm", "campaign-warm", bash(RU), core("state", "roundup")),
    Case("tick-coverage-roundup/plateau", "campaign-plateau", bash(RU), core("state", "roundup")),
    Case("tick-coverage-roundup/cold", "campaign-cold", bash(RU), core("state", "roundup")),
    Case("tick-coverage-roundup/warm-long-threshold", "campaign-warm", bash(RU),
         core("state", "roundup"), env={"STALE_THRESHOLD_SECONDS": "100000"}),
]

CP = "scripts/ceiling-probe.sh"
CEILING_CASES = [
    Case("ceiling-probe/plateau", "campaign-plateau", bash(CP), core("state", "ceiling-probe")),
    Case("ceiling-probe/no-current", "campaign-cold", bash(CP), core("state", "ceiling-probe")),
]


# -- derive-tick-state variants (yolo modes, halts, ladder stages) -------------

def _derive(setup):
    def s(sb):
        _strip_derived(sb)
        if setup:
            setup(sb)
    return s


def _stage_events(*, consult):
    def s(sb):
        rows = [{"schema": "event/v1", "ts": N - 500, "tick": 13, "event": "tick",
                 "branch": "harness_new", "reason": "structural:new_harness:free_chunk",
                 "agent_called": "harness-writer", "tokens_in": 1000, "tokens_out": 100}]
        if consult:
            rows.append({"schema": "event/v1", "ts": N - 400, "tick": 13, "event": "agent_call",
                         "agent_called": "planner-consult", "tokens_in": 2000, "tokens_out": 300})
        _jsonl_append(sb, "fuzz/state/events.jsonl", *rows)
    return s


def _plateau_rich(sb):
    """Aggressive plateau with code-review + CVE signals, operator steering,
    a redqueen-heavy gap mix and a dead function."""
    snaps = "fuzz/state/snapshots"

    def gaps(d):
        d["gaps"] += [
            {"id": "g003", "function": "crc_check", "reason": "checksum_barrier"},
            {"id": "g004", "function": "magic", "reason": "direct_compare"},
            {"id": "g005", "function": "fmt", "reason": "format_barrier"},
            {"id": "g006", "function": "old_api", "reason": "dead"},
            {"id": "g007", "function": "state_machine", "reason": "state_precondition"},
            {"id": "g008", "function": "net_io", "reason": "harness_gap", "harness_action": "mock",
             "mock_target": "socket"},
        ]
    sb.edit_json(f"{snaps}/gaps-parser-1789996340.json", gaps)
    cov = sorted(p.name for p in sb.path(snaps).glob("coverage-parser-*.json"))[-1]
    sb.edit_json(f"{snaps}/{cov}", lambda d: d.update(
        top_unreached_functions=["parse_exif", "free_chunk", "old_api", "lookup", "cve_fn"]))
    sb.write(f"{snaps}/code-review-1789996000.json", json.dumps({
        "schema": "code-review/v1", "findings": [
            {"id": "cr001", "function": "lookup", "confidence": "high"},
            {"id": "cr002", "function": "parse_exif", "confidence": "low"}]}) + "\n")
    sb.write(f"{snaps}/cve-context-1789996000.json", json.dumps({
        "schema": "cve-context/v1", "hotspots": {
            "by_function": [{"name": "cve_fn"}], "by_file": [{"top_funcs": ["old_api"]}]}}) + "\n")
    sb.write("fuzz/guidance.md", "focus on chunk lifecycles\n")
    sb.write("fuzz/docs/spec.md", "spec\n")
    sb.write("fuzz/docs/sub/notes.txt", "notes\n")
    sb.write("fuzz/state/cve-patterns.md", "patterns\n")
    _jsonl_append(sb, "fuzz/state/findings.jsonl", {
        "schema": "finding/v2", "id": "f001", "category": "auth-bypass", "exploitability": "likely",
        "reproducer": "fuzz/crashes/known/f001/repro.bin", "first_seen": "2026-09-21T14:00:00Z",
        "harnesses": ["parser"], "verification": {"deterministic_replay": "pass",
                                                  "exploit_built": False},
        "poc_path": "fuzz/pocs/f001/"})
    sb.path("fuzz/pocs/f001").mkdir(parents=True)


def _warm_yolo_throttle(sb):
    _yolo(sb, enabled=True, mode="hybrid", max_cost_usd=0.2, soft_cost_fraction=0.5,
          enabled_at_ts=0, enabled_at_tick=0)


def _warm_yolo_cost_halt(sb):
    _yolo(sb, enabled=True, mode="guided", max_cost_usd=0.05, enabled_at_ts=0, enabled_at_tick=0)


def _crashes_guided_storm(sb):
    _yolo(sb, enabled=True, mode="guided", crash_storm_threshold=1, interval_seconds=86400,
          enabled_at_ts=0, enabled_at_tick=0, cost_cap_enabled=False)


def _crashes_self_loop(sb):
    _yolo(sb, enabled=True, mode="self_loop", enabled_at_ts=0, enabled_at_tick=0,
          redundancy_threshold=1)


def _plateau_mode(mode, **extra):
    def s(sb):
        def f(d):
            d["yolo"]["mode"] = mode
            d["yolo"].pop("aggressiveness", None)
            d["yolo"].update(extra)
        sb.edit_json("fuzz/state/fuzz-config.json", f)
    return s


def _plateau_tick_cap(sb):
    _yolo(sb, max_ticks=5)


def _plateau_zero_cfg(sb):
    # User-set zeros must survive (".get(key, default)", not "or default").
    _yolo(sb, max_ticks=0, max_backoff_multiplier=0, stop_on_no_progress_ticks=0)


def _warm_consult_due(sb):
    sb.edit_json("fuzz/state/fuzz-config.json", lambda d: d["tick"].update(consult_every_n=1))
    sb.write("fuzz/state/snapshots/planner-consult-1789990000.json", json.dumps(
        {"schema": "planner-consult/v1", "ts": 1789990000, "tick_number": 1, "verdict": "continue",
         "reason": "r"}) + "\n")


DTS = "scripts/_lib/derive-tick-state.py"


def _dts(name, fixture, setup=None):
    return Case(f"derive-tick-state/{name}", fixture,
                python_script(DTS, "fuzz/state/current.json"),
                core("state", "derive", "fuzz/state/current.json"), setup=_derive(setup))


DERIVE_CASES = [
    _dts("plateau-stage2", "campaign-plateau", _stage_events(consult=False)),
    _dts("plateau-stage3-halt", "campaign-plateau", _stage_events(consult=True)),
    _dts("plateau-rich", "campaign-plateau", _plateau_rich),
    _dts("plateau-hybrid", "campaign-plateau", _plateau_mode("hybrid")),
    _dts("plateau-guided", "campaign-plateau", _plateau_mode("guided")),
    _dts("plateau-bogus-mode", "campaign-plateau", _plateau_mode("turbo")),
    _dts("plateau-tick-cap", "campaign-plateau", _plateau_tick_cap),
    _dts("plateau-zero-config", "campaign-plateau", _plateau_zero_cfg),
    _dts("warm-yolo-throttle", "campaign-warm", _warm_yolo_throttle),
    _dts("warm-yolo-cost-halt", "campaign-warm", _warm_yolo_cost_halt),
    _dts("warm-consult-due", "campaign-warm", _warm_consult_due),
    _dts("crashes-guided-storm", "campaign-crashes", _crashes_guided_storm),
    _dts("crashes-self-loop", "campaign-crashes", _crashes_self_loop),
]

UC = bash("scripts/update-current.sh")
UCC = core("state", "update-current")


def _no_state_files(sb):
    for f in ("fuzzers.json", "harnesses.json", "events.jsonl"):
        p = sb.path(f"fuzz/state/{f}")
        if p.exists():
            p.unlink()


UPDATE_CASES = [
    Case("update-current/plateau-rich", "campaign-plateau", UC, UCC, setup=_plateau_rich),
    Case("update-current/crashes-self-loop", "campaign-crashes", UC, UCC, setup=_crashes_self_loop),
    Case("update-current/cold-bare", "campaign-cold", UC, UCC, setup=_no_state_files),
]


# ---------------------------------------------------------------------------
# row 4: is-crash.sh, detect-crashes.sh
# ---------------------------------------------------------------------------

LOGS_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                        "fixtures", "sanitizer-logs")
IC = "scripts/is-crash.sh"


def _log_text(name):
    with open(os.path.join(LOGS_DIR, name)) as f:
        return f.read()


def _ic(name, *args, stdin=None):
    return Case(f"is-crash/{name}", None, bash(IC, *args), core("crash", "classify", *args),
                stdin=stdin)


CLASSIFY_CASES = [
    _ic("path-with-exit-code", "--exit-code", "139", os.path.join(LOGS_DIR, "asan-uaf.log")),
    _ic("stdin-asan-segv", stdin=_log_text("asan-segv.log")),
    _ic("stdin-exit-132", "--exit-code", "132", stdin="no output\n"),
    _ic("stdin-exit-135-deadly", "--exit-code", "135",
        stdin="==1==ERROR: libFuzzer: deadly signal\nMS: 1 DEADLYSIGNAL\n"),
    _ic("frames-infra-and-ubsan", stdin=(
        "src/a.c:3:1: runtime error: division by zero\n"
        "    #0 0x1 in __ubsan_handle_divrem_overflow compiler-rt/ubsan.cc:10\n"
        "    #1 0x2 in LLVMFuzzerTestOneInput fuzz/h.c:5:2\n"
        "    #2 fuzzer::Fuzzer::ExecuteCallback lib/F.cpp:600\n"
        "    in divide src/a.c:3:1\n")),
    _ic("frame-without-location", stdin="Segmentation fault\n    #0 0x1 in lonely\n"),
    _ic("summary-other-category", stdin=(
        "SUMMARY: AddressSanitizer: use-after-poison /x.c:1 in f\n    #0 0x1 in f /x.c:1:2\n")),
    _ic("summary-leak", stdin="SUMMARY: LeakSanitizer: 64 byte(s) leaked in 1 allocation(s).\n"),
    _ic("empty-stdin", stdin=""),
]

DC = bash("scripts/detect-crashes.sh")
DCC = core("crash", "detect", "--json")


def _sha(data: bytes) -> str:
    import hashlib
    return hashlib.sha256(data).hexdigest()


def _slot_live(sb):
    sb.add_sub(str(sb.live_pid), "<PID>")
    sb.edit_json("fuzz/state/fuzzers.json",
                 lambda d: d["slots"][0].update(pid=str(sb.live_pid), pgid=str(sb.live_pid)))


def _crash_files(sb):
    """Crash files in the engine output locations the launcher uses, plus
    crash-like names elsewhere (source files, stray artifacts) that must be
    ignored."""
    real = sb.now
    lf = "fuzz/harnesses/parser/.libfuzzer-cwd"
    sb.write(f"{lf}/crash-aaa", b"CRASH-A payload")
    sb.write(f"{lf}/leak-bbb", b"leak payload")
    sb.write("crash-at-root", b"unattributed")               # not a launcher location
    sb.write("fuzz/harnesses/encoder/aflpp-out/default/crashes/id:000000,sig:11", b"afl crash")
    sb.write("fuzz/harnesses/encoder/aflpp-out/encoder-afl/crashes/id:000001,sig:06", b"afl crash 2")
    sb.write("fuzz/harnesses/encoder/aflpp-out/encoder-afl/crashes/README.txt", b"afl readme")
    sb.write("fuzz/harnesses/encoder/aflpp-out/encoder-afl/hangs/id:000000", b"afl hang")
    sb.write("src/crash-handler.c", b"void crash_handler(void) {}\n")   # source files
    sb.write("fuzz/harnesses/parser/harness/crash-test.c", b"int main(void) { return 0; }\n")
    sb.write(f"{lf}/nested/crash-deeper", b"not where libFuzzer writes")
    # identical to a known finding's repro -> skipped
    sb.write(f"{lf}/timeout-ccc", sb.path("fuzz/crashes/known/f001/repro.bin").read_bytes())
    # already queued -> skipped
    dup = b"already queued"
    sb.write(f"{lf}/oom-ddd", dup)
    sb.write(f"fuzz/crashes/new/parser__{_sha(dup)[:16]}.bin", dup)
    # too old (10 min) -> skipped; outside fuzz/harnesses -> never scanned
    old = sb.write(f"{lf}/crash-old", b"old crash")
    os.utime(old, (real - 600, real - 600))
    sb.write("a/b/c/d/e/f/crash-deep", b"deep")
    sb.write("a/b/c/d/e/crash-depth6", b"depth six")
    for p in sb.project.rglob("*"):
        if p != old and p.is_file():
            os.utime(p, (real - 30, real - 30))


def _detect_live(sb):
    _slot_live(sb)
    _crash_files(sb)


def _detect_legacy_pid(sb):
    sb.path("fuzz/state/fuzzers.json").unlink()
    sb.write("fuzz/state/fuzzer.pid", f"{sb.live_pid}\n")
    sb.add_sub(str(sb.live_pid), "<PID>")
    sb.write("fuzz/harnesses/parser/.libfuzzer-cwd/crash-legacy", b"legacy")


def _dc(name, fixture, setup, live=True, **kw):
    return Case(f"detect-crashes/{name}", fixture, DC, DCC, setup=setup, live=live, real_now=True,
                core_ignore=("stdout",), **kw)


DETECT_CASES = [
    _dc("live-slot", "campaign-crashes", _detect_live),
    _dc("no-live-slot", "campaign-crashes", _crash_files, live=False),
    _dc("legacy-pid", "campaign-crashes", _detect_legacy_pid),
    _dc("state-dir-override", "campaign-crashes",
        lambda sb: (_detect_live(sb), shutil.move(str(sb.path("fuzz/state")), str(sb.path("alt-state")))),
        env={"FUZZ_STATE_DIR": "alt-state"}),
]


# ---------------------------------------------------------------------------
# row 5: launch-fuzzer-slot.sh, check-slot-liveness.sh
# ---------------------------------------------------------------------------

REAP = str(TESTS / "support" / "reap-slots.sh")
STUB_AFL_PATH = f"{TESTS / 'support' / 'stub-afl'}{os.pathsep}{SUPPORT_BIN}{os.pathsep}{os.environ.get('PATH', '/usr/bin:/bin')}"
LS = "scripts/launch-fuzzer-slot.sh"
_STUB_HARNESS = ('#!/bin/sh\n# test stub fuzzer: record cwd + argv, then idle until reaped\n'
                 'echo "harness cwd=$(pwd)"\nfor a in "$@"; do echo "  $a"; done\nexec sleep 30\n')


def _pid_regexes(sb):
    sb.add_regex(r"\b(pid|pgid)=\d+", r"\1=<PID>")
    sb.add_regex(r'"(pid|pgid)": "\d+"', r'"\1": "<PID>"')
    sb.add_regex(r"(?m)^\d+$", "<PID>")
    sb.add_regex(r"PID \d+", "PID <PID>")


def _stub_harnesses(sb):
    """Replace the fixture's harness binaries with long-lived argv recorders."""
    _pid_regexes(sb)
    for p in sb.path("fuzz/harnesses").glob("*/harness/*_fuzzer"):
        sb.write(str(p.relative_to(sb.project)), _STUB_HARNESS, mode=0o755)


def _ls(name, fixture, *args, setup=None, env=None, reap=False, live=False):
    b, c = bash(LS, *args), core("slots", "launch", *args)
    if reap:
        b, c = [REAP, *b], [REAP, *c]
    return Case(f"launch-fuzzer-slot/{name}", fixture, b, c,
                setup=setup or _pid_regexes, env=env or {}, live=live)


def _dicts(sb):
    _stub_harnesses(sb)
    sb.write("fuzz/dicts/a.dict", '"GIF8"\n')
    sb.write("fuzz/dicts/b.dict", 'kw="\\x00\\x01"\n')

    def hs(d):
        for h in d["harnesses"]:
            h["dict_files"] = ["fuzz/dicts/a.dict", "fuzz/dicts/missing.dict", "fuzz/dicts/b.dict"]
        d["harnesses"][0]["fuzzing_mode"] = "process_based"
    sb.edit_json("fuzz/state/harnesses.json", hs)


def _single_dict_string(sb):
    _stub_harnesses(sb)
    sb.write("fuzz/dicts/a.dict", '"GIF8"\n')
    sb.edit_json("fuzz/state/harnesses.json",
                 lambda d: d["harnesses"][0].update(dict_files="fuzz/dicts/a.dict"))


def _already_running(sb):
    _pid_regexes(sb)
    sb.write("fuzz/state/fuzzer-parser-main.pid", f"{sb.live_pid}\n")


LAUNCH_CASES = [
    _ls("unknown-arg", "campaign-warm", "--frobnicate"),
    _ls("undeclared-harness", "campaign-warm", "--harness", "ghost", "--engine", "libfuzzer"),
    _ls("no-declared-harness", "campaign-cold", "--engine", "libfuzzer",
        setup=lambda sb: sb.edit_json("fuzz/state/fuzz-config.json", lambda d: d.update(harnesses=[]))),
    _ls("bad-slot-name", "campaign-warm", "--slot", "Main_1", "--harness", "parser"),
    _ls("slot-too-long", "campaign-warm", "--slot", "a" * 33, "--harness", "parser"),
    _ls("binary-not-executable", "campaign-warm", "--harness", "parser", "--binary", "fuzz/nope"),
    _ls("unsafe-asan-options", "campaign-warm", "--harness", "parser", "--engine", "libfuzzer",
        env={"ASAN_OPTIONS": "detect_leaks=0:abort_on_error=1"}),
    _ls("already-running", "campaign-warm", "--slot", "parser-main", "--harness", "parser",
        "--engine", "libfuzzer", setup=_already_running, live=True),
    _ls("auto-engine-undetectable", "campaign-warm", "--harness", "parser"),
    _ls("bad-engine", "campaign-warm", "--harness", "parser", "--engine", "honggfuzz"),
    _ls("bad-timeout", "campaign-warm", "--harness", "parser", "--engine", "libfuzzer",
        "--timeout-ms", "fast"),
    _ls("timeout-below-floor", "campaign-warm", "--harness", "parser", "--engine", "libfuzzer",
        "--timeout-ms", "50"),
    _ls("aflpp-missing", "campaign-warm", "--slot", "encoder-afl", "--harness", "encoder",
        "--engine", "aflpp"),
    _ls("aflpp-bad-role", "campaign-warm", "--slot", "encoder-afl", "--harness", "encoder",
        "--engine", "aflpp", "--role", "boss", env={"PATH": STUB_AFL_PATH}),
    _ls("aflpp-bad-schedule", "campaign-warm", "--slot", "encoder-afl", "--harness", "encoder",
        "--engine", "aflpp", "--power-schedule", "slow", env={"PATH": STUB_AFL_PATH}),
    _ls("libfuzzer-forks", "campaign-warm", "--slot", "parser-main", "--harness", "parser",
        "--engine", "libfuzzer", "--libfuzzer-forks", "3", setup=_stub_harnesses, reap=True),
    _ls("libfuzzer-single-dicts-process-based", "campaign-warm", "--slot", "p2", "--harness", "parser",
        "--engine", "libfuzzer", "--timeout-ms", "2500", "--corpus", "fuzz/corpus",
        setup=_dicts, env={"FUZZ_FORKS": "0"}, reap=True),
    _ls("libfuzzer-default-harness-dict-string", "campaign-warm", "--engine", "libfuzzer",
        setup=_single_dict_string, env={"FUZZ_FORKS_OVERRIDE": "0"}, reap=True),
    _ls("aflpp-restart-cmplog-dicts", "campaign-warm", "--slot", "encoder-afl", "--harness", "encoder",
        "--engine", "aflpp", "--role", "master", "--power-schedule", "explore",
        "--restart-of", "encoder-afl", setup=_dicts, env={"PATH": STUB_AFL_PATH}, reap=True),
    _ls("aflpp-auto-secondary-process-based", "campaign-warm", "--slot", "parser-s1", "--harness",
        "parser", "--role", "secondary", "--binary", "fuzz/harnesses/parser/harness/parser_fuzzer",
        setup=_dicts, env={"PATH": STUB_AFL_PATH}, reap=True),
    _ls("state-dir-override", "campaign-warm", "--slot", "parser-main", "--harness", "parser",
        "--engine", "libfuzzer", "--libfuzzer-forks", "0",
        setup=lambda sb: (_stub_harnesses(sb),
                          shutil.move(str(sb.path("fuzz/state")), str(sb.path("fuzz/alt-state")))),
        env={"FUZZ_STATE_DIR": "fuzz/alt-state"}, reap=True),
]

CSL = "scripts/check-slot-liveness.sh"


def _csl(name, fixture, *args, setup=None, env=None):
    # FUZZ_FORKS_OVERRIDE=0: the fork count is otherwise capped at nproc-1.
    return Case(f"check-slot-liveness/{name}", fixture, [REAP, *bash(CSL, *args)],
                [REAP, *core("slots", "liveness", *args)], setup=setup,
                env={"FUZZ_FORKS_OVERRIDE": "0", **(env or {})})


def _one_declared_slot_missing(sb):
    _stub_harnesses(sb)
    sb.edit_json("fuzz/state/fuzzers.json", lambda d: d.update(slots=d["slots"][1:]))


def _no_declared_slots(sb):
    _stub_harnesses(sb)
    sb.edit_json("fuzz/state/fuzz-config.json", lambda d: d.pop("fuzzer_slots") and None)


def _slot_options(sb):
    _stub_harnesses(sb)

    def cfg(d):
        d["fuzzer_slots"][0].update(libfuzzer_forks=0, timeout_ms=3000)
    sb.edit_json("fuzz/state/fuzz-config.json", cfg)


LIVENESS_CASES = [
    _csl("relaunch-libfuzzer-afl-missing", "campaign-warm", setup=_stub_harnesses),
    _csl("relaunch-both", "campaign-warm", setup=_stub_harnesses, env={"PATH": STUB_AFL_PATH}),
    _csl("declared-slot-missing-from-manifest", "campaign-warm", setup=_one_declared_slot_missing,
         env={"PATH": STUB_AFL_PATH}),
    _csl("manifest-only-slots", "campaign-warm", setup=_no_declared_slots, env={"PATH": STUB_AFL_PATH}),
    _csl("slot-options", "campaign-warm", setup=_slot_options),
    _csl("state-dir-override", "campaign-warm",
         setup=lambda sb: (_stub_harnesses(sb),
                           shutil.move(str(sb.path("fuzz/state")), str(sb.path("fuzz/alt-state")))),
         env={"FUZZ_STATE_DIR": "fuzz/alt-state"}),
]


# ---------------------------------------------------------------------------
# row 6: extract-cmplog-dict.sh, snapshot-coverage.sh, corpus-quarantine.sh,
#        check-seed-safety.sh, find-delta-targets.sh
# ---------------------------------------------------------------------------

EC = "scripts/extract-cmplog-dict.sh"
AFL_ENC = "fuzz/harnesses/encoder/aflpp-out"


def _ec(name, fixture, *args, setup=None, env=None):
    return Case(f"extract-cmplog-dict/{name}", fixture, bash(EC, *args), core("cmplog", "extract", *args),
                setup=setup, env=env or {})


def _rich_afl(sb):
    """Two AFL++ instances, both cmplog layouts, noisy strings to filter."""
    sb.write(f"{AFL_ENC}/default/fuzzer_stats", "execs_done : 10\n")
    sb.write(f"{AFL_ENC}/default/.cmplog/sub/op-1",
             b"\x00MAGIC\x00\x00\t tab\"q\\u\x00" + b"x" * 70 + b"\x00/usr/lib/libz.so\x00123456789a\x00MAGIC\x00")
    sb.write(f"{AFL_ENC}/default/.cmplog/op-2", b"\x01\x02KEYWORD\x00abc\x00")
    sb.write(f"{AFL_ENC}/default/queue/id:000000,orig:seed", b"QUEUESTR\x00\x00    \x00")
    sb.write(f"{AFL_ENC}/encoder-s1/queue/id:000003", b"SECONDARY\x00")
    sb.write(f"{AFL_ENC}/encoder-s1/cmplog/legacy.bin", b"\xffLEGACY_OP\xff")
    sb.write(f"{AFL_ENC}/not-an-instance/.cmplog/x", b"IGNORED_STR")


def _instance_without_cmplog(sb):
    sb.write("fuzz/harnesses/parser/aflpp-out/default/fuzzer_stats", "execs_done : 10\n")


CMPLOG_CASES = [
    _ec("rich-instances", "campaign-warm", "--harness", "encoder", setup=_rich_afl),
    _ec("rich-root-as-aflpp-out", "campaign-warm", "--aflpp-out", AFL_ENC, "--output", "out.dict",
        setup=_rich_afl),
    _ec("no-cmplog-dirs", "campaign-warm", "--harness", "parser", setup=_instance_without_cmplog),
    _ec("harness-and-aflpp-out", "campaign-warm", "--harness", "parser", "--aflpp-out",
        f"{AFL_ENC}/encoder-afl"),
    _ec("no-declared-harnesses", "campaign-cold",
        setup=lambda sb: sb.edit_json("fuzz/state/fuzz-config.json", lambda d: d.update(harnesses=[]))),
    _ec("from-subdir", "campaign-warm", "--harness", "encoder", "--output", "fuzz/d/enc.dict"),
]
CMPLOG_CASES[-1].cwd = "src"

SC = "scripts/snapshot-coverage.sh"
STUB_LLVM_PATH = f"{TESTS / 'support' / 'stub-llvm'}{os.pathsep}{SUPPORT_BIN}{os.pathsep}{os.environ.get('PATH', '/usr/bin:/bin')}"
_STUB_COV = ('#!/bin/sh\n# test stub coverage binary: one profraw per run\n'
             'f=$(printf %s "$LLVM_PROFILE_FILE" | sed "s/%p/$$/")\necho "run $1" > "$f"\n')


def _sc(name, fixture, *args, setup=None, env=None, cwd=None):
    return Case(f"snapshot-coverage/{name}", fixture, bash(SC, *args), core("coverage", "snapshot", *args),
                setup=setup, env=env or {}, cwd=cwd)


def _stub_cov(sb):
    for p in sb.path("fuzz/harnesses").glob("*/harness/*_fuzzer_cov"):
        sb.write(str(p.relative_to(sb.project)), _STUB_COV, mode=0o755)
    sb.write("fuzz/harnesses/parser/corpus/seed_magic.bin", b"magic")
    sb.write("fuzz/harnesses/parser/corpus/seed_notes.txt", b"notes")


def _cov_dso(sb):
    _stub_cov(sb)
    sb.write("fuzz/lib/libparse.so", b"\x7fELF")
    sb.edit_json("fuzz/state/harnesses.json", lambda d: d["harnesses"][0].update(
        coverage_dso=[str(sb.path("fuzz/lib/libparse.so")), "/nonexistent/lib.so"]))


def _afl_multi(sb):
    sb.write(f"{AFL_ENC}/encoder-s1/fuzzer_stats",
             "execs_done        : 50001\ncorpus_count      : 3\nsaved_crashes     : 1\n"
             "saved_hangs       : 2\nexecs_per_sec     : 10.25\n")
    sb.write(f"{AFL_ENC}/encoder-s1/queue/id:000000", b"q")


def _fork_log(sb):
    sb.write("fuzz/state/fuzzer-parser-main.log",
             "INFO: -fork=2: fuzzing in separate process(s)\nJob 12 exited with exit code 0\n")


def _fork_log_status(sb):
    sb.write("fuzz/state/fuzzer-parser-main.log",
             "INFO: fork_mode\n#1971: cov: 88 ft: 90 corp: 12 exec/s: 450 rss: 40Mb\n"
             "#2400: cov: 91 ft: 95 corp: 13 exec/s: 470 rss: 41Mb\n")


def _no_tracking(sb):
    sb.edit_json("fuzz/state/harnesses.json",
                 lambda d: [h.update(coverage_tracking=False) for h in d["harnesses"]] and None)


def _crash_files_new(sb):
    sb.write("fuzz/crashes/new/parser__aaaabbbbccccdddd.bin", b"x")
    sb.write("fuzz/crashes/new/other__aaaabbbbccccdddd.bin", b"x")


COVERAGE_CASES = [
    _sc("warm-all-no-llvm", "campaign-warm"),
    _sc("warm-parser-stub-llvm", "campaign-warm", "--harness", "parser", setup=_stub_cov,
        env={"PATH": STUB_LLVM_PATH}),
    _sc("warm-parser-dso-samples", "campaign-warm", "--harness", "parser", setup=_cov_dso,
        env={"PATH": STUB_LLVM_PATH, "SNAPSHOT_COVERAGE_MAX_SAMPLES": "3"}),
    _sc("warm-encoder-afl-multi", "campaign-warm", "--harness", "encoder",
        setup=lambda sb: (_stub_cov(sb), _afl_multi(sb)), env={"PATH": STUB_LLVM_PATH}),
    _sc("warm-fork-job-lines", "campaign-warm", "--harness", "parser", setup=_fork_log),
    _sc("warm-fork-status-lines", "campaign-warm", "--harness", "parser", setup=_fork_log_status),
    _sc("warm-no-tracking", "campaign-warm", setup=_no_tracking),
    _sc("cold", "campaign-cold"),
    _sc("crashes", "campaign-crashes", setup=_crash_files_new),
    _sc("unknown-arg", "campaign-warm", "--bogus"),
    _sc("from-subdir", "campaign-plateau", "--harness", "parser", cwd="src"),
]

CQ = "scripts/corpus-quarantine.sh"
_HANG_HARNESS = '#!/bin/sh\ncase "$1" in *hang*) exec sleep 30 ;; *odd*) exit 3 ;; esac\nexit 0\n'


def _cq(name, fixture, *args, setup=None, env=None):
    return Case(f"corpus-quarantine/{name}", fixture, bash(CQ, *args), core("quarantine", "run", *args),
                setup=setup, env=env or {})


def _hang_seed(sb):
    sb.write("fuzz/harnesses/parser/harness/parser_fuzzer", _HANG_HARNESS, mode=0o755)
    sb.write("fuzz/harnesses/parser/corpus-quarantine/seed-hang.bin", b"h")
    sb.write("fuzz/harnesses/parser/corpus-quarantine/seed-odd.bin", b"k")
    sb.write("fuzz/harnesses/parser/corpus-quarantine/seed-ok.bin", b"o")


def _destructive_variants(sb):
    q = "fuzz/harnesses/parser/corpus-quarantine"
    for f in sb.path(q).iterdir():
        f.unlink()
    sb.write(f"{q}/fork-bomb.sh", ":(){ :|:& };:\n")
    sb.write(f"{q}/dd.sh", b"\x00\x01dd if=/dev/zero of=/dev/sda bs=1M\n")
    sb.write(f"{q}/sysrq.txt", "echo b > /proc/sysrq-trigger\n")
    sb.write(f"{q}/rm-quoted.sh", "rm -rf '/tmp/x'\n")         # quoted target: allowed
    sb.write(f"{q}/rm-split.sh", "rm -rf\n/etc\n")            # target on the next line: allowed


QUARANTINE_CASES = [
    _cq("hang-and-odd-exit", "campaign-cold", "--harness", "parser", setup=_hang_seed),
    _cq("destructive-variants", "campaign-cold", "--harness", "parser", setup=_destructive_variants),
    _cq("allow-destructive", "campaign-cold", "--harness", "parser",
        env={"CCFUZZ_ALLOW_DESTRUCTIVE_SEEDS": "1"}),
    _cq("missing-explicit-file", "campaign-cold", "--harness", "parser", "nope.bin",
        "fuzz/harnesses/parser/corpus-quarantine/seed-b.bin"),
    _cq("no-harness-no-current", "campaign-cold"),
]

CSS = "scripts/check-seed-safety.sh"
_SAFE_FILES = ("fuzz/harnesses/parser/corpus-quarantine/seed-a.bin",
               "fuzz/harnesses/parser/corpus-quarantine/seed-destructive.sh")


def _css(name, fixture, *args, setup=None, env=None, stdin=None, cwd=None):
    return Case(f"check-seed-safety/{name}", fixture, bash(CSS, *args), core("quarantine", "safety", *args),
                setup=setup, env=env or {}, stdin=stdin, cwd=cwd)


SAFETY_CASES = [
    _css("files", "campaign-cold", *_SAFE_FILES, "missing.bin"),
    _css("stdin-list", "campaign-cold", stdin="\n".join(_SAFE_FILES) + "\n\n"),
    _css("all-safe", "campaign-cold", _SAFE_FILES[0]),
    _css("override", "campaign-cold", *_SAFE_FILES, env={"CCFUZZ_ALLOW_DESTRUCTIVE_SEEDS": "1"}),
    _css("empty-stdin", "campaign-cold", stdin=""),
    _css("from-subdir", "campaign-cold", "../" + _SAFE_FILES[1], cwd="src"),
]

FD = "scripts/find-delta-targets.sh"


def _git_repo(sb, *, branch="main"):
    sb.write(".gitignore", "fuzz/\n")
    sb.git("init", "-q", "-b", branch)
    sb.git("add", ".gitignore", "src")
    sb.git("commit", "-q", "-m", "base")


def _delta_master(sb):
    _git_repo(sb, branch="master")
    sb.git("checkout", "-q", "-b", "topic")
    sb.write("src/parser.c", sb.path("src/parser.c").read_text() + "/* tail */\n")
    sb.git("commit", "-q", "-am", "tail comment")
    sb.git("rm", "-q", "src/encoder.c")
    sb.git("commit", "-q", "-m", "drop encoder")


def _delta_on_main(sb):
    _git_repo(sb)
    sb.write("src/parser.c", "/* head */\n" + sb.path("src/parser.c").read_text())
    sb.git("commit", "-q", "-am", "head comment")


def _fd(name, fixture, *args, setup=None, env=None, cwd=None):
    return Case(f"find-delta-targets/{name}", fixture, bash(FD, *args), core("delta", "find", *args),
                setup=setup, env=env or {}, cwd=cwd)


DELTA_CASES = [
    _fd("auto-master-deleted-file", "campaign-warm", setup=_delta_master),
    _fd("on-main-head30-fallback", "campaign-warm", setup=_delta_on_main),
    _fd("three-dot-range", "campaign-warm", "--range", "master...topic", setup=_delta_master),
    _fd("bad-tip", "campaign-warm", "--range", "master..nope", setup=_delta_master),
    _fd("empty-base", "campaign-warm", "--range", "..HEAD", setup=_delta_master),
    _fd("quote-in-range", "campaign-warm", "--range", 'master..topic"', setup=_delta_master),
    _fd("unknown-arg", "campaign-warm", "--since", "x"),
    _fd("state-dir-override", "campaign-warm", "--range", "master..topic",
        setup=lambda sb: (_delta_master(sb), shutil.move(str(sb.path("fuzz/state")), str(sb.path("fuzz/alt")))),
        env={"FUZZ_STATE_DIR": "fuzz/alt"}),
    _fd("from-subdir", "campaign-warm", setup=_delta_master, cwd="src"),
]


# ---------------------------------------------------------------------------
# row 7: code-review-run.sh (+ _lib/code_review_prescan.py, sast_scan.py,
# code_review_merge.py). SAST runs against the stub semgrep / codeql in
# tests/support/stub-sast (neither tool is installed here).
# ---------------------------------------------------------------------------

CR = "scripts/code-review-run.sh"
STUB_SAST_PATH = f"{TESTS / 'support' / 'stub-sast'}{os.pathsep}{SUPPORT_BIN}{os.pathsep}{os.environ.get('PATH', '/usr/bin:/bin')}"
_SAST_ENV = {"PATH": STUB_SAST_PATH, "STUB_SEMGREP_LOG": "../semgrep-argv.log"}


def _cr(name, fixture, *args, setup=None, env=None, cwd=None):
    return Case(f"code-review-prescan/{name}", fixture, bash(CR, *args), core("prescan", "run", *args),
                setup=setup, env=env or {}, cwd=cwd)


def _cr_config(block):
    def setup(sb):
        sb.edit_json("fuzz/state/fuzz-config.json", lambda d: d.update(code_review=block))
    return setup


def _cve_contexts(sb):
    snaps = "fuzz/state/snapshots"
    old = sb.write(f"{snaps}/cve-context-1789990000.json", json.dumps(
        {"hotspots": {"by_function": [{"name": "free_chunk"}]}}) + "\n")
    os.utime(old, (sb.now - 600, sb.now - 600))
    sb.write(f"{snaps}/cve-context-1789999000.json", json.dumps({
        "hotspots": {"by_file": [{"path": "src/parser.c"}, {"nopath": 1}],
                     "by_function": [{"name": "parse_exif"}, {"name": ""}]},
        "pattern_frequency": {"oob_read": 3, "integer_overflow": 1}}) + "\n")


def _extra_rule_packs(sb):
    sb.write("rules-extra/plain/r1.yml", "rules: []\n")
    sb.write("rules-extra/dotted/.github/workflows/ci.yml", "on: push\n")
    sb.write("rules-extra/dotted/pack-a/a.yaml", "rules: []\n")
    sb.write("rules-extra/dotted/pack-b/README", "no rules\n")
    sb.write("rules-extra/dotted/top.yml", "rules: []\n")
    sb.write("rules-extra/empty/.keep", "")


def _git_recent(sb):
    """src/ as a git repo with a commit dated (really) yesterday, so git's
    --since=30.days.ago (real clock) sees it whatever the frozen clock says."""
    when = f"@{int(time.time()) - 86400} +0000"
    env = dict(sb.env(), GIT_AUTHOR_NAME="F", GIT_AUTHOR_EMAIL="f@example.invalid",
               GIT_COMMITTER_NAME="F", GIT_COMMITTER_EMAIL="f@example.invalid",
               GIT_AUTHOR_DATE=when, GIT_COMMITTER_DATE=when,
               GIT_CONFIG_NOSYSTEM="1", GIT_CONFIG_GLOBAL=os.devnull)
    src = sb.path("src")
    for args in (["init", "-q"], ["add", "parser.c"], ["commit", "-q", "-m", "x"]):
        subprocess.run(["git", *args], cwd=src, env=env, check=True, capture_output=True)


def _codeql_db(sb):
    sb.write("fuzz/codeql/db/codeql-database.yml", "x: 1\n")


def _rich_source(sb):
    """A second tree exercising the inventory: oracle pairs, lifecycle pairs,
    gates, recursion, a >100 LOC function, excluded dirs and odd extensions."""
    body = "\n".join(f"    x += {i};" for i in range(120))
    sb.write("lib/codec.c", (
        "#include <string.h>\n"
        "static int json_parse(const char *s) {\n    return json_parse(s + 1) + atoi(s);\n}\n"
        "int encode_json(char *out, const char *s) {\n    strcpy(out, s);\n    sprintf(out, s);\n    return 0;\n}\n"
        "int validate_token(const char *t)\n{\n    return system(t);\n}\n"
        "void *ctx_create(void) {\n    return malloc(n * 4 + 1);\n}\n"
        "void ctx_destroy(void *c) {\n    free(c);\n}\n"
        "int parseDoc(int x) {\n    printf(x);\n    for (i = 0; i < len; i++) buf[i] = 0;\n    return 0;\n}\n"
        "int big(int x) {\n" + body + "\n    return x;\n}\n"
        "int unbalanced(void) {\n#if 0\n{\n#endif\n    return 0;\n}\n"
        "typedef int (*fnptr)(int);\n"
        "int proto(int a);\n"))
    sb.write("lib/codec.hpp", "inline int deserialize_blob(int x) { return gets(x); }\n")
    sb.write("lib/tests/t.c", "int test_one(void) { strcpy(a, b); return 0; }\n")
    sb.write("lib/vendor/v.c", "int vend(void) { return 0; }\n")
    sb.write("lib/notes.txt", "int nope(void) { return 0; }\n")
    sb.write("lib/private/p.c", "int private_fn(void) { gets(x); return 0; }\n")


PRESCAN_CASES = [
    _cr("sast-on-stub", "campaign-crashes", "--sast", "on", env=_SAST_ENV),
    _cr("sast-auto-stub-extra-rules", "campaign-crashes", "--sast", "auto", "--sast-rules",
        "rules-extra/plain,rules-extra/dotted,rules-extra/empty,p/trailofbits,https://example.invalid/r.yml,auto,nope/../missing,, ",
        setup=_extra_rule_packs, env=_SAST_ENV),
    _cr("sast-stub-rule-load-errors", "campaign-crashes", env=dict(_SAST_ENV, STUB_SEMGREP_MODE="errors")),
    _cr("sast-stub-all-fail", "campaign-crashes", "--sast-rules", "p/x",
        env=dict(_SAST_ENV, STUB_SEMGREP_MODE="fail")),
    _cr("sast-stub-garbage", "campaign-crashes", env=dict(_SAST_ENV, STUB_SEMGREP_MODE="garbage")),
    _cr("sast-stub-empty", "campaign-crashes", env=dict(_SAST_ENV, STUB_SEMGREP_MODE="empty")),
    _cr("sast-stub-partial-fail", "campaign-crashes", "--sast-rules", "p/bad-pack,rules-extra/plain",
        setup=_extra_rule_packs, env=dict(_SAST_ENV, STUB_SEMGREP_FAIL_ON="bad-pack")),
    _cr("codeql-db-stub", "campaign-crashes", "--codeql-db", "fuzz/codeql/db", setup=_codeql_db,
        env=_SAST_ENV),
    _cr("codeql-db-stub-fail", "campaign-crashes", "--codeql-db", "fuzz/codeql/db", setup=_codeql_db,
        env=dict(_SAST_ENV, STUB_CODEQL_MODE="fail")),
    _cr("codeql-db-missing", "campaign-crashes", "--codeql-db", "fuzz/codeql/nope", env=_SAST_ENV),
    _cr("config-codeql-db", "campaign-crashes",
        setup=lambda sb: (_codeql_db(sb), _cr_config({"sast": {"codeql_db": "fuzz/codeql/db"}})(sb)),
        env=_SAST_ENV),
    _cr("config-defaults", "campaign-crashes",
        setup=_cr_config({"scan_paths": ["src"], "max_functions_to_review": 2,
                          "excluded_paths": ["gen/", "old/"], "sast": {"mode": "off"}})),
    _cr("config-sast-bool-false", "campaign-crashes",
        setup=_cr_config({"scan_paths": "src", "sast": False}), env=_SAST_ENV),
    _cr("config-sast-bool-true", "campaign-crashes", setup=_cr_config({"sast": True}), env=_SAST_ENV),
    _cr("config-sast-enabled-false", "campaign-crashes",
        setup=_cr_config({"sast": {"enabled": False}}), env=_SAST_ENV),
    _cr("config-unparseable", "campaign-crashes", "--no-sast",
        setup=lambda sb: sb.write("fuzz/state/fuzz-config.json", "{not json\n")),
    _cr("cli-overrides-config", "campaign-crashes", "--target-root", "src", "--max-functions", "1",
        "--excluded-paths", "x/", "--sast", "off",
        setup=_cr_config({"scan_paths": ["nowhere"], "max_functions_to_review": 9, "sast": {"mode": "on"}})),
    _cr("cve-context-latest", "campaign-crashes", "--no-sast", setup=_cve_contexts),
    _cr("cve-context-skipped", "campaign-crashes", "--no-sast", "--no-cve-context", setup=_cve_contexts),
    _cr("git-recently-changed", "campaign-crashes", "--no-sast", setup=_git_recent),
    _cr("rich-inventory", "campaign-crashes", "--target-root", "lib", "--no-sast", "--excluded-paths",
        "private", setup=_rich_source),
    _cr("rich-sweep-windows", "campaign-crashes", "--target-root", "lib", "--sweep", "--batch-size", "3",
        "--max-functions", "2", "--no-sast", setup=_rich_source),
    _cr("max-all", "campaign-crashes", "--max-functions", "all", "--no-sast"),
    _cr("max-zero", "campaign-crashes", "--max-functions", "0", "--no-sast"),
    _cr("max-bad", "campaign-crashes", "--max-functions", "lots", "--no-sast"),
    _cr("max-negative", "campaign-crashes", "--max-functions", "-3", "--no-sast"),
    _cr("empty-tree", "campaign-crashes", "--target-root", "empty", "--no-sast",
        setup=lambda sb: sb.path("empty").mkdir()),
    _cr("target-root-missing", "campaign-crashes", "--target-root", "nope", "--no-sast"),
    _cr("no-target-source", "campaign-cold", "--no-sast",
        setup=lambda sb: (sb.edit_json("fuzz/state/harness-built.json", lambda d: d.pop("target_source")))),
    _cr("target-source-is-dir", "campaign-cold", "--no-sast",
        setup=lambda sb: sb.edit_json("fuzz/state/harness-built.json", lambda d: d.update(target_source="src"))),
    _cr("from-subdir", "campaign-crashes", "--no-sast", cwd="src"),
    _cr("state-dir-override", "campaign-crashes", "--no-sast",
        setup=lambda sb: shutil.move(str(sb.path("fuzz/state")), str(sb.path("alt-state"))),
        env={"FUZZ_STATE_DIR": "alt-state"}),
    Case("code-review-prescan/help", "campaign-cold", bash(CR, "--help"), None),
]

# _lib/code_review_prescan.py and _lib/sast_scan.py are gone (their only
# caller was code-review-run.sh); these goldens were recorded from them and the
# core CLI is now both sides of the case.


def _lib(name, verb, *args, setup=None, env=None):
    return Case(name, "campaign-crashes", core("prescan", verb, *args), core("prescan", verb, *args),
                setup=setup, env=env or {})


LIB_PRESCAN_CASES = [
    _lib("code-review-prescan/lib-direct", "scan", "--target-root", "src", "--out", "out/p.json",
         "--sast", "on", "--sast-timeout", "8", env=_SAST_ENV),
    _lib("code-review-prescan/lib-bad-root", "scan", "--target-root", "nope", "--out", "p.json"),
    _lib("sast-scan/json", "sast", "--target-root", "src", "--rules", "rules-extra/plain,p/pack",
         "--excluded-paths", "a/,/b/,", "--json", "--timeout", "40", setup=_extra_rule_packs, env=_SAST_ENV),
    _lib("sast-scan/text", "sast", "--target-root", "src", "--rules", "rules-extra/plain",
         setup=_extra_rule_packs, env=_SAST_ENV),
    _lib("sast-scan/off", "sast", "--target-root", "src", "--mode", "off", "--json"),
    _lib("sast-scan/only-auto", "sast", "--target-root", "src", "--rules", "auto,nope", "--json", env=_SAST_ENV),
    _lib("sast-scan/no-rules", "sast", "--target-root", "src", "--json", env=_SAST_ENV),
]


# merge-code-review: window partials -> canonical snapshot + markdown.
SNAP = "fuzz/state/snapshots"


def _cr_finding(i, **kw):
    f = {"cr_hash": f"h{i:02d}", "id": f"w{i}", "status": "candidate", "file": f"src/f{i % 3}.c",
         "function": f"fn{i}", "line_range": [10 + i, 20 + i], "pattern": "oob_read",
         "confidence": ("high", "medium", "low")[i % 3], "evidence": f"evidence {i}",
         "tier_classified": "sonnet"}
    f.update(kw)
    return f


def _merge_inputs(sb, *, n_extra=0, sweep=False, reviewed=(3, 2)):
    sb.write(f"{SNAP}/code-review-prescan-1789999000.json", json.dumps({
        "schema": "code-review-prescan/v1", "ts": 1789999000, "target_root": "src",
        "scope": {"files_scanned": 4, "functions_inventoried": 5, "loc_total": 321,
                  "mode": "sweep" if sweep else "capped", "excluded_paths": ["tests/"]},
        "top_candidates": []}) + "\n")
    w1 = {"schema": "code-review/v1", "ts": 1789999100, "target": "",
          "scope": {"candidates_reviewed": reviewed[0], "files_scanned": 99},
          "tiers_run": ["sonnet", "prescan"], "model_costs": {"sonnet_tokens": 100, "note": "x"},
          "revisit_passes": [{"pass": 1}],
          "focus_areas": [{"rank": 2, "scope": "parse_*", "rationale": "r1", "fuzzing_recommendation": "fr1"},
                          {"rank": 1, "scope": "exif", "rationale": "r2"}],
          "findings": [_cr_finding(1), _cr_finding(2, status="dismissed"),
                       _cr_finding(3, oracle_kind="auth", trust_boundary_crossed="user->admin",
                                   precondition="login", exploitability_hint="easy",
                                   fuzzing_recommendation="seed tokens", needs_deep_pass=True,
                                   deep_pass_question="is it reachable?"),
                       {"id": "nohash", "confidence": "high", "pattern": "p", "file": "x.c",
                        "line_start": 7}]}
    w2 = {"schema": "code-review/v1", "ts": 1789999200, "target": "libfoo",
          "scope": {"candidates_reviewed": reviewed[1]}, "tiers_run": ["opus"],
          "model_costs": {"sonnet_tokens": 50, "opus_tokens": 7},
          "focus_areas": [{"rank": 1, "scope": "exif", "rationale": "dup"},
                          {"scope": "crc", "rationale": "r3"}],
          "findings": [_cr_finding(2, status="confirmed", tier_classified="opus"),
                       _cr_finding(1, status="candidate"),
                       *[_cr_finding(10 + i, confidence="high") for i in range(n_extra)]]}
    sb.write(f"{SNAP}/code-review-1789999100-w01.json", json.dumps(w1) + "\n")
    sb.write(f"{SNAP}/code-review-1789999100-w02.json", json.dumps(w2) + "\n")


_MERGE_ARGS = ("--prescan", f"{SNAP}/code-review-prescan-1789999000.json",
               "--out", f"{SNAP}/code-review-1789999100.json", "--md", "fuzz/state/code-review.md")
_PARTS = (f"{SNAP}/code-review-1789999100-w01.json", f"{SNAP}/code-review-1789999100-w02.json")


def _merge(name, *args, setup=_merge_inputs, fixture="campaign-crashes"):
    return Case(f"code-review-merge/{name}", fixture, bash(CR, "merge-code-review", *args),
                core("prescan", "merge", *args), setup=setup)


MERGE_CASES = [
    _merge("capped-two-windows", *_MERGE_ARGS, "--target", "tgt", *_PARTS),
    _merge("target-from-partial", *_MERGE_ARGS, *_PARTS),
    _merge("sweep-complete", *_MERGE_ARGS, *_PARTS, setup=lambda sb: _merge_inputs(sb, sweep=True)),
    _merge("sweep-incomplete-many-findings", *_MERGE_ARGS, *_PARTS,
           setup=lambda sb: _merge_inputs(sb, sweep=True, n_extra=21, reviewed=(1, 1))),
    _merge("single-empty-partial", *_MERGE_ARGS, f"{SNAP}/w.json",
           setup=lambda sb: (_merge_inputs(sb), sb.write(f"{SNAP}/w.json", "{}\n"))),
    _merge("bad-prescan", "--prescan", "nope.json", "--out", "o.json", "--md", "o.md", *_PARTS),
    _merge("bad-partial", *_MERGE_ARGS, _PARTS[0], "missing.json"),
    _merge("no-partials", *_MERGE_ARGS),
]


# ---------------------------------------------------------------------------
# row 8: findings.sh (+ _lib/findings_ops.py). The campaign-crashes stub
# harnesses "crash" on inputs containing CRASH; setups swap in other stubs.
# ---------------------------------------------------------------------------

FS = "scripts/findings.sh"
HB = "fuzz/harnesses/parser/harness/parser_fuzzer"
VB = "fuzz/harnesses/parser/harness/parser_fuzzer_verify"
LEDGER = "fuzz/state/findings.jsonl"
NEW_HASH = "abcdef0123456789"


def _fs(name, *args, fixture="campaign-crashes", setup=None, env=None, cwd=None, core_args=True):
    return Case(f"findings/{name}", fixture, bash(FS, *args),
                core("findings", *args) if core_args else None, setup=setup, env=env or {}, cwd=cwd)


def _stub_bin(rel, body):
    def setup(sb):
        sb.write(rel, "#!/bin/sh\n" + body, mode=0o755)
    return setup


# Harness stub bodies (the input path is $1).
_ASAN = ('echo "==1==ERROR: AddressSanitizer: heap-buffer-overflow" >&2\n'
         'echo "SUMMARY: AddressSanitizer: heap-buffer-overflow src/parser.c:14:5 in parse_chunk" >&2\nexit 77\n')
_CLEAN = "echo clean run\nexit 0\n"
_KILLED = "kill -KILL $$\n"  # rc 137; no core dump (whose timeout(1) note is host-dependent)
_DEADLY = 'echo "==1== ERROR: libFuzzer: deadly signal" >&2\nexit 1\n'
_ORACLE = 'echo "CCFUZZ_ORACLE_VIOLATION property=roundtrip" >&2\nexit 1\n'
_UBSAN = 'echo "src/parser.c:12:20: runtime error: left shift of 255 by 8 places" >&2\nexit 1\n'
_REAL_ONLY = 'if grep -q REAL "$1"; then\n' + _ASAN.replace("\n", "\n  ") + 'fi\nexit 0\n'


def _nth_crash(crash_runs):
    """Crash only on the given (1-based) runs; a counter file under $TMPDIR."""
    cond = " || ".join(f'[ "$n" -eq {k} ]' for k in crash_runs) or "false"
    return ('n=$(cat "$TMPDIR/runs" 2>/dev/null || echo 0); n=$((n+1)); echo "$n" > "$TMPDIR/runs"\n'
            f'if {cond}; then\n  {_ASAN.replace(chr(10), chr(10) + "  ")}fi\nexit 0\n')


def _repro(rel="fuzz/crashes/known/f003/repro.bin", data=b"eXIf\x01\x00\x00\x00CRASH REAL"):
    def setup(sb):
        sb.write(rel, data)
    return setup


def _chain(*fns):
    def setup(sb):
        for f in fns:
            f(sb)
    return setup


REPRO = "fuzz/crashes/known/f003/repro.bin"
_ADD = ("add", NEW_HASH, "heap-buffer-overflow", "parse_chunk@src/parser.c:14", "likely",
        "chunk length not bounded", REPRO)
_ADDX = _ADD + ("==1==ERROR: AddressSanitizer: heap-buffer-overflow",)


def _ids_with_octal_trap(sb):
    _jsonl_append(sb, LEDGER,
                  '{"schema": "finding/v2", "id": "f009", "stack_hash": "9999999999999999", "status": "candidate"}',
                  {"schema": "finding/v2", "id": "f020", "stack_hash": "2020202020202020", "status": "stale"})


def _spaced_line(sb):
    _jsonl_append(sb, LEDGER, '{"schema": "finding/v2", "id": "f003", "stack_hash": "3333333333333333", '
                              '"status": "candidate", "category": "oom", "location": "a@b.c:1", '
                              '"first_seen": "2026-09-21T10:00:00Z", "harnesses": ["parser"]}')


def _junk_line(sb):
    _jsonl_append(sb, LEDGER, "not json at all")


def _dedup_high(sb):
    lines = sb.path(LEDGER).read_text().splitlines()
    d = json.loads(lines[1])
    d["dedup_count"] = 4
    lines[1] = json.dumps(d, separators=(",", ":"))
    sb.write(LEDGER, "\n".join(lines) + "\n")


def _second_harness(sb):
    def cfg(d):
        d["harnesses"].append({"name": "encoder", "entry_function": "encode"})
    sb.edit_json("fuzz/state/fuzz-config.json", cfg)


def _verify_findings(sb):
    """f001: reproduces on both binaries; f002: harness only; f003: stale;
    f004: reproducer missing (f001/f002 in the fixture, 3/4 added)."""
    _stub_bin(VB, _REAL_ONLY)(sb)
    sb.write("fuzz/crashes/known/f001/repro.bin", b"CRASH REAL")
    sb.write("fuzz/crashes/known/f003/repro.bin", b"benign")
    _jsonl_append(sb, LEDGER,
                  {"schema": "finding/v2", "id": "f003", "stack_hash": "3333333333333333",
                   "reproducer": "fuzz/crashes/known/f003/repro.bin", "status": "candidate"},
                  {"schema": "finding/v2", "id": "f004", "stack_hash": "4444444444444444",
                   "reproducer": "fuzz/crashes/known/f004/repro.bin", "status": "candidate"},
                  "", {"schema": "finding/v2", "stack_hash": "5555555555555555"})


def _stale_dest_exists(sb):
    sb.write("fuzz/crashes/stale/f002/repro.bin", b"older stale copy")


def _promote_files(sb, lines=20, tools=3):
    sb.write("fuzz/findings/f002/repro/driver.c", "int main(void) { return 0; }\n")
    body = ["#!/bin/sh", "set -e"]
    names = ["clang", "gcc", "objdump", "readelf", "nm", "strace", "ltrace", "gdb", "python3"]
    body += [f"{names[i]} --version | head -1" for i in range(tools)]
    body += [f"# filler {i}" for i in range(max(0, lines - len(body)))]
    sb.write("fuzz/findings/f002/repro/verify.sh", "\n".join(body) + "\n", mode=0o755)


_PROMOTE = ("promote", "f002", "--driver", "fuzz/findings/f002/repro/driver.c",
            "--verifier", "fuzz/findings/f002/repro/verify.sh", "--boundary", "confidentiality",
            "--precondition", "attacker file", "--projected", "demonstrated")


def _promote_cfg(sb):
    _promote_files(sb, lines=30, tools=4)
    sb.edit_json("fuzz/state/fuzz-config.json", lambda d: d.update(
        poc={"verifier_complexity_soft_max_lines": 10, "verifier_complexity_soft_max_tools": 2}))


def _status(fid, status):
    def setup(sb):
        lines = sb.path(LEDGER).read_text().splitlines()
        out = []
        for ln in lines:
            d = json.loads(ln)
            if d.get("id") == fid:
                d["status"] = status
            out.append(json.dumps(d, separators=(",", ":")))
        sb.write(LEDGER, "\n".join(out) + "\n")
    return setup


def _remove_dirs(sb):
    sb.write("fuzz/findings/f001/report.md", "# f001\n")


def _cr_snapshot(rel="fuzz/state/snapshots/code-review-1789999000.json", mtime_ago=60, findings=None):
    if findings is None:
        findings = [
            {"id": "cr001", "cr_hash": "c0ffee01", "confidence": "high", "pattern": "oob_read",
             "function": "parse_chunk", "file": "src/parser.c", "line_range": [8, 19],
             "evidence": "len unchecked", "oracle_kind": "memory"},
            {"id": "cr002", "cr_hash": "c0ffee02", "confidence": "medium", "pattern": "auth_bypass",
             "function": "check_token", "file": "src/auth.c", "line_range": [],
             "evidence": "", "oracle_kind": "auth", "trust_boundary_crossed": "user->admin",
             "precondition": "valid session", "needs_deep_pass": True},
            {"id": "cr003", "cr_hash": "c0ffee03", "confidence": "low", "pattern": "oob_read"},
            {"id": "cr004", "confidence": "high", "pattern": "uaf"},
            {"id": "cr005", "cr_hash": "c0ffee05", "confidence": "high", "pattern": "mystery_pattern",
             "function": "f", "file": "g.c", "line_range": [3]},
        ]

    def setup(sb):
        p = sb.write(rel, json.dumps({"schema": "code-review/v1", "ts": 1, "findings": findings}) + "\n")
        os.utime(p, (sb.now - mtime_ago, sb.now - mtime_ago))
    return setup


def _cr_two_snapshots(sb):
    _cr_snapshot("fuzz/state/snapshots/code-review-1789990000.json", mtime_ago=900,
                 findings=[{"cr_hash": "01d", "confidence": "high", "pattern": "oob_write"}])(sb)
    _cr_snapshot()(sb)


def _cr_reimport(sb):
    _cr_snapshot()(sb)
    _jsonl_append(sb, LEDGER, {"schema": "finding/v2", "id": "f007", "status": "candidate",
                               "source": "code_review", "cr_ref": "c0ffee01"})


FINDINGS_CASES = [
    # help / dispatch
    _fs("help", "help"),
    _fs("no-args", core_args=False),
    _fs("unknown-subcommand", "frobnicate", core_args=False),
    _fs("help-creates-ledger", "help", fixture="campaign-cold"),
    # count / list / find-by-hash
    _fs("count", "count"),
    _fs("count-spaced", "count", setup=_spaced_line),
    _fs("count-empty", "count", fixture="campaign-cold"),
    _fs("list", "list", setup=_junk_line),
    _fs("find-by-hash-hit", "find-by-hash", "0f1e2d3c4b5a6978"),
    _fs("find-by-hash-miss", "find-by-hash", "ffffffffffffffff"),
    _fs("find-by-hash-spaced", "find-by-hash", "3333333333333333", setup=_spaced_line),
    _fs("find-by-hash-no-arg", "find-by-hash"),
    # add: argument validation
    _fs("add-usage", "add", NEW_HASH, "oom"),
    _fs("add-flag-style", "add", "--id", "f009", "--category", "oom", "--location", "x"),
    _fs("add-bad-hash", "add", "xyz", "oom", "l", "likely", "r", REPRO),
    _fs("add-bad-category", "add", NEW_HASH, "bad-thing", "l", "likely", "r", REPRO),
    _fs("add-bad-exploitability", "add", NEW_HASH, "oom", "l", "sure", "r", REPRO),
    _fs("add-duplicate", "add", "0f1e2d3c4b5a6978", "oom", "l", "likely", "r", REPRO),
    _fs("add-reproducer-missing", *_ADD),
    # add: verification
    _fs("add-stage2-ok", *_ADDX, setup=_repro()),
    _fs("add-stage2-ok-no-sidecar-dir", *_ADD[:-1], "fuzz/crashes/new/parser__deadbeefcafe0001.bin",
        setup=_stub_bin(VB, _ASAN)),
    _fs("add-stage1-none", *_ADD, setup=_chain(_repro(data=b"benign"))),
    _fs("add-stage1-one-of-three", *_ADD, setup=_chain(_repro(), _stub_bin(HB, _nth_crash([1])))),
    _fs("add-stage1-two-of-three", *_ADD, setup=_chain(_repro(), _stub_bin(HB, _nth_crash([1, 3])))),
    _fs("add-stage2-harness-artifact", *_ADD, setup=_chain(_repro(data=b"CRASH only"), _stub_bin(VB, _REAL_ONLY))),
    _fs("add-stage2-one-of-three", *_ADD, setup=_chain(_repro(), _stub_bin(VB, _nth_crash([2])))),
    _fs("add-no-verify-binary", *_ADD, setup=_chain(
        _repro(), lambda sb: sb.edit_json("fuzz/state/harnesses.json",
                                          lambda d: d["harnesses"][0].update(verify_binary=None)),
        lambda sb: sb.edit_json("fuzz/state/harness-built.json", lambda d: d.update(verify_binary=None)))),
    _fs("add-verify-binary-not-executable", *_ADD, setup=_chain(
        _repro(), lambda sb: sb.path(VB).chmod(0o644))),
    _fs("add-verify-binary-from-mirror", *_ADD, setup=_chain(
        _repro(), lambda sb: sb.edit_json("fuzz/state/harnesses.json",
                                          lambda d: d["harnesses"][0].pop("verify_binary")))),
    _fs("add-no-harness-binary", *_ADD, setup=_chain(
        _repro(), lambda sb: sb.edit_json("fuzz/state/harnesses.json",
                                          lambda d: d["harnesses"][0].update(harness_binary=None)),
        lambda sb: sb.edit_json("fuzz/state/harness-built.json", lambda d: d.pop("harness_binary")))),
    _fs("add-harness-binary-from-mirror", *_ADD, setup=_chain(
        _repro(), lambda sb: sb.edit_json("fuzz/state/harnesses.json",
                                          lambda d: d["harnesses"][0].update(harness_binary=None)))),
    _fs("add-harness-binary-not-executable", *_ADD, setup=_chain(_repro(), lambda sb: sb.path(HB).chmod(0o644))),
    _fs("add-signal-rc", *_ADD, setup=_chain(_repro(), _stub_bin(HB, _KILLED), _stub_bin(VB, _KILLED))),
    _fs("add-deadly-signal", *_ADD, setup=_chain(_repro(), _stub_bin(HB, _DEADLY), _stub_bin(VB, _DEADLY))),
    _fs("add-oracle-marker", *_ADD, setup=_chain(_repro(), _stub_bin(HB, _ORACLE), _stub_bin(VB, _ORACLE)),
        env={"ORACLE_TYPE": "roundtrip",
             "DIVERGENCE": '{"property_id":"rt1","comparison":"eq","observed":"a","expected":"b"}'}),
    _fs("add-ubsan-runtime-error", "add", NEW_HASH, "ubsan-shift-exponent", "p@src/parser.c:12", "medium", "shift",
        REPRO, setup=_chain(_repro(), _stub_bin(HB, _UBSAN), _stub_bin(VB, _UBSAN))),
    _fs("add-repro-binary-kept", *_ADD, setup=_chain(
        _repro(), lambda sb: sb.write("fuzz/crashes/known/f003/repro.binary", b"older binary"))),
    # add: skip-verify / record shape
    _fs("add-skip-verify", *_ADDX, env={"FINDINGS_SKIP_VERIFY": "1"}),
    _fs("add-skip-verify-sidecar", *_ADD, setup=_repro(), env={"FINDINGS_SKIP_VERIFY": "1"}),
    _fs("add-oracle-malformed-divergence", *_ADD[:2], "invariant-violation", *_ADD[3:],
        env={"FINDINGS_SKIP_VERIFY": "1", "ORACLE_TYPE": "invariant", "DIVERGENCE": "{not json"}),
    _fs("add-oracle-type-crash", *_ADD, env={"FINDINGS_SKIP_VERIFY": "1", "ORACLE_TYPE": "crash",
                                             "DIVERGENCE": '{"x":1}'}),
    _fs("add-harness-env", *_ADD, setup=_chain(_second_harness, _repro("fuzz/crashes/known/f003/repro.bin")),
        env={"HARNESS": "encoder", "FINDINGS_SKIP_VERIFY": "1"}),
    _fs("add-harness-env-verify-fallback", *_ADD, setup=_chain(_second_harness, _repro()),
        env={"HARNESS": "encoder"}),
    _fs("add-id-octal-trap", *_ADD, setup=_ids_with_octal_trap, env={"FINDINGS_SKIP_VERIFY": "1"}),
    _fs("add-empty-ledger", *_ADD, fixture="campaign-cold", env={"FINDINGS_SKIP_VERIFY": "1"}),
    _fs("add-state-dir-override", *_ADD, setup=_chain(
        _repro(), lambda sb: shutil.move(str(sb.path("fuzz/state")), str(sb.path("alt-state")))),
        env={"FUZZ_STATE_DIR": "alt-state"}),
    _fs("add-from-subdir", *_ADD[:-1], "../" + REPRO, setup=_repro(), cwd="src",
        env={"FINDINGS_SKIP_VERIFY": "1"}),
    # dedup
    _fs("dedup-missing", "dedup", "ffffffffffffffff"),
    _fs("dedup-no-arg", "dedup"),
    _fs("dedup-ok", "dedup", "0f1e2d3c4b5a6978", setup=_junk_line),
    _fs("dedup-threshold-default", "dedup", "0f1e2d3c4b5a6978", setup=_dedup_high),
    _fs("dedup-threshold-env", "dedup", "a1b2c3d4e5f60718", env={"FINDINGS_DEDUP_THRESHOLD": "4"}),
    _fs("dedup-new-harness", "dedup", "a1b2c3d4e5f60718", setup=_second_harness, env={"HARNESS": "encoder"}),
    _fs("dedup-spaced", "dedup", "3333333333333333", setup=_spaced_line),
    # add-harness
    _fs("add-harness-missing-id", "add-harness", "f099", "encoder"),
    _fs("add-harness-no-args", "add-harness"),
    _fs("add-harness-no-harness-arg", "add-harness", "f001"),
    _fs("add-harness-new", "add-harness", "f002", "encoder", setup=_junk_line),
    _fs("add-harness-noop", "add-harness", "f001", "parser"),
    _fs("add-harness-no-known-dir", "add-harness", "f003", "encoder", setup=_spaced_line),
    # verify
    _fs("verify-all", "verify", setup=_verify_findings),
    _fs("verify-one", "verify", "f002", setup=_verify_findings),
    _fs("verify-no-stage2", "verify", setup=_chain(
        _verify_findings, lambda sb: sb.edit_json("fuzz/state/harness-built.json",
                                                  lambda d: d.update(verify_binary="")))),
    _fs("verify-no-harness-binary", "verify",
        setup=lambda sb: sb.edit_json("fuzz/state/harness-built.json", lambda d: d.pop("harness_binary"))),
    _fs("verify-deadly-signal", "verify", "f001",
        setup=_chain(_stub_bin(HB, _DEADLY), _stub_bin(VB, _ORACLE))),
    # stale-mark
    _fs("stale-mark-missing", "stale-mark", "f099"),
    _fs("stale-mark-no-arg", "stale-mark"),
    _fs("stale-mark-ok", "stale-mark", "f002", setup=_junk_line),
    _fs("stale-mark-dest-exists", "stale-mark", "f002", setup=_stale_dest_exists),
    # list-candidates
    _fs("list-candidates", "list-candidates", setup=_chain(_spaced_line, _junk_line)),
    _fs("list-candidates-empty", "list-candidates", fixture="campaign-cold"),
    # promote
    _fs("promote-no-id", "promote"),
    _fs("promote-unknown-flag", "promote", "f002", "--driver", "x", "--bogus", "y"),
    _fs("promote-missing-fields", "promote", "f002", "--driver", "d.c"),
    _fs("promote-missing-all", "promote", "f002"),
    _fs("promote-driver-missing", *_PROMOTE[:3], "nope.c", *_PROMOTE[4:], setup=_promote_files),
    _fs("promote-verifier-missing", *_PROMOTE[:5], "nope.sh", *_PROMOTE[6:], setup=_promote_files),
    _fs("promote-no-such-id", "promote", "f099", *_PROMOTE[2:], setup=_promote_files),
    _fs("promote-stale-refused", *_PROMOTE, setup=_chain(_promote_files, _status("f002", "stale"))),
    _fs("promote-no-status", *_PROMOTE, setup=_chain(_promote_files, _status("f002", ""))),
    _fs("promote-already-finding", "promote", "f001", *_PROMOTE[2:], setup=_promote_files),
    _fs("promote-ok", *_PROMOTE, setup=_chain(_promote_files, _junk_line)),
    _fs("promote-soft-warnings", *_PROMOTE, setup=lambda sb: _promote_files(sb, lines=240, tools=9)),
    _fs("promote-config-thresholds", *_PROMOTE, setup=_promote_cfg),
    # remove
    _fs("remove-missing", "remove", "f099"),
    _fs("remove-no-arg", "remove"),
    _fs("remove-ok", "remove", "f001", setup=_remove_dirs),
    _fs("remove-no-dirs", "remove", "f003", setup=_spaced_line),
    # drop
    _fs("drop-usage", "drop", "x", "artifact_filter"),
    _fs("drop-bad-stage", "drop", "fuzz/crashes/new/parser__deadbeefcafe0001.bin", "vibes", "meh"),
    _fs("drop-principle-required", "drop", "fuzz/crashes/new/parser__deadbeefcafe0001.bin",
        "artifact_filter", "harness bug"),
    _fs("drop-principle-invalid", "drop", "fuzz/crashes/new/parser__deadbeefcafe0001.bin",
        "artifact_filter", "harness bug", "--principle", "vibes"),
    _fs("drop-artifact-filter", "drop", "fuzz/crashes/new/parser__deadbeefcafe0001.bin",
        "artifact_filter", "harness frees the buffer", "--principle", "harness_correctness",
        "--evidence", "harness.c:12 double free"),
    _fs("drop-replay-missing-file", "drop", "fuzz/crashes/new/gone.bin", "deterministic_replay", "0/3 crashed"),
    _fs("drop-realistic", "drop", "fuzz/crashes/new/parser__deadbeefcafe0002.bin",
        "target_realistic_reproducer", "needs a debug-only API", "--principle", "api_contract"),
    _fs("drop-unknown-flag", "drop", "x", "deterministic_replay", "r", "--why", "z"),
    # import-cr
    _fs("import-cr-no-snapshot", "import-cr"),
    _fs("import-cr-not-found", "import-cr", "fuzz/state/snapshots/nope.json"),
    _fs("import-cr-latest", "import-cr", setup=_cr_two_snapshots),
    _fs("import-cr-explicit", "import-cr", "fuzz/state/snapshots/code-review-1789990000.json",
        setup=_cr_two_snapshots),
    _fs("import-cr-reimport", "import-cr", setup=_cr_reimport, env={"HARNESS": "encoder"}),
    _fs("import-cr-malformed", "import-cr", "bad.json",
        setup=lambda sb: sb.write("bad.json", "{not json\n")),
    _fs("import-cr-no-harness", "import-cr", fixture="campaign-cold",
        setup=_chain(_cr_snapshot(), lambda sb: sb.edit_json("fuzz/state/fuzz-config.json",
                                                              lambda d: d.update(harnesses=[])))),
]

ROW1_CASES = CONFIG_CASES + ENUMS_CASES
ROW2_CASES = VALIDATE_CASES
ROW3_CASES = YOLO_CASES + ROUNDUP_CASES + CEILING_CASES + DERIVE_CASES + UPDATE_CASES
ROW4_CASES = CLASSIFY_CASES + DETECT_CASES
ROW5_CASES = LAUNCH_CASES + LIVENESS_CASES
ROW6_CASES = CMPLOG_CASES + COVERAGE_CASES + QUARANTINE_CASES + SAFETY_CASES + DELTA_CASES
ROW7_CASES = PRESCAN_CASES + LIB_PRESCAN_CASES + MERGE_CASES
ROW8_CASES = FINDINGS_CASES
ALL_CASES = (ROW1_CASES + ROW2_CASES + ROW3_CASES + ROW4_CASES + ROW5_CASES + ROW6_CASES
             + ROW7_CASES + ROW8_CASES)
