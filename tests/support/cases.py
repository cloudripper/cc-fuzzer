"""Shared golden cases for the §2 ports (UPDATE_ROADMAP.md table rows 1-6).

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
    """Crash-like files in every engine location detect-crashes.sh scans."""
    real = sb.now
    lf = "fuzz/harnesses/parser/.libfuzzer-cwd"
    sb.write(f"{lf}/crash-aaa", b"CRASH-A payload")
    sb.write(f"{lf}/leak-bbb", b"leak payload")
    sb.write("crash-at-root", b"unattributed")
    sb.write("fuzz/harnesses/encoder/aflpp-out/default/crashes/id:000000,sig:11", b"afl crash")
    # identical to a known finding's repro -> skipped
    sb.write(f"{lf}/timeout-ccc", sb.path("fuzz/crashes/known/f001/repro.bin").read_bytes())
    # already queued -> skipped
    dup = b"already queued"
    sb.write(f"{lf}/oom-ddd", dup)
    sb.write(f"fuzz/crashes/new/parser__{_sha(dup)[:16]}.bin", dup)
    # too old (10 min) and too deep (depth 7) -> skipped
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

ROW1_CASES = CONFIG_CASES + ENUMS_CASES
ROW2_CASES = VALIDATE_CASES
ROW3_CASES = YOLO_CASES + ROUNDUP_CASES + CEILING_CASES + DERIVE_CASES + UPDATE_CASES
ROW4_CASES = CLASSIFY_CASES + DETECT_CASES
ROW5_CASES = LAUNCH_CASES + LIVENESS_CASES
ALL_CASES = ROW1_CASES + ROW2_CASES + ROW3_CASES + ROW4_CASES + ROW5_CASES
