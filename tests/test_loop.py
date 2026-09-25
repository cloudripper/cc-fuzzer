"""UPDATE_ROADMAP.md §7: one tick, and no scheduler in the core.

The plugin drives the loop by re-firing itself through ScheduleWakeup. A
container has its own loop and must not need one. So step() advances exactly
one tick and returns; a `wait` carries a hint and the CALLER decides what to
do about it.

The other half of §7 is accounting: the orchestrator was never obliged to
report its own spend, so `cost_cap` was a declaration. A runner returns real
token counts and the driver writes them to the ledger, which makes the cap a
measurement.
"""
from __future__ import annotations

import json
import os
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path

from cc_fuzzer_core import ledger, loop
from cc_fuzzer_core.paths import campaign as _campaign
from tests.support.golden import FIXTURES, REPO, core


class StubRunner:
    """What a host supplies: it calls the model and reports what that cost."""

    def __init__(self, text: str, tokens_in: int = 12000, tokens_out: int = 800):
        self.text, self.tokens_in, self.tokens_out = text, tokens_in, tokens_out
        self.calls = []

    def run(self, agent, inputs, *, model="", budget=None):
        self.calls.append({"agent": agent, "model": model, "inputs": inputs})
        return loop.AgentResult(self.text, tokens_in=self.tokens_in,
                                tokens_out=self.tokens_out, model=model)


class ParseTest(unittest.TestCase):
    def test_each_kind_round_trips(self):
        for line, kind in (
                ('YOLO_NEXT: dispatch agent=crash-triager args="--harness p" reason="crashes"', loop.DISPATCH),
                ('YOLO_NEXT: run script="run-fuzzer.sh" reason="relaunch"', loop.RUN),
                ('YOLO_NEXT: schedule delay=900 prompt=/cc-fuzzer:tick reason="let it run"', loop.WAIT),
                ('YOLO_NEXT: halt reason="cost cap"', loop.HALT),
                ('YOLO_NEXT: done reason="finished"', loop.DONE),
                ('YOLO_NEXT: inactive', loop.INACTIVE)):
            with self.subTest(kind=kind):
                d = loop.parse_directive(line)
                self.assertIsNotNone(d, line)
                self.assertEqual(d.kind, kind)

    def test_the_last_directive_wins(self):
        """A model that reasons out loud may mention the vocabulary on the way
        to its answer; the contract has always been the final line."""
        text = ('I considered YOLO_NEXT: dispatch agent=mutator reason="no"\n'
                'but the coverage is flat, so:\n'
                'YOLO_NEXT: run script="snapshot-coverage.sh" reason="refresh"\n')
        d = loop.parse_directive(text)
        self.assertEqual(d.kind, loop.RUN)
        self.assertEqual(d.script, "snapshot-coverage.sh")

    def test_schedule_is_the_wire_name_for_wait(self):
        d = loop.parse_directive('YOLO_NEXT: schedule delay=600 reason="x"')
        self.assertEqual(d.kind, loop.WAIT)
        self.assertIn("schedule", d.as_line())

    def test_delay_is_clamped(self):
        for given, want in ((5, loop.MIN_DELAY_S), (99999, loop.MAX_DELAY_S),
                            (900, 900), ("abc", loop.DEFAULT_DELAY_S)):
            with self.subTest(given=given):
                d = loop.parse_directive(f'YOLO_NEXT: schedule delay={given} reason="x"')
                self.assertEqual(d.delay_hint_s, want)

    def test_text_without_a_directive_is_none(self):
        for text in ("", "no directive", "YOLO_NEXT without colon", None):
            self.assertIsNone(loop.parse_directive(text))

    def test_an_unknown_kind_is_not_invented(self):
        self.assertIsNone(loop.parse_directive("YOLO_NEXT: teleport reason=x"))

    def test_bad_kind_is_refused_at_construction(self):
        with self.assertRaises(loop.LoopError):
            loop.Directive("teleport")


class RouteTest(unittest.TestCase):
    """The port of yolo-route.sh: the setup chain is decided by which
    artifacts exist, so it never costs a dispatch."""

    def setUp(self):
        self.td = tempfile.TemporaryDirectory()
        self.addCleanup(self.td.cleanup)
        self.root = Path(self.td.name)
        (self.root / "fuzz" / "state").mkdir(parents=True)

    class FakeCampaign:
        def __init__(self, root):
            self.project_root = root
            self.fuzz_root = root / "fuzz"
            self.state_dir = root / "fuzz" / "state"

    def _c(self):
        return self.FakeCampaign(self.root)

    def test_no_plan_asks_for_the_planner(self):
        d = loop.route(self._c(), loop.S_STOPPED)
        self.assertEqual((d.kind, d.agent), (loop.DISPATCH, "campaign-planner"))

    def test_plan_without_harness_asks_for_the_harness_writer(self):
        (self.root / "fuzz/state/plan.md").write_text("# plan\n")
        d = loop.route(self._c(), loop.S_STOPPED)
        self.assertEqual((d.kind, d.agent), (loop.DISPATCH, "harness-writer"))

    def test_harness_without_corpus_asks_for_seeds(self):
        (self.root / "fuzz/state/plan.md").write_text("# plan\n")
        (self.root / "fuzz/state/harness-built.json").write_text("{}")
        d = loop.route(self._c(), loop.S_STOPPED)
        self.assertEqual((d.kind, d.agent), (loop.DISPATCH, "seed-generator"))

    def test_everything_ready_launches_the_fuzzer(self):
        (self.root / "fuzz/state/plan.md").write_text("# plan\n")
        (self.root / "fuzz/state/harness-built.json").write_text("{}")
        corpus = self.root / "fuzz/harnesses/parser/corpus"
        corpus.mkdir(parents=True)
        (corpus / "seed.bin").write_bytes(b"x")
        d = loop.route(self._c(), loop.S_STOPPED)
        self.assertEqual((d.kind, d.script), (loop.RUN, "run-fuzzer.sh"))

    def test_a_running_campaign_needs_judgement(self):
        d = loop.route(self._c(), loop.S_RUNNING)
        self.assertEqual(d.kind, loop.ORCHESTRATOR)

    def test_unsafe_state_defers_rather_than_acting(self):
        for state in (loop.S_STALE, loop.S_CORRUPTED, "weird"):
            with self.subTest(state=state):
                self.assertEqual(loop.route(self._c(), state).kind, loop.ORCHESTRATOR)


class StepTest(unittest.TestCase):
    """A tick against a real fixture campaign."""

    def setUp(self):
        self.td = tempfile.TemporaryDirectory()
        self.addCleanup(self.td.cleanup)
        self.project = Path(self.td.name) / "campaign"
        shutil.copytree(FIXTURES / "campaign-warm", self.project)
        self.cwd = os.getcwd()
        os.chdir(self.project)
        self.addCleanup(os.chdir, self.cwd)
        self.c = _campaign()

    def _force_running(self):
        """Patch the state probe, restoring the ORIGINAL on cleanup. Capturing
        loop.__dict__[...] after patching would restore the patch itself and
        leak it into every later test in the process."""
        orig = loop.campaign_state
        self.addCleanup(setattr, loop, "campaign_state", orig)
        loop.campaign_state = lambda _c: loop.S_RUNNING

    def test_a_tick_runs_the_deterministic_phases(self):
        r = loop.step(self.c)
        names = [p["phase"] for p in r.phases]
        self.assertIn("campaign_state", names)
        self.assertIn("crash_detect", names)
        self.assertIn("update_current", names)
        self.assertIn("evaluate", names)
        self.assertTrue(all(p["ok"] for p in r.phases),
                        [p for p in r.phases if not p["ok"]])

    def test_a_tick_returns_a_directive_and_does_not_sleep(self):
        import time as _t
        t0 = _t.monotonic()
        r = loop.step(self.c)
        self.assertLess(_t.monotonic() - t0, 60, "step() must not sleep")
        self.assertIn(r.directive.kind, loop.KINDS)

    def test_without_a_runner_a_decision_is_reported_not_guessed(self):
        self._force_running()
        r = loop.step(self.c, None)
        self.assertEqual(r.directive.kind, loop.ORCHESTRATOR)
        self.assertEqual(r.agent, "fuzz-orchestrator")

    def test_the_result_is_serialisable(self):
        d = loop.step(self.c).as_dict()
        self.assertEqual(json.loads(json.dumps(d))["schema"], loop.TICK_SCHEMA)

    def test_a_failing_phase_does_not_end_the_tick(self):
        """A coverage snapshot that cannot run is not a reason to stop the
        campaign; it is a recorded event."""
        from cc_fuzzer_core import coverage
        orig = coverage.snapshot
        coverage.snapshot = lambda *a, **k: (_ for _ in ()).throw(RuntimeError("boom"))
        self.addCleanup(setattr, coverage, "snapshot", orig)
        self._force_running()
        r = loop.step(self.c)
        self.assertIn("phase_failed", [e.get("event") for e in r.events])
        self.assertIn(r.directive.kind, loop.KINDS)


class RunnerAndLedgerTest(unittest.TestCase):
    """§7's accounting claim: the cap becomes a measurement."""

    def setUp(self):
        self.td = tempfile.TemporaryDirectory()
        self.addCleanup(self.td.cleanup)
        self.project = Path(self.td.name) / "campaign"
        shutil.copytree(FIXTURES / "campaign-warm", self.project)
        self.cwd = os.getcwd()
        os.chdir(self.project)
        self.addCleanup(os.chdir, self.cwd)
        self.c = _campaign()
        self._orig_state = loop.campaign_state
        loop.campaign_state = lambda _c: loop.S_RUNNING   # the judgement path
        self.addCleanup(setattr, loop, "campaign_state", self._orig_state)

    def test_the_runner_decides_and_the_tokens_are_recorded(self):
        before = ledger.spend(self.c)
        runner = StubRunner('YOLO_NEXT: dispatch agent=coverage-analyst '
                            'args="--harness parser" reason="plateau"')
        r = loop.step(self.c, runner)
        self.assertEqual((r.directive.kind, r.directive.agent),
                         (loop.DISPATCH, "coverage-analyst"))
        after = ledger.spend(self.c)
        self.assertEqual(after.tokens["tokens_in"] - before.tokens["tokens_in"], 12000)
        self.assertEqual(after.tokens["tokens_out"] - before.tokens["tokens_out"], 800)
        self.assertGreater(after.usd, before.usd)
        self.assertIn("agent_call", [e.get("event") for e in r.events])

    def test_the_model_comes_from_the_mapping(self):
        runner = StubRunner('YOLO_NEXT: halt reason="x"')
        loop.step(self.c, runner)
        from cc_fuzzer_core import models
        self.assertEqual(runner.calls[0]["model"], models.resolve("fuzz-orchestrator"))

    def test_a_reply_without_a_directive_waits_instead_of_re_dispatching(self):
        """The old loop paid for a second Opus call to recover one missing
        line. Saying so and coming back is cheaper and honest."""
        r = loop.step(self.c, StubRunner("I had a think but forgot the format."))
        self.assertEqual(r.directive.kind, loop.WAIT)
        self.assertIn("no_directive", [e.get("event") for e in r.events])

    def test_a_ledger_failure_does_not_end_the_tick(self):
        from cc_fuzzer_core import ledger as _l
        orig = _l.append
        _l.append = lambda *a, **k: (_ for _ in ()).throw(RuntimeError("disk full"))
        self.addCleanup(setattr, _l, "append", orig)
        r = loop.step(self.c, StubRunner('YOLO_NEXT: halt reason="x"'))
        self.assertIn("ledger_failed", [e.get("event") for e in r.events])
        self.assertEqual(r.directive.kind, loop.HALT)


class CliTest(unittest.TestCase):
    def setUp(self):
        self.td = tempfile.TemporaryDirectory()
        self.addCleanup(self.td.cleanup)
        self.project = Path(self.td.name) / "campaign"
        shutil.copytree(FIXTURES / "campaign-warm", self.project)

    def _run(self, *args):
        env = dict(os.environ)
        env.update({"PYTHONPATH": str(REPO / "src"), "CC_FUZZER_ROOT": str(REPO)})
        return subprocess.run(core(*args), capture_output=True, text=True,
                              cwd=self.project, env=env)

    def test_tick_run_prints_a_directive(self):
        r = self._run("tick", "run")
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertTrue(r.stdout.startswith("YOLO_NEXT:"), r.stdout)

    def test_tick_run_json(self):
        r = self._run("tick", "run", "--json")
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertEqual(json.loads(r.stdout)["schema"], loop.TICK_SCHEMA)

    def test_tick_prepare_runs_only_the_deterministic_half(self):
        r = self._run("tick", "run", "--prepare")
        self.assertEqual(r.returncode, 0, r.stderr)
        doc = json.loads(r.stdout)
        self.assertIn("phases", doc)
        self.assertNotIn("directive", doc)

    def test_route(self):
        r = self._run("tick", "route")
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertTrue(r.stdout.startswith("YOLO_NEXT:"))

    def test_parse_reads_stdin(self):
        env = dict(os.environ)
        env.update({"PYTHONPATH": str(REPO / "src"), "CC_FUZZER_ROOT": str(REPO)})
        p = subprocess.run(core("tick", "parse", "--json"),
                           input='YOLO_NEXT: halt reason="done"',
                           capture_output=True, text=True, env=env)
        self.assertEqual(json.loads(p.stdout)["kind"], "halt")

    def test_parse_exits_1_when_there_is_no_directive(self):
        env = dict(os.environ)
        env.update({"PYTHONPATH": str(REPO / "src"), "CC_FUZZER_ROOT": str(REPO)})
        p = subprocess.run(core("tick", "parse", "--text", "nothing here"),
                           capture_output=True, text=True, env=env)
        self.assertEqual(p.returncode, 1)


if __name__ == "__main__":
    unittest.main()
