"""Budget errors and the advisory ledger guard (cc_fuzzer_core.errors, ledger).

When a gateway owns the budget (OSS-CRS hands out a LiteLLM key with a hard
max_budget), the first sign the money is gone is an API error mid-run. Retrying
it burns the rest of the wall-clock against a wall; these tests hold the core
to "never retried, always recorded".
"""
from __future__ import annotations

import os
import shutil
import tempfile
import unittest
from pathlib import Path

from cc_fuzzer_core import errors, events, ledger, loop
from cc_fuzzer_core.ledger import Usage
from cc_fuzzer_core.paths import campaign as _campaign
from tests.support.golden import FIXTURES

LITELLM = ("litellm.BudgetExceededError: Budget has been exceeded! "
           "Current cost: 50.02, Max budget: 50.0")


class GatewayError(Exception):
    """Shaped like an SDK error: the budget text may only be in the body."""

    def __init__(self, msg, body=None):
        super().__init__(msg)
        self.body = body


class ClassifyTest(unittest.TestCase):
    def test_gateway_and_provider_wordings(self):
        for e in (Exception(LITELLM),
                  GatewayError("Error code: 400", body={"error": {"type": "budget_exceeded"}}),
                  Exception("Your credit balance is too low to access the Anthropic API"),
                  Exception("insufficient_quota")):
            with self.subTest(e=str(e)):
                self.assertTrue(errors.is_budget_error(e))

    def test_ordinary_failures_are_not_budget_errors(self):
        for e in (TimeoutError("read timed out"), Exception("529 overloaded"),
                  Exception("rate limit exceeded, retry after 3s")):
            with self.subTest(e=str(e)):
                self.assertFalse(errors.is_budget_error(e))
                self.assertIsNone(errors.as_budget_exhausted(e))

    def test_a_local_cap_is_not_a_provider_refusal(self):
        self.assertIsNone(errors.as_budget_exhausted(errors.CapReached()))
        self.assertIsInstance(errors.CapReached(), errors.BudgetError)


class CallTest(unittest.TestCase):
    def test_transient_errors_are_retried(self):
        calls = []

        def flaky():
            calls.append(1)
            if len(calls) < 3:
                raise TimeoutError("read timed out")
            return "ok"
        self.assertEqual(errors.call(flaky, attempts=3, sleep=lambda s: None), "ok")
        self.assertEqual(len(calls), 3)

    def test_budget_exhausted_not_retried(self):
        calls = []

        def broke():
            calls.append(1)
            raise Exception(LITELLM)
        with self.assertRaises(errors.BudgetExhausted) as cm:
            errors.call(broke, attempts=5, sleep=lambda s: None)
        self.assertEqual(len(calls), 1)
        self.assertIn("Max budget", cm.exception.cause)


class BrokeRunner:
    def __init__(self):
        self.calls = 0

    def run(self, agent, inputs, *, model="", budget=None):
        self.calls += 1
        raise Exception(LITELLM)


class _Campaign(unittest.TestCase):
    def setUp(self):
        self.td = tempfile.TemporaryDirectory()
        self.addCleanup(self.td.cleanup)
        self.project = Path(self.td.name) / "campaign"
        shutil.copytree(FIXTURES / "campaign-warm", self.project)
        self.cwd = os.getcwd()
        os.chdir(self.project)
        self.addCleanup(os.chdir, self.cwd)
        self.c = _campaign()


class LoopBudgetTest(_Campaign):
    def setUp(self):
        super().setUp()
        orig = loop.campaign_state
        loop.campaign_state = lambda _c: loop.S_RUNNING
        self.addCleanup(setattr, loop, "campaign_state", orig)

    def test_budget_exhausted_not_retried(self):
        """Raised once, never retried, and the log shows where spend stopped."""
        before = ledger.spend(self.c)
        runner = BrokeRunner()
        with self.assertRaises(errors.BudgetExhausted):
            loop.step(self.c, runner)
        self.assertEqual(runner.calls, 1)
        rows = [r for r in events.read(self.c.state_dir)
                if r.get("event") == ledger.EXHAUSTED_EVENT]
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["agent_called"], "fuzz-orchestrator")
        self.assertIn("Max budget", rows[0]["reason"])
        self.assertEqual(ledger.spend(self.c).usd, before.usd, "a refusal costs nothing")

    def test_other_runner_failures_still_propagate_as_themselves(self):
        class Boom:
            def run(self, *a, **k):
                raise ValueError("bad inputs")
        with self.assertRaises(ValueError):
            loop.step(self.c, Boom())


class LedgerGuardTest(_Campaign):
    def _spend(self, usd_scope):
        # price-independent: compare against spend() itself
        for i, scope in enumerate(usd_scope):
            ledger.append(self.c, agent="crash-triager", usage=Usage(200000, 20000,
                          model="claude-opus-4-1"), source="driver",
                          call_id=f"g{i}-{scope}", scope=scope)

    def test_scopes_are_independent(self):
        base_all = ledger.spend(self.c).usd
        self._spend(["find", "find", "patch"])
        find = ledger.spend(self.c, scope="find").usd
        patch = ledger.spend(self.c, scope="patch").usd
        self.assertGreater(find, 0)
        self.assertAlmostEqual(find, 2 * patch, places=6)
        self.assertAlmostEqual(ledger.spend(self.c).usd - base_all, find + patch, places=6)

    def test_ledger_reserve(self):
        """Trips at cap minus reserve, not at the cap."""
        self._spend(["find"])
        one = ledger.spend(self.c, scope="find").usd
        cap = one / 0.95           # spent is 95% of the cap
        self.assertTrue(ledger.guard(self.c, scope="find", cap_usd=cap).allowed)
        with self.assertRaises(errors.CapReached) as cm:
            ledger.guard(self.c, scope="find", cap_usd=cap, reserve=0.1)
        self.assertEqual(cm.exception.scope, "find")
        self.assertTrue(ledger.guard(self.c, scope="patch", cap_usd=cap, reserve=0.1).allowed,
                        "another scope's spend does not count")

    def test_bad_arguments_are_refused(self):
        for kw in ({"cap_usd": 0}, {"cap_usd": 10, "reserve": 1.0}, {"cap_usd": 10, "reserve": -0.1}):
            with self.subTest(kw=kw), self.assertRaises(ledger.LedgerError):
                ledger.check(self.c, **kw)

    def test_cli_follows_the_gate_exit_contract(self):
        import subprocess
        import sys
        self._spend(["find"])
        one = ledger.spend(self.c, scope="find").usd
        env = {**os.environ, "PYTHONPATH": str(Path(__file__).resolve().parents[1] / "src")}

        def run(*args):
            return subprocess.run([sys.executable, "-m", "cc_fuzzer_core", "ledger", "guard",
                                   *args], capture_output=True, text=True, env=env).returncode
        self.assertEqual(run("--scope", "find", "--cap", str(one * 10)), 0)
        self.assertEqual(run("--scope", "find", "--cap", str(one), "--reserve", "0.1"), 1)
        self.assertNotEqual(run("--cap", "-1"), 0)


if __name__ == "__main__":
    unittest.main()
