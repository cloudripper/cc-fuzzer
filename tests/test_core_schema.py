"""UPDATE_ROADMAP.md §2 row 2: schema validation ported into cc_fuzzer_core.schema.

  - parity: `cc-fuzzer schema validate` reproduces every validate-state golden
    (the Stage 0 ones and tests/support/cases.py's extra ones)
  - validate(campaign) -> [Problem] as an API; SCHEMA_VERSION agrees with
    STATE_SCHEMA.md and the shipped fixtures
  - state_checks.py is a shim onto the core checks
"""
from __future__ import annotations

import os
import re
import shutil
import subprocess
import sys
import unittest

from cc_fuzzer_core import schema
from cc_fuzzer_core.paths import Campaign
from cc_fuzzer_core.schema import checks, fields
from tests.support.cases import ROW2_CASES, run_case
from tests.support.golden import FIXTURES, REPO, GoldenTestCase, Sandbox, core

VC = core("schema", "validate")


class TestValidateParity(GoldenTestCase):
    def _golden(self, fixture, name, setup=None, env=None, cwd=None):
        sb = self.sandbox(fixture)
        if fixture is None:
            (sb.project / "fuzz").mkdir() if name != "validate-state/not-a-project" else None
        if setup:
            setup(sb)
        self.assertGolden(name, sb.run(VC, env=env, cwd=cwd))

    def test_stage0_goldens(self):
        for fixture, case in (("campaign-cold", "cold"), ("campaign-warm", "warm"),
                              ("campaign-plateau", "plateau"), ("campaign-crashes", "crashes")):
            with self.subTest(case=case):
                self._golden(fixture, f"validate-state/{case}")
        self._golden(None, "validate-state/no-state")
        self._golden(None, "validate-state/not-a-project")
        self._golden("campaign-cold", "validate-state/cwd-inside-fuzz", cwd="fuzz/state")
        self._golden("campaign-cold", "validate-state/recursive-fuzz",
                     setup=lambda sb: (sb.project / "fuzz" / "fuzz").mkdir())

    def test_stage0_broken(self):
        from tests.test_golden_bash import TestValidateState  # the same setup as the bash golden

        captured = {}

        class _Probe(TestValidateState):
            def _run(inner, fixture, case, setup=None, env=None):
                captured.update(fixture=fixture, case=case, setup=setup, env=env)
        _Probe("test_broken").test_broken()
        self._golden(captured["fixture"], f"validate-state/{captured['case']}", setup=captured["setup"])
        _Probe("test_state_dir_override").test_state_dir_override()
        self._golden(captured["fixture"], f"validate-state/{captured['case']}", setup=captured["setup"],
                     env=captured["env"])

    def test_extra_cases(self):
        for case in ROW2_CASES:
            with self.subTest(case=case.name):
                self.assertGolden(case.name, run_case(self, case, case.core_argv))


class TestValidateApi(unittest.TestCase):
    def _campaign(self, fixture):
        sb = Sandbox(fixture)
        self.addCleanup(sb.cleanup)
        return sb, Campaign(sb.project, sb.project / "fuzz", sb.project / "fuzz" / "state")

    def test_clean_campaign_has_no_errors(self):
        _sb, c = self._campaign("campaign-warm")
        self.assertEqual([p for p in schema.validate(c) if p.severity == schema.ERROR], [])
        self.assertEqual(schema.render(schema.validate(c)), ("ok\n", 0))

    def test_state_dir_argument_and_no_cwd_dependence(self):
        sb, c = self._campaign("campaign-crashes")
        os.unlink(sb.path("fuzz/crashes/known/f001/repro.bin"))
        here = os.getcwd()
        try:
            os.chdir("/")
            problems = schema.validate(str(c.state_dir))
        finally:
            os.chdir(here)
        msgs = [p.message for p in problems if p.severity == schema.ERROR]
        self.assertIn(f"missing canonical reproducer: {c.crashes_dir}/known/f001//repro.bin", msgs)
        self.assertTrue(any("reproducer file does not exist: fuzz/crashes/known/f001/repro.bin" in m
                            for m in msgs), msgs)

    def test_json_output(self):
        sb, _c = self._campaign("campaign-cold")
        r = sb.run(core("schema", "validate", "--json"))
        self.assertEqual(r.exit_code, 0, r.stderr)
        import json
        doc = json.loads(r.stdout)
        self.assertTrue(doc["ok"])
        self.assertEqual(doc["problems"][0]["severity"], "warning")


class TestSchemaVersion(unittest.TestCase):
    def test_matches_docs_and_fixtures(self):
        self.assertEqual(fields.SCHEMA_VERSION, "v13")
        self.assertIn(f"schema {fields.SCHEMA_VERSION}", (REPO / "STATE_SCHEMA.md").read_text())
        for sv in FIXTURES.glob("campaign-*/fuzz/state/schema-version"):
            self.assertEqual(sv.read_text().strip(), fields.SCHEMA_VERSION, sv)

    def test_cli(self):
        r = subprocess.run(core("schema", "version"), capture_output=True, text=True, timeout=60,
                           env={**os.environ, "PYTHONPATH": str(REPO / "src")})
        self.assertEqual(r.stdout, "v13\n")

    def test_harness_built_field_lists_compose(self):
        self.assertEqual(fields.HARNESS_BUILT_REQUIRED_V7[:2], ("name", "build_backend"))
        self.assertTrue(set(fields.HARNESS_BUILT_REQUIRED_V7) <= set(fields.HARNESS_BUILT_ALLOWED_V7))


class TestStateChecksShim(GoldenTestCase):
    def test_field_matches_core(self):
        hb = FIXTURES / "campaign-warm" / "fuzz" / "state" / "harness-built.json"
        env = {**os.environ, "PYTHONPATH": str(REPO / "src")}
        for args in (("coverage_tracking",), ("cmplog_binary", "dflt"), ("sanitizers",), ("nope.deep", "x")):
            with self.subTest(args=args):
                r = subprocess.run([sys.executable, str(REPO / "scripts/_lib/state_checks.py"), "field",
                                    str(hb), *args], capture_output=True, text=True, env=env, timeout=60)
                self.assertEqual(r.returncode, 0, r.stderr)
                self.assertEqual(r.stdout, checks.field(hb, *args) + "\n")
        self.assertEqual(checks.field(hb, "coverage_tracking"), "True")

    def test_env_subcommands_still_work(self):
        cfg = FIXTURES / "campaign-warm" / "fuzz" / "state" / "fuzz-config.json"
        env = {**os.environ, "PYTHONPATH": str(REPO / "src"), "CFG": str(cfg)}
        r = subprocess.run([sys.executable, str(REPO / "scripts/_lib/state_checks.py"),
                            "config-harness-names"], capture_output=True, text=True, env=env, timeout=60)
        self.assertEqual(r.stdout.split(), ["parser", "encoder"])
        r = subprocess.run([sys.executable, str(REPO / "scripts/_lib/state_checks.py"), "bogus"],
                           capture_output=True, text=True, env=env, timeout=60)
        self.assertEqual(r.returncode, 2)


class TestShim(unittest.TestCase):
    def test_validate_state_is_a_shim(self):
        text = (REPO / "scripts" / "validate-state.sh").read_text()
        code = [ln for ln in text.splitlines() if ln.strip() and not ln.lstrip().startswith("#")]
        self.assertLessEqual(len(code), 4, code)
        self.assertTrue(any("cc_fuzzer_core schema validate" in ln for ln in code))
        self.assertFalse(re.search(r"python3 -c|<<'PY'", text))


if __name__ == "__main__":
    unittest.main()
