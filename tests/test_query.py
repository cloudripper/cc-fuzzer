"""UPDATE_ROADMAP.md §5: the loop asks a question instead of re-reading.

Every other plateau branch re-examines what the campaign already has. `query`
writes a fresh semgrep rule to test a stated hypothesis about the code, runs
it under a budget the CORE enforces, and records what was asked alongside what
came back.

Also covers the GAP_REASONS drift the survey found: the enum and
STATE_SCHEMA.md disagreed on 9 of 11 values, and nothing validated against it,
so nobody noticed.
"""
from __future__ import annotations

import json
import os
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path

from cc_fuzzer_core import enums, query
from cc_fuzzer_core.paths import campaign as _campaign
from tests.support.golden import FIXTURES, REPO, core

STUB_SAST = REPO / "tests" / "support" / "stub-sast"

RULE = """\
rules:
  - id: unbounded-copy
    patterns:
      - pattern: strcpy($D, $S)
    message: unbounded copy
    languages: [c]
    severity: WARNING
"""


class EnumTest(unittest.TestCase):
    def test_query_branch_and_agent_and_snapshot_exist(self):
        self.assertIn("query", enums.REC_BRANCHES)
        self.assertIn("query-analyst", enums.HARNESS_ACTIONS)
        self.assertIn("query-result", enums.SNAPSHOT_PREFIXES)

    def test_gap_reasons_match_what_is_actually_emitted(self):
        """The enum had six values, four of which nothing ever wrote, and was
        missing `value_constraint`, which the prompts emit ten times."""
        self.assertIn("value_constraint", enums.GAP_REASONS)
        for reason in ("harness_gap", "format_barrier", "state_precondition",
                       "direct_compare", "delta_target", "cve_hotspot",
                       "code_review_target", "dead"):
            self.assertIn(reason, enums.GAP_REASONS)
        for gone in ("magic_value", "format_invariant", "resource_guard",
                     "unreached_function"):
            self.assertNotIn(gone, enums.GAP_REASONS)

    def test_gap_reasons_are_now_under_the_doc_mirror_check(self):
        """The drift was invisible because nothing compared the two."""
        r = subprocess.run(core("enums", "doc-drift", str(REPO / "STATE_SCHEMA.md")),
                           capture_output=True, text=True,
                           env={**os.environ, "PYTHONPATH": str(REPO / "src")})
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertIn("GAP_REASONS", (REPO / "STATE_SCHEMA.md").read_text())


class BudgetTest(unittest.TestCase):
    def test_defaults(self):
        b = query.budget({})
        self.assertTrue(b.enabled)
        self.assertEqual(b.max_queries_per_dispatch, 3)
        self.assertEqual(b.engines, query.ENGINES)

    def test_config_overrides(self):
        b = query.budget({"query": {"max_queries_per_dispatch": 1,
                                    "engines": ["semgrep"], "enabled": False}})
        self.assertEqual(b.max_queries_per_dispatch, 1)
        self.assertEqual(b.engines, ("semgrep",))
        self.assertFalse(b.enabled)

    def test_a_bad_number_falls_back_rather_than_crashing(self):
        b = query.budget({"query": {"per_query_timeout_s": "soon"}})
        self.assertEqual(b.per_query_timeout_s, query.DEFAULTS["per_query_timeout_s"])

    def test_unknown_engines_are_dropped(self):
        self.assertEqual(query.budget({"query": {"engines": ["semgrep", "grep"]}}).engines,
                         ("semgrep",))


class RunTest(unittest.TestCase):
    def setUp(self):
        self.td = tempfile.TemporaryDirectory()
        self.addCleanup(self.td.cleanup)
        self.project = Path(self.td.name) / "campaign"
        shutil.copytree(FIXTURES / "campaign-warm", self.project)
        (self.project / "src").mkdir(exist_ok=True)
        (self.project / "src" / "p.c").write_text(
            '#include <string.h>\nvoid f(char*d,const char*s){strcpy(d,s);}\n')
        self.rule = self.project / "rule.yaml"
        self.rule.write_text(RULE)
        self.cwd = os.getcwd()
        os.chdir(self.project)
        self.addCleanup(os.chdir, self.cwd)
        self.c = _campaign()
        self._path = os.environ.get("PATH", "")
        os.environ["PATH"] = f"{STUB_SAST}{os.pathsep}{self._path}"
        self.addCleanup(os.environ.__setitem__, "PATH", self._path)

    def _run(self, **kw):
        kw.setdefault("engine", "semgrep")
        kw.setdefault("rule", str(self.rule))
        kw.setdefault("hypothesis", "does the parser copy without bounds?")
        return query.run(self.c, **kw)

    def test_a_query_runs_and_is_recorded(self):
        r = self._run(dispatch_id="d1", disposition=query.D_CANDIDATE)
        self.assertEqual(r.status, "ok")
        self.assertTrue(r.hits)
        self.assertEqual(r.disposition, query.D_CANDIDATE)
        logged = query.runs(self.c)
        self.assertEqual(len(logged), 1)
        self.assertEqual(logged[0]["hypothesis"], r.hypothesis)

    def test_the_hypothesis_is_required(self):
        """The hits alone do not record what was being asked, so a query
        without a stated hypothesis cannot be judged later."""
        with self.assertRaises(query.QueryError) as cm:
            self._run(hypothesis="   ")
        self.assertIn("hypothesis", str(cm.exception))

    def test_a_snapshot_is_written(self):
        r = self._run(dispatch_id="d1")
        p = query.write_snapshot(self.c, r, now=1790000000)
        self.assertTrue(p.is_file())
        doc = json.loads(p.read_text())
        self.assertEqual(doc["schema"], query.RESULT_SCHEMA)
        self.assertTrue(p.name.startswith(query.SNAPSHOT_PREFIX))

    def test_per_dispatch_cap_binds(self):
        cfg = {"query": {"max_queries_per_dispatch": 2}}
        self._run(dispatch_id="d2", config=cfg)
        self._run(dispatch_id="d2", config=cfg)
        with self.assertRaises(query.BudgetExhausted):
            self._run(dispatch_id="d2", config=cfg)

    def test_campaign_cap_binds(self):
        cfg = {"query": {"max_dispatches_per_campaign": 2}}
        self._run(dispatch_id="a", config=cfg)
        self._run(dispatch_id="b", config=cfg)
        with self.assertRaises(query.BudgetExhausted):
            self._run(dispatch_id="c", config=cfg)

    def test_disabled_refuses_rather_than_running_anyway(self):
        with self.assertRaises(query.BudgetExhausted):
            self._run(config={"query": {"enabled": False}})

    def test_an_engine_outside_the_allowed_set_is_refused(self):
        with self.assertRaises(query.BudgetExhausted):
            self._run(engine="codeql", config={"query": {"engines": ["semgrep"]}})

    def test_unknown_engine_and_disposition_are_refused(self):
        with self.assertRaises(query.QueryError):
            self._run(engine="grep")
        with self.assertRaises(query.QueryError):
            self._run(disposition="maybe")

    def test_a_missing_rule_file_is_refused(self):
        with self.assertRaises(query.QueryError):
            self._run(rule=str(self.project / "nope.yaml"))

    def test_a_missing_engine_is_a_result_not_a_crash(self):
        os.environ["PATH"] = "/nonexistent"
        r = self._run(dispatch_id="d9")
        self.assertNotEqual(r.status, "ok")
        self.assertEqual(r.hits, ())
        self.assertEqual(len(query.runs(self.c)), 1, "a failed query is still recorded")

    def test_exhausted_reports_for_the_lever(self):
        cfg = {"query": {"max_dispatches_per_campaign": 1}}
        self.assertFalse(query.exhausted(self.c, cfg))
        self._run(dispatch_id="only", config=cfg)
        self.assertTrue(query.exhausted(self.c, cfg))

    def test_exhausted_when_disabled(self):
        self.assertTrue(query.exhausted(self.c, {"query": {"enabled": False}}))


class CliTest(unittest.TestCase):
    def setUp(self):
        self.td = tempfile.TemporaryDirectory()
        self.addCleanup(self.td.cleanup)
        self.project = Path(self.td.name) / "campaign"
        shutil.copytree(FIXTURES / "campaign-warm", self.project)
        (self.project / "rule.yaml").write_text(RULE)

    def _cli(self, *args, path_extra=""):
        env = dict(os.environ)
        env.update({"PYTHONPATH": str(REPO / "src"), "CC_FUZZER_ROOT": str(REPO)})
        if path_extra:
            env["PATH"] = f"{path_extra}{os.pathsep}{env.get('PATH','')}"
        return subprocess.run(core(*args), capture_output=True, text=True,
                              cwd=self.project, env=env)

    def test_budget_json(self):
        r = self._cli("query", "budget")
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertIn("remaining", json.loads(r.stdout))

    def test_run_and_log(self):
        r = self._cli("query", "run", "--rule", "rule.yaml", "--hypothesis",
                      "unbounded copy?", "--dispatch-id", "d1", "--json",
                      path_extra=str(STUB_SAST))
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertEqual(json.loads(r.stdout)["schema"], query.RUN_SCHEMA)
        log = self._cli("query", "log")
        self.assertIn("unbounded copy?", log.stdout)

    def test_budget_exhaustion_has_its_own_exit_code(self):
        """3, not 2: 'the budget is spent' is not the same as 'you asked for
        something impossible', and the loop reacts differently."""
        cfg = self.project / "off.json"
        cfg.write_text(json.dumps({"query": {"enabled": False}}))
        r = self._cli("query", "run", "--rule", "rule.yaml",
                      "--hypothesis", "x", "--config", str(cfg))
        self.assertEqual(r.returncode, 3)

    def test_a_bad_request_exits_2(self):
        r = self._cli("query", "run", "--rule", "nope.yaml", "--hypothesis", "x")
        self.assertEqual(r.returncode, 2)


if __name__ == "__main__":
    unittest.main()
