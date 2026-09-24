"""UPDATE_ROADMAP.md §2 row 7: the Tier-1 code-review prescan ported into
cc_fuzzer_core.prescan (code_review_prescan, sast_scan, merge).

  - parity: the core CLI reproduces the Stage 0 code-review-run.sh goldens and
    every row-7 case in tests/support/cases.py (SAST against the stub semgrep /
    codeql in tests/support/stub-sast, merge-code-review, the prescan and SAST
    debug CLIs)
  - the semgrep invocation is one reusable function (run_semgrep_config), which
    §5's `query run` calls with a single authored rule
  - rules come from paths.data("rules"); tools resolve through tools.which
  - fixes: local --sast-rules dirs are passed to semgrep absolute (semgrep runs
    with cwd=target_root, where the relative path named nothing); a flag given
    last without its value no longer hangs code-review-run.sh
  - code-review-run.sh is a shim; the three _lib modules are gone
"""
from __future__ import annotations

import json
import os
import subprocess
import sys
import unittest
from pathlib import Path

from cc_fuzzer_core.paths import Campaign
from cc_fuzzer_core.prescan import ReviewOptions, plan_review, review, window_count
from cc_fuzzer_core.prescan import sast_scan
from cc_fuzzer_core.prescan.code_review_prescan import PrescanError, parse_max_functions, prescan
from tests.support.cases import ROW7_CASES, STUB_SAST_PATH, assert_core_case
from tests.support.golden import REPO, TESTS, GoldenTestCase, core

STUB_SEMGREP = TESTS / "support" / "stub-sast" / "semgrep"


class TestRow7Parity(GoldenTestCase):
    def test_extra_cases(self):
        for case in ROW7_CASES:
            if case.core_argv is None:
                continue
            with self.subTest(case=case.name):
                assert_core_case(self, case)

    def test_stage0_goldens(self):
        """The Stage 0 code-review-run.sh goldens, with the core CLI in place of the script."""
        from tests import test_golden_bash as g
        from tests.support.golden import Sandbox
        orig = Sandbox.run
        target = ["bash", str(REPO / "scripts" / "code-review-run.sh")]

        def run_core(sb, argv, **kw):
            argv = list(argv)
            if argv[:2] == target:
                argv = core("prescan", "run", *argv[2:])
            return orig(sb, argv, **kw)

        cls = g.TestCodeReviewPrescan
        for method in sorted(m for m in dir(cls) if m.startswith("test_")):
            with self.subTest(test=method):
                t = cls(method)
                Sandbox.run = run_core
                try:
                    getattr(t, method)()
                finally:
                    Sandbox.run = orig
                    t.doCleanups()


class _StubEnv:
    """Put the stub semgrep / codeql on PATH for in-process API calls."""

    def setUp(self):
        self._path = os.environ.get("PATH", "")
        os.environ["PATH"] = STUB_SAST_PATH
        for k in ("STUB_SEMGREP_MODE", "STUB_SEMGREP_FAIL_ON", "STUB_SEMGREP_LOG",
                  "CC_FUZZER_TOOL_SEMGREP", "CC_FUZZER_TOOL_CODEQL"):
            os.environ.pop(k, None)

    def tearDown(self):
        os.environ["PATH"] = self._path
        for k in ("STUB_SEMGREP_MODE", "STUB_SEMGREP_LOG", "CC_FUZZER_TOOL_SEMGREP"):
            os.environ.pop(k, None)


class TestSemgrepEngine(_StubEnv, GoldenTestCase):
    def setUp(self):
        super().setUp()
        sb = self.sandbox("campaign-crashes")
        self.src = sb.path("src")
        self.rule = sb.write("rules/q.yml", "rules: []\n")
        self.log = sb.tmpdir / "argv.log"

    def test_run_semgrep_config_one_rule(self):
        # The single-invocation API §5's query runner uses.
        os.environ["STUB_SEMGREP_LOG"] = str(self.log)
        status, findings = sast_scan.run_semgrep_config(self.src, str(self.rule), ["tests/"], 40)
        self.assertEqual(status, "ok")
        self.assertEqual({(f["rule_id"], f["line"], f["severity"]) for f in findings},
                         {("q.yml.include", 2, "low"), ("q.yml.strcpy", 15, "high"),
                          ("q.yml.sprintf", 27, "medium"), ("q.yml.free", 32, "low"),
                          ("q.yml.free", 33, "low")})
        self.assertTrue(all(f["tool"] == "semgrep" and f["path"] == "parser.c" for f in findings))
        argv = self.log.read_text().split()
        self.assertIn("--metrics=off", argv)
        self.assertEqual(argv[argv.index("--timeout") + 1], "10")
        self.assertEqual(argv[argv.index("--exclude") + 1], "tests")
        self.assertEqual(argv[-1], str(self.src))

    def test_run_semgrep_config_statuses(self):
        os.environ["STUB_SEMGREP_MODE"] = "errors"
        self.assertEqual(sast_scan.run_semgrep_config(self.src, "p/x", [], 20)[0],
                         "ok (2 rule-load errors ignored)")
        os.environ["STUB_SEMGREP_MODE"] = "fail"
        status, findings = sast_scan.run_semgrep_config(self.src, "p/x", [], 20)
        self.assertEqual((status, findings), ("error: semgrep: fatal: cannot load rules from p/x", []))
        os.environ["STUB_SEMGREP_MODE"] = "garbage"
        self.assertEqual(sast_scan.run_semgrep_config(self.src, "p/x", [], 20)[0],
                         "error: unparseable JSON output")

    def test_semgrep_missing(self):
        os.environ["PATH"] = "/nonexistent"
        self.assertEqual(sast_scan.run_semgrep_config(self.src, "p/x", [], 20),
                         ("skipped: semgrep not on PATH", []))
        run, _ = sast_scan.run_semgrep(self.src, ["p/x"], [], 20)
        self.assertEqual(run.status, "skipped: semgrep not on PATH")

    def test_semgrep_resolves_through_tools_which(self):
        os.environ["PATH"] = os.path.dirname(sys.executable)  # the stub's python3, no semgrep
        os.environ["CC_FUZZER_TOOL_SEMGREP"] = str(STUB_SEMGREP)
        status, findings = sast_scan.run_semgrep_config(self.src, "p/x", [], 20)
        self.assertEqual(status, "ok")
        self.assertEqual(len(findings), 5)
        self.assertEqual(sast_scan.detect_tools(), {"semgrep": True, "codeql": False})

    def test_relative_rule_dir_is_passed_absolute(self):
        # Fix: semgrep runs with cwd=target_root, so a relative rule dir
        # (relative to the caller) must reach it absolute.
        os.environ["STUB_SEMGREP_LOG"] = str(self.log)
        base = self.rule.parent.parent
        run, _ = sast_scan.run_semgrep(self.src, ["rules"], [], 20, base=base)
        self.assertEqual(run.rules_source, [str(base / "rules")])
        self.assertIn(f"--config {base / 'rules'} ", self.log.read_text())


class TestPrescanApi(_StubEnv, GoldenTestCase):
    def test_parse_max_functions(self):
        self.assertIsNone(parse_max_functions("ALL"))
        self.assertIsNone(parse_max_functions(" 0 "))
        self.assertEqual(parse_max_functions("7"), 7)
        with self.assertRaises(PrescanError):
            parse_max_functions("-1")
        with self.assertRaises(PrescanError):
            parse_max_functions("x")

    def test_window_count(self):
        self.assertEqual(window_count("61", "30"), 3)
        self.assertEqual(window_count("0", "0"), 0)
        self.assertEqual(window_count("5", "0"), "1")
        self.assertEqual(window_count("5", "x"), "1")

    def test_rules_from_data_root(self):
        # The bundled packs are every rule-bearing subdir of paths.data("rules").
        sb = self.sandbox("campaign-crashes")
        alt = sb.tmp / "alt-root"
        (alt / "rules" / "pack").mkdir(parents=True)
        (alt / "rules" / "pack" / "r.yaml").write_text("rules: []\n")
        (alt / "rules" / "no-rules").mkdir()
        (alt / "STATE_SCHEMA.md").write_text("x\n")
        old = os.environ.get("CC_FUZZER_ROOT")
        os.environ["CC_FUZZER_ROOT"] = str(alt)
        try:
            r = prescan(sb.path("src"), sb.path("out.json"), sast="on")
        finally:
            if old is None:
                os.environ.pop("CC_FUZZER_ROOT")
            else:
                os.environ["CC_FUZZER_ROOT"] = old
        semgrep = r.doc["sast"]["tools"][0]
        self.assertEqual(semgrep["rules_source"], [str(alt / "rules" / "pack")])
        self.assertEqual(r.scope["sast_attributed_findings"], 4)

    def test_review_api(self):
        sb = self.sandbox("campaign-crashes")
        c = Campaign(sb.project, sb.project / "fuzz", sb.project / "fuzz" / "state")
        r = review(c, ReviewOptions(sweep=True, batch_size="2", sast="off"), now=123)
        self.assertEqual(r.plan.out, f"{c.state_dir}/snapshots/code-review-prescan-123.json")
        self.assertEqual((r.candidates, r.mode, r.windows), ("3", "sweep", 2))
        self.assertEqual(r.batch_plan_line(), "BATCH_PLAN windows=2 batch_size=2 candidates=3 mode=sweep")
        doc = json.loads((c.snapshots_dir / "code-review-prescan-123.json").read_text())
        self.assertEqual(doc["target_root"], str(sb.path("src")))

    def test_plan_review_defaults(self):
        sb = self.sandbox("campaign-crashes")
        c = Campaign(sb.project, sb.project / "fuzz", sb.project / "fuzz" / "state")
        p = plan_review(c, ReviewOptions(), now=5)
        self.assertEqual((p.target_root, p.max_functions, p.sast, p.batch_size, p.cve_context),
                         (str(sb.path("src")), "50", "auto", "30", ""))
        self.assertEqual(p.prescan_argv()[-2:], ["--sast", "auto"])


class TestRunCli(GoldenTestCase):
    def test_flag_without_value_does_not_hang(self):
        # code-review-run.sh's `shift 2` failed on a trailing value-less flag
        # and the arg loop spun forever; the value now reads as "".
        sb = self.sandbox("campaign-crashes")
        r = sb.run(["bash", str(REPO / "scripts" / "code-review-run.sh"), "--no-sast", "--batch-size"],
                   timeout=30)
        self.assertEqual(r.exit_code, 0, r.stderr)
        self.assertIn("BATCH_PLAN windows=1 batch_size=30 candidates=3 mode=capped", r.stdout)

    def test_shim(self):
        text = (REPO / "scripts" / "code-review-run.sh").read_text()
        body = [ln for ln in text.splitlines() if ln and not ln.startswith("#")]
        self.assertEqual(len(body), 6, body)
        self.assertIn("exec python3 -m cc_fuzzer_core prescan run", text)
        for gone in ("code_review_prescan.py", "sast_scan.py", "code_review_merge.py"):
            self.assertFalse((REPO / "scripts" / "_lib" / gone).exists(), gone)


if __name__ == "__main__":
    unittest.main()
