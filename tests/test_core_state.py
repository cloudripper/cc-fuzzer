"""UPDATE_ROADMAP.md §2 row 3: the state machine ported into cc_fuzzer_core.state.

  - parity: `cc-fuzzer state ...` / `cc-fuzzer yolo ...` reproduce the goldens
    recorded from update-current.sh, derive-tick-state.py, yolo-state.sh,
    tick-coverage-roundup.sh and ceiling-probe.sh (Stage 0 + tests/support/cases.py)
  - the YOLO defaults live in one place (yolo_state.YOLO_DEFAULTS)
  - the scripts and old _lib modules are shims
"""
from __future__ import annotations

import os
import re
import subprocess
import sys
import unittest

from tests.support.cases import ROW3_CASES, run_case
from tests.support.golden import REPO, FIXTURES, GoldenTestCase, core


class TestRow3Parity(GoldenTestCase):
    def test_extra_cases(self):
        for case in ROW3_CASES:
            if case.core_argv is None:
                continue
            with self.subTest(case=case.name):
                self.assertGolden(case.name, run_case(self, case, case.core_argv))

    def _stage0(self, fixture, name, argv, setup=None):
        sb = self.sandbox(fixture)
        if setup:
            setup(sb)
        self.assertGolden(name, sb.run(argv))

    def test_stage0_update_current(self):
        for fixture, case in (("campaign-cold", "cold"), ("campaign-warm", "warm"),
                              ("campaign-plateau", "plateau"), ("campaign-crashes", "crashes")):
            with self.subTest(case=case):
                self._stage0(fixture, f"update-current/{case}", core("state", "update-current"))

    def test_stage0_derive(self):
        from tests.support.cases import _strip_derived
        for fixture, case in (("campaign-warm", "warm"), ("campaign-plateau", "plateau"),
                              ("campaign-crashes", "crashes")):
            with self.subTest(case=case):
                self._stage0(fixture, f"derive-tick-state/{case}",
                             core("state", "derive", "fuzz/state/current.json"), _strip_derived)
        self._stage0("campaign-cold", "derive-tick-state/missing",
                     core("state", "derive", "fuzz/state/current.json"))

    def test_stage0_next_tick(self):
        def halt(sb):
            def h(doc):
                doc["yolo_state"]["halt_triggered"] = True
                doc["yolo_state"]["halt_reason"] = 'no_progress: ladder stage 3 ("consult" returned nothing)'
            sb.edit_json("fuzz/state/current.json", h)
        for fixture, case, setup in (("campaign-cold", "no-current", None), ("campaign-warm", "inactive", None),
                                     ("campaign-plateau", "schedule", None), ("campaign-plateau", "halt", halt)):
            with self.subTest(case=case):
                self._stage0(fixture, f"yolo-next-tick/{case}", core("yolo", "next-tick"), setup)


class TestYoloDefaultsSingleSource(unittest.TestCase):
    def test_settings(self):
        from cc_fuzzer_core.state.yolo_state import YOLO_DEFAULTS, YoloSettings
        s = YoloSettings({})
        self.assertEqual(s.mode, "hybrid")
        self.assertEqual(s.aggressiveness, "balanced")
        self.assertEqual(s.int("max_ticks"), YOLO_DEFAULTS["max_ticks"])
        self.assertEqual(s.float("soft_cost_fraction"), 0.6)
        s = YoloSettings({"mode": "self_loop", "max_ticks": 0})
        self.assertEqual(s.aggressiveness, "aggressive")
        self.assertEqual(s.float("soft_cost_fraction"), 0.8)
        self.assertEqual(s.int("max_ticks"), 0)  # user-set zero survives
        s = YoloSettings({"mode": "turbo", "aggressiveness": "conservative", "redundancy_threshold": "x"})
        self.assertEqual((s.mode, s.aggressiveness), ("hybrid", "conservative"))
        self.assertEqual(s.int("max_backoff_multiplier"), 4)  # a bad field only fails its own read
        with self.assertRaises(ValueError):
            s.int("redundancy_threshold")
        self.assertEqual(YoloSettings(None).resolved()["interval_seconds"], 1800)

    def test_no_restated_defaults(self):
        # The old modules each carried `.get("max_ticks", 24)`-style defaults;
        # every read now goes through YoloSettings.
        pat = re.compile(r"""\.get\(\s*["'](interval_seconds|max_ticks|max_cost_usd|stop_on_no_progress_ticks|"""
                         r"""plateau_escalate_ticks|crash_storm_threshold|redundancy_threshold|soft_cost_fraction|"""
                         r"""max_backoff_multiplier|cost_cap_enabled|enabled_at_ts|enabled_at_tick)["']\s*,""")
        hits = []
        for p in sorted((REPO / "src" / "cc_fuzzer_core").rglob("*.py")):
            for i, ln in enumerate(p.read_text().splitlines(), 1):
                if pat.search(ln):
                    hits.append(f"{p.relative_to(REPO)}:{i}: {ln.strip()}")
        self.assertEqual(hits, [])
        text = (REPO / "scripts" / "yolo-state.sh").read_text()
        self.assertNotIn("DEFAULT_MAX_TICKS", text)


class TestUpdateCurrentApi(GoldenTestCase):
    def test_absolute_state_dir_inside_project_records_relative_paths(self):
        # run-fuzzer.sh / snapshot-coverage.sh pass an absolute FUZZ_STATE_DIR;
        # the recorded paths are still the documented project-relative form.
        sb = self.sandbox("campaign-warm")
        r = sb.run(core("state", "update-current"), env={"FUZZ_STATE_DIR": str(sb.path("fuzz/state"))})
        self.assertEqual(r.exit_code, 0, r.stderr)
        self.assertEqual(r.stdout, "fuzz/state/current.json\n")
        doc = r.file_json("fuzz/state/current.json")
        self.assertEqual(doc["findings"]["file"], "fuzz/state/findings.jsonl")
        self.assertTrue(doc["coverage"]["snapshot_file"].startswith("fuzz/state/snapshots/coverage-"))

    def test_state_dir_outside_project(self):
        sb = self.sandbox("campaign-warm")
        import shutil
        shutil.move(str(sb.path("fuzz/state")), str(sb.tmp / "elsewhere"))
        r = sb.run(core("state", "update-current"), env={"FUZZ_STATE_DIR": str(sb.tmp / "elsewhere")})
        self.assertEqual(r.exit_code, 0, r.stderr)
        self.assertEqual(r.stdout, "<TMP>/elsewhere/current.json\n")

    def test_equal_snapshot_timestamps_do_not_crash(self):
        sb = self.sandbox("campaign-plateau")
        snaps = sorted(sb.path("fuzz/state/snapshots").glob("coverage-parser-*.json"))
        sb.edit_json(str(snaps[0].relative_to(sb.project)),
                     lambda d: d.update(timestamp=__import__("json").loads(snaps[1].read_text())["timestamp"]))
        r = sb.run(core("state", "update-current"))
        self.assertEqual(r.exit_code, 0, r.stderr)

    def test_python_api(self):
        from cc_fuzzer_core.paths import Campaign
        from cc_fuzzer_core.state import update_current
        sb = self.sandbox("campaign-plateau")
        c = Campaign(sb.project, sb.project / "fuzz", sb.project / "fuzz" / "state")
        r = update_current(c, now=1790000000)
        self.assertEqual(r.code, 0)
        self.assertEqual(r.doc["recommendation"]["harness"], "parser")
        self.assertTrue(r.doc["yolo_state"]["active"])


class TestShims(unittest.TestCase):
    SHIMS = {
        "scripts/update-current.sh": "cc_fuzzer_core state update-current",
        "scripts/tick-coverage-roundup.sh": "cc_fuzzer_core state roundup",
        "scripts/ceiling-probe.sh": "cc_fuzzer_core state ceiling-probe",
        "scripts/yolo-state.sh": "cc_fuzzer_core yolo",
    }

    def test_scripts_are_shims(self):
        for rel, cmd in self.SHIMS.items():
            text = (REPO / rel).read_text()
            with self.subTest(script=rel):
                self.assertIn(f"exec python3 -m {cmd}", text)
                self.assertNotIn("<<'PY'", text)
                self.assertNotIn("python3 -c", text)

    def test_lib_modules_are_reexports(self):
        env = {**os.environ, "PYTHONPATH": str(REPO / "src")}
        code = ("import sys; sys.path.insert(0, %r)\n"
                "import yolo_evaluate, toolbox_eval, ceiling_probe\n"
                "from cc_fuzzer_core.state import yolo_evaluate as y, toolbox as t, ceiling as c\n"
                "assert (yolo_evaluate, toolbox_eval, ceiling_probe) == (y, t, c)\n") % str(REPO / "scripts" / "_lib")
        r = subprocess.run([sys.executable, "-c", code], capture_output=True, text=True, env=env, timeout=60)
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertFalse((REPO / "scripts" / "_lib" / "build_current_multi.py").exists())

    def test_lib_testing_clis(self):
        env = {**os.environ, "PYTHONPATH": str(REPO / "src")}
        cur = FIXTURES / "campaign-plateau" / "fuzz" / "state" / "current.json"
        for mod, key in (("yolo_evaluate", "suggested_disposition"), ("toolbox_eval", "eligible_levers")):
            with self.subTest(mod=mod):
                r = subprocess.run([sys.executable, str(REPO / "scripts" / "_lib" / f"{mod}.py"), str(cur)],
                                   capture_output=True, text=True, env=env, timeout=60)
                self.assertEqual(r.returncode, 0, r.stderr)
                self.assertIn(key, __import__("json").loads(r.stdout))
        r = subprocess.run([sys.executable, str(REPO / "scripts" / "_lib" / "derive-tick-state.py")],
                           capture_output=True, text=True, env=env, timeout=60)
        self.assertEqual(r.returncode, 2)


if __name__ == "__main__":
    unittest.main()
