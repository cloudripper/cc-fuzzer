"""UPDATE_ROADMAP.md §2 row 4: crash classification and detection ported into
cc_fuzzer_core.crash.

  - parity: `cc-fuzzer crash classify` reproduces every is-crash golden (Stage 0
    and tests/support/cases.py); `cc-fuzzer crash detect` stages the same files
    as detect-crashes.sh (its stdout is data, not hook JSON)
  - the is-crash top-frame fix: frames are filled, whatever awk is installed
  - is-crash.sh / detect-crashes.sh are shims; hook JSON stays in the plugin
"""
from __future__ import annotations

import json
import os
import unittest
from pathlib import Path

from cc_fuzzer_core.crash import classify as cl
from cc_fuzzer_core.crash import detect as dt
from cc_fuzzer_core.paths import Campaign
from tests.support.cases import DETECT_CASES, ROW4_CASES, assert_core_case, run_case
from tests.support.golden import FIXTURES, REPO, GoldenTestCase, core

LOGS = FIXTURES / "sanitizer-logs"


class TestRow4Parity(GoldenTestCase):
    def test_extra_cases(self):
        for case in ROW4_CASES:
            with self.subTest(case=case.name):
                assert_core_case(self, case)

    def test_stage0_is_crash(self):
        sb = self.sandbox(None)
        for log in sorted(p.name for p in LOGS.glob("*.log")):
            with self.subTest(log=log):
                self.assertGolden(f"is-crash/{log[:-4]}", sb.run(core("crash", "classify", str(LOGS / log))))
        text = (LOGS / "clean.log").read_text()
        for code in ("0", "134", "137", "139"):
            with self.subTest(code=code):
                self.assertGolden(f"is-crash/stdin-exit-{code}",
                                  sb.run(core("crash", "classify", "--exit-code", code), stdin=text))
        self.assertGolden("is-crash/unknown-flag", sb.run(core("crash", "classify", "--bogus")))
        self.assertGolden("is-crash/unreadable", sb.run(core("crash", "classify", "/nonexistent.log")))
        self.assertGolden("is-crash/two-paths", sb.run(core("crash", "classify", "a", "b")))

    def test_detect_json(self):
        case = next(c for c in DETECT_CASES if c.name == "detect-crashes/live-slot")
        r = run_case(self, case, case.core_argv)
        doc = json.loads(r.stdout)
        self.assertTrue(doc["alive"])
        self.assertEqual(doc["queued"], 4)
        self.assertEqual(doc["new_dir"], "<PROJECT>/fuzz/crashes/new")
        self.assertIn({"source": "crash-at-root", "staged": "fuzz/crashes/new/unknown__1532a206699ec079.bin"},
                      doc["files"])
        case = next(c for c in DETECT_CASES if c.name == "detect-crashes/no-live-slot")
        doc = json.loads(run_case(self, case, case.core_argv).stdout)
        self.assertEqual((doc["alive"], doc["queued"]), (False, 0))

    def test_detect_outside_project(self):
        sb = self.sandbox(None)
        r = sb.run(core("crash", "detect", "--missing-ok"))
        self.assertEqual((r.exit_code, r.stdout, r.stderr), (0, "", ""))
        r = sb.run(core("crash", "detect"))
        self.assertEqual(r.exit_code, 2)
        self.assertIn("not inside a cc-fuzzer project", r.stderr)


class TestClassifyApi(unittest.TestCase):
    def test_top_frame_filled(self):
        r = cl.classify_file(LOGS / "asan-uaf.log")
        self.assertTrue(r.is_crash)
        self.assertEqual(r.category, "heap-use-after-free")
        self.assertRegex(r.top_frame, r"^\w+ @ \S+:\d+$")

    def test_infra_frames_skipped(self):
        text = ("==1==ERROR: AddressSanitizer: SEGV on unknown address\n"
                "    #0 0x1 in __asan_memcpy compiler-rt/asan.cc:1:2\n"
                "    #1 0x2 in fuzzer::Fuzzer::Run F.cpp:3\n"
                "    #2 0x3 in real_fn src/x.c:44:7\n")
        r = cl.classify(text)
        self.assertEqual((r.category, r.top_frame), ("null-deref", "real_fn @ src/x.c:44"))

    def test_not_a_crash(self):
        r = cl.classify("all good\n")
        self.assertFalse(r.is_crash)
        self.assertEqual(r.to_dict(), {"is_crash": False, "category": "none", "summary_line": "",
                                       "top_frame": "", "exit_code": None})
        self.assertEqual(cl.classify("", 7).to_dict()["exit_code"], 7)

    def test_exit_code_fallback(self):
        self.assertEqual(cl.classify("", 139).category, "segfault")
        self.assertEqual(cl.classify("", "137").summary_line, "exit=137 (SIGKILL — OOM or external)")
        self.assertFalse(cl.classify("", 1).is_crash)


class TestDetectApi(unittest.TestCase):
    def test_harness_from_path(self):
        self.assertEqual(dt.harness_from_path("./fuzz/harnesses/png-read/.libfuzzer-cwd/crash-1"), "png-read")
        self.assertEqual(dt.harness_from_path("x/fuzz/harnesses/a_b/aflpp-out/q"), "a_b")
        self.assertIsNone(dt.harness_from_path("./crash-1"))
        self.assertIsNone(dt.harness_from_path("fuzz/harnesses/Bad/crash-1"))

    def test_no_slot_no_scan(self):
        import tempfile
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            (root / "fuzz" / "state").mkdir(parents=True)
            (root / "crash-1").write_bytes(b"x")
            c = Campaign(root, root / "fuzz", root / "fuzz" / "state")
            r = dt.detect(c)
            self.assertFalse(r.alive)
            self.assertFalse((root / "fuzz" / "crashes" / "new").exists())
            (root / "fuzz" / "state" / "fuzzer.pid").write_text(f"{os.getpid()}\n")
            r = dt.detect(c)
            self.assertEqual([s for s, _ in r.queued], ["crash-1"])


class TestShims(unittest.TestCase):
    def test_scripts_are_shims(self):
        for script, verb in (("is-crash.sh", "crash classify"), ("detect-crashes.sh", "crash detect")):
            text = (REPO / "scripts" / script).read_text()
            self.assertIn(f"python3 -m cc_fuzzer_core {verb}", text)
            self.assertNotIn("awk", text)

    def test_hook_json_only_in_plugin(self):
        self.assertIn("hookSpecificOutput", (REPO / "scripts" / "detect-crashes.sh").read_text())


if __name__ == "__main__":
    unittest.main()
