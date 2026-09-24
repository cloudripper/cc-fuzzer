"""UPDATE_ROADMAP.md §2 row 4: crash classification and detection ported into
cc_fuzzer_core.crash.

  - parity: `cc-fuzzer crash classify` reproduces every is-crash golden (Stage 0
    and tests/support/cases.py); `cc-fuzzer crash detect` stages the same files
    as detect-crashes.sh (its stdout is data, not hook JSON)
  - the is-crash top-frame fix: frames are filled, whatever awk is installed
  - detection scans only the launcher's engine output locations (AFL++
    instance crashes/ are reached; crash-*-named source files are not)
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
        self.assertIn({"source": "fuzz/harnesses/encoder/aflpp-out/encoder-afl/crashes/id:000001,sig:06",
                       "staged": "fuzz/crashes/new/encoder__842c0168ff613838.bin"}, doc["files"])
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
            lf = root / "fuzz" / "harnesses" / "h" / ".libfuzzer-cwd"
            lf.mkdir(parents=True)
            (lf / "crash-1").write_bytes(b"x")
            c = Campaign(root, root / "fuzz", root / "fuzz" / "state")
            r = dt.detect(c)
            self.assertFalse(r.alive)
            self.assertFalse((root / "fuzz" / "crashes" / "new").exists())
            (root / "fuzz" / "state" / "fuzzer.pid").write_text(f"{os.getpid()}\n")
            r = dt.detect(c)
            self.assertEqual([s for s, _ in r.queued], ["fuzz/harnesses/h/.libfuzzer-cwd/crash-1"])


class TestDetectLocations(unittest.TestCase):
    """Fixes: AFL++ crashes (fuzz/harnesses/<h>/aflpp-out/<inst>/crashes/id:*,
    depth 7) were never queued by the old depth-6 scan, and crash-*-named files
    anywhere in the project (source files included) were."""

    def _campaign(self, d):
        root = Path(d)
        (root / "fuzz" / "state").mkdir(parents=True)
        (root / "fuzz" / "state" / "fuzzer.pid").write_text(f"{os.getpid()}\n")  # a live "slot"
        return Campaign(root, root / "fuzz", root / "fuzz" / "state")

    def _write(self, c, rel, data=b"x"):
        p = c.project_root / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_bytes(data)

    def test_only_launcher_locations(self):
        import tempfile
        with tempfile.TemporaryDirectory() as d:
            c = self._campaign(d)
            queued = {
                "fuzz/harnesses/h1/aflpp-out/default/crashes/id:000000,sig:11": b"a1",
                "fuzz/harnesses/h1/aflpp-out/h1-sec/crashes/id:000003,sig:06": b"a2",
                "fuzz/harnesses/h2/.libfuzzer-cwd/crash-0a1b": b"l1",
                "fuzz/harnesses/h2/.libfuzzer-cwd/timeout-0a1b": b"l2",
            }
            ignored = {
                "src/crash-handler.c": b"s1",
                "src/lib/oom-guard.h": b"s2",
                "crash-at-root": b"s3",
                "fuzz/harnesses/h2/harness/crash-test.c": b"s4",
                "fuzz/harnesses/h2/.libfuzzer-cwd/sub/crash-nested": b"s5",
                "fuzz/harnesses/h1/aflpp-out/default/crashes/README.txt": b"s6",
                "fuzz/harnesses/h1/aflpp-out/default/hangs/id:000000": b"s7",
                "fuzz/harnesses/h1/aflpp-out/crashes/id:000009": b"s8",
            }
            for rel, data in {**queued, **ignored}.items():
                self._write(c, rel, data)
            r = dt.detect(c)
            self.assertTrue(r.alive)
            self.assertEqual(sorted(src for src, _ in r.queued), sorted(queued))
            self.assertEqual(sorted(os.path.basename(dst).split("__")[0] for _, dst in r.queued),
                             ["h1", "h1", "h2", "h2"])

    def test_old_files_skipped(self):
        import tempfile
        import time
        with tempfile.TemporaryDirectory() as d:
            c = self._campaign(d)
            rel = "fuzz/harnesses/h1/aflpp-out/default/crashes/id:000000"
            self._write(c, rel)
            old = time.time() - dt.RECENT_SECONDS - 60
            os.utime(c.project_root / rel, (old, old))
            self.assertEqual(dt.detect(c).queued, [])


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
