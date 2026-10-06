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

    def test_a_frame_without_a_column_keeps_its_line(self):
        """gcc's ASan prints file:line; only file:line:column loses a suffix."""
        for loc, want in (("/src/parse.c:13", "/src/parse.c:13"),
                          ("/src/parse.c:13:7", "/src/parse.c:13"),
                          ("/src/parse.c", "/src/parse.c")):
            with self.subTest(loc=loc):
                self.assertEqual(cl.top_frame([f"    #0 0x4f5a in parse_chunk {loc}"]),
                                 f"parse_chunk @ {want}")

    def test_infra_frames_skipped(self):
        text = ("==1==ERROR: AddressSanitizer: SEGV on unknown address\n"
                "    #0 0x1 in __asan_memcpy compiler-rt/asan.cc:1:2\n"
                "    #1 0x2 in fuzzer::Fuzzer::Run F.cpp:3\n"
                "    #2 0x3 in real_fn src/x.c:44:7\n")
        r = cl.classify(text)
        self.assertEqual((r.category, r.top_frame), ("null-deref", "real_fn @ src/x.c:44"))

    def test_an_abort_is_named_by_the_function_that_called_abort(self):
        """file's apprentice_sort abort(): the site was "raise @ libc", the same
        for every abort in every target."""
        text = ("==1== ERROR: libFuzzer: deadly signal\n"
                "    #0 0x1 in __sanitizer_print_stack_trace compiler-rt/x.cpp:87:3\n"
                "    #1 0x2 in fuzzer::PrintStackTrace() FuzzerUtil.cpp:210:5\n"
                "    #2 0x3 in __pthread_kill_implementation (/lib/x86_64-linux-gnu/libc.so.6+0x8e9fb)\n"
                "    #3 0x4 in raise (/lib/x86_64-linux-gnu/libc.so.6+0x4300a)\n"
                "    #4 0x5 in abort (/lib/x86_64-linux-gnu/libc.so.6+0x2a4d7)\n"
                "    #5 0x6 in apprentice_sort /src/file/src/apprentice.c:1143:9\n")
        r = cl.classify(text)
        self.assertEqual((r.category, r.top_frame), ("deadly-signal", "apprentice_sort @ /src/file/src/apprentice.c:1143"))
        self.assertEqual(cl.top_frame(["    #0 0x1 in __assert_fail (/lib/libc.so.6+0x1)",
                                       "    #1 0x2 in check_hdr src/h.c:9:3"]), "check_hdr @ src/h.c:9")
        # a project function that merely starts with the word is still a frame
        self.assertEqual(cl.top_frame(["    #0 0x1 in raise_error src/e.c:4:1"]), "raise_error @ src/e.c:4")

    def test_segv_is_split_by_address_and_access(self):
        def segv(addr, access=None, hint=""):
            text = f"==1==ERROR: AddressSanitizer: SEGV on unknown address {addr} (pc 0x1 bp 0x2 sp 0x3 T0)\n"
            if access:
                text += f"==1==The signal is caused by a {access} memory access.\n"
            if hint:
                text += f"==1==Hint: {hint}\n"
            return cl.classify(text + "    #0 0x1 in f src/x.c:1:2\n").category
        self.assertEqual(segv("0x000000000000", "READ", "address points to the zero page."), "null-deref")
        self.assertEqual(segv("0x000000000018", "WRITE"), "null-deref")      # null + a field offset
        self.assertEqual(segv("0x602000a1b2c8", "WRITE"), "wild-write")
        self.assertEqual(segv("0x602000a1b2c8", "READ"), "wild-read")
        self.assertEqual(segv("0x602000a1b2c8", "UNKNOWN"), "wild-access")
        self.assertEqual(segv("0x602000a1b2c8"), "wild-access")
        self.assertEqual(cl.classify_file(LOGS / "asan-segv-wild-write.log").category, "wild-write")

    def test_a_segv_inside_printf_is_a_format_string_bug(self):
        r = cl.classify_file(LOGS / "asan-segv-printf.log")
        self.assertEqual((r.category, r.top_frame), ("format-string", "log_message @ /src/target/src/log.c:44"))
        # printf below the top frames is just a caller, not the fault
        text = ("==1==ERROR: AddressSanitizer: SEGV on unknown address 0x602000a1b2c8\n"
                "==1==The signal is caused by a READ memory access.\n"
                "    #0 0x1 in a src/x.c:1:2\n    #1 0x2 in b src/x.c:2:2\n"
                "    #2 0x3 in c src/x.c:3:2\n    #3 0x4 in snprintf libc.c:9\n")
        self.assertEqual(cl.classify(text).category, "wild-read")

    def test_new_crash_categories_are_valid_findings(self):
        from cc_fuzzer_core import enums
        for cat in ("wild-read", "wild-write", "wild-access", "format-string"):
            self.assertIn(cat, enums.CATEGORIES_CRASH)

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
