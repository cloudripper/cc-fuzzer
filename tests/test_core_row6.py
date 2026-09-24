"""UPDATE_ROADMAP.md §2 row 6: cmplog dict, coverage snapshot, corpus quarantine
and delta targets ported into cc_fuzzer_core.{cmplog,coverage,quarantine,delta}.

  - parity: the core CLI reproduces the Stage 0 goldens for extract-cmplog-dict,
    corpus-quarantine and find-delta-targets and every row-6 case in
    tests/support/cases.py (snapshot-coverage, check-seed-safety included)
  - the corpus-quarantine `set -e` leak is fixed (a failed move no longer aborts)
  - llvm tools resolve through tools.which ($CC_FUZZER_TOOL_<NAME> works)
  - the scripts are shims; _lib/snapshot_helpers.py is gone
"""
from __future__ import annotations

import os
import shutil
import stat
import tempfile
import time
import unittest
from pathlib import Path

from cc_fuzzer_core import cmplog, coverage, delta, quarantine
from tests.support.cases import ROW6_CASES, STUB_LLVM_PATH, _stub_cov, assert_core_case
from tests.support.golden import FIXTURES, REPO, TESTS, GoldenTestCase, core


class TestRow6Parity(GoldenTestCase):
    def test_extra_cases(self):
        for case in ROW6_CASES:
            with self.subTest(case=case.name):
                assert_core_case(self, case)

    def _stage0(self, test_cls, method, script, verb):
        """Re-run a Stage 0 bash golden test with the core CLI in place of the script."""
        from tests.support.golden import Sandbox
        orig = Sandbox.run
        target = ["bash", str(REPO / "scripts" / script)]

        def run_core(sb, argv, **kw):
            argv = list(argv)
            if argv[:2] == target:
                argv = core(*verb, *argv[2:])
            return orig(sb, argv, **kw)

        t = test_cls(method)
        Sandbox.run = run_core
        try:
            getattr(t, method)()
        finally:
            Sandbox.run = orig
            t.doCleanups()

    def test_stage0_goldens(self):
        from tests import test_golden_bash as g
        for cls, script, verb in ((g.TestExtractCmplogDict, "extract-cmplog-dict.sh", ("cmplog", "extract")),
                                  (g.TestCorpusQuarantine, "corpus-quarantine.sh", ("quarantine", "run")),
                                  (g.TestFindDeltaTargets, "find-delta-targets.sh", ("delta", "find"))):
            for method in sorted(m for m in dir(cls) if m.startswith("test_")):
                with self.subTest(test=f"{cls.__name__}.{method}"):
                    self._stage0(cls, method, script, verb)


class TestQuarantine(GoldenTestCase):
    @unittest.skipIf(os.geteuid() == 0, "root ignores directory permissions")
    def test_failed_move_does_not_abort(self):
        # corpus-quarantine.sh's `set +e ... set -e` switched errexit on for the
        # rest of the run: the first failing mv aborted it with no summary.
        sb = self.sandbox("campaign-cold")
        corpus = sb.path("fuzz/harnesses/parser/corpus")
        corpus.chmod(0o555)
        self.addCleanup(corpus.chmod, 0o755)
        r = sb.run(core("quarantine", "run", "--harness", "parser"))
        self.assertEqual(r.exit_code, 1)
        self.assertIn("promoted=0   crashed=1 (-> crashes/new/)   hung=0 (-> flaky/)   rejected=1", r.stdout)
        self.assertEqual(r.stderr.count("Permission denied; left in place"), 2)
        self.assertIn("fuzz/crashes/new/parser__360b3c72c514e016.bin", r.files)

    def test_seed_safety_patterns(self):
        cases = {
            b"rm -rf /": None,                         # needs a char after the slash
            b"rm -rf /etc": "rm -rf with absolute-path target",
            b"rm -fr /var/x": "rm -fr with absolute-path target",
            b"rm -rf '/x'": None,
            b"mkfs.ext4 /dev/nvme0n1": "mkfs on a real block device",
            b"mkfs /dev/loop0": None,
            b"shred -n1 /dev/sda": "shred on a real block device",
            b"chmod -R 777 /": "chmod on / (root recursive)",
            b"cat x > /dev/sdb1  ": "stdout redirect into a real block device",
            b"cat x > /dev/sdb1 && y": None,
            b"farm -rf /etc": None,                    # \\b word boundary
        }
        with tempfile.TemporaryDirectory() as d:
            for i, (payload, want) in enumerate(cases.items()):
                p = Path(d) / f"s{i}"
                p.write_bytes(b"\x00junk\n" + payload + b"\n")
                with self.subTest(payload=payload):
                    self.assertEqual(quarantine.seed_safety(p), want)
            big = Path(d) / "big"
            big.write_bytes(b"x" * quarantine.SCAN_BYTES + b"\nrm -rf /etc\n")
            self.assertIsNone(quarantine.seed_safety(big))  # only the first 64 KiB are scanned

    def test_run_input_timeout(self):
        with tempfile.TemporaryDirectory() as d:
            h = Path(d) / "h"
            h.write_text('#!/bin/sh\ncase "$1" in *hang*) exec sleep 30 ;; *trap*) trap "" TERM; sleep 30 ;; esac\n'
                         'exit "$(cat "$1")"\n')
            h.chmod(0o755)
            for name, content, want in (("ok", "0", 0), ("rej", "1", 1), ("crash", "77", 77)):
                (Path(d) / name).write_text(content)
                self.assertEqual(quarantine.run_input(str(h), str(Path(d) / name), d), want)
            (Path(d) / "hang").write_text("")
            t0 = time.monotonic()
            self.assertEqual(quarantine.run_input(str(h), str(Path(d) / "hang"), d, timeout=0.3), 124)
            (Path(d) / "trap").write_text("")
            self.assertEqual(quarantine.run_input(str(h), str(Path(d) / "trap"), d, timeout=0.3,
                                                  kill_after=0.3), 137)
            self.assertLess(time.monotonic() - t0, 10)


class TestCmplog(unittest.TestCase):
    def test_filter_and_escape(self):
        raw = "\n".join(["abc", "GOOD", "GOOD", "12345678a", "/usr/lib/x", "/tmp", "    ", "x" * 65,
                         'q"b\\\t'])
        self.assertEqual(cmplog.filter_entries(raw), ["GOOD", "/tmp", 'q"b\\\t'])
        self.assertEqual(cmplog.escape('q"b\\\t\x7f'), 'q\\"b\\\\\\x09\\x7f')
        self.assertEqual(cmplog.printable_runs(b"\x00abcd\x01ab\x00efgh\tij"), b"abcd\nefgh\tij\n")


class TestDelta(unittest.TestCase):
    def test_parse_diff(self):
        text = ("diff --git a/x.c b/x.c\nnew file mode 100644\n@@ -0,0 +1,3 @@\n+a\n"
                "diff --git a/y.c b/y.c\n@@ -5 +5 @@ int f(void) {\n-x\n+y\n@@ -9,2 +8,0 @@\n"
                "diff --git a/z.c b/z.c\ndeleted file mode 100644\n@@ -1,2 +0,0 @@\n")
        self.assertEqual(delta.parse_diff(text), [
            {"file": "x.c", "function_context": None, "lines_changed": [1, 3], "kind": "added"},
            {"file": "y.c", "function_context": "int f(void) {", "lines_changed": [5, 5], "kind": "modified"},
            {"file": "y.c", "function_context": None, "lines_changed": [8, 8], "kind": "modified"},
            {"file": "z.c", "function_context": None, "lines_changed": [0, 0], "kind": "deleted"},
        ])


class TestCoverage(GoldenTestCase):
    def test_helpers(self):
        self.assertEqual(coverage.cov_summary('{"data":[{"totals":{"lines":{"covered":1,"count":3}}}]}'),
                         (1, 3, "33.33"))
        self.assertEqual(coverage.cov_summary("nope"), (0, 0, 0))
        self.assertEqual(coverage.parse_status_line("#1971: cov: 88 ft: 90 exec/s: 450"), (1971, 88, 450))
        self.assertEqual(coverage.parse_status_line("#12 INITED ft: 3"), (12, 0, 0))
        with tempfile.TemporaryDirectory() as d:
            a, b = Path(d) / "a", Path(d) / "b"
            a.write_text("execs_done : 10\ncorpus_count : 7\nexecs_per_sec : 1.5\n")
            b.write_text("execs_done : 5\ncorpus_count : 3\nexecs_per_sec : 2.25\nsaved_hangs : 1\n")
            self.assertEqual(coverage.aggregate_afl_stats([a, b]), (15, 7, 0, 1, "3.75"))
            self.assertEqual(coverage.aggregate_afl_stats([a])[-1], "1.50")

    def test_llvm_via_tool_env(self):
        # No llvm on PATH: CC_FUZZER_TOOL_LLVM_COV / _LLVM_PROFDATA are enough.
        sb = self.sandbox("campaign-warm")
        _stub_cov(sb)
        stub = TESTS / "support" / "stub-llvm"
        r = sb.run(core("coverage", "snapshot", "--harness", "parser"),
                   env={"CC_FUZZER_TOOL_LLVM_COV": stub / "llvm-cov",
                        "CC_FUZZER_TOOL_LLVM_PROFDATA": stub / "llvm-profdata"})
        self.assertEqual(r.exit_code, 0, r.stderr)
        doc = r.file_json(r.stdout.strip())
        self.assertTrue(doc["instrumentation"]["ok"])
        self.assertEqual(doc["coverage"]["lines_covered"], 37)
        self.assertEqual(doc["top_unreached_functions"], ["parse_exif", "free_chunk"])


class TestShims(unittest.TestCase):
    def test_scripts_are_shims(self):
        for script, verb in (("extract-cmplog-dict.sh", "cmplog extract"),
                             ("snapshot-coverage.sh", "coverage snapshot"),
                             ("corpus-quarantine.sh", "quarantine run"),
                             ("check-seed-safety.sh", "quarantine safety"),
                             ("find-delta-targets.sh", "delta find")):
            text = (REPO / "scripts" / script).read_text()
            self.assertIn(f"exec python3 -m cc_fuzzer_core {verb}", text)
            code = "\n".join(ln for ln in text.splitlines() if not ln.lstrip().startswith("#"))
            self.assertNotIn("set -e", code)
        self.assertFalse((REPO / "scripts" / "_lib" / "snapshot_helpers.py").exists())
        self.assertIn("nix_export_tools llvm-cov llvm-profdata",
                      (REPO / "scripts" / "snapshot-coverage.sh").read_text())


if __name__ == "__main__":
    unittest.main()
