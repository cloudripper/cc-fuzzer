"""UPDATE_ROADMAP.md §2 row 1: enums + config ported into cc_fuzzer_core.

  - parity: `cc-fuzzer enums|config ...` reproduce the goldens recorded from
    scripts/_lib/enums.py and scripts/_lib/fuzz-config.sh (tests/support/cases.py)
  - scripts/_lib/enums.py is a re-export shim (same module objects)
  - config: nested (dotted) keys, container output, atomic writers
"""
from __future__ import annotations

import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from cc_fuzzer_core import config, enums
from cc_fuzzer_core.paths import Campaign
from tests.support.cases import ROW1_CASES, run_case
from tests.support.golden import REPO, GoldenTestCase, core


class TestRow1Parity(GoldenTestCase):
    def test_core_matches_bash_goldens(self):
        for case in ROW1_CASES:
            if case.core_argv is None:
                continue
            with self.subTest(case=case.name):
                self.assertGolden(case.name, run_case(self, case, case.core_argv))


class TestEnumsShim(unittest.TestCase):
    def test_sibling_import_is_the_core_module(self):
        code = ("import sys; sys.path.insert(0, %r)\n"
                "import enums, cc_fuzzer_core.enums as c\n"
                "assert enums is c, enums\n"
                "assert enums.CATEGORIES is c.CATEGORIES\n"
                "print(enums.cr_to_category('uaf'))\n") % str(REPO / "scripts" / "_lib")
        r = subprocess.run([sys.executable, "-c", code], capture_output=True, text=True,
                           env={**os.environ, "PYTHONPATH": str(REPO / "src")}, timeout=60)
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertEqual(r.stdout.strip(), "heap-use-after-free")

    def test_api_unchanged(self):
        for name in ("CATEGORIES", "CATEGORIES_CRASH", "CATEGORIES_LOGIC", "EXPLOITABILITY",
                     "FINDING_STATUS", "CR_STATUS", "FINDING_SOURCE", "CONFIDENCE",
                     "CR_REVIEW_MODE", "ORACLE_TYPE", "ORACLE_KIND", "HIGH_IMPACT_ORACLE_KINDS",
                     "HIGH_IMPACT_CATEGORIES", "CR_TO_CATEGORY", "CR_PATTERN_CLASSES",
                     "REC_BRANCHES", "GAP_REASONS", "HARNESS_ACTIONS", "ENGINES", "YOLO_VERBS",
                     "CR_LENS_TOKENS", "SNAPSHOT_PREFIXES", "cr_to_category", "_main", "_REGISTRY"):
            self.assertTrue(hasattr(enums, name), name)
        self.assertEqual(enums.cr_to_category("nonsense"), "logic-error")

    def test_list_verb(self):
        r = subprocess.run(core("enums", "list"), capture_output=True, text=True, timeout=60,
                           env={**os.environ, "PYTHONPATH": str(REPO / "src")})
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertIn("rec_branches", r.stdout.split())


class TestConfig(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp())
        self.addCleanup(lambda: __import__("shutil").rmtree(self.tmp, ignore_errors=True))
        state = self.tmp / "fuzz" / "state"
        state.mkdir(parents=True)
        self.c = Campaign(self.tmp, self.tmp / "fuzz", state)
        (state / "fuzz-config.json").write_text(json.dumps({
            "schema": "fuzz-config/v3", "fuzz_forks": 2,
            "yolo": {"enabled": True, "max_ticks": 5}, "odd.key": "literal"}))

    def test_lookup_nested_and_literal(self):
        doc = config.load(self.c)
        self.assertEqual(config.lookup(doc, "yolo.max_ticks"), 5)
        self.assertEqual(config.lookup(doc, "odd.key"), "literal")
        self.assertIsNone(config.lookup(doc, "yolo.nope"))
        self.assertEqual(config.lookup(doc, "yolo.nope", 7), 7)

    def test_get_text(self):
        self.assertEqual(config.get_text(self.c, "yolo.enabled"), "True")
        self.assertEqual(json.loads(config.get_text(self.c, "yolo")), {"enabled": True, "max_ticks": 5})
        self.assertEqual(config.get_text(self.c, "missing"), "")
        (self.c.state_dir / "fuzz-config.json").write_text("{bad")
        self.assertIsNone(config.get_text(self.c, "fuzz_forks"))
        self.assertEqual(config.load(self.c), {})

    def test_set_nested_creates_blocks(self):
        config.set_value(self.c, "yolo.max_ticks", "9")
        config.set_value(self.c, "query.engines", "semgrep")
        doc = config.load(self.c)
        self.assertEqual(doc["yolo"], {"enabled": True, "max_ticks": 9})
        self.assertEqual(doc["query"], {"engines": "semgrep"})
        with self.assertRaises(ValueError):
            config.set_value(self.c, "fuzz_forks.x", "1")

    def test_update_block_and_block(self):
        merged = config.update_block(self.c, "yolo", {"enabled": False})
        self.assertEqual(merged, {"enabled": False, "max_ticks": 5})
        self.assertEqual(config.block(self.c, "yolo"), merged)
        self.assertEqual(config.block(self.c, "fuzz_forks"), {})
        text = (self.c.state_dir / "fuzz-config.json").read_text()
        self.assertTrue(text.endswith("}\n"))

    def test_fork_resolution(self):
        cap = config.fork_cap()
        r = config.resolve_fuzz_forks(self.c, {})
        self.assertEqual(r.source, "file")
        self.assertEqual(r.value, str(min(2, cap)))
        r = config.resolve_fuzz_forks(self.c, {"FUZZ_FORKS": "0"})
        self.assertEqual((r.value, r.source, r.warning), ("0", "env", None))
        r = config.resolve_fuzz_forks(self.c, {"FUZZ_FORKS_OVERRIDE": "x1"})
        self.assertEqual((r.requested, r.source), ("x1", "override"))
        r = config.resolve_fuzz_forks(self.c, {"FUZZ_FORKS": str(cap + 5)})
        self.assertEqual(r.value, str(cap))
        self.assertIn("exceeds cap", r.warning)

    def test_cli_nested(self):
        env = {**os.environ, "PYTHONPATH": str(REPO / "src")}
        for k in [k for k in env if k.startswith(("FUZZ_", "PROJECT_ROOT"))]:
            env.pop(k)
        r = subprocess.run(core("config", "set", "yolo.interval_seconds", "60"), cwd=self.tmp,
                           env=env, capture_output=True, text=True, timeout=60)
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertEqual(r.stdout, "set yolo.interval_seconds = 60 in fuzz/state/fuzz-config.json\n")
        r = subprocess.run(core("config", "get", "yolo.interval_seconds"), cwd=self.tmp / "fuzz" / "state",
                           env=env, capture_output=True, text=True, timeout=60)
        self.assertEqual(r.stdout, "60\n")


if __name__ == "__main__":
    unittest.main()
