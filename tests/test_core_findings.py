"""UPDATE_ROADMAP.md §2 row 8: findings.sh + _lib/findings_ops.py ported into
cc_fuzzer_core.findings.

  - parity: the core CLI reproduces every findings/* golden (recorded from the
    pre-port findings.sh, one or more cases per subcommand and branch)
  - promote() is the one promotion function (§4/§11 replace it with
    pipeline.finalize + a verification marker)
  - reproducer runs: timeout / signal exit codes and crash markers
  - findings.sh is a shim; _lib/findings_ops.py is gone
"""
from __future__ import annotations

import json
import unittest

from cc_fuzzer_core import findings as F
from cc_fuzzer_core.paths import Campaign
from tests.support.cases import ROW8_CASES, assert_core_case
from tests.support.golden import REPO, GoldenTestCase


class TestRow8Parity(GoldenTestCase):
    def test_cases(self):
        for case in ROW8_CASES:
            if case.core_argv is None:
                continue
            with self.subTest(case=case.name):
                assert_core_case(self, case)


def _campaign(sb) -> Campaign:
    return Campaign(sb.project, sb.project / "fuzz", sb.project / "fuzz" / "state")


class TestPromote(GoldenTestCase):
    ARGS = dict(driver="d.c", verifier="v.sh", boundary="b", precondition="p", projected="demonstrated")

    def setUp(self):
        self.sb = self.sandbox("campaign-crashes")
        self.sb.write("d.c", "int main(void){return 0;}\n")
        self.sb.write("v.sh", "#!/bin/sh\nset -e\nclang -v | head -1\n", mode=0o755)
        self.c = _campaign(self.sb)

    def _rec(self, fid):
        for ln in F.ledger_path(self.c).read_text().splitlines():
            d = json.loads(ln)
            if d.get("id") == fid:
                return d

    def test_promotes_candidate(self):
        r = F.promote(self.c, "f002", **self.ARGS)
        self.assertEqual((r.verifier_lines, r.verifier_tools, r.warnings), (3, 2, []))
        d = self._rec("f002")
        self.assertEqual(d["status"], "finding")
        self.assertEqual(d["realism_attestation"], r.attestation)
        self.assertEqual(r.attestation["projected_vs_demonstrated"], "demonstrated")

    def test_refusals(self):
        with self.assertRaises(F.FindingsError) as e:
            F.promote(self.c, "f002", **dict(self.ARGS, boundary="", projected=""))
        self.assertEqual(e.exception.code, 2)
        self.assertIn("missing required attestation fields: --boundary --projected", str(e.exception))
        with self.assertRaises(F.FindingsError) as e:
            F.promote(self.c, "f002", **dict(self.ARGS, verifier="nope.sh"))
        self.assertEqual(e.exception.code, 2)
        with self.assertRaises(F.FindingsError) as e:
            F.promote(self.c, "f099", **self.ARGS)
        self.assertEqual(e.exception.code, 1)
        F.stale_mark(self.c, "f002")
        with self.assertRaises(F.FindingsError) as e:
            F.promote(self.c, "f002", **self.ARGS)
        self.assertIn("has status=stale", str(e.exception))
        self.assertEqual(self._rec("f002")["status"], "stale")

    def test_reattest_warns(self):
        seen = []
        r = F.promote(self.c, "f001", **self.ARGS, log=seen.append)
        self.assertEqual(seen, r.warnings)
        self.assertIn("already status=finding", r.warnings[0])

    def test_verifier_complexity(self):
        p = self.sb.write("x.sh", "a=1\nif true; then\n  foo | bar; baz && $(qux)\nfi\necho hi\n")
        self.assertEqual(F.verifier_complexity(p), (5, 5))  # a foo bar baz qux


class TestLedger(GoldenTestCase):
    def setUp(self):
        self.sb = self.sandbox("campaign-crashes")
        self.c = _campaign(self.sb)

    def test_values_match_literally(self):
        # findings.sh interpolated the value into a grep -E regex.
        self.assertEqual(F.find_by_hash(self.c, "a1b2.*"), [])
        self.assertEqual(len(F.find_by_hash(self.c, "a1b2c3d4e5f60718")), 1)
        with self.assertRaises(F.FindingsError):
            F.add_harness(self.c, "f00.", "encoder")

    def test_non_object_lines_survive_a_rewrite(self):
        # findings_ops.py crashed mid-rewrite on a JSON line that isn't an
        # object, and findings.sh then mv'd the truncated output into place.
        with open(F.ledger_path(self.c), "a") as f:
            f.write('["not", "an", "object"]\n')
        r = F.dedup(self.c, "0f1e2d3c4b5a6978")
        self.assertEqual((r.id, r.dedup_count, r.warning), ("f002", "3", ""))
        lines = F.ledger_path(self.c).read_text().splitlines()
        self.assertEqual(len(lines), 3)
        self.assertEqual(lines[2], '["not","an","object"]')

    def test_add_skip_verify_and_count(self):
        r = F.add(self.c, "abcdef012345", "oom", "f@x.c:1", "unlikely", "rc", "none.bin",
                  skip_verify=True, oracle_type="differential", divergence='{"a":1}')
        self.assertEqual(r.id, "f003")
        self.assertEqual(r.record["divergence"], {"a": 1})
        self.assertEqual(r.record["harnesses"], ["parser"])
        self.assertEqual(F.count(self.c), 3)
        self.assertEqual([d["id"] for d in F.list_candidates(self.c)], ["f002", "f003"])

    def test_drop_and_import(self):
        rec = F.drop(self.c, "fuzz/crashes/new/parser__deadbeefcafe0001.bin", "deterministic_replay", "flaky")
        self.assertEqual(len(rec["stack_hash_partial"]), 8)
        self.assertIsNone(rec["principle"])
        with self.assertRaises(F.FindingsError):
            F.import_cr(self.c)                       # no snapshot yet
        self.sb.write("fuzz/state/snapshots/code-review-1.json", json.dumps({"findings": [
            {"cr_hash": "h1", "confidence": "high", "pattern": "oob_read"}]}))
        r = F.import_cr(self.c)
        self.assertEqual(([d["id"] for d in r.imported], r.skipped), (["f003"], 0))
        self.assertEqual(F.import_cr(self.c).skipped, 1)


class TestReproducerRuns(GoldenTestCase):
    def setUp(self):
        self.sb = self.sandbox("campaign-crashes")
        self.c = _campaign(self.sb)
        self.sb.write("in.bin", b"x")

    def _bin(self, body):
        self.sb.write("h", "#!/bin/sh\n" + body, mode=0o755)
        return "h"

    def test_timeout_is_124(self):
        rc, _ = F.run_reproducer(self.c, self._bin("sleep 5\n"), "in.bin", timeout=0.3)
        self.assertEqual(rc, 124)

    def test_signal_is_128_plus_n(self):
        rc, out = F.run_reproducer(self.c, self._bin("echo before\nkill -TERM $$\n"), "in.bin")
        self.assertEqual((rc, out), (143, "before"))
        self.assertTrue(F.crashed(rc, out))

    def test_env_and_markers(self):
        rc, out = F.run_reproducer(self.c, self._bin('echo "$ASAN_OPTIONS|$1"\n\n\n'), "in.bin", leaks=False)
        self.assertEqual((rc, out), (0, f"{F.ASAN_OPTIONS_NO_LEAKS}|in.bin"))
        self.assertFalse(F.crashed(0, "all good"))
        for marker in ("SUMMARY: MemorySanitizer: x", "==1== ERROR: libFuzzer: deadly signal",
                       "CCFUZZ_ORACLE_VIOLATION", "a.c:1:2: runtime error: x"):
            self.assertTrue(F.crashed(1, marker), marker)


class TestShim(GoldenTestCase):
    def test_trailing_flag_does_not_hang(self):
        # findings.sh's `shift 2` failed on a value-less trailing flag and its
        # flag loop spun forever.
        sb = self.sandbox("campaign-crashes")
        r = sb.run(["bash", str(REPO / "scripts" / "findings.sh"), "promote", "f002", "--driver"], timeout=30)
        self.assertEqual(r.exit_code, 2)
        self.assertIn("missing required attestation fields: --driver --verifier", r.stderr)

    def test_shim(self):
        text = (REPO / "scripts" / "findings.sh").read_text()
        self.assertIn("exec python3 -m cc_fuzzer_core findings", text)
        self.assertFalse((REPO / "scripts" / "_lib" / "findings_ops.py").exists())


if __name__ == "__main__":
    unittest.main()
