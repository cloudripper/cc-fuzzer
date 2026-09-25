"""The CRS adapter (cc_fuzzer_core.crs): two seams, no loop.

A CRS owns its scheduler, its fuzzers and its corpus. What it wants from
cc-fuzzer is the judgement either side of the fuzzer -- is this crash real and
what is the smallest input that shows it, and does this patch actually fix it
without breaking the program.

These tests assert the adapter needs nothing tick-shaped: no current.json, no
campaign, no scheduler. One dict saying where the binaries are.
"""
from __future__ import annotations

import json
import os
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path

from cc_fuzzer_core import crs, patch, variants
from tests.test_minimize import SCANNER, compile_c

HAVE_CLANG = shutil.which("clang") is not None
HAVE_GIT = shutil.which("git") is not None

ORACLE_OK = """#!/usr/bin/env bash
r=$(cat); p=$(printf '%s' "$r" | python3 -c 'import json,sys;print(json.load(sys.stdin)["reproducer"])')
grep -q BOOM "$p" \\
  && printf '{"schema":"verify-verdict/v1","status":"confirmed","reason":"oracle reproduced it","evidence":["%s"]}\\n' "$p" \\
  || printf '{"schema":"verify-verdict/v1","status":"rejected","reason":"no repro"}\\n'
"""
ORACLE_NO = ('#!/usr/bin/env bash\ncat >/dev/null\n'
             'printf \'{"schema":"verify-verdict/v1","status":"rejected","reason":"not ours"}\\n\'\n')
ORACLE_BROKEN = "#!/usr/bin/env bash\ncat >/dev/null\nexit 7\n"


@unittest.skipUnless(HAVE_CLANG, "needs clang")
class TriageTest(unittest.TestCase):
    def setUp(self):
        self.td = tempfile.TemporaryDirectory()
        self.addCleanup(self.td.cleanup)
        self.d = Path(self.td.name)
        self.record = {"verify_binary": compile_c(SCANNER, self.d / "parser_verify")}
        self.crash = self.d / "crash.bin"
        payload = bytearray(b"\xcd" * 4096)
        payload[3000:3004] = b"BOOM"
        self.crash.write_bytes(bytes(payload))

    def _oracle(self, body=ORACLE_OK, name="oracle.sh"):
        p = self.d / name
        p.write_text(body)
        p.chmod(0o755)
        return {"verification": {"final_step": f"command:{p}", "timeout_s": 30}}

    def test_a_real_crash_is_confirmed_and_minimized(self):
        r = crs.triage(self.record, str(self.crash), harness="parser",
                       config=self._oracle())
        self.assertEqual(r.status, crs.CONFIRMED)
        self.assertTrue(r.submittable)
        self.assertEqual(r.original_size, 4096)
        self.assertEqual(r.size, 4)
        self.assertEqual(Path(r.pov).read_bytes(), b"BOOM")

    def test_the_minimized_pov_is_what_gets_carried_forward(self):
        """Submitting the 4KB original when four bytes will do is the thing
        this seam exists to avoid."""
        r = crs.triage(self.record, str(self.crash), harness="parser",
                       config=self._oracle())
        self.assertNotEqual(r.pov, r.original_pov)
        self.assertLess(r.size, r.original_size)

    def test_a_confirmed_bug_carries_its_byte_map(self):
        """The patch author's question: which of these bytes decide the bug."""
        r = crs.triage(self.record, str(self.crash), harness="parser",
                       config=self._oracle())
        self.assertEqual(r.sensitivity["mask"], "####")
        self.assertEqual(r.sensitivity["stack_hash"], r.stack_hash)
        self.assertEqual(r.as_dict()["sensitivity"]["schema"], "input-sensitivity/v1")

    def test_the_byte_map_can_be_skipped_and_is_not_spent_on_rejects(self):
        r = crs.triage(self.record, str(self.crash), harness="parser",
                       config=self._oracle(), do_sensitivity=False)
        self.assertEqual(r.sensitivity, {})
        r = crs.triage(self.record, str(self.crash), harness="parser",
                       config=self._oracle(ORACLE_NO, "no.sh"))
        self.assertEqual(r.sensitivity, {})

    def test_minimization_can_be_skipped(self):
        r = crs.triage(self.record, str(self.crash), harness="parser",
                       config=self._oracle(), do_minimize=False)
        self.assertEqual(r.pov, str(self.crash))
        self.assertEqual(r.status, crs.CONFIRMED)

    def test_a_non_crashing_input_stops_before_the_oracle(self):
        clean = self.d / "clean.bin"
        clean.write_bytes(b"nothing")
        r = crs.triage(self.record, str(clean), harness="parser", config=self._oracle())
        self.assertEqual(r.status, crs.NOT_A_CRASH)
        self.assertFalse(r.submittable)

    def test_the_oracle_can_reject(self):
        r = crs.triage(self.record, str(self.crash), harness="parser",
                       config=self._oracle(ORACLE_NO, "no.sh"))
        self.assertEqual(r.status, crs.REJECTED)
        self.assertFalse(r.submittable)

    def test_a_broken_oracle_is_inconclusive_not_rejected(self):
        """A bad day for the oracle must not read as 'not a bug'."""
        r = crs.triage(self.record, str(self.crash), harness="parser",
                       config=self._oracle(ORACLE_BROKEN, "broken.sh"))
        self.assertEqual(r.status, crs.INCONCLUSIVE)
        self.assertFalse(r.submittable)

    def test_weak_evidence_is_confirmed_but_not_submittable(self):
        """No verify binary was built, so the crash was only shown on the
        fuzzing binary. Good enough to triage, not to submit."""
        rec = {"harness_binary": self.record["verify_binary"]}
        r = crs.triage(rec, str(self.crash), harness="parser", config=self._oracle())
        self.assertEqual(r.status, crs.CONFIRMED)
        self.assertEqual(r.evidence_grade, variants.WEAK)
        self.assertFalse(r.submittable)

    def _authoritative(self, body=ORACLE_OK, name="oracle.sh"):
        cfg = self._oracle(body, name)
        cfg["verification"]["authoritative"] = True
        return cfg

    def test_an_authoritative_oracle_upgrades_weak_evidence(self):
        """The OSS-CRS case: every binary is a fuzzing build, so local replay is
        weak, but the scoring oracle itself reproduced it."""
        rec = {"harness_binary": self.record["verify_binary"]}
        r = crs.triage(rec, str(self.crash), harness="parser",
                       config=self._authoritative())
        self.assertEqual(r.replay_grade, variants.WEAK)
        self.assertEqual(r.evidence_grade, variants.STRONG)
        self.assertEqual(r.evidence_source, "oracle")
        self.assertTrue(r.submittable)

    def test_an_authoritative_rejection_upgrades_nothing(self):
        rec = {"harness_binary": self.record["verify_binary"]}
        r = crs.triage(rec, str(self.crash), harness="parser",
                       config=self._authoritative(ORACLE_NO, "no.sh"))
        self.assertEqual(r.evidence_grade, variants.WEAK)
        self.assertFalse(r.submittable)

    def test_authoritative_must_be_literally_true(self):
        rec = {"harness_binary": self.record["verify_binary"]}
        cfg = self._oracle()
        cfg["verification"]["authoritative"] = "yes"
        r = crs.triage(rec, str(self.crash), harness="parser", config=cfg)
        self.assertEqual(r.evidence_grade, variants.WEAK)

    def test_strong_replay_evidence_is_credited_to_replay(self):
        r = crs.triage(self.record, str(self.crash), harness="parser",
                       config=self._authoritative())
        self.assertEqual((r.evidence_grade, r.evidence_source),
                         (variants.STRONG, "replay"))

    def test_the_marker_records_the_oracle_and_the_oracle_runs_once(self):
        count = self.d / "calls"
        body = ORACLE_OK.replace("r=$(cat);", f"echo x >> {count}; r=$(cat);")
        rec = {"harness_binary": self.record["verify_binary"]}

        class C:
            project_root = self.d
            fuzz_root = self.d / "fuzz"
            state_dir = self.d / "fuzz" / "state"
        r = crs.triage(rec, str(self.crash), harness="parser",
                       config=self._authoritative(body, "counting.sh"),
                       campaign=C(), finding_id="pov-1")
        doc = json.loads(Path(r.marker).read_text())
        self.assertEqual((doc["evidence_grade"], doc["evidence_source"]),
                         ("strong", "oracle"))
        self.assertEqual(len(count.read_text().split()), 1)

    def test_it_refuses_an_instrumented_binary(self):
        rec = {"cmplog_binary": self.record["verify_binary"]}
        with self.assertRaises(variants.SelectionError):
            crs.triage(rec, str(self.crash), harness="parser", config=self._oracle())

    def test_no_campaign_or_tick_state_is_required(self):
        """The whole point: one dict, no current.json, no scheduler."""
        r = crs.triage(self.record, str(self.crash), harness="parser",
                       config=self._oracle())
        self.assertEqual(r.status, crs.CONFIRMED)
        self.assertEqual(r.marker, "", "no campaign was given, so nothing is written")
        self.assertFalse((self.d / "fuzz").exists())

    def test_a_marker_is_written_when_a_campaign_is_given(self):
        class C:
            project_root = self.d
            fuzz_root = self.d / "fuzz"
            state_dir = self.d / "fuzz" / "state"
        r = crs.triage(self.record, str(self.crash), harness="parser",
                       config=self._oracle(), campaign=C(), finding_id="pov-1")
        self.assertTrue(Path(r.marker).is_file())
        from cc_fuzzer_core.crash import pipeline
        self.assertTrue(pipeline.verified(r.directory))

    def test_the_result_carries_what_a_downstream_record_needs(self):
        """A patcher in another container keys the evidence record on the PoV's
        sha256 and reads the report, without re-running anything."""
        import hashlib
        r = crs.triage(self.record, str(self.crash), harness="parser",
                       config=self._oracle())
        self.assertEqual(r.pov_sha256, hashlib.sha256(b"BOOM").hexdigest())
        self.assertEqual(r.original_sha256,
                         hashlib.sha256(self.crash.read_bytes()).hexdigest())
        self.assertEqual(r.frames[0], r.top_frame)
        self.assertTrue(r.sanitizer_excerpt.startswith("==1==ERROR: AddressSanitizer"))
        self.assertIn("SUMMARY:", r.sanitizer_excerpt)
        d = r.as_dict()
        for k in ("pov_sha256", "original_sha256", "frames", "sanitizer_excerpt"):
            self.assertIn(k, d)

    def test_an_unminimized_pov_has_its_own_sha(self):
        r = crs.triage(self.record, str(self.crash), harness="parser",
                       config=self._oracle(), do_minimize=False)
        self.assertEqual(r.pov_sha256, r.original_sha256)

    def test_the_result_serialises(self):
        d = crs.triage(self.record, str(self.crash), harness="parser",
                       config=self._oracle()).as_dict()
        self.assertEqual(json.loads(json.dumps(d))["schema"], crs.TRIAGE_SCHEMA)


@unittest.skipUnless(HAVE_CLANG and HAVE_GIT, "needs clang and git")
class PatchSeamTest(unittest.TestCase):
    """check_patch is a facade; its gates are tested in test_patch.py. What
    matters here is that it takes the PoV triage produced."""

    def test_a_patch_is_checked_against_the_minimized_pov(self):
        from tests.test_patch import BUILD, PARSER, TEST
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            (root / "bin").mkdir()
            (root / "parser.c").write_text(PARSER)
            for n, b in (("build.sh", BUILD), ("test.sh", TEST)):
                p = root / n
                p.write_text(b)
                p.chmod(0o755)
            for args in (("init", "-q", "."), ("add", "-A"),
                         ("-c", "user.email=t@t", "-c", "user.name=t",
                          "commit", "-qm", "base")):
                subprocess.run(["git", *args], cwd=root, capture_output=True)
            subprocess.run(["./build.sh"], cwd=root, check=True, capture_output=True)

            oracle = root / "oracle.sh"
            oracle.write_text(ORACLE_OK)
            oracle.chmod(0o755)
            crash = root / "pov.bin"
            crash.write_bytes(b"\x00" * 500 + b"BOOM" + b"\x00" * 500)
            record = {"verify_binary": str(root / "bin" / "parser_fuzzer_verify")}
            cfg = {"verification": {"final_step": f"command:{oracle}", "timeout_s": 30},
                   "patch": {"apply": "command:git apply {patch}",
                             "build": "command:./build.sh", "test": "command:./test.sh",
                             "revert": "command:git checkout -- .", "timeout_s": 120}}

            t = crs.triage(record, str(crash), harness="parser", config=cfg)
            self.assertTrue(t.submittable)
            self.assertEqual(t.size, 4)

            src = (root / "parser.c").read_text()
            s = src.index('      fprintf(stderr,"==1==ERROR')
            e = src.index("      abort();\n") + len("      abort();\n")
            (root / "parser.c").write_text(src[:s] + "      continue;\n" + src[e:])
            diff = subprocess.run(["git", "diff"], cwd=root, capture_output=True,
                                  text=True).stdout
            (root / "fix.diff").write_text(diff)
            subprocess.run(["git", "checkout", "--", "parser.c"], cwd=root,
                           capture_output=True)

            v = crs.check_patch(record, str(root / "fix.diff"), t.pov,
                                project_root=root, config=cfg, harness="parser",
                                stack_hash=t.stack_hash)
            self.assertEqual(v.status, patch.FIXES, v.reason)
            self.assertTrue(v.validated)


class ExcerptTest(unittest.TestCase):
    def test_the_report_is_cut_from_its_header_through_summary(self):
        from cc_fuzzer_core.crash import replay
        text = ("INFO: Running with entropic power schedule\nnoise\n"
                "==7==ERROR: AddressSanitizer: heap-buffer-overflow\n"
                "    #0 0x1 in f /a.c:1\n"
                "SUMMARY: AddressSanitizer: heap-buffer-overflow /a.c:1 in f\n"
                "MS: 1 ChangeByte-; base unit: 0\n")
        e = replay.excerpt(text)
        self.assertTrue(e.startswith("==7==ERROR"))
        self.assertTrue(e.endswith("in f"))

    def test_it_is_bounded(self):
        from cc_fuzzer_core.crash import replay
        text = "==1==ERROR: x\n" + "    #9 0x1 in g /b.c:2\n" * 5000
        e = replay.excerpt(text)
        self.assertLessEqual(len(e.splitlines()), replay.EXCERPT_MAX_LINES)
        self.assertLessEqual(len(e), replay.EXCERPT_MAX_CHARS)

    def test_no_header_falls_back_to_the_tail(self):
        from cc_fuzzer_core.crash import replay
        self.assertEqual(replay.excerpt("a\nb\nTIMEOUT after 5s"), "a\nb\nTIMEOUT after 5s")


class AuthoritativeTest(unittest.TestCase):
    def test_poc_realism_cannot_be_declared_authoritative(self):
        """It checks an agent's work; it is not an oracle."""
        from cc_fuzzer_core.crash import verifiers
        self.assertFalse(verifiers.authoritative(
            {"verification": {"final_step": "poc-realism", "authoritative": True}}))
        self.assertTrue(verifiers.authoritative(
            {"verification": {"final_step": "command:/x", "authoritative": True}}))
        self.assertFalse(verifiers.authoritative({"verification": {"final_step": "command:/x"}}))


class SurfaceTest(unittest.TestCase):
    def test_the_adapter_does_not_import_the_loop(self):
        """If the CRS surface reached for the tick machinery, 'no loop needed'
        would be a claim rather than a fact."""
        src = Path(crs.__file__).read_text()
        self.assertNotIn("cc_fuzzer_core.loop", src)
        self.assertNotIn("from cc_fuzzer_core import loop", src)

    def test_the_corpus_helpers_bind_to_real_functions(self):
        import inspect
        for fn in (crs.safe_seeds, crs.dictionary, crs.delta_targets):
            self.assertTrue(callable(fn))
            inspect.signature(fn)


if __name__ == "__main__":
    unittest.main()
