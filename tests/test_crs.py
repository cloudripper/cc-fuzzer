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

    def test_triage_reports_the_sanitizer_and_a_policy_verdict(self):
        r = crs.triage(self.record, str(self.crash), harness="parser",
                       config={**self._oracle(),
                               "submission": {"policy": "builtin:memory-safety"}})
        self.assertEqual(r.sanitizer, "address")
        self.assertEqual(r.policy_verdict["verdict"], crs.ACCEPT)
        self.assertTrue(r.should_submit)

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


def _result(**kw):
    base = dict(status=crs.CONFIRMED, stack_hash="h1", evidence_grade=variants.STRONG)
    base.update(kw)
    return crs.TriageResult(**base)


class PolicyTest(unittest.TestCase):
    MS = {"submission": {"policy": "builtin:memory-safety"}}

    def test_policy_memory_safety(self):
        rejected = [dict(category="signed-integer-overflow", sanitizer="undefined"),
                    dict(category="ubsan-shift", sanitizer="undefined"),
                    dict(category="oom", sanitizer="libfuzzer"),
                    dict(category="timeout", sanitizer="libfuzzer"),
                    dict(category="detected", sanitizer="leak"),
                    dict(category="generic-crash", sanitizer="")]
        for kw in rejected:
            with self.subTest(**kw):
                self.assertEqual(crs.judge(_result(**kw), config=self.MS)["verdict"], crs.REJECT)
        for cat in ("heap-buffer-overflow", "heap-use-after-free", "stack-buffer-overflow"):
            with self.subTest(cat=cat):
                v = crs.judge(_result(category=cat, sanitizer="address"), config=self.MS)
                self.assertEqual(v["verdict"], crs.ACCEPT)
                self.assertEqual(v["schema"], "policy-verdict/v1")

    def test_the_default_accepts_any_confirmed_and_rejects_the_rest(self):
        self.assertEqual(crs.judge(_result(category="oom"))["verdict"], crs.ACCEPT)
        self.assertEqual(crs.judge(_result(status=crs.REJECTED))["verdict"], crs.REJECT)

    def test_the_argument_overrides_config(self):
        v = crs.judge(_result(category="oom"), config=self.MS, policy="builtin:any-confirmed")
        self.assertEqual(v["verdict"], crs.ACCEPT)

    def test_max_variants_per_stack_hash(self):
        cfg = {"submission": {"max_variants_per_stack_hash": 2}}
        self.assertEqual(crs.judge(_result(), config=cfg, seen={"h1": 1})["verdict"], crs.ACCEPT)
        v = crs.judge(_result(), config=cfg, seen={"h1": 2})
        self.assertEqual(v["verdict"], crs.REJECT)
        self.assertIn("already submitted", v["reason"])

    def test_a_custom_python_policy(self):
        import sys
        import types
        mod = types.ModuleType("my_policy_mod")
        mod.decide = lambda result, ctx: (crs.REJECT, "top frame in vendored code") \
            if "vendor" in result["top_frame"] else True
        sys.modules["my_policy_mod"] = mod
        self.addCleanup(sys.modules.pop, "my_policy_mod")
        cfg = {"submission": {"policy": "python:my_policy_mod:decide"}}
        self.assertEqual(crs.judge(_result(top_frame="f @ vendor/z.c:1"), config=cfg)["verdict"],
                         crs.REJECT)
        self.assertEqual(crs.judge(_result(top_frame="f @ src/a.c:1"), config=cfg)["verdict"],
                         crs.ACCEPT)

    def test_a_bad_policy_is_an_error(self):
        with self.assertRaises(crs.PolicyError):
            crs.judge(_result(), policy="builtin:nonsense")
        import sys
        import types
        mod = types.ModuleType("bad_policy_mod")
        mod.decide = lambda result, ctx: "maybe"
        sys.modules["bad_policy_mod"] = mod
        self.addCleanup(sys.modules.pop, "bad_policy_mod")
        with self.assertRaises(crs.PolicyError):
            crs.judge(_result(), policy="python:bad_policy_mod:decide")

    def test_a_host_policy_composes_a_builtin_through_the_public_api(self):
        """A CRS policy wraps a builtin with crs.policy(), never the private helper."""
        ms = crs.policy("builtin:memory-safety")
        self.assertEqual(ms(_result(category="oom", sanitizer="libfuzzer"))[0], crs.REJECT)
        self.assertEqual(ms(_result(category="heap-buffer-overflow", sanitizer="address")),
                         (crs.ACCEPT, "heap-buffer-overflow reported by address"))
        self.assertEqual(crs.policy()(_result().as_dict())[0], crs.ACCEPT, "the default")
        with self.assertRaises(crs.PolicyError):
            crs.policy("builtin:nonsense")

    def test_normalize_is_public(self):
        self.assertEqual(crs.normalize(True), (crs.ACCEPT, ""))
        self.assertEqual(crs.normalize(crs.REJECT), (crs.REJECT, ""))
        self.assertEqual(crs.normalize((crs.REJECT, "why")), (crs.REJECT, "why"))
        self.assertEqual(crs.normalize({"verdict": crs.ACCEPT, "reason": "r"}), (crs.ACCEPT, "r"))
        for bad in ("maybe", 3, (crs.ACCEPT,)):
            with self.subTest(bad=bad), self.assertRaises(crs.PolicyError):
                crs.normalize(bad)

    def test_should_submit_needs_both(self):
        r = _result(category="oom", sanitizer="libfuzzer")
        from dataclasses import replace
        r = replace(r, policy_verdict=crs.judge(r, config=self.MS))
        self.assertTrue(r.submittable)
        self.assertFalse(r.should_submit)


class SegvPolicyTest(unittest.TestCase):
    """A static tool that points at null dereferences (cull does by default)
    needs ASan's SEGV accepted; a bare deadly signal with no report is not a
    memory-safety finding."""
    ASAN_SEGV = ("AddressSanitizer:DEADLYSIGNAL\n"
                 "=================================================================\n"
                 "==1==ERROR: AddressSanitizer: SEGV on unknown address 0x000000000000 "
                 "(pc 0x55 bp 0x7f sp 0x7f T0)\n"
                 "==1==The signal is caused by a READ memory access.\n"
                 "==1==Hint: address points to the zero page.\n"
                 "    #0 0x55 in parse_hdr /src/p.c:12:9\n"
                 "SUMMARY: AddressSanitizer: SEGV /src/p.c:12:9 in parse_hdr")
    BARE = "AddressSanitizer:DEADLYSIGNAL\n==1==ERROR: libFuzzer: deadly signal"

    def _verdict(self, text):
        from cc_fuzzer_core.crash import classify, replay
        c = classify.classify(text, 1)
        r = _result(category=c.category, sanitizer=replay.sanitizer_of(text))
        return c.category, crs.judge(r, policy="builtin:memory-safety")["verdict"]

    def test_segv_policy(self):
        self.assertEqual(self._verdict(self.ASAN_SEGV), ("null-deref", crs.ACCEPT))
        self.assertEqual(self._verdict(self.BARE), ("generic-crash", crs.REJECT))

    def test_a_segv_category_from_another_classifier_is_accepted_too(self):
        v = crs.judge(_result(category="segv", sanitizer="address"),
                      policy="builtin:memory-safety")
        self.assertEqual(v["verdict"], crs.ACCEPT)


class SanitizerOfTest(unittest.TestCase):
    def test_first_detector_named_wins(self):
        from cc_fuzzer_core.crash import replay
        leak = ("==1==ERROR: LeakSanitizer: detected memory leaks\n"
                "SUMMARY: AddressSanitizer: 24 byte(s) leaked in 1 allocation(s).")
        self.assertEqual(replay.sanitizer_of(leak), "leak")
        self.assertEqual(replay.sanitizer_of("a.c:3:5: runtime error: signed integer overflow"),
                         "undefined")
        self.assertEqual(replay.sanitizer_of("==2==ERROR: AddressSanitizer: heap-use-after-free"),
                         "address")
        self.assertEqual(replay.sanitizer_of("==3== ERROR: libFuzzer: timeout after 25 seconds"),
                         "libfuzzer")
        self.assertEqual(replay.sanitizer_of("Segmentation fault"), "")


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


class ClusterTest(unittest.TestCase):
    """Which PoVs are one bug: stack hash first, then a patch settles it."""

    def setUp(self):
        self.td = tempfile.TemporaryDirectory()
        self.addCleanup(self.td.cleanup)
        self.d = Path(self.td.name)
        (self.d / "p.diff").write_text("--- a/x.c\n+++ b/x.c\n@@\n-a\n+b\n")
        self.docs = []
        for name, h, size in (("a1", "hA", 9), ("a2", "hA", 3), ("b1", "hB", 5), ("c1", "hC", 7)):
            p = self.d / name
            p.write_bytes(b"x" * size)
            self.docs.append({"pov": str(p), "stack_hash": h})

    def test_grouped_by_stack_hash_shortest_first(self):
        cs = crs.cluster(self.docs)
        self.assertEqual([c.id for c in cs], ["hA", "hB", "hC"])
        self.assertEqual(Path(cs[0].representative).name, "a2")
        self.assertEqual(cs[0].as_dict()["schema"], "pov-cluster/v1")

    def _merge(self, fixes):
        def fn(pov, phase, build):
            name = Path(pov).name
            return patch.PovRun(phase == "before" or name not in fixes, "h")
        return crs.merge_by_patch(crs.cluster(self.docs), str(self.d / "p.diff"), record={},
                                  project_root=self.d, replay_fn=fn)

    def test_one_patch_that_stops_two_groups_makes_them_one_bug(self):
        cs, v = self._merge({"a2", "b1"})
        self.assertEqual(cs[0].stack_hashes, ("hA", "hB"))
        self.assertEqual(Path(cs[0].representative).name, "a2")
        self.assertEqual(len(cs[0].povs), 3)
        self.assertTrue(cs[0].merged_by.endswith("p.diff"))
        self.assertEqual([c.id for c in cs[1:]], ["hC"])
        self.assertEqual(v.status, patch.DOES_NOT_FIX, "hC still crashes")

    def test_a_patch_that_stops_one_group_merges_nothing(self):
        cs, _ = self._merge({"b1"})
        self.assertEqual(len(cs), 3)

    def test_a_stale_representative_merges_nothing(self):
        def fn(pov, phase, build):
            return patch.PovRun(False)
        cs, v = crs.merge_by_patch(crs.cluster(self.docs), str(self.d / "p.diff"), record={},
                                   project_root=self.d, replay_fn=fn)
        self.assertEqual((len(cs), v.status), (3, patch.STALE))


class RankTest(unittest.TestCase):
    """A delta that plants several bugs: every in-diff crash passes the policy,
    and the most specific one has to go first."""

    IN_HUNK = {"schema": "delta-relevance/v1", "touches_diff": True,
               "frames_in_diff": ["handle_auth @ src/proto.c:230"], "functions_in_diff": []}
    IN_FUNC = {"schema": "delta-relevance/v1", "touches_diff": True,
               "frames_in_diff": [], "functions_in_diff": ["handle_auth @ src/proto.c:90"]}
    OUTSIDE = {"schema": "delta-relevance/v1", "touches_diff": False,
               "frames_in_diff": [], "functions_in_diff": []}

    def _r(self, h, category, excerpt="", delta=None, **kw):
        base = dict(stack_hash=h, category=category, sanitizer="address",
                    sanitizer_excerpt=excerpt, delta_relevance=delta or self.IN_HUNK,
                    policy_verdict={"verdict": crs.ACCEPT}, pov=f"/p/{h}")
        return _result(**{**base, **kw})

    def _order(self, results):
        return [x.result["stack_hash"] for x in crs.rank(results)]

    def test_writes_before_reads_before_missing_terminators(self):
        scan = self._r("a-scan", "heap-buffer-overflow",
                       "==1==ERROR: AddressSanitizer: heap-buffer-overflow on address 0x1\n"
                       "READ of size 1033 at 0x1 thread T0\n"
                       "    #0 0x1 in __interceptor_strchr compiler-rt/sanitizer_common_interceptors.inc:1\n"
                       "    #1 0x2 in handle_auth src/proto.c:230:9\n")
        read = self._r("b-read", "heap-buffer-overflow",
                       "READ of size 4 at 0x1 thread T0\n    #0 0x2 in handle_auth src/proto.c:231:9\n")
        write = self._r("c-write", "heap-buffer-overflow",
                        "WRITE of size 512 at 0x1 thread T0\n"
                        "    #0 0x1 in __asan_memcpy compiler-rt/asan_interceptors.cpp:1\n"
                        "    #1 0x2 in handle_auth src/proto.c:240:5\n")
        fmt = self._r("d-fmt", "format-string")
        null = self._r("e-null", "null-deref")
        uaf = self._r("f-uaf", "heap-use-after-free", "READ of size 8 at 0x1 thread T0\n")
        ranked = crs.rank([scan, null, read, uaf, write, fmt])
        self.assertEqual([x.result["stack_hash"] for x in ranked],
                         ["c-write", "d-fmt", "f-uaf", "b-read", "a-scan", "e-null"])
        self.assertIn("missing terminator", ranked[4].why[2])
        self.assertEqual([x.rank for x in ranked], [1, 2, 3, 4, 5, 6])

    def test_the_diff_outranks_the_class(self):
        out = self._r("a-out", "heap-buffer-overflow", "WRITE of size 4 at 0x1\n", delta=self.OUTSIDE)
        func = self._r("b-func", "null-deref", delta=self.IN_FUNC)
        hunk = self._r("c-hunk", "null-deref")
        self.assertEqual(self._order([out, func, hunk]), ["c-hunk", "b-func", "a-out"])

    def test_submittable_first_and_nothing_is_dropped(self):
        weak = self._r("a-weak", "wild-write", evidence_grade=variants.WEAK)
        rejected = self._r("b-pol", "wild-write", policy_verdict={"verdict": crs.REJECT})
        leak = self._r("c-leak", "leak")
        good = self._r("d-good", "null-deref")
        self.assertEqual(self._order([weak, rejected, leak, good]),
                         ["d-good", "c-leak", "b-pol", "a-weak"])
        # among the unsubmittable, a crash of any kind is above no crash
        nothing = self._r("0-none", "none", status=crs.NOT_A_CRASH, policy_verdict={})
        leaked = self._r("1-leak", "leak", status=crs.REJECTED, policy_verdict={})
        self.assertEqual(self._order([nothing, leaked]), ["1-leak", "0-none"])

    def test_exports_and_results_rank_alike_and_stably(self):
        rs = [self._r("b", "wild-read"), self._r("a", "wild-read")]
        self.assertEqual(self._order(rs), ["a", "b"])
        self.assertEqual(self._order([r.as_dict() for r in reversed(rs)]), ["a", "b"])
        doc = crs.rank(rs)[0].as_dict()
        self.assertEqual((doc["schema"], doc["rank"], doc["pov"]), (crs.RANK_SCHEMA, 1, "/p/a"))

    def test_rank_cli(self):
        import sys
        from tests.support.golden import REPO
        with tempfile.TemporaryDirectory() as td:
            paths = []
            for r in (self._r("a", "null-deref"), self._r("b", "wild-write")):
                p = Path(td) / f"{r.stack_hash}.json"
                p.write_text(json.dumps(r.as_dict()))
                paths.append(str(p))
            out = subprocess.run([sys.executable, "-m", "cc_fuzzer_core", "crs", "rank", "--json", *paths],
                                 capture_output=True, text=True,
                                 env={**os.environ, "PYTHONPATH": str(REPO / "src")})
            self.assertEqual(out.returncode, 0, out.stderr)
            self.assertEqual([d["stack_hash"] for d in json.loads(out.stdout)], ["b", "a"])


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
