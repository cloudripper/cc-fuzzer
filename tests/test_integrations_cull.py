"""The optional cull integration (cc_fuzzer_core.integrations.cull).

The fixture, tests/fixtures/cull/bug-candidates.sarif, was rendered by cull's
own writer (`cull.report.render_sarif_bug_candidates`, cull 0.1.0, evidence
1.6.0) and passes cull's `check_bug_candidates`, so these tests read what
cull actually emits, not a guess at it.
"""
from __future__ import annotations

import copy
import json
import os
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from cc_fuzzer_core import features, ledger, query
from cc_fuzzer_core.integrations.cull import (cards, crmap, feedback, hints, intake,
                                              queue)
from cc_fuzzer_core.paths import campaign as _campaign
from tests.support.golden import FIXTURES, REPO

SARIF = REPO / "tests" / "fixtures" / "cull" / "bug-candidates.sarif"          # evidence 1.7.0
OLD_SARIF = REPO / "tests" / "fixtures" / "cull" / "bug-candidates-1.6.sarif"  # the fallbacks
GOLDEN = REPO / "tests" / "golden" / "cull" / "code-review-v1.json"


def _doc():
    return json.loads(SARIF.read_text())


def _older(doc):
    """What an evidence-1.3 cull wrote: no candidate_id, no cull/v1 bag, and a
    record from before reachability."""
    doc = copy.deepcopy(doc)
    run = doc["runs"][0]
    run["properties"].pop("cull/v1:provenance", None)
    for r in run["results"]:
        r["properties"].pop("cull/v1", None)
        r["partialFingerprints"].pop("cullCandidateV1", None)
        ev = r["properties"]["evidence"]
        ev["version"] = "1.3.0"
        for k in ("candidate_id", "reachability", "reach_tier", "call_chain", "why",
                  "sink_class", "access"):
            ev.pop(k, None)
    return doc


class _Campaign(unittest.TestCase):
    def setUp(self):
        self.td = tempfile.TemporaryDirectory()
        self.addCleanup(self.td.cleanup)
        self.project = Path(self.td.name) / "campaign"
        shutil.copytree(FIXTURES / "campaign-warm", self.project)
        self.cwd = os.getcwd()
        os.chdir(self.project)
        self.addCleanup(os.chdir, self.cwd)
        self.c = _campaign()


class IntakeTest(unittest.TestCase):
    def test_current_cull_needs_no_local_derivation_of_ids(self):
        d = intake.intake(SARIF)
        self.assertEqual({c["id_source"] for c in d["candidates"]}, {"cull"})
        self.assertEqual(d["provenance"]["db_sha256"], "b" * 64)
        self.assertEqual(d["provenance"]["cull_run"], "b" * 64)
        self.assertEqual(d["counts"]["candidates"], 6)

    def test_intake_version_gate(self):
        """An older evidence record degrades field by field and never fails."""
        d = intake.intake(_older(_doc()))
        c = d["candidates"][0]
        self.assertEqual((c["id_source"], c["confidence_source"], c["reach_tier"]),
                         ("local", "local", "unknown"))
        for f in ("candidate_id", "confidence", "reach_tier", "provenance"):
            self.assertIn(f, d["degraded_fields"])
        self.assertIsNone(d["provenance"]["db_sha256"])
        self.assertEqual(d["provenance"]["cull_version"], "0.3.0", "from the driver")

    def test_candidate_id_formula_match(self):
        """The local formula gives exactly cull's ids."""
        for r in _doc()["runs"][0]["results"]:
            ev = r["properties"]["evidence"]
            self.assertEqual(intake.candidate_id(ev), ev["candidate_id"])
            self.assertEqual(intake.candidate_id(ev), r["partialFingerprints"]["cullCandidateV1"])
        old = intake.intake(_older(_doc()))
        new = intake.intake(SARIF)
        self.assertEqual(sorted(c["candidate_id"] for c in old["candidates"]),
                         sorted(c["candidate_id"] for c in new["candidates"]))

    def test_candidate_id_matches_culls_pinned_values(self):
        """The three values cull pins in tests/test_consumer_fields.py."""
        cases = [({"family": "CWE-787", "location": {"path": "src/chunk.c", "line": 88,
                                                     "function": "copy_chunk"}}, "d6145ac3250782fb"),
                 ({"family": "CWE-476", "alert": {"rule": "cpp/missing-null-test"},
                   "location": {"path": "a.c", "line": 5, "function": "f"}}, "d4f879f70c6b4d8e"),
                 ({"family": "CWE-787", "location": {}}, "c57b4e446f10fa75")]
        for ev, want in cases:
            with self.subTest(want=want):
                self.assertEqual(intake.candidate_id(ev), want)

    def test_an_invalid_file_is_an_error_not_an_empty_intake(self):
        bad = _doc()
        del bad["runs"][0]["results"][0]["locations"][0]["logicalLocations"]
        with self.assertRaises(intake.IntakeError):
            intake.intake(bad)
        with self.assertRaises(intake.IntakeError):
            intake.intake({"version": "2.0.0", "runs": []})

    def test_an_unknown_major_version_is_refused(self):
        doc = _doc()
        for r in doc["runs"][0]["results"]:
            r["properties"]["evidence"]["version"] = "2.0.0"
        with self.assertRaises(intake.IntakeError):
            intake.intake(doc)

    def test_a_degraded_run_is_accepted_unless_configured_not_to_be(self):
        doc = _doc()
        doc["runs"][0]["properties"]["cull/v1:provenance"]["degraded"] = True
        self.assertTrue(intake.intake(doc)["provenance"]["degraded"])
        with self.assertRaises(intake.IntakeError):
            intake.intake(doc, config={"cull": {"accept_degraded": False}})

    def test_evidence_1_7_needs_no_local_derivation(self):
        """cull's acceptance check: every field decided by cull."""
        d = intake.intake(SARIF)
        self.assertEqual(d["degraded_fields"], [])
        for c in d["candidates"]:
            self.assertEqual((c["id_source"], c["confidence_source"], c["reach_source"]),
                             ("cull", "cull", "cull"))

    def test_position_is_culls_order_not_rank(self):
        d = intake.intake(SARIF)
        self.assertEqual([c["function"] for c in d["candidates"]],
                         ["copy_name", "drop_node", "fmt_path", "read_header",
                          "parse_chunk", "lookup"])
        self.assertEqual([c["position"] for c in d["candidates"]], [1, 2, 3, 4, 5, 6])

    def test_a_null_reach_tier_is_culls_answer(self):
        """null = no entry point in the database: an answer, not a gap."""
        c = [x for x in intake.intake(SARIF)["candidates"] if x["function"] == "fmt_path"][0]
        self.assertEqual((c["reach_tier"], c["reach_source"]), ("unknown", "cull"))

    def test_cull_decides_tier_confidence_sink_and_chain(self):
        by = {c["function"]: c for c in intake.intake(SARIF)["candidates"]}
        pc = by["parse_chunk"]
        self.assertEqual((pc["reach_tier"], pc["confidence"], pc["sink_class"]),
                         ("harness", "high", "stack-buffer-overflow"))
        self.assertEqual(pc["call_chain"], ["LLVMFuzzerTestOneInput", "parse", "parse_chunk"])
        self.assertTrue(pc["why"].startswith("the length read from the header"))
        self.assertEqual(by["lookup"]["call_chain"], [], "none-found has no path")

    def test_reach_tiers_map_from_reachability(self):
        """The pre-1.7 fallback."""
        by = {c["function"]: c["reach_tier"] for c in intake.intake(OLD_SARIF)["candidates"]}
        self.assertEqual(by["parse_chunk"], "harness")     # input
        self.assertEqual(by["drop_node"], "harness")       # harness
        self.assertEqual(by["read_header"], "indirect")    # entry-point
        self.assertEqual(by["lookup"], "none-found")       # null

    def test_patterns(self):
        by = {c["function"]: c["pattern"] for c in intake.intake(SARIF)["candidates"]}
        self.assertEqual(by, {"parse_chunk": "oob_write", "copy_name": "oob_write",
                              "read_header": "oob_read", "drop_node": "uaf",
                              "lookup": "null_deref", "fmt_path": "other"})

    def test_the_call_chain_comes_from_the_flow_steps(self):
        """The pre-1.7 fallback: data flow standing in for a call path."""
        c = [x for x in intake.intake(OLD_SARIF)["candidates"] if x["function"] == "parse_chunk"][0]
        self.assertEqual(c["call_chain"][0], "fread(buf, 1, n, f) @ src/io.c:40")
        self.assertEqual(c["call_chain"][-1], "parse_chunk()")


class CodeReviewMappingTest(_Campaign):
    def test_cr_mapping_golden(self):
        snap = crmap.snapshot(intake.intake(SARIF, now=1780000000), now=1780000000)
        text = json.dumps(snap, indent=2, sort_keys=True) + "\n"
        if os.environ.get("CC_FUZZER_WRITE_CULL_GOLDENS") == "1":
            GOLDEN.parent.mkdir(parents=True, exist_ok=True)
            GOLDEN.write_text(text)
        self.assertEqual(json.loads(text), json.loads(GOLDEN.read_text()))

    def test_the_snapshot_passes_the_core_validator(self):
        from cc_fuzzer_core.schema import checks
        p = self.project / "cr.json"
        p.write_text(json.dumps(crmap.snapshot(intake.intake(SARIF))))
        self.assertEqual(checks.code_review(str(p)), [])

    def test_other_is_left_out_unless_asked_for(self):
        d = intake.intake(SARIF)
        self.assertNotIn("fmt_path", [f["function"] for f in crmap.snapshot(d)["findings"]])
        self.assertIn("fmt_path", [f["function"] for f in crmap.snapshot(
            d, config={"cull": {"import_other": True}})["findings"]])

    def test_import_cr_takes_only_high_and_medium(self):
        from cc_fuzzer_core import findings
        d = intake.intake(SARIF)
        paths = intake.write(d, self.c.state_dir)
        r = findings.import_cr(self.c, paths["code_review"])
        snap = json.loads(Path(paths["code_review"]).read_text())
        want = sorted(f["cr_hash"] for f in snap["findings"] if f["confidence"] in ("high", "medium"))
        self.assertEqual(sorted(x["cr_ref"] for x in r.imported), want)
        self.assertGreater(len(want), 0)
        self.assertLess(len(want), len(snap["findings"]))
        again = findings.import_cr(self.c, paths["code_review"])
        self.assertEqual(len(again.imported), 0, "dedup on cr_hash = candidate_id")

    def test_the_snapshot_stays_out_of_snapshots(self):
        """It must never shadow a model review as import-cr's 'latest'."""
        paths = intake.write(intake.intake(SARIF), self.c.state_dir)
        self.assertNotIn("/snapshots/", paths["code_review"])


class QueueTest(unittest.TestCase):
    C = [{"candidate_id": "n1", "reach_tier": "none-found", "position": 1},
         {"candidate_id": "i1", "reach_tier": "indirect", "position": 2},
         {"candidate_id": "h2", "reach_tier": "harness", "position": 4},
         {"candidate_id": "h1", "reach_tier": "harness", "position": 3},
         {"candidate_id": "u1", "reach_tier": "unknown", "position": 5}]

    def ids(self, r):
        return [c["candidate_id"] for c in r["queue"]]

    def test_queue_tier_order(self):
        r = queue.order(self.C)
        self.assertEqual(self.ids(r), ["h1", "h2", "i1", "u1"])
        self.assertEqual([c["candidate_id"] for c in r["held"]], ["n1"])

    def test_none_found_after_the_reached_tiers_are_exhausted(self):
        r = queue.order(self.C, done=["h1", "h2", "i1", "u1"])
        self.assertEqual(self.ids(r), ["n1"])

    def test_none_found_while_the_budget_is_above_the_floor(self):
        self.assertEqual(self.ids(queue.order(self.C, budget_remaining=0.5))[-1], "n1")
        self.assertNotIn("n1", self.ids(queue.order(self.C, budget_remaining=0.2)))
        self.assertIn("n1", self.ids(queue.order(
            self.C, budget_remaining=0.2, config={"cull": {"none_found_budget_floor": 0.1}})))


class CardsTest(unittest.TestCase):
    def test_cards_token_cap(self):
        long = {"candidate_id": "x", "function": "f", "path": "a.c", "line": 1,
                "why": "w" * 5000, "reach_tier": "harness"}
        r = cards.render([long], config={"cull": {"card_max_tokens": 50}})
        self.assertLessEqual(cards.tokens(r["text"].split("\n", 1)[1]), 60)
        self.assertTrue(r["text"].rstrip().endswith(cards.ELLIPSIS))
        many = [dict(long, candidate_id=str(i)) for i in range(20)]
        r = cards.render(many, config={"cull": {"card_max_tokens": 100, "cards_max_tokens": 350,
                                               "cards_top_k": 20}})
        self.assertLessEqual(r["tokens"], 350)
        self.assertEqual(r["cards"] + r["omitted"], 20)
        self.assertGreater(r["omitted"], 0)

    def test_a_card_says_where_why_and_how(self):
        d = intake.intake(SARIF)
        c = [x for x in d["candidates"] if x["function"] == "parse_chunk"][0]
        text = cards.card(c, 300)
        for want in ("parse_chunk", "src/parse.c:120", "why: the length read",
                     "path: LLVMFuzzerTestOneInput \u2192 parse \u2192 parse_chunk",
                     "guards: if (len > 64)"):
            self.assertIn(want, text)


class FeedbackTest(_Campaign):
    CAND = {"candidate_id": "c1", "function": "parse_chunk", "path": "src/parse.c",
            "line": 120, "position": 1}

    def test_feedback_match_rules(self):
        m = feedback.match
        self.assertEqual(m(self.CAND, ["parse_chunk @ /src/proj/src/parse.c:123"]), feedback.STRONG)
        self.assertEqual(m(self.CAND, ["parse_chunk @ /src/proj/src/parse.c:140"]), feedback.WEAK)
        self.assertEqual(m(self.CAND, ["parse_chunk @ /src/proj/src/other.c:120"]), feedback.NONE)
        six = ["f @ x.c:1"] * 5 + ["parse_chunk @ /src/parse.c:120"]
        self.assertEqual(m(self.CAND, six), feedback.NONE, "only the top five frames count")

    def _intake(self):
        return {"candidates": [self.CAND], "provenance": {"cull_run": "r1"}}

    def test_confirmed_needs_submittable_and_a_strong_match(self):
        tri = {"frames": ["parse_chunk @ /src/parse.c:121"], "submittable": True,
               "stack_hash": "h", "status": "confirmed"}
        row = feedback.from_triage(self.c.state_dir, self._intake(), tri)
        self.assertEqual((row["outcome"], row["match"], row["cull_run"]),
                         ("confirmed", "strong", "r1"))
        tri["submittable"] = False
        self.assertEqual(feedback.from_triage(self.c.state_dir, self._intake(), tri)["outcome"],
                         "inconclusive")
        self.assertIsNone(feedback.from_triage(self.c.state_dir, self._intake(),
                                               {"frames": ["g @ z.c:1"]}))

    def test_refuted_requires_evidence(self):
        with self.assertRaises(feedback.FeedbackError):
            feedback.refute(self.c.state_dir, self._intake(), "c1")
        with self.assertRaises(feedback.FeedbackError):
            feedback.refute(self.c.state_dir, self._intake(), "c1", sink_execs=10)
        row = feedback.refute(self.c.state_dir, self._intake(), "c1", sink_execs=20000)
        self.assertEqual(row["evidence"]["kind"], "coverage")
        row = feedback.refute(self.c.state_dir, self._intake(), "c1",
                              targeted={"dispatch_id": "d7", "budget_exhausted": True})
        self.assertEqual(row["evidence"]["kind"], "targeted")

    def test_feedback_append_only(self):
        tri = {"frames": ["parse_chunk @ /src/parse.c:121"], "submittable": True}
        feedback.from_triage(self.c.state_dir, self._intake(), tri)
        first = feedback.path(self.c.state_dir).read_text().splitlines()[0]
        feedback.refute(self.c.state_dir, self._intake(), "c1", sink_execs=20000)
        lines = feedback.path(self.c.state_dir).read_text().splitlines()
        self.assertEqual((len(lines), lines[0]), (2, first))
        self.assertEqual(json.loads(lines[0])["schema"], "cull-feedback/v1")


class ProvenanceTest(_Campaign):
    def test_provenance_links(self):
        """Ledger rows and triage exports reference the cull run and candidate."""
        d = intake.intake(SARIF)
        row = ledger.append(self.c, agent="seed-generator",
                            usage=ledger.Usage(10, 5, model="m"), source="driver",
                            call_id="cull-1", refs={"cull_run": d["provenance"]["cull_run"],
                                                    "candidate_id": "133f151e2cb72d29"}).row
        self.assertEqual(row["refs"]["cull_run"], "b" * 64)
        m = feedback.matcher(d)
        self.assertEqual(m({"frames": ["parse_chunk @ /work/proj/src/parse.c:121"]}),
                         "133f151e2cb72d29")
        self.assertEqual(m({"frames": ["parse_chunk @ /work/proj/src/parse.c:190"]}), "",
                         "a weak match links nothing")

    @unittest.skipUnless(shutil.which("clang"), "needs clang")
    def test_triage_carries_the_matched_candidate(self):
        from cc_fuzzer_core import crs
        from tests.test_crs import ORACLE_OK
        from tests.test_minimize import SCANNER, compile_c
        rec = {"verify_binary": compile_c(SCANNER, self.project / "scan_verify")}
        crash = self.project / "c.bin"
        crash.write_bytes(b"zBOOMz")
        o = self.project / "o.sh"
        o.write_text(ORACLE_OK)
        o.chmod(0o755)
        d = {"candidates": [{"candidate_id": "cand-parse", "function": "parse_chunk",
                             "path": "parser.c", "line": 24, "position": 1}]}
        r = crs.triage(rec, str(crash), harness="p", do_sensitivity=False,
                       config={"verification": {"final_step": f"command:{o}"}},
                       candidate_matcher=feedback.matcher(d))
        self.assertEqual(r.source_candidate_id, "cand-parse")
        self.assertEqual(r.as_dict()["source_candidate_id"], "cand-parse")

    def test_a_rerun_is_explained_by_provenance_first(self):
        a = intake.intake(SARIF)
        doc = _doc()
        doc["runs"][0]["properties"]["cull/v1:provenance"]["db_sha256"] = "c" * 64
        doc["runs"][0]["results"].pop()
        b = intake.intake(doc)
        r = intake.compare(a, b)
        self.assertIn("db_sha256", r["provenance_changed"])
        self.assertIn("database changed", r["explanation"])
        self.assertEqual(len(r["removed"]), 1)
        self.assertIn("same provenance", intake.compare(a, a)["explanation"])


class PrescanSignalTest(unittest.TestCase):
    def test_cull_hits_raise_the_suspicion_of_their_function(self):
        from cc_fuzzer_core.prescan import code_review_prescan as P
        with tempfile.TemporaryDirectory() as td:
            root = Path(td) / "proj" / "src"
            root.mkdir(parents=True)
            body = "int parse_chunk(char *b, int n) {\n" + "  n++;\n" * 130 + "  return n;\n}\n"
            (root / "parse.c").write_text(body)
            state = Path(td) / "fuzz" / "state"
            out = state / "snapshots" / "prescan.json"
            base = json.loads(Path(P.prescan(root.parent, out, sast="off").path).read_text())
            sig = intake.signal(intake.intake(SARIF))
            (state / "signals").mkdir(parents=True)
            (state / "signals" / "cull.json").write_text(json.dumps(sig))
            got = json.loads(Path(P.prescan(root.parent, out, sast="off").path).read_text())
        self.assertNotIn("signals", base)
        # both src/parse.c candidates land in the one function the file has:
        # parse_chunk (harness tier, 15) and read_header's line (indirect, 12)
        self.assertEqual(got["signals"]["attributed"], 2)
        score = lambda d: [f["suspicion_score"] for f in d["top_candidates"]  # noqa: E731
                           if f["name"] == "parse_chunk"][0]
        self.assertEqual(score(got) - score(base), 15 + 12)

    def test_a_cull_hit_outweighs_a_semgrep_high(self):
        from cc_fuzzer_core.prescan import sast_scan
        w = intake.signal(intake.intake(SARIF))["findings"]
        self.assertTrue(all(f["weight"] > sast_scan.SEVERITY_WEIGHT["high"] for f in w))


class QueryEngineTest(unittest.TestCase):
    def test_codeql_engine_no_raw_ql(self):
        """With cull configured and no engine mode, codeql runs nothing."""
        cfg = {"cull": {}, "query": {"codeql_db": "/tmp"}}
        self.assertEqual(query.budget(cfg).engines, (query.SEMGREP,))
        self.assertFalse(query.budget(cfg).codeql_direct)
        explicit = {"cull": {}, "query": {"engines": ["semgrep", "codeql"]}}
        self.assertFalse(query.budget(explicit).codeql_direct)
        self.assertTrue(query.budget({}).codeql_direct, "no cull: unchanged")

    def test_the_engine_command_is_run_and_recorded(self):
        with tempfile.TemporaryDirectory() as td:
            proj = Path(td) / "campaign"
            shutil.copytree(FIXTURES / "campaign-warm", proj)
            eng = proj / "eng.sh"
            eng.write_text('#!/bin/sh\necho "{\\"status\\":\\"ok\\",\\"hits\\":[{\\"path\\":\\"src/a.c\\",'
                           '\\"line\\":3,\\"message\\":\\"$2\\",\\"rule_id\\":\\"cull/t\\"}]}"\n')
            eng.chmod(0o755)
            cwd = os.getcwd()
            os.chdir(proj)
            try:
                c = _campaign()
                cfg = {"cull": {}, "query": {"engines": ["codeql"],
                                             "codeql_engine": f"command:{eng} --template {{template}} "
                                                              f"--params {{params}}"}}
                r = query.run(c, engine="codeql", rule="unchecked-length", params={"sink": "memcpy"},
                              hypothesis="does parse pass len to memcpy?", config=cfg)
            finally:
                os.chdir(cwd)
        self.assertEqual(r.status, "ok", r.reason)
        self.assertEqual(r.hits[0]["file"], "src/a.c")
        self.assertIn("unchecked-length", r.hits[0]["message"])
        self.assertEqual(r.as_dict()["params"], {"sink": "memcpy"})


class HintsTest(unittest.TestCase):
    def test_merge_escapes_dedups_and_tags(self):
        with tempfile.TemporaryDirectory() as td:
            p = Path(td) / "h.dict"
            p.write_text('kw1="PNG"\n')
            cands = [{"input_hints": ["PNG", 'a"b', b"\x00\xff", {"value": "IHDR"}]}]
            r = hints.merge(cands, p)
            text = p.read_text()
        self.assertEqual((r["added"], r["skipped"]), (3, 1))
        self.assertIn("# cull", text)
        self.assertIn('"a\\"b"', text)
        self.assertIn('"\\x00\\xFF"', text)
        for ln in text.splitlines():
            if ln and not ln.startswith("#"):
                self.assertTrue(hints.valid(ln), ln)

    def test_no_hints_is_a_no_op(self):
        with tempfile.TemporaryDirectory() as td:
            p = Path(td) / "h.dict"
            self.assertEqual(hints.merge(intake.intake(SARIF)["candidates"], p)["added"], 0)
            self.assertFalse(p.exists())


class GateAndIsolationTest(_Campaign):
    def _cli(self, *args, env=None):
        return subprocess.run([sys.executable, "-m", "cc_fuzzer_core", *args],
                              capture_output=True, text=True,
                              env={**os.environ, "PYTHONPATH": str(REPO / "src"), **(env or {})})

    def test_intake_is_off_until_its_flag_is_on(self):
        r = self._cli("intake", "cull", str(SARIF))
        self.assertEqual(r.returncode, 2)
        self.assertIn("cull_intake", r.stderr)
        self.assertFalse((self.c.state_dir / "cull").exists())
        r = self._cli("intake", "cull", str(SARIF), "--import", "--json",
                      env={"CC_FUZZER_FEATURES": "+cull_intake"})
        self.assertEqual(r.returncode, 0, r.stderr)
        out = json.loads(r.stdout)
        self.assertTrue(Path(out["paths"]["signal"]).is_file())
        self.assertGreater(out["imported"], 0)

    def test_the_core_never_imports_the_integration(self):
        src = REPO / "src" / "cc_fuzzer_core"
        hits = []
        for p in src.rglob("*.py"):
            if "integrations" in p.parts or p.name == "cli.py":
                continue
            import re
            if re.search(r"^\s*(from|import)\s+cc_fuzzer_core\.integrations|"
                         r"from\s+cc_fuzzer_core\s+import\s+integrations",
                         p.read_text(), re.M):
                hits.append(str(p.relative_to(src)))
        self.assertEqual(hits, [])

    def test_the_cli_survives_without_the_integration(self):
        from cc_fuzzer_core import cli
        orig = cli.OPTIONAL_SUBSYSTEMS
        cli.OPTIONAL_SUBSYSTEMS = ("cc_fuzzer_core.integrations.not_installed",)
        self.addCleanup(setattr, cli, "OPTIONAL_SUBSYSTEMS", orig)
        cli.build_parser()

    def test_default_flags_leave_the_optional_integration_off(self):
        f = features.load(None, env={})
        self.assertFalse(any(f.enabled(n) for n in
                             ("cull_intake", "cull_feedback", "cull_query_engine")))


if __name__ == "__main__":
    unittest.main()
