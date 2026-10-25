"""The optional cull integration (cc_fuzzer_core.integrations.cull).

The fixture, tests/fixtures/cull/bug-candidates.sarif, was rendered by cull's
own writer (`cull.report.render_sarif_bug_candidates`, cull 0.3.0, evidence
1.8.0; regenerate with tests/fixtures/cull/make_fixture.py) and passes cull's
`check_bug_candidates`, so these tests read what cull actually emits, not a
guess at it. bug-candidates-1.6.sarif keeps the local fallbacks exercised.
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

SARIF = REPO / "tests" / "fixtures" / "cull" / "bug-candidates.sarif"          # evidence 1.8.0
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

    def test_a_hang_alert_is_a_timeout_candidate_not_dropped(self):
        """cull's `redos` preset (CWE-1333) and other hangs libFuzzer reports:
        file's ReDoS CPV is a hang; an unmapped CWE was imported as `other`
        and, with import_other off, dropped."""
        for cwe in ("CWE-1333", "1333", "CWE-400", "CWE-835"):
            ev = {"family": "CWE-1333", "alert": {"rule": "cull/cpp/redos/x", "cwes": [cwe]}}
            self.assertEqual(intake.pattern_of(ev, {}), "infinite_loop", cwe)
        self.assertEqual(intake._SINK_CLASS["infinite_loop"], "timeout")
        from cc_fuzzer_core import enums
        self.assertEqual(enums.cr_to_category("infinite_loop"), "timeout")

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

    def test_the_bag_is_culls_eight_keys(self):
        doc = json.loads(SARIF.read_text())
        for r in doc["runs"][0]["results"]:
            self.assertEqual(r["properties"]["evidence"]["version"], "1.8.0")
            self.assertEqual(set(r["properties"]["cull/v1"]),
                             {"candidate_id", "position", "reach_tier", "confidence",
                              "sink_class", "access", "call_chain", "input_hints"})

    def test_a_1_7_record_misses_only_input_hints(self):
        doc = json.loads(SARIF.read_text())
        for r in doc["runs"][0]["results"]:
            r["properties"]["evidence"]["version"] = "1.7.0"
            r["properties"]["evidence"].pop("input_hints", None)
        self.assertEqual(intake.intake(doc)["degraded_fields"], ["evidence.input_hints"])

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

    def test_reached_candidates_in_culls_order(self):
        """cull's position already weighs reachability; the tier only breaks ties."""
        r = queue.order(self.C)
        self.assertEqual(self.ids(r), ["i1", "h1", "h2", "u1"])
        self.assertEqual([c["candidate_id"] for c in r["held"]], ["n1"])
        tie = [{"candidate_id": "i", "reach_tier": "indirect", "position": 1},
               {"candidate_id": "h", "reach_tier": "harness", "position": 1}]
        self.assertEqual(self.ids(queue.order(tie)), ["h", "i"])

    def test_full_scan_spreads_the_queue_over_functions(self):
        """finals Q45, sqlite3: the generated parser yy_reduce held the first ~25
        places, and the CPVs sat at 365 and 460 with ~10 cards a round."""
        flood = [{"candidate_id": f"yy{i}", "reach_tier": "harness", "position": i + 1,
                  "function": "yy_reduce", "line": 100 + i, "family": "CWE-787"} for i in range(30)]
        other = [{"candidate_id": "cpv", "reach_tier": "harness", "position": 40,
                  "function": "shell_error_context", "line": 23158, "family": "CWE-125", "path": "bld/shell.c"},
                 {"candidate_id": "cpv-copy", "reach_tier": "harness", "position": 41,
                  "function": "shell_error_context", "line": 23158, "family": "CWE-125", "path": "test/shell.c"},
                 {"candidate_id": "cpv2", "reach_tier": "harness", "position": 42,
                  "function": "shell_error_context", "line": 23150, "family": "CWE-125"},
                 {"candidate_id": "x", "reach_tier": "indirect", "position": 35, "function": "other_fn",
                  "line": 1, "family": "CWE-787"}]
        ids = self.ids(queue.order(flood + other))
        self.assertEqual(ids[:3], ["yy0", "x", "cpv"])            # one per function, cull's order
        self.assertNotIn("cpv-copy", ids)                           # same line under another path
        # then the rest in cull's order: yy_reduce's other lines, then the CPV's other line
        self.assertEqual(ids[3:], [f"yy{i}" for i in range(1, 30)] + ["cpv2"])
        # the queue is rebuilt each round: a worked function's next line must not
        # come before a function no round has seen
        late = {"candidate_id": "late", "reach_tier": "harness", "position": 90,
                "function": "late_fn", "line": 5, "family": "CWE-125"}
        nxt = self.ids(queue.order(flood + other + [late], done=["yy0", "x", "cpv"]))
        self.assertEqual(nxt[:3], ["late", "yy1", "yy2"])
        # switched off: cull's order as before (delta mode spreads per band, Q85)
        off = self.ids(queue.order(flood + other, config={"cull": {"per_function": False}}))
        self.assertEqual(off[:3], ["yy0", "yy1", "yy2"])

    def test_full_scan_boost_by_entry_distance_confidence_and_tier(self):
        """finals Q77: cull's position divided by queue.boost, full scan only."""
        def c(cid, pos, chain=0, **kw):
            return dict({"candidate_id": cid, "reach_tier": "harness", "position": pos,
                         "function": cid, "line": 1, "family": "CWE-787",
                         "call_chain": ["f"] * chain}, **kw)
        far = c("far", 1, chain=8)                     # 1 / (4/8)**1.5 = 2.83
        near = c("near", 3, chain=2)                   # 3 / 2**1.5 = 1.06
        mid = c("mid", 4, chain=4)                     # 4 / 1 = 4
        none = c("nochain", 5)                         # no chain: 5
        harn = c("harness_code", 2, chain=1, path="fuzz/fuzz_x.c")    # harness code: 2
        conf = c("conf", 7, chain=4, confidence="medium")             # 7 / 2 = 3.5
        weak = c("weak", 6, chain=4, tier="fixed-offset")             # 6 / 0.5 = 12
        n690 = c("n690", 5.5, chain=4, family="CWE-690")              # 5.5 / 0.5 = 11
        cands = [far, near, mid, none, harn, conf, weak, n690]
        self.assertEqual(self.ids(queue.order(cands)),
                         ["near", "harness_code", "far", "conf", "mid", "nochain", "n690", "weak"])
        self.assertAlmostEqual(queue.boost(c("one", 1, chain=1)), 2 ** 1.5)  # a chain of 1 counts as 2
        self.assertEqual(queue.boost({}), 1.0)
        # off, and delta mode: cull's position as before
        culls = ["far", "harness_code", "near", "mid", "nochain", "n690", "weak", "conf"]
        self.assertEqual(self.ids(queue.order(cands, config={"cull": {"entry_boost": False}})), culls)
        self.assertEqual(self.ids(queue.order(cands, delta=True)), culls)

    def test_rare_classes_go_first_once_the_delta_sweep_is_complete(self):
        """finals Q48: file's ReDoS CPV has a candidate out of the diff (the only
        hang candidate) and sat 88th in delta order after a sweep that finished
        in round 1."""
        common = [{"candidate_id": f"w{i}", "reach_tier": "harness", "position": i + 1,
                   "pattern": "oob_write", "function": f"f{i}", "line": i} for i in range(40)]
        indiff = {"candidate_id": "d", "reach_tier": "harness", "position": 60, "pattern": "oob_write",
                  "function": "g", "line": 1, "diff_proximity": {"label": "in-diff"}}
        hang = {"candidate_id": "hang", "reach_tier": "harness", "position": 90,
                "pattern": "infinite_loop", "function": "regc", "line": 734}
        uaf = [{"candidate_id": f"u{i}", "reach_tier": "harness", "position": 70 + i,
                "pattern": "uaf", "function": f"h{i}", "line": i} for i in range(3)]
        cands = common + [indiff, hang] + uaf
        ids = lambda **kw: self.ids(queue.order(cands, delta=True, **kw))
        before = ids()
        self.assertEqual(before[0], "d")                          # sweep open: delta order
        self.assertGreater(before.index("hang"), 40)
        after = ids(sweep_done=True)
        self.assertEqual(after[:2], ["u0", "hang"])               # rare firsts, by cull position
        self.assertEqual(after[2], "d")                           # then the delta order
        self.assertEqual(sorted(after), sorted(before))           # nothing dropped
        # once per class: with u0 done, uaf is not lifted again; the hang still is
        nxt = self.ids(queue.order(cands, delta=True, sweep_done=True, done=["u0"]))
        self.assertEqual(nxt[0], "hang")
        self.assertGreater(nxt.index("u1"), nxt.index("d"))
        # a big class is never lifted; off, and full mode: unchanged
        self.assertNotEqual(ids(sweep_done=True)[0], "w0")
        self.assertEqual(self.ids(queue.order(cands, delta=True, sweep_done=True,
                                              config={"cull": {"rare_after_sweep": False}})), before)
        full = self.ids(queue.order(cands))
        self.assertEqual(self.ids(queue.order(cands, sweep_done=True)), full)

    def test_none_found_after_the_reached_tiers_are_exhausted(self):
        r = queue.order(self.C, done=["h1", "h2", "i1", "u1"])
        self.assertEqual(self.ids(r), ["n1"])

    def test_delta_orders_by_diff_proximity_then_position(self):
        C = [{"candidate_id": "h_none", "reach_tier": "harness", "position": 1},
             {"candidate_id": "h_file", "reach_tier": "harness", "position": 2,
              "diff_proximity": {"label": "changed-file", "hops": None}},
             {"candidate_id": "h_near", "reach_tier": "harness", "position": 3,
              "diff_proximity": {"label": "near-change", "hops": 1}},
             {"candidate_id": "h_flow", "reach_tier": "harness", "position": 4,
              "diff_proximity": {"label": "diff-flow", "hops": None}},
             {"candidate_id": "h_fn", "reach_tier": "harness", "position": 5,
              "diff_proximity": {"label": "changed-function", "hops": None}},
             {"candidate_id": "h_in2", "reach_tier": "harness", "position": 7,
              "diff_proximity": {"label": "in-diff", "hops": None}},
             {"candidate_id": "h_in1", "reach_tier": "harness", "position": 6,
              "diff_proximity": {"label": "in-diff", "hops": None}},
             {"candidate_id": "i_in", "reach_tier": "indirect", "position": 8,
              "diff_proximity": {"label": "in-diff", "hops": None}},
             {"candidate_id": "i_none", "reach_tier": "indirect", "position": 9}]
        self.assertEqual(self.ids(queue.order(C, delta=True)),
                         ["h_in1", "h_in2", "i_in", "h_fn", "h_flow", "h_near", "h_file", "h_none",
                          "i_none"])
        self.assertEqual(self.ids(queue.order(C)),
                         ["h_none", "h_file", "h_near", "h_flow", "h_fn", "h_in1", "h_in2",
                          "i_in", "i_none"], "without delta: position only")

    def test_delta_spreads_each_band_over_functions(self):
        """finals Q85: a large diff put a thousand in-diff lines in a few
        functions, and a CPV in another changed function sat behind them."""
        def c(cid, pos, fn, band=None, line=None, tier="harness"):
            d = {"candidate_id": cid, "reach_tier": tier, "position": pos, "function": fn,
                 "line": line or pos, "family": "CWE-787"}
            if band:
                d["diff_proximity"] = {"label": band, "hops": None}
            return d
        flood = [c(f"big{i}", i + 1, "big_fn", "in-diff") for i in range(20)]
        cpv = c("cpv", 30, "small_fn", "in-diff")
        again = c("cpv-again", 31, "big_fn", "in-diff", line=5)          # same line, other path
        fn = [c("fn1", 2, "changed_a", "changed-function"),
              c("fn2", 3, "changed_a", "changed-function"),
              c("fn3", 4, "changed_b", "changed-function")]
        far = [c("far1", 1, "far_fn"), c("far2", 2, "far_fn")]
        held = [c("n_in1", 5, "big_fn", "in-diff", line=99, tier="none-found"),
                c("n_in2", 6, "lonely", "in-diff", tier="none-found")]
        cands = flood + [cpv, again] + fn + far + held
        ids = self.ids(queue.order(cands, delta=True))
        # one per function inside each band, then the band's rest; bands in order
        self.assertEqual(ids[:2], ["big0", "cpv"])
        self.assertEqual(ids[2:21], [f"big{i}" for i in range(1, 20)])
        self.assertNotIn("cpv-again", ids)
        self.assertEqual(ids[21:24], ["fn1", "fn3", "fn2"])
        self.assertEqual(ids[24:26], ["far1", "far2"])
        # the admitted none-found in-diff candidates are spread too, after the reached
        self.assertEqual(ids[26:], ["n_in1", "n_in2"])
        # rebuilt next round: a worked function's next line comes after a fresh one,
        # but never ahead of its band's other functions or behind a later band
        nxt = self.ids(queue.order(cands, delta=True, done=["big0"]))
        self.assertEqual(nxt[:2], ["cpv", "big1"])
        self.assertLess(nxt.index("big19"), nxt.index("fn1"))
        # off: band, then cull's position
        off = self.ids(queue.order(cands, delta=True, config={"cull": {"delta_spread": False}}))
        self.assertEqual(off[:21], [f"big{i}" for i in range(20)] + ["cpv"])
        # full mode does not see bands
        self.assertEqual(self.ids(queue.order(cands))[:2], ["big0", "far1"])

    def test_triage_orders_the_head_and_drops_nothing(self):
        """finals Q88: a model's first look at the first cards; a high score
        goes first, a zero goes behind the last scored card, nothing is lost."""
        def c(cid, pos, fn):
            return {"candidate_id": cid, "reach_tier": "harness", "position": pos,
                    "function": fn, "line": pos, "family": "CWE-787"}
        cands = [c(f"k{i}", i + 1, f"fn{i}") for i in range(12)]
        base = self.ids(queue.order(cands))
        self.assertEqual(base, [f"k{i}" for i in range(12)])
        # k0..k7 looked at: k6 a visible bug, k3 plausible, k1 and k4 clearly safe;
        # k5 unscored (a failed window) stays put; k8.. were not looked at
        scores = {"k0": 2, "k1": 0, "k2": 1, "k3": 6, "k4": 0, "k6": 9, "k7": 3}
        ids = self.ids(queue.order(cands, triage=scores))
        self.assertEqual(ids, ["k6", "k3", "k0", "k2", "k5", "k7", "k1", "k4",
                               "k8", "k9", "k10", "k11"])
        self.assertEqual(sorted(ids), sorted(base))
        # rebuilt next round with the head worked: still applied, nothing comes back
        nxt = self.ids(queue.order(cands, triage=scores, done=["k6", "k3", "k0"]))
        self.assertEqual(nxt[:5], ["k2", "k5", "k7", "k1", "k4"])
        # a score for a candidate not in the queue, or none at all, changes nothing
        self.assertEqual(self.ids(queue.order(cands, triage={"gone": 9})), base)
        self.assertEqual(self.ids(queue.order(cands, triage={})), base)
        # off, and other thresholds
        self.assertEqual(self.ids(queue.order(cands, triage=scores,
                                              config={"cull": {"triage": False}})), base)
        hi = self.ids(queue.order(cands, triage=scores, config={"cull": {"triage_promote": 9,
                                                                        "triage_demote": -1}}))
        self.assertEqual(hi[:4], ["k6", "k0", "k1", "k2"])
        # held none-found candidates stay held whatever their score
        held = cands + [{"candidate_id": "n1", "reach_tier": "none-found", "position": 1}]
        r = queue.order(held, triage={"n1": 10})
        self.assertNotIn("n1", self.ids(r))
        self.assertEqual([x["candidate_id"] for x in r["held"]], ["n1"])

    def test_triage_windows_and_parse(self):
        from cc_fuzzer_core.integrations.cull import triage
        with tempfile.TemporaryDirectory() as d:
            src = Path(d) / "p" / "a.c"
            src.parent.mkdir()
            src.write_text("\n".join(f"line {i}" for i in range(1, 401)) + "\n")
            q = [{"candidate_id": f"c{i}", "function": "f" if i < 2 else f"g{i}", "path": "p/a.c",
                  "line": 250 if i == 0 else 10 + i, "function_span": {"start": 5, "end": 300 if i == 0 else 30},
                  "family": "CWE-787", "reach_tier": "harness"} for i in range(13)]
            w = triage.windows(q, q, d, size=5)
            self.assertEqual([n for n, _ in w], [[1, 2, 3, 4, 5], [6, 7, 8, 9, 10], [11, 12, 13]])
            self.assertTrue(w[0][1].startswith(triage.PROMPT))
            self.assertIn("### Candidate 1\n", w[0][1])
            self.assertNotIn("### Candidate 6\n", w[0][1])
            self.assertIn("    11  line 11", w[0][1])
            # a long function is cut to its head and the lines around the sink
            long_src = triage.function_source(q[0], d)
            self.assertIn("     5  line 5\n", long_src)
            self.assertIn("   ...", long_src)
            self.assertIn("   250  line 250\n", long_src)
            self.assertLessEqual(len(long_src.splitlines()), triage.MAX_SOURCE_LINES + 2)
            self.assertEqual(triage.function_source({"path": "nope.c", "line": 3}, d),
                             "(source not available)")
        reply = ('thinking {"card": 1, "score": 9, "why": "x"}\n{"card": 2, "score": "3"}\n'
                 '{"card": 7, "score": 9}\n{"card": 3, "score": 11}\n{"card": 4}\nnot json {"card": x}')
        self.assertEqual(triage.parse(reply, [1, 2, 3, 4, 5]), {1: 9.0, 2: 3.0})
        self.assertEqual(triage.parse("", [1]), {})

    def test_delta_admits_a_none_found_candidate_in_the_diff(self):
        C = self.C + [
            {"candidate_id": "n_in", "reach_tier": "none-found", "position": 9,
             "diff_proximity": {"label": "in-diff", "hops": None}},
            {"candidate_id": "n_flow", "reach_tier": "none-found", "position": 8,
             "diff_proximity": {"label": "diff-flow", "hops": None}},
            {"candidate_id": "n_near", "reach_tier": "none-found", "position": 7,
             "diff_proximity": {"label": "near-change", "hops": 1}}]
        r = queue.order(C, delta=True)
        self.assertEqual(self.ids(r), ["i1", "h1", "h2", "u1", "n_in", "n_flow"])
        self.assertEqual([c["candidate_id"] for c in r["held"]], ["n_near", "n1"])
        self.assertIn("near the change admitted", r["reason"])
        self.assertNotIn("n_in", self.ids(queue.order(C)), "only in delta mode")

    def test_delta_on_the_fixture(self):
        cands = intake.intake(SARIF)["candidates"]
        delta = queue.order(cands, delta=True)
        # the in-diff candidate first, though its tier is `indirect`
        self.assertEqual([c["function"] for c in delta["queue"]],
                         ["read_header", "drop_node", "parse_chunk", "fmt_path", "lookup"])
        self.assertEqual([c["function"] for c in delta["held"]], ["copy_name"])

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


class CardContentTest(unittest.TestCase):
    """finals Q46: sqlite3's first cards said "no comparison is possible:
    missing sink.dest_capacity", listed integers in both byte orders, and
    never showed the code."""
    H = [{"value": "\\x00\\x00\\x00d", "hex": "00000064", "kind": "int", "tainted": False},
         {"value": "d\\x00\\x00\\x00", "hex": "64000000", "kind": "int", "tainted": False},
         {"value": "\\x0a", "hex": "0a", "kind": "int", "tainted": True},
         {"value": "PRAGMA", "hex": "505241474d41", "kind": "string", "tainted": True},
         {"value": "-", "hex": "2d", "kind": "int", "tainted": False}]

    def test_hints_text_first_one_byte_order_and_a_limit(self):
        self.assertEqual(cards.hints(self.H, 8), ["PRAGMA", "\\x0a", "\\x00\\x00\\x00d", "-"])
        self.assertEqual(cards.hints(self.H, 2), ["PRAGMA", "\\x0a"])
        self.assertEqual(cards.hints(["a", "a", "b"], 8), ["a", "b"])           # bare values

    def test_unsized_access_is_said_plainly(self):
        w = cards.plain_why("no comparison is possible: missing sink.dest_capacity; guarded by n > 0")
        self.assertNotIn("dest_capacity", w)
        self.assertIn("could not determine the buffer size", w)
        self.assertTrue(w.endswith("guarded by n > 0"))

    def test_the_card_shows_the_code_and_the_siblings(self):
        import tempfile
        root = Path(tempfile.mkdtemp())
        (root / "proj" / "src").mkdir(parents=True)
        (root / "proj" / "src" / "p.c").write_text("int a;\n  memcpy(buf, in, len);\n")
        c = {"candidate_id": "x", "function": "parse", "path": "proj/src/p.c", "line": 2,
             "family": "CWE-787", "reach_tier": "harness", "input_hints": self.H,
             "why": "no comparison is possible: missing sink.dest_capacity"}
        sib = [dict(c, candidate_id="y", line=9), dict(c, candidate_id="z", line=7)]
        r = cards.render([c], source_root=root, pool=[c] + sib)
        self.assertIn("code: `memcpy(buf, in, len);`", r["text"])
        self.assertIn("also in parse: 2 more candidate(s), lines 7, 9", r["text"])
        self.assertNotIn("d\\x00\\x00\\x00", r["text"])
        plain = cards.render([c])                                    # no tree, no pool
        self.assertNotIn("code:", plain["text"])
        self.assertNotIn("also in", plain["text"])
        self.assertIn("code:", cards.render([c], source_root=root)["text"])
        gone = cards.render([dict(c, path="proj/src/missing.c")], source_root=root)
        self.assertNotIn("code:", gone["text"])                      # unreadable: no line


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

    @unittest.skipUnless(shutil.which("cull"), "cull is not installed")
    def test_the_engine_runs_the_real_cull_query(self):
        """`cull engine` finds cull's engine mode, and query.run reads the
        cull-query/v1 that the real `cull query` writes."""
        from cc_fuzzer_core.integrations.cull import cli
        self.assertTrue(cli.engine_available())
        with tempfile.TemporaryDirectory() as td:
            proj = Path(td) / "campaign"
            shutil.copytree(FIXTURES / "campaign-warm", proj)
            cwd = os.getcwd()
            os.chdir(proj)
            try:
                c = _campaign()
                cfg = {"cull": {}, "query": {"engines": ["codeql"], "codeql_db": str(proj / "nodb"),
                                             "codeql_engine": cli.ENGINE_COMMAND}}
                r = query.run(c, engine="codeql", rule="oob-write",
                              params={"function": "parse", "sink": "memcpy"},
                              hypothesis="can input make parse write past its buffer?", config=cfg)
                bad = query.run(c, engine="codeql", rule="oob-write", params={"bogus": "x"},
                                hypothesis="h", config=cfg)
            finally:
                os.chdir(cwd)
        self.assertEqual(r.status, "unavailable", "no database: cull says so, nothing runs")
        self.assertEqual(r.as_dict()["params"], {"function": "parse", "sink": "memcpy"})
        self.assertEqual(bad.status, "error", "an unknown parameter is cull's error")

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

    def test_a_binary_hint_is_built_from_its_hex(self):
        """cull escapes a binary value already (`\\x89PNG`); the token comes
        from `hex`, so it is never escaped twice."""
        hint = {"value": "\\x89PNG", "encoding": "escaped", "hex": "89504e47"}
        with tempfile.TemporaryDirectory() as td:
            p = Path(td) / "h.dict"
            r = hints.merge([{"input_hints": [hint]}], p)
            text = p.read_text()
        self.assertEqual(r["added"], 1)
        self.assertIn('="\\x89PNG"', text)
        self.assertNotIn("\\\\x", text)

    def test_an_escaped_hint_without_hex_is_dropped(self):
        with tempfile.TemporaryDirectory() as td:
            p = Path(td) / "h.dict"
            r = hints.merge([{"input_hints": [{"value": "\\x89PNG", "encoding": "escaped"},
                                              {"value": "IHDR", "encoding": "text"},
                                              {"value": "x", "hex": "zz"}]}], p)
        self.assertEqual(r["added"], 1)
        self.assertEqual(len(r["invalid"]), 2)

    def test_the_fixtures_hints_are_merged_exactly(self):
        with tempfile.TemporaryDirectory() as td:
            p = Path(td) / "h.dict"
            r = hints.merge(intake.intake(SARIF)["candidates"], p)
            lines = [ln for ln in p.read_text().splitlines() if ln and not ln.startswith("#")]
        self.assertEqual(r["added"], 4)
        self.assertEqual(sorted(ln.split("=", 1)[1] for ln in lines),
                         sorted(['"IHDR"', '"GNP\\x89"', '"\\x89PNG"', '"a\\"b\\\\c"']))
        for ln in lines:
            self.assertTrue(hints.valid(ln), ln)
            self.assertNotIn("\\\\x", ln)

    def test_no_hints_is_a_no_op(self):
        """A cull before evidence 1.8.0 ships no input_hints."""
        with tempfile.TemporaryDirectory() as td:
            p = Path(td) / "h.dict"
            self.assertEqual(hints.merge(intake.intake(OLD_SARIF)["candidates"], p)["added"], 0)
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
