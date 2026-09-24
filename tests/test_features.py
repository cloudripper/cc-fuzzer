"""UPDATE_ROADMAP.md §9: feature flags for the unscored subsystems.

  - cc_fuzzer_core.features: defaults, fuzz-config `features`, the cve.enabled
    alias, $CC_FUZZER_FEATURES, the `feature` CLI, strip_blocks()
  - each flag off on its own gates its code paths (scripts + state + findings)
  - with every flag off the state machine still completes on the fixtures
  - the two toolbox fixes (cve-patterns.md under the campaign state dir; the
    impact_review "since the last gain" floor from the probe's ticks_since_gain)
"""
from __future__ import annotations

import json
import os
import tempfile
import unittest

from cc_fuzzer_core import features
from cc_fuzzer_core.features import FeatureError, strip_blocks
from tests.support.cases import _plateau_rich, _promote_files, _strip_derived
from tests.support.golden import GoldenTestCase, bash, core

ALL_OFF = "-impact_tiering,-disclosure_reporting,-logic_oracles,-advisory_lookup"
CUR = "fuzz/state/current.json"


def _off(name):
    return {"CC_FUZZER_FEATURES": f"-{name}"}


class TestLoad(unittest.TestCase):
    def test_defaults_all_on(self):
        f = features.load(None, env={})
        self.assertEqual(f.flags, {n: True for n in features.FEATURES})
        self.assertEqual(f.disabled(), [])
        self.assertEqual(set(f.sources.values()), {features.SRC_DEFAULT})

    def test_config_block(self):
        f = features.load({"features": {"logic_oracles": False, "impact_tiering": True}}, env={})
        self.assertEqual(f.disabled(), ["logic_oracles"])
        self.assertEqual(f.sources["logic_oracles"], features.SRC_CONFIG)

    def test_cve_enabled_alias_and_precedence(self):
        cfg = {"cve": {"enabled": False}}
        f = features.load(cfg, env={})
        self.assertFalse(f.enabled("advisory_lookup"))
        self.assertEqual(f.sources["advisory_lookup"], features.SRC_CVE_ALIAS)
        # the features block wins over the alias ...
        f = features.load({**cfg, "features": {"advisory_lookup": True}}, env={})
        self.assertTrue(f.enabled("advisory_lookup"))
        # ... and the env wins over both
        f = features.load({"cve": {"enabled": True}, "features": {"advisory_lookup": True}},
                          env={"CC_FUZZER_FEATURES": "-advisory_lookup"})
        self.assertFalse(f.enabled("advisory_lookup"))
        self.assertEqual(f.sources["advisory_lookup"], features.SRC_ENV)
        f = features.load(cfg, env={"CC_FUZZER_FEATURES": "+advisory_lookup"})
        self.assertTrue(f.enabled("advisory_lookup"))
        # the alias only ever touches advisory_lookup
        self.assertEqual(features.load(cfg, env={}).disabled(), ["advisory_lookup"])

    def test_env_syntax(self):
        flags, problems = features.parse_env(" -logic_oracles, impact_tiering -impact_tiering,+logic_oracles bogus")
        self.assertEqual(flags, {"logic_oracles": True, "impact_tiering": False})
        self.assertEqual(len(problems), 1)
        self.assertIn("bogus", problems[0])

    def test_bad_entries_are_ignored_and_reported(self):
        f = features.load({"features": {"advisory_lookup": "no", "typo": False}}, env={})
        self.assertEqual(f.disabled(), [])
        self.assertEqual(len(f.problems), 2)
        self.assertEqual(features.block_problems(None), [])
        self.assertEqual(len(features.block_problems([])), 1)

    def test_unknown_name_raises(self):
        with self.assertRaises(FeatureError):
            features.load(None, env={}).enabled("nope")

    def test_state_dir_and_campaign_inputs(self):
        with tempfile.TemporaryDirectory() as d:
            with open(os.path.join(d, "fuzz-config.json"), "w") as f:
                json.dump({"features": {"disclosure_reporting": False}}, f)
            self.assertFalse(features.enabled("disclosure_reporting", d, env={}))
            self.assertTrue(features.enabled("disclosure_reporting", os.path.join(d, "missing"), env={}))


class TestStripBlocks(unittest.TestCase):
    TEXT = ("intro\n"
            "<!-- feature:logic_oracles -->\n"
            "oracle section\n"
            "  <!-- feature:advisory_lookup -->\n"
            "  nested cve bit\n"
            "  <!-- /feature -->\n"
            "<!-- /feature -->\n"
            "mid <!-- feature:advisory_lookup -->inline cve<!-- /feature --> tail\n"
            "<!-- feature:impact_tiering -->\n"
            "tiers\n"
            "<!-- /feature -->\n"
            "end\n")

    def test_all_on_is_identity(self):
        self.assertEqual(strip_blocks(self.TEXT, features.ALL_ON), self.TEXT)
        self.assertEqual(strip_blocks(self.TEXT, {}), self.TEXT)

    def test_outer_off_takes_nested(self):
        out = strip_blocks(self.TEXT, {"logic_oracles": False})
        self.assertNotIn("oracle section", out)
        self.assertNotIn("nested cve bit", out)
        self.assertIn("mid <!-- feature:advisory_lookup -->inline cve<!-- /feature --> tail\n", out)
        self.assertTrue(out.startswith("intro\nmid "))

    def test_inner_off_inside_enabled(self):
        out = strip_blocks(self.TEXT, {"advisory_lookup": False})
        self.assertIn("oracle section\n<!-- /feature -->\n", out)
        self.assertNotIn("cve", out)
        self.assertIn("mid  tail\n", out)          # inline span only; the line stays

    def test_all_off(self):
        f = features.load(None, env={"CC_FUZZER_FEATURES": ALL_OFF})
        self.assertEqual(strip_blocks(self.TEXT, f), "intro\nmid  tail\nend\n")
        # an iterable names the ENABLED features
        self.assertEqual(strip_blocks(self.TEXT, []), "intro\nmid  tail\nend\n")

    def test_unknown_feature_raises(self):
        with self.assertRaises(FeatureError):
            strip_blocks("<!-- feature:nope -->x<!-- /feature -->", features.ALL_ON)
        # even inside a block that is being removed
        with self.assertRaises(FeatureError):
            strip_blocks("<!-- feature:impact_tiering --><!-- feature:nope -->x<!-- /feature -->"
                         "<!-- /feature -->", {"impact_tiering": False})

    def test_unbalanced_raises(self):
        with self.assertRaises(FeatureError):
            strip_blocks("<!-- feature:impact_tiering -->x", features.ALL_ON)
        with self.assertRaises(FeatureError):
            strip_blocks("x<!-- /feature -->", features.ALL_ON)


class TestCli(GoldenTestCase):
    def test_enabled_exit_codes(self):
        sb = self.sandbox("campaign-warm")
        self.assertEqual(sb.run(core("feature", "enabled", "logic_oracles")).exit_code, 0)
        self.assertEqual(sb.run(core("feature", "enabled", "logic_oracles"),
                                env=_off("logic_oracles")).exit_code, 1)
        r = sb.run(core("feature", "enabled", "nope"))
        self.assertEqual(r.exit_code, 2)
        self.assertIn("unknown feature", r.stderr)
        sb.edit_json("fuzz/state/fuzz-config.json", lambda d: d.update(features={"impact_tiering": False}))
        self.assertEqual(sb.run(core("feature", "enabled", "impact_tiering")).exit_code, 1)
        self.assertEqual(sb.run(core("feature", "enabled", "impact_tiering"),
                                env={"CC_FUZZER_FEATURES": "+impact_tiering"}).exit_code, 0)
        # FUZZ_STATE_DIR moves the config it reads
        self.assertEqual(sb.run(core("feature", "enabled", "impact_tiering"),
                                env={"FUZZ_STATE_DIR": str(sb.tmp)}).exit_code, 0)
        self.assertEqual(sb.run(core("feature", "enabled", "impact_tiering", "--state-dir",
                                     str(sb.path("fuzz/state")))).exit_code, 1)

    def test_list(self):
        sb = self.sandbox("campaign-warm")
        sb.edit_json("fuzz/state/fuzz-config.json", lambda d: d.update(cve={"enabled": False}))
        r = sb.run(core("feature", "list", "--json"), env={"CC_FUZZER_FEATURES": "-logic_oracles,-typo"})
        self.assertEqual(r.exit_code, 0, r.stderr)
        doc = json.loads(r.stdout)
        self.assertEqual(doc["disabled"], ["logic_oracles", "advisory_lookup"])
        self.assertEqual(doc["features"]["advisory_lookup"]["source"], "fuzz-config.json:cve.enabled")
        self.assertIn("typo", r.stderr)
        r = sb.run(core("feature", "list"))
        self.assertEqual(r.stdout.splitlines()[0].split()[:2], ["impact_tiering", "on"])
        # outside any campaign: defaults + env
        r = self.sandbox().run(core("feature", "list"), env=_off("impact_tiering"))
        self.assertEqual(r.exit_code, 0)
        self.assertIn("impact_tiering         off", r.stdout)

    def test_schema_validates_block(self):
        sb = self.sandbox("campaign-warm")
        r = sb.run(core("schema", "validate"))
        base = r.exit_code
        sb.edit_json("fuzz/state/fuzz-config.json", lambda d: d.update(features={"logic_oracles": False}))
        r = sb.run(core("schema", "validate"))
        self.assertEqual(r.exit_code, base, r.stdout + r.stderr)
        self.assertNotIn("features", r.stdout + r.stderr)
        sb.edit_json("fuzz/state/fuzz-config.json", lambda d: d.update(features={"logic_oracles": "no", "x": True}))
        r = sb.run(core("schema", "validate"))
        out = r.stdout + r.stderr
        self.assertNotEqual(r.exit_code, 0)
        self.assertIn("features.logic_oracles must be true or false", out)
        self.assertIn("features.x is not a known feature", out)


# ---------------------------------------------------------------------------
# each flag off
# ---------------------------------------------------------------------------

def _levers(doc):
    return [l["lever"] for l in doc["yolo_state"]["evaluation"]["toolbox"]["eligible_levers"]]


class TestAdvisoryLookupOff(GoldenTestCase):
    def test_cve_context_build_skips(self):
        sb = self.sandbox("campaign-plateau")
        r = sb.run(bash("scripts/cve-context-build.sh", "--offline"), env=_off("advisory_lookup"))
        self.assertEqual(r.exit_code, 0, r.stderr)
        self.assertEqual(r.stdout, "")
        self.assertIn("advisory_lookup feature disabled", r.stderr)
        self.assertFalse([f for f in r.files if "cve" in f], r.files)
        # the cve.enabled alias gates it too
        sb.edit_json("fuzz/state/fuzz-config.json", lambda d: d.update(cve={"enabled": False}))
        r = sb.run(bash("scripts/cve-context-build.sh", "--offline"))
        self.assertEqual((r.exit_code, r.stdout), (0, ""))
        self.assertIn("skip", r.stderr)

    def test_cve_refresh_lever_ineligible(self):
        sb = self.sandbox("campaign-plateau")
        on = sb.run(core("state", "update-current"))
        self.assertIn("cve_refresh", _levers(on.file_json(CUR)))
        sb = self.sandbox("campaign-plateau")
        off = sb.run(core("state", "update-current"), env=_off("advisory_lookup"))
        self.assertEqual(off.exit_code, 0, off.stderr)
        self.assertNotIn("cve_refresh", _levers(off.file_json(CUR)))

    def test_stale_cve_context_is_ignored(self):
        sb = self.sandbox("campaign-plateau")
        _plateau_rich(sb)
        r = sb.run(core("state", "update-current"), env=_off("advisory_lookup"))
        self.assertEqual(r.exit_code, 0, r.stderr)
        ev = r.file_json(CUR)["yolo_state"]["evaluation"]
        whys = {c["why"] for c in ev["ceiling_probe"]["structural_candidates"]}
        self.assertNotIn("cve_hotspot", whys)
        self.assertIsNone(ev["toolbox"]["references"]["cve_patterns_md"])
        sb = self.sandbox("campaign-plateau")
        _plateau_rich(sb)
        r = sb.run(core("state", "ceiling-probe"), env=_off("advisory_lookup"))
        self.assertEqual(r.exit_code, 0, r.stderr)
        self.assertNotIn("cve_hotspot", r.stdout)

    def test_prescan_does_not_cross_link(self):
        from cc_fuzzer_core.paths import Campaign
        from cc_fuzzer_core.prescan import ReviewOptions, plan_review
        sb = self.sandbox("campaign-plateau")
        _plateau_rich(sb)
        sb.write("src/a.c", "int f(void) { return 0; }\n")
        c = Campaign(sb.project, sb.project / "fuzz", sb.project / "fuzz" / "state")
        opts = ReviewOptions(target_root=str(sb.project / "src"))
        self.assertTrue(plan_review(c, opts, now=1).cve_context)
        sb.edit_json("fuzz/state/fuzz-config.json", lambda d: d.update(features={"advisory_lookup": False}))
        self.assertEqual(plan_review(c, opts, now=1).cve_context, "")

    def test_cross_ref_ignores_cve_context(self):
        sb = self.sandbox("campaign-plateau")
        sb.write("fuzz/state/snapshots/cve-context-1789996000.json", json.dumps({
            "schema": "cve-context/v1", "cves": [{"cve": "CVE-1", "category": "x",
                                                  "patches": [{"functions": ["parse"], "files": ["a.c"]}]}]}))
        argv = bash("scripts/cross-ref-findings.sh", "parse@a.c:1")
        on = sb.run(argv)
        off = sb.run(argv, env=_off("advisory_lookup"))
        self.assertEqual(on.exit_code, 0, on.stderr)
        self.assertEqual(off.exit_code, 0, off.stderr)
        self.assertIn("cve-context-1789996000.json", on.stdout)
        doc = json.loads(off.stdout)
        self.assertEqual((doc["cve_history"], doc["snapshots"]["cve_context_file"]), ([], None))


class TestLogicOraclesOff(GoldenTestCase):
    def _oracle_harness(self, sb):
        sb.edit_json("fuzz/state/harnesses.json",
                     lambda d: d["harnesses"][0].update(oracle={"type": "roundtrip"}))

    def test_oracle_smoke_test_is_noop(self):
        sb = self.sandbox("campaign-crashes")
        self._oracle_harness(sb)
        r = sb.run(bash("scripts/oracle-smoke-test.sh"), env=_off("logic_oracles"))
        self.assertEqual(r.exit_code, 0, r.stderr)
        self.assertIn("logic_oracles feature disabled", r.stdout)
        self.assertEqual((r.files, r.created_dirs), ({}, []))

    def test_findings_add_refuses_logic_oracle(self):
        sb = self.sandbox("campaign-crashes")
        argv = core("findings", "add", "abcdef0123456789", "heap-buffer-overflow",
                    "parse_chunk@src/parser.c:14", "likely", "cause", "fuzz/crashes/known/f003/repro.bin")
        env = {**_off("logic_oracles"), "ORACLE_TYPE": "roundtrip", "FINDINGS_SKIP_VERIFY": "1"}
        r = sb.run(argv, env=env)
        self.assertEqual(r.exit_code, 2, r.stdout + r.stderr)
        self.assertIn("logic_oracles feature is disabled", r.stderr)
        self.assertEqual(r.files, {})
        r = sb.run(argv, env={**env, "ORACLE_TYPE": "crash"})
        self.assertEqual(r.exit_code, 0, r.stderr)

    def test_write_harness_built_refuses_logic_oracle(self):
        sb = self.sandbox("campaign-crashes")
        for f in ("t/target.c", "t/build.sh", "t/harness.c"):
            sb.write(f, "x\n")
        sb.write("t/bin", "#!/bin/sh\n", mode=0o755)
        argv = bash("scripts/write-harness-built.sh", "--target-source", "t/target.c", "--build-script",
                    "t/build.sh", "--harness-source", "t/harness.c", "--harness-binary", "t/bin",
                    "--entry-function", "parse_chunk", "--fuzzing-mode", "in_process", "--no-coverage",
                    "--coverage-disabled-reason", "x", "--no-verify", "--no-cmplog",
                    "--cmplog-disabled-reason", "y", "--harness", "parser",
                    "--oracle-config", '{"type": "invariant"}')
        r = sb.run(argv, env=_off("logic_oracles"))
        self.assertEqual(r.exit_code, 2, r.stdout + r.stderr)
        self.assertIn("logic_oracles feature is disabled", r.stderr)
        self.assertEqual(r.files, {})
        r = sb.run(argv)
        self.assertEqual(r.exit_code, 0, r.stderr)
        self.assertIn("fuzz/state/harnesses.json", r.files)


class TestImpactTieringOff(GoldenTestCase):
    def test_levers_quiet(self):
        sb = self.sandbox("campaign-plateau")
        _plateau_rich(sb)
        on = _levers(sb.run(core("state", "update-current")).file_json(CUR))
        self.assertIn("impact_review", on)
        self.assertIn("poc_upgrade", on)
        sb = self.sandbox("campaign-plateau")
        _plateau_rich(sb)
        r = sb.run(core("state", "update-current"), env=_off("impact_tiering"))
        self.assertEqual(r.exit_code, 0, r.stderr)
        off = _levers(r.file_json(CUR))
        self.assertNotIn("impact_review", off)
        self.assertNotIn("poc_upgrade", off)
        self.assertEqual([l for l in on if l not in ("impact_review", "poc_upgrade")], off)

    def test_promote_without_boundary_fields(self):
        argv = core("findings", "promote", "f002", "--driver", "fuzz/findings/f002/repro/driver.c",
                    "--verifier", "fuzz/findings/f002/repro/verify.sh")
        sb = self.sandbox("campaign-crashes")
        _promote_files(sb)
        r = sb.run(argv)
        self.assertEqual(r.exit_code, 2)
        self.assertIn("--boundary --precondition --projected", r.stderr)
        r = sb.run(argv, env=_off("impact_tiering"))
        self.assertEqual(r.exit_code, 0, r.stderr)
        rows = [json.loads(ln) for ln in sb.path("fuzz/state/findings.jsonl").read_text().splitlines() if ln]
        att = next(d for d in rows if d["id"] == "f002")["realism_attestation"]
        self.assertEqual(set(att) & {"boundary", "precondition", "projected_vs_demonstrated"}, set())
        # driver + verifier stay required
        r = sb.run(core("findings", "promote", "f002", "--driver", "fuzz/findings/f002/repro/driver.c"),
                   env=_off("impact_tiering"))
        self.assertEqual(r.exit_code, 2)
        self.assertIn("--verifier", r.stderr)


class TestDisclosureReportingOff(GoldenTestCase):
    def test_header(self):
        sb = self.sandbox("campaign-warm")
        on = sb.run(bash("scripts/campaign-header.sh"))
        self.assertEqual(on.exit_code, 0, on.stderr)
        self.assertIn("authorization:", on.stdout)
        self.assertNotIn("Features disabled", on.stdout)
        sb.write("fuzz/state/authorization.json", "{not json")
        off = sb.run(bash("scripts/campaign-header.sh"), env=_off("disclosure_reporting"))
        self.assertEqual(off.exit_code, 0, off.stderr)
        self.assertNotIn("authorization", off.stdout)
        self.assertIn("Features disabled: disclosure_reporting\n", off.stdout)
        # the rest of the digest is unchanged
        strip = lambda t: [ln for ln in t.splitlines()
                           if not ln.startswith(("===", "Features disabled", "authorization:", "  ownership",
                                                 "  disclosure", "  framing"))]
        self.assertEqual([ln for ln in strip(on.stdout) if ln], [ln for ln in strip(off.stdout) if ln])

    def test_report_helpers_skip(self):
        sb = self.sandbox("campaign-warm")
        for argv in (bash("scripts/cross-ref-findings.sh", "parse@a.c:1"),
                     bash("scripts/blame-finding.sh", "src/parser.c", "1")):
            with self.subTest(argv=argv[1]):
                r = sb.run(argv, env=_off("disclosure_reporting"))
                self.assertEqual((r.exit_code, r.stdout, r.files), (0, "", {}))
                self.assertIn("disclosure_reporting feature disabled", r.stderr)
                self.assertEqual(sb.run(argv).exit_code, 0)
                self.assertTrue(sb.run(argv).stdout.startswith("{"))

    def test_authorization_example_template(self):
        from tests.support.golden import REPO
        doc = json.loads((REPO / "templates" / "authorization.json.example").read_text())
        # the fields campaign-header.sh reads
        self.assertLessEqual({"target_ownership", "disclosure_intent", "demo_framing"}, set(doc))
        text = (REPO / "scripts" / "campaign-init.sh").read_text()
        self.assertIn('"$SRC/templates/authorization.json.example" "$AUTHZ_EXAMPLE"', text)


# ---------------------------------------------------------------------------
# every flag off together
# ---------------------------------------------------------------------------

class TestAllOff(GoldenTestCase):
    ENV = {"CC_FUZZER_FEATURES": ALL_OFF}

    def test_state_machine_completes(self):
        for fixture in ("campaign-cold", "campaign-warm", "campaign-plateau", "campaign-crashes"):
            with self.subTest(fixture=fixture):
                sb = self.sandbox(fixture)
                if fixture == "campaign-plateau":
                    _plateau_rich(sb)
                r = sb.run(core("state", "update-current"), env=self.ENV)
                self.assertEqual(r.exit_code, 0, r.stderr)
                if fixture == "campaign-cold":
                    continue
                self.assertIn("yolo_state", r.file_json(CUR))
                _strip_derived(sb)
                r = sb.run(core("state", "derive", CUR), env=self.ENV)
                self.assertEqual(r.exit_code, 0, r.stderr)
                r = sb.run(core("state", "evaluate", CUR), env=self.ENV)
                self.assertEqual(r.exit_code, 0, r.stderr)
                ev = json.loads(r.stdout)
                self.assertIn("suggested_disposition", ev)
                self.assertIsNotNone(ev["toolbox"])
                levers = [l["lever"] for l in ev["toolbox"]["eligible_levers"]]
                for gated in ("cve_refresh", "impact_review", "poc_upgrade"):
                    self.assertNotIn(gated, levers)
                r = sb.run(core("yolo", "next-tick"), env=self.ENV)
                self.assertIn(r.exit_code, (0, 1), r.stderr)

    def test_gated_entry_points(self):
        sb = self.sandbox("campaign-plateau")
        h = sb.run(bash("scripts/campaign-header.sh"), env=self.ENV)
        self.assertIn("Features disabled: impact_tiering, disclosure_reporting, logic_oracles, "
                      "advisory_lookup\n", h.stdout)
        for argv, stream in ((bash("scripts/cve-context-build.sh", "--offline"), "stderr"),
                             (bash("scripts/oracle-smoke-test.sh"), "stdout"),
                             (bash("scripts/cross-ref-findings.sh", "f@a.c:1"), "stderr")):
            with self.subTest(argv=argv[1]):
                r = sb.run(argv, env=self.ENV)
                self.assertEqual(r.exit_code, 0, r.stderr)
                self.assertIn("disabled", getattr(r, stream))
                self.assertFalse([f for f in r.files if "snapshots" in f])


# ---------------------------------------------------------------------------
# the two named toolbox fixes (default flags)
# ---------------------------------------------------------------------------

class TestToolboxFixes(unittest.TestCase):
    def _compute(self, state_dir, *, events=(), ceiling=None, fuzz_dir=None):
        from cc_fuzzer_core.state import toolbox
        return toolbox.compute(state_dir, os.path.join(state_dir, "snapshots"), {}, {}, list(events), [],
                               0, "normal", [], 2, 1000, ceiling=ceiling, fuzz_dir=fuzz_dir)

    def test_cve_patterns_md_follows_the_state_dir(self):
        with tempfile.TemporaryDirectory() as d:
            fuzz = os.path.join(d, "project", "fuzz")
            state = os.path.join(d, "elsewhere")
            os.makedirs(fuzz)
            os.makedirs(state)
            with open(os.path.join(state, "cve-patterns.md"), "w") as f:
                f.write("patterns\n")
            ref = self._compute(state, fuzz_dir=fuzz)["references"]["cve_patterns_md"]
            self.assertEqual(ref["path"], os.path.join(state, "cve-patterns.md"))
            # the default layout still reports the project-relative path
            os.makedirs(os.path.join(fuzz, "state"))
            os.rename(os.path.join(state, "cve-patterns.md"), os.path.join(fuzz, "state", "cve-patterns.md"))
            ref = self._compute(os.path.join(fuzz, "state"))["references"]["cve_patterns_md"]
            self.assertEqual(ref["path"], "fuzz/state/cve-patterns.md")

    def test_impact_review_floor_is_the_last_gain(self):
        ticks = [{"event": "tick", "ts": t, "branch": "wait"} for t in (100, 200, 300, 400, 500)]
        old_review = {"event": "agent_call", "ts": 250, "agent_called": "code-reviewer-deep",
                      "reason": "structural:impact_review"}
        with tempfile.TemporaryDirectory() as d:
            # the gain landed 1 roundup ago (at/before tick 400): the review at
            # 250 predates it, so the lever is eligible again.
            ceiling = {"ladder_stage": 1, "ticks_since_gain": 1}
            levers = [l["lever"] for l in self._compute(d, events=ticks + [old_review],
                                                        ceiling=ceiling)["eligible_levers"]]
            self.assertIn("impact_review", levers)
            # a review after the gain satisfies it
            new_review = dict(old_review, ts=450)
            levers = [l["lever"] for l in self._compute(d, events=ticks + [new_review],
                                                        ceiling=ceiling)["eligible_levers"]]
            self.assertNotIn("impact_review", levers)
            # no gain inside the tick window: the floor is enabled_at_ts, as before
            levers = [l["lever"] for l in self._compute(d, events=ticks + [old_review],
                                                        ceiling={"ladder_stage": 1, "ticks_since_gain": 9})
                      ["eligible_levers"]]
            self.assertNotIn("impact_review", levers)


if __name__ == "__main__":
    unittest.main()
