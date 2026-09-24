"""UPDATE_ROADMAP.md §8: model aliasing in one place (cc_fuzzer_core.models).

  - data/models.json preserves today's agent frontmatter and the old advisory rates
  - overrides: fuzz-config.json `models` block < $CC_FUZZER_MODELS file, tier- and agent-level
  - the evaluator / lever board / halt gate consume the mapping (no hard-coded
    OPUS_AGENTS, _RATE, blended rate or model-name cost tiers left in the core)
"""
from __future__ import annotations

import json
import os
import re
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from cc_fuzzer_core import models, paths
from cc_fuzzer_core.paths import Campaign
from tests.support.golden import REPO, GoldenTestCase, core


def _frontmatter_model(md: Path) -> str | None:
    text = md.read_text()
    m = re.match(r"---\n(.*?)\n---", text, re.S)
    if not m:
        return None
    for ln in m.group(1).splitlines():
        if ln.startswith("model:"):
            return ln.split(":", 1)[1].strip()
    return None


class TestPackagedMapping(unittest.TestCase):
    def setUp(self):
        self.m = models.load(None, env={})

    def test_is_package_data(self):
        p = paths.data("models.json")
        self.assertEqual(p, REPO / "src" / "cc_fuzzer_core" / "data" / "models.json")
        self.assertEqual(paths.data("models.json", env={"CC_FUZZER_ROOT": str(REPO)}), p)
        self.assertEqual(json.loads(p.read_text())["schema"], "models/v1")

    def test_tiers(self):
        self.assertEqual(self.m.tiers, {"deep": "opus", "standard": "sonnet", "fast": "haiku"})

    def test_agents_preserve_frontmatter(self):
        seen = set()
        for md in sorted((REPO / "agents").glob("*.md")):
            fm = _frontmatter_model(md)
            if fm is None:
                continue
            with self.subTest(agent=md.stem):
                self.assertEqual(self.m.resolve(md.stem), fm)
            seen.add(md.stem)
        self.assertEqual(seen, set(self.m.agents))

    def test_pricing_lifted_from_old_rates(self):
        for model, (i, o) in {"opus": (15e-6, 75e-6), "sonnet": (3e-6, 15e-6), "haiku": (0.8e-6, 4e-6)}.items():
            ri, ro = self.m.rate(model)
            self.assertAlmostEqual(ri, i, places=12)
            self.assertAlmostEqual(ro, o, places=12)

    def test_deep_tier_is_the_old_opus_set(self):
        self.assertEqual(self.m.agents_in_tier(models.DEEP), {
            "planner-consult", "poc-builder", "campaign-planner",
            "reporting-agent", "crash-triager", "code-reviewer-deep"})

    def test_unknown_agent(self):
        self.assertEqual(self.m.resolve("nobody"), "sonnet")
        self.assertIsNone(self.m.tier_of("nobody"))
        self.assertAlmostEqual(self.m.cost(1_000_000, 0, agent="nobody"), 3.0)
        self.assertAlmostEqual(self.m.cost(0, 1_000_000, agent="poc-builder"), 75.0)
        self.assertAlmostEqual(self.m.cost(1_000_000, 0, agent="poc-builder", model="haiku"), 0.8)
        self.assertAlmostEqual(self.m.event_cost({"agent_called": "mutator", "tokens_in": 10**6}), 0.8)


class TestOverrides(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp())
        self.addCleanup(lambda: __import__("shutil").rmtree(self.tmp, ignore_errors=True))

    def _file(self, doc):
        p = self.tmp / f"m{len(list(self.tmp.iterdir()))}.json"
        p.write_text(json.dumps(doc))
        return str(p)

    def test_config_block_tier_and_agent_level(self):
        cfg = {"models": {"tiers": {"deep": "claude-opus-x"},
                          "agents": {"mutator": "standard", "seed-generator": "my-local-model"},
                          "pricing": {"my-local-model": {"input_per_mtok": 0, "output_per_mtok": 0}}}}
        m = models.load(cfg, env={})
        self.assertEqual(m.resolve("crash-triager"), "claude-opus-x")
        self.assertEqual(m.tier_of("crash-triager"), "deep")
        self.assertEqual(m.resolve("mutator"), "sonnet")
        self.assertEqual(m.resolve("seed-generator"), "my-local-model")
        self.assertIsNone(m.tier_of("seed-generator"))
        self.assertEqual(m.cost(10**6, 10**6, agent="seed-generator"), 0.0)
        # unpriced model id: charged at the default tier's rate
        self.assertAlmostEqual(m.cost(10**6, 0, agent="crash-triager"), 3.0)
        self.assertEqual(m.sources[-1], "fuzz-config.json:models")

    def test_env_file_wins_over_config(self):
        cfg = {"models": {"agents": {"mutator": "standard"}}}
        env = {models.ENV_MODELS: self._file({"agents": {"mutator": "deep"}, "tiers": {"fast": "tiny"}})}
        m = models.load(cfg, env=env)
        self.assertEqual(m.resolve("mutator"), "opus")
        self.assertEqual(m.resolve("ops-runner"), "tiny")
        self.assertEqual(models.resolve("ops-runner", env=env), "tiny")

    def test_campaign_and_state_dir_accepted(self):
        state = self.tmp / "fuzz" / "state"
        state.mkdir(parents=True)
        (state / "fuzz-config.json").write_text(json.dumps({"models": {"default_tier": "fast"}}))
        c = Campaign(self.tmp, self.tmp / "fuzz", state)
        self.assertEqual(models.load(c, env={}).resolve("nobody"), "haiku")
        self.assertEqual(models.load(str(state), env={}).resolve("nobody"), "haiku")

    def test_malformed(self):
        for bad in ({"models": []}, {"models": {"tiers": ["x"]}}, {"models": {"default_tier": "huge"}},
                    {"models": {"pricing": {"x": {"input_per_mtok": "a"}}}}):
            with self.subTest(bad=bad), self.assertRaises(models.ModelsError):
                models.load(bad, env={})
        with self.assertRaises(models.ModelsError):
            models.load(None, env={models.ENV_MODELS: str(self.tmp / "missing.json")})


class TestConsumers(GoldenTestCase):
    def test_no_hard_coded_model_policy_left(self):
        src = REPO / "src" / "cc_fuzzer_core"
        bad = re.compile(r"OPUS_AGENTS|_RATE\b|5e-6|25e-6|\"(opus|sonnet|haiku|cheap)\"")
        hits = [f"{p.relative_to(REPO)}:{i}: {ln.strip()}"
                for p in sorted((src / "state").glob("*.py"))
                for i, ln in enumerate(p.read_text().splitlines(), 1) if bad.search(ln)]
        self.assertEqual(hits, [])

    def test_lever_tier_follows_agent_override(self):
        from cc_fuzzer_core.state import toolbox
        m = models.load({"models": {"agents": {"poc-builder": "fast"}}}, env={})
        self.assertEqual(toolbox.lever_tier("poc_build", m), "fast")
        self.assertEqual(toolbox.lever_tier("poc_upgrade", models.load(None, env={})), "deep")
        self.assertEqual(toolbox.lever_tier("instrumentation", m), models.TIER_NONE)
        self.assertEqual(toolbox.lever_tier("cve_refresh", m), "standard")

    def test_overrides_reach_the_evaluator(self):
        # Price every agent at zero via $CC_FUZZER_MODELS: the yolo cost estimate
        # drops to 0 and the deep-tier share with it.
        sb = self.sandbox("campaign-plateau")
        mf = sb.write("models.json", json.dumps({"pricing": {
            m: {"input_per_mtok": 0, "output_per_mtok": 0} for m in ("opus", "sonnet", "haiku")}}))
        r = sb.run(core("state", "update-current"), env={"CC_FUZZER_MODELS": str(mf)})
        self.assertEqual(r.exit_code, 0, r.stderr)
        ys = r.file_json("fuzz/state/current.json")["yolo_state"]
        self.assertEqual(ys["estimated_cost_usd"], 0.0)
        self.assertEqual(ys["evaluation"]["cost"]["total_usd"], 0.0)
        # A broken override keeps the halt gate alive on the packaged mapping.
        (sb.tmp / "bad.json").write_text("{nope")
        r = sb.run(core("state", "update-current"), env={"CC_FUZZER_MODELS": str(sb.tmp / "bad.json")})
        ys = r.file_json("fuzz/state/current.json")["yolo_state"]
        self.assertIn("models_error", ys)
        self.assertGreater(ys["estimated_cost_usd"], 0)

    def test_models_block_is_valid_config(self):
        sb = self.sandbox("campaign-warm")
        sb.edit_json("fuzz/state/fuzz-config.json",
                     lambda d: d.update(models={"agents": {"crash-triager": "standard"}}))
        self.assertEqual(sb.run(core("schema", "validate")).stdout, "ok\n")
        r = sb.run(core("models", "resolve", "crash-triager"))
        self.assertEqual((r.exit_code, r.stdout), (0, "sonnet\n"))
        r = sb.run(core("models", "tier", "nobody"))
        self.assertEqual(r.exit_code, 1)
        r = sb.run(core("models", "show", "--json"))
        self.assertEqual(json.loads(r.stdout)["agents"]["crash-triager"], {"tier": "standard", "model": "sonnet"})
        r = sb.run(core("models", "price", "opus"))
        self.assertEqual(r.stdout, "opus: input $15/MTok, output $75/MTok\n")
        r = sb.run(core("models", "show"), env={"CC_FUZZER_MODELS": "/nonexistent.json"})
        self.assertEqual(r.exit_code, 2)
        self.assertIn("CC_FUZZER_MODELS", r.stderr)


if __name__ == "__main__":
    unittest.main()
