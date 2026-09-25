"""UPDATE_ROADMAP.md §3: host-neutral prompt sources + the agent renderer.

  - agents/*.md is RENDERED from prompts/*.md (the drift check is the contract)
  - the frontmatter `model:` comes from §8, not from the prompt text
  - environment-specific text comes from a profile, spliced at a marker
  - a disabled feature's blocks are stripped (§9's prompt half)
  - nothing host-specific leaks into the core: prompts/ is data, not code
"""
from __future__ import annotations

import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from cc_fuzzer_core import features, models, prompts
from tests.support.golden import REPO, core

AGENTS = REPO / "agents"
SOURCES = REPO / "prompts"


def run_cli(*args, env=None):
    e = dict(os.environ)
    e.update({"PYTHONPATH": str(REPO / "src"), "CC_FUZZER_ROOT": str(REPO)})
    e.pop("CC_FUZZER_FEATURES", None)
    e.pop("CC_FUZZER_MODELS", None)
    if env:
        e.update(env)
    return subprocess.run(core(*args), capture_output=True, text=True, env=e)


class SourcesTest(unittest.TestCase):
    def test_every_source_has_an_agent_file(self):
        for agent in prompts.agents(REPO):
            self.assertTrue((AGENTS / f"{agent}.md").is_file(), agent)

    def test_render_json_declares_the_host_layout(self):
        doc = prompts.render_settings(REPO)
        self.assertEqual(doc["output_dir"], "agents")
        self.assertIn(doc["profile"], prompts.PROFILES)

    def test_plugin_only_agents_have_no_source(self):
        for agent in prompts.plugin_only(REPO):
            self.assertTrue((AGENTS / f"{agent}.md").is_file(), agent)
            self.assertFalse((SOURCES / f"{agent}.md").exists(), agent)

    def test_agents_dir_is_sources_plus_plugin_only(self):
        have = {p.stem for p in AGENTS.glob("*.md")}
        self.assertEqual(have, set(prompts.agents(REPO)) | set(prompts.plugin_only(REPO)))

    def test_unknown_agent_is_an_error(self):
        with self.assertRaises(prompts.PromptError):
            prompts.render("no-such-agent", root=REPO)

    def test_unknown_profile_is_an_error(self):
        with self.assertRaises(prompts.PromptError):
            prompts.render("mutator", profile="gentoo", root=REPO)


class DriftTest(unittest.TestCase):
    """The committed plugin agents must be exactly what the sources render."""

    def test_no_drift(self):
        drifts = prompts.check(REPO)
        if drifts:
            self.fail("agents/ is out of date; run `cc-fuzzer prompts write`\n" +
                      "\n".join(d.diff or str(d) for d in drifts))

    def test_check_cli_passes(self):
        r = run_cli("prompts", "check")
        self.assertEqual(r.returncode, 0, r.stderr)

    def test_check_cli_fails_on_drift(self):
        with tempfile.TemporaryDirectory() as td:
            out = Path(td) / "agents"
            out.mkdir()
            for agent in prompts.agents(REPO):
                (out / f"{agent}.md").write_text(prompts.render(agent, root=REPO))
            victim = out / "mutator.md"
            victim.write_text(victim.read_text() + "\nhand-edited\n")
            r = run_cli("prompts", "check", "--dir", str(out))
            self.assertEqual(r.returncode, 1)
            self.assertIn("mutator", r.stderr)
            self.assertIn("prompts write", r.stderr)

    def test_write_is_idempotent(self):
        with tempfile.TemporaryDirectory() as td:
            out = Path(td) / "agents"
            first = prompts.write(REPO, out)
            self.assertEqual(len(first), len(prompts.agents(REPO)))
            self.assertEqual(prompts.write(REPO, out), [])
            self.assertEqual(prompts.check(REPO, out), [])


class FrontmatterTest(unittest.TestCase):
    def test_model_comes_from_the_model_map(self):
        for agent in prompts.agents(REPO):
            text = prompts.render(agent, root=REPO, env={})
            line = [ln for ln in text.splitlines()[:20] if ln.startswith("model:")]
            self.assertEqual(line, [f"model: {models.resolve(agent, env={})}"], agent)

    def test_a_model_override_reaches_the_rendered_frontmatter(self):
        with tempfile.TemporaryDirectory() as td:
            over = Path(td) / "models.json"
            over.write_text(json.dumps({"tiers": {"fast": "haiku-next"}}))
            text = prompts.render("mutator", root=REPO,
                                  env={"CC_FUZZER_MODELS": str(over)})
            self.assertIn("model: haiku-next", text)

    def test_no_frontmatter_drops_the_block(self):
        text = prompts.render("mutator", root=REPO, frontmatter=False)
        self.assertFalse(text.startswith("---"))
        self.assertNotIn("\nmodel:", text.split("\n\n", 1)[0])

    def test_cli_no_frontmatter(self):
        r = run_cli("prompts", "render", "mutator", "--no-frontmatter")
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertFalse(r.stdout.startswith("---"))


class ProfileTest(unittest.TestCase):
    """Splicing is exercised on a synthetic source tree so it is independent of
    which agents have been ported to a profile marker yet."""

    def _tree(self, td, body):
        root = Path(td)
        (root / "prompts" / "profiles").mkdir(parents=True)
        (root / "prompts" / "demo.md").write_text(body)
        (root / "prompts" / "profiles" / "nix.md").write_text(
            "header, ignored\n\n<!-- slot:environment -->\nRun `nix develop`.\n")
        (root / "prompts" / "profiles" / "oss-fuzz.md").write_text(
            "<!-- slot:environment -->\nThe base image already has the toolchain.\n")
        return root

    def test_slot_is_spliced_per_profile(self):
        body = "# demo\n\n<!-- profile:environment -->\n\ntail\n"
        with tempfile.TemporaryDirectory() as td:
            src = self._tree(td, body)
            nix = prompts.render("demo", "nix", root=src)
            oss = prompts.render("demo", "oss-fuzz", root=src)
            self.assertIn("nix develop", nix)
            self.assertNotIn("base image", nix)
            self.assertIn("base image", oss)
            self.assertNotIn("nix develop", oss)
            for text in (nix, oss):
                self.assertNotIn("<!-- profile:", text)
                self.assertNotIn("header, ignored", text)

    def test_missing_slot_names_the_profile(self):
        body = "<!-- profile:toolchain -->\n"
        with tempfile.TemporaryDirectory() as td:
            src = self._tree(td, body)
            with self.assertRaises(prompts.PromptError) as cm:
                prompts.render("demo", "nix", root=src)
            self.assertIn("toolchain", str(cm.exception))
            self.assertIn("nix", str(cm.exception))

    def test_profiles_that_exist_parse(self):
        for profile in prompts.PROFILES:
            prompts.load_profile(profile, REPO)   # no exception


class FullyResolvedTest(unittest.TestCase):
    """Every profile must render every source completely. A marker that is not
    on a line of its own silently survives into the output, which is how a raw
    `<!-- profile:driver_bash_note -->` reached a committed agent file once."""

    def test_no_marker_or_variable_survives_any_profile(self):
        for profile in prompts.PROFILES:
            for agent in prompts.agents(REPO):
                text = prompts.render(agent, profile, root=REPO)
                with self.subTest(profile=profile, agent=agent):
                    self.assertNotIn("<!-- profile:", text)
                    self.assertNotIn("<!-- slot:", text)
                    self.assertNotRegex(text, r"\{\{[A-Za-z0-9_]+\}\}")

    def test_no_host_env_var_survives_a_container_render(self):
        for agent in prompts.agents(REPO):
            text = prompts.render(agent, "oss-fuzz", root=REPO, frontmatter=False)
            with self.subTest(agent=agent):
                self.assertNotIn("CLAUDE_", text)

    def test_sources_name_no_host(self):
        """The sources themselves stay host-neutral: only profiles may name a
        host's variables or tools."""
        banned = ("CLAUDE_", "ctxctl", "TodoWrite", "SendMessage", "ScheduleWakeup")
        for agent in prompts.agents(REPO):
            src = (SOURCES / f"{agent}.md").read_text()
            for word in banned:
                with self.subTest(agent=agent, word=word):
                    self.assertNotIn(word, src)


class FeatureBlockTest(unittest.TestCase):
    def test_disabled_feature_block_is_stripped(self):
        body = ("keep\n\n<!-- feature:advisory_lookup -->\nCVE talk\n<!-- /feature -->\n"
                "\n<!-- feature:logic_oracles -->\noracle talk\n<!-- /feature -->\n")
        with tempfile.TemporaryDirectory() as td:
            src = Path(td)
            (src / "prompts").mkdir()
            (src / "prompts" / "demo.md").write_text(body)
            on = prompts.render("demo", root=src)
            self.assertIn("CVE talk", on)
            self.assertIn("oracle talk", on)
            off = prompts.render("demo", root=src,
                                 features={"advisory_lookup": False, "logic_oracles": True})
            self.assertNotIn("CVE talk", off)
            self.assertIn("oracle talk", off)
            self.assertIn("keep", off)

    def test_cli_features_flag(self):
        r = run_cli("prompts", "render", "mutator", "--features=-advisory_lookup")
        self.assertEqual(r.returncode, 0, r.stderr)

    def test_cli_reads_the_features_env_var(self):
        body = "keep\n\n<!-- feature:advisory_lookup -->\nCVE talk\n<!-- /feature -->\n"
        with tempfile.TemporaryDirectory() as td:
            (Path(td) / "prompts").mkdir()
            (Path(td) / "prompts" / "demo.md").write_text(body)
            r = run_cli("prompts", "render", "demo", "--root", td,
                        env={"CC_FUZZER_FEATURES": "-advisory_lookup"})
            self.assertEqual(r.returncode, 0, r.stderr)
            self.assertNotIn("CVE talk", r.stdout)

    def test_plugin_agents_keep_every_block(self):
        """The committed agents are rendered with all features ON (§9)."""
        for agent in prompts.agents(REPO):
            src = (SOURCES / f"{agent}.md").read_text()
            for name in features.FEATURES:
                if f"feature:{name}" in src:
                    self.assertIn(f"feature:{name}", (AGENTS / f"{agent}.md").read_text(),
                                  f"{agent} lost its {name} block")


class CliSurfaceTest(unittest.TestCase):
    def test_list_json(self):
        r = run_cli("prompts", "list", "--json")
        self.assertEqual(r.returncode, 0, r.stderr)
        doc = json.loads(r.stdout)
        self.assertEqual(doc["agents"], prompts.agents(REPO))
        self.assertEqual(doc["profiles"], list(prompts.PROFILES))
        self.assertIn("nix-builder", doc["plugin_only"])

    def test_render_matches_the_committed_agent(self):
        r = run_cli("prompts", "render", "crash-triager")
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertEqual(r.stdout, (AGENTS / "crash-triager.md").read_text())

    def test_bad_agent_exits_2(self):
        r = run_cli("prompts", "render", "nix-builder")
        self.assertEqual(r.returncode, 2)
        self.assertIn("host-only", r.stderr)


if __name__ == "__main__":
    unittest.main()
