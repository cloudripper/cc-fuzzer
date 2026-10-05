"""Everything the plugin uses from Claude Code is listed in claude-code.contract.json.

The contract records the Claude Code version the plugin was last tested on
and every name it relies on; scripts/claude-code-contract.py checks them
against that version's binary, and doctor warns when the installed Claude
Code is older. These tests keep the contract and the plugin from drifting:
a hook event, hook field, frontmatter key, model alias or agent tool the
plugin starts using fails here until the contract lists it.
"""
from __future__ import annotations

import json
import os
import re
import stat
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
CONTRACT = json.loads((REPO / "claude-code.contract.json").read_text())
REQ = {k: set(v) for k, v in CONTRACT["requires"].items()}
SCRIPT = REPO / "scripts" / "claude-code-contract.py"


def _frontmatter(path: Path) -> dict:
    text = path.read_text()
    if not text.startswith("---\n"):
        return {}
    block = text[4:text.index("\n---", 4)]
    return dict(ln.split(":", 1) for ln in block.splitlines() if re.match(r"^[a-z-]+:", ln))


class ContractCoversThePlugin(unittest.TestCase):
    def test_hook_events(self):
        events = set(json.loads((REPO / "hooks" / "hooks.json").read_text())["hooks"])
        self.assertIn("SubagentStop", events)
        self.assertLessEqual(events, REQ["hook_event"], events - REQ["hook_event"])

    def test_opt_in_hooks(self):
        """Hook scripts not in hooks.json (a host installs them) name their event."""
        for p in (REPO / "hooks").glob("*.sh"):
            m = re.search(r"^# (\w+) hook, OPT-IN", p.read_text(), re.M)
            if m:
                self.assertIn(m.group(1), REQ["hook_event"], p.name)

    def test_hook_output_fields(self):
        used = set()
        for p in [*(REPO / "hooks").glob("*.sh"), *(REPO / "scripts").glob("*.sh")]:
            used |= set(re.findall(r'"(hookSpecificOutput|hookEventName|additionalContext|'
                                   r'permissionDecision|permissionDecisionReason|updatedInput|'
                                   r'systemMessage|suppressOutput|continue|decision)"', p.read_text()))
        self.assertIn("hookSpecificOutput", used)
        self.assertLessEqual(used, REQ["hook_output"], used - REQ["hook_output"])

    def test_frontmatter_keys_aliases_and_tools(self):
        files = [*(REPO / "agents").glob("*.md"), *(REPO / "skills").glob("*/SKILL.md")]
        keys, aliases, tools = set(), set(), set()
        for f in files:
            fm = _frontmatter(f)
            keys |= set(fm)
            if "model" in fm:
                aliases.add(fm["model"].strip())
            if "tools" in fm and f.parent.name == "agents":
                tools |= {t.strip() for t in fm["tools"].split(",") if t.strip()}
        self.assertTrue({"name", "model", "tools"} <= keys)
        self.assertLessEqual(keys, REQ["frontmatter"], keys - REQ["frontmatter"])
        self.assertLessEqual(aliases, REQ["model_alias"], aliases - REQ["model_alias"])
        self.assertLessEqual(tools, REQ["tool"], tools - REQ["tool"])

    def test_plugin_root_env(self):
        hooks = (REPO / "hooks" / "hooks.json").read_text()
        self.assertIn("${CLAUDE_PLUGIN_ROOT}", hooks)
        self.assertIn("CLAUDE_PLUGIN_ROOT", REQ["env"])

    def test_semantics_name_listed_things(self):
        every = set().union(*REQ.values())
        for name, s in CONTRACT["semantics"].items():
            self.assertIn(name, every)
            self.assertRegex(s["verified"], r"^\d+\.\d+\.\d+$")


class InstalledVersion(unittest.TestCase):
    """`installed` (what doctor runs) warns below the tested version, never refuses."""

    def _run(self, version_line):
        with tempfile.TemporaryDirectory() as d:
            if version_line is not None:
                fake = Path(d) / "claude"
                fake.write_text(f"#!/bin/sh\necho '{version_line}'\n")
                fake.chmod(fake.stat().st_mode | stat.S_IEXEC)
            env = {**os.environ, "PATH": f"{d}:/usr/bin:/bin" if version_line is not None else d}
            return subprocess.run([sys.executable, str(SCRIPT), "installed"], env=env,
                                  capture_output=True, text=True)

    def test_older_newer_and_absent(self):
        tested = CONTRACT["version"]
        major, minor, patch = (int(x) for x in tested.split("."))
        self.assertEqual(self._run(f"{major}.{minor}.{patch + 3} (Claude Code)").returncode, 0)
        self.assertEqual(self._run(f"{tested} (Claude Code)").returncode, 0)
        old = self._run(f"{major}.{minor}.{max(0, patch - 100)} (Claude Code)")
        self.assertEqual(old.returncode, 3)
        self.assertIn("older than", old.stdout)
        self.assertEqual(self._run(None).returncode, 4)


if __name__ == "__main__":
    unittest.main()
