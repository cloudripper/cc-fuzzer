"""Things that must agree across the repo: versions, config blocks."""
from __future__ import annotations

import json
import re
import unittest
from pathlib import Path

import cc_fuzzer_core
from tests.support.golden import REPO


class VersionTest(unittest.TestCase):
    def test_package_pyproject_and_plugin_agree(self):
        py = re.search(r'^version = "([^"]+)"', (REPO / "pyproject.toml").read_text(), re.M).group(1)
        plugin = json.loads((REPO / ".claude-plugin" / "plugin.json").read_text())["version"]
        self.assertEqual({cc_fuzzer_core.__version__, py, plugin}, {py},
                         "bump src/cc_fuzzer_core/__init__.py, pyproject.toml and "
                         ".claude-plugin/plugin.json together")


if __name__ == "__main__":
    unittest.main()


class ConfigBlocksTest(unittest.TestCase):
    """A config block the core reads must be one the validator allows, or a
    host that sets it gets a `corrupted` campaign."""

    def test_every_block_the_core_reads_is_allowed(self):
        import re as _re
        from cc_fuzzer_core.schema import fields
        src = REPO / "src" / "cc_fuzzer_core"
        read = set()
        for p in src.rglob("*.py"):
            read |= set(_re.findall(r'\(config or \{\}\)\.get\("([a-z_]+)"\)', p.read_text()))
        read |= {"poc", "variants", "features", "models"}   # read through helpers
        self.assertEqual(sorted(read - set(fields.FUZZ_CONFIG.allowed)), [])

    def test_a_config_with_the_new_blocks_is_not_corrupted(self):
        import shutil
        import subprocess
        import sys
        import tempfile
        from tests.support.golden import FIXTURES
        with tempfile.TemporaryDirectory() as td:
            proj = Path(td) / "c"
            shutil.copytree(FIXTURES / "campaign-warm", proj)
            p = proj / "fuzz" / "state" / "fuzz-config.json"
            d = json.loads(p.read_text())
            d.update({"verification": {"final_step": "command:/x", "authoritative": True},
                      "submission": {"policy": "builtin:memory-safety"},
                      "patch": {"steps": {"test": "preferred"}},
                      "determinism": {"replay_attempts": 3}, "gate": {"protected_dirs": ["findings"]},
                      "query": {"engines": ["semgrep"]}, "cull": {}, "poc": {},
                      "build": {"verify_variant_source": "debug"}})
            p.write_text(json.dumps(d))
            r = subprocess.run([sys.executable, "-m", "cc_fuzzer_core", "tick", "state"],
                               cwd=proj, capture_output=True, text=True,
                               env={**__import__("os").environ, "PYTHONPATH": str(REPO / "src")})
        self.assertEqual(r.stdout.strip(), "stopped", r.stdout + r.stderr)
