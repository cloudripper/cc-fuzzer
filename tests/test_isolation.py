"""Isolation contract for src/cc_fuzzer_core (UPDATE_ROADMAP.md "Hard rule").

The core must be usable by any host, so it:
  - never reads CLAUDE_* environment variables (or mentions them at all),
  - never refers to the plugin-only trees agents/, skills/, hooks/,
  - imports only the stdlib (third-party imports only behind ImportError guards),
  - imports and runs with no plugin environment, from an unrelated cwd.
"""
from __future__ import annotations

import ast
import os
import re
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
SRC = REPO / "src"
PKG = SRC / "cc_fuzzer_core"

PLUGIN_TREE_RE = re.compile(r"(?<![\w.-])(agents|skills|hooks)/")


def _sources():
    return sorted(p for p in PKG.rglob("*") if p.is_file() and "__pycache__" not in p.parts)


def _clean_env():
    env = {k: v for k, v in os.environ.items()
           if not k.startswith(("CLAUDE", "PYTHON", "CC_FUZZER_", "FUZZ_"))}
    env["PYTHONPATH"] = str(SRC)
    env["PYTHONDONTWRITEBYTECODE"] = "1"
    return env


class TestSourceGrep(unittest.TestCase):
    def test_package_exists(self):
        self.assertTrue((PKG / "__init__.py").is_file())

    def test_no_claude_strings(self):
        hits = []
        for p in _sources():
            for i, line in enumerate(p.read_text(errors="replace").splitlines(), 1):
                if "CLAUDE_" in line:
                    hits.append(f"{p.relative_to(REPO)}:{i}: {line.strip()}")
        self.assertEqual(hits, [], "core must not reference CLAUDE_* (host env):\n" + "\n".join(hits))

    def test_no_plugin_tree_references(self):
        hits = []
        for p in _sources():
            for i, line in enumerate(p.read_text(errors="replace").splitlines(), 1):
                if PLUGIN_TREE_RE.search(line):
                    hits.append(f"{p.relative_to(REPO)}:{i}: {line.strip()}")
        self.assertEqual(hits, [], "core must not refer to agents/, skills/ or hooks/:\n" + "\n".join(hits))

    def test_no_hook_json(self):
        hits = [str(p.relative_to(REPO)) for p in _sources()
                if "hookSpecificOutput" in p.read_text(errors="replace")]
        self.assertEqual(hits, [], "core must not emit host hook JSON")

    def test_stdlib_only_imports(self):
        stdlib = set(sys.stdlib_module_names)
        bad = []
        for p in PKG.rglob("*.py"):
            tree = ast.parse(p.read_text(), str(p))
            guarded = set()
            for node in ast.walk(tree):
                if isinstance(node, ast.Try) and any(
                        h.type is not None and "ImportError" in ast.unparse(h.type)
                        for h in node.handlers):
                    for sub in node.body:
                        for n in ast.walk(sub):
                            guarded.add(id(n))
            for node in ast.walk(tree):
                if isinstance(node, ast.Import):
                    mods = [a.name for a in node.names]
                elif isinstance(node, ast.ImportFrom) and node.level == 0:
                    mods = [node.module or ""]
                else:
                    continue
                for m in mods:
                    top = m.split(".")[0]
                    if top in stdlib or top == "cc_fuzzer_core" or id(node) in guarded:
                        continue
                    bad.append(f"{p.relative_to(REPO)}:{node.lineno}: import {m}")
        self.assertEqual(bad, [], "non-stdlib imports must be optional (try/except ImportError):\n"
                         + "\n".join(bad))


class TestCleanImport(unittest.TestCase):
    def _run(self, *argv):
        with tempfile.TemporaryDirectory() as cwd:
            return subprocess.run([sys.executable, *argv], cwd=cwd, env=_clean_env(),
                                  capture_output=True, text=True, timeout=60)

    def test_import_every_module(self):
        code = (
            "import importlib, pkgutil, cc_fuzzer_core\n"
            "for m in pkgutil.walk_packages(cc_fuzzer_core.__path__, 'cc_fuzzer_core.'):\n"
            "    if m.name != 'cc_fuzzer_core.__main__':\n"
            "        importlib.import_module(m.name)\n"
            "import os\n"
            "leaked = [k for k in os.environ if k.startswith('CLAUDE')]\n"
            "assert not leaked, leaked\n"
            "print('ok', cc_fuzzer_core.__version__)\n"
        )
        r = self._run("-c", code)
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertTrue(r.stdout.startswith("ok "), r.stdout)

    def test_cli_help(self):
        r = self._run("-m", "cc_fuzzer_core", "--help")
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertIn("cc-fuzzer", r.stdout)

    def test_cli_version_matches_pyproject(self):
        r = self._run("-m", "cc_fuzzer_core", "--version")
        self.assertEqual(r.returncode, 0, r.stderr)
        m = re.search(r'^version = "([^"]+)"', (REPO / "pyproject.toml").read_text(), re.M)
        self.assertEqual(r.stdout.strip(), f"cc-fuzzer {m.group(1)}")

    def test_no_subsystem_is_usage_error(self):
        r = self._run("-m", "cc_fuzzer_core")
        self.assertEqual(r.returncode, 2)


if __name__ == "__main__":
    unittest.main()
