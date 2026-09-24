"""`cc-fuzzer manifest write|check` and its consumer scripts/integrity-check.sh."""
from __future__ import annotations

import os
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from cc_fuzzer_core import manifest

REPO = Path(__file__).resolve().parents[1]


def _env():
    env = {k: v for k, v in os.environ.items() if not k.startswith(("CLAUDE", "CC_FUZZER_", "PYTHON"))}
    env["PYTHONPATH"] = str(REPO / "src")
    env["PYTHONDONTWRITEBYTECODE"] = "1"
    return env


class TestManifestModule(unittest.TestCase):
    def setUp(self):
        self.root = Path(tempfile.mkdtemp(prefix="ccf-manifest-"))
        self.addCleanup(shutil.rmtree, self.root, True)
        for rel, text in {
            "STATE_SCHEMA.md": "# schema\n",
            "scripts/a.sh": "echo a\n",
            "scripts/_lib/b.py": "print('b')\n",
            "scripts/_lib/__pycache__/b.cpython-312.pyc": "junk",
            "rules/semgrep/x.yml": "rules: []\n",
            "extra/tree/c.md": "c\n",
            "README.md": "readme\n",
        }.items():
            p = self.root / rel
            p.parent.mkdir(parents=True, exist_ok=True)
            p.write_text(text)

    def test_tracked_set(self):
        self.assertEqual(manifest.tracked_files(self.root),
                         ["STATE_SCHEMA.md", "scripts/_lib/b.py", "scripts/a.sh"])
        self.assertIn("extra/tree/c.md", manifest.tracked_files(self.root, ["extra"]))

    def test_write_then_check(self):
        out = manifest.write(self.root, include=["extra"])
        text = out.read_text()
        self.assertTrue(text.startswith("# cc-fuzzer plugin file manifest"))
        body = [ln for ln in text.splitlines() if ln and not ln.startswith("#")]
        self.assertEqual(len(body), 4)
        self.assertRegex(body[0], r"^[0-9a-f]{32}  STATE_SCHEMA\.md$")
        self.assertEqual(manifest.check(self.root, include=["extra"]), [])
        (self.root / "scripts/a.sh").write_text("echo changed\n")
        (self.root / "scripts/new.sh").write_text("new\n")
        (self.root / "extra/tree/c.md").unlink()
        self.assertEqual(manifest.check(self.root, include=["extra"]),
                         ["MODIFIED: scripts/a.sh", "UNTRACKED: scripts/new.sh", "MISSING: extra/tree/c.md"])

    def test_write_replaces_readonly_manifest(self):
        out = manifest.write(self.root)
        out.chmod(0o444)
        manifest.write(self.root)  # os.replace: no EACCES on the old file
        self.assertTrue(out.exists())


class TestIntegrityCheck(unittest.TestCase):
    """integrity-check.sh against a manifest produced by the generator."""

    def _plugin_copy(self, parent: Path) -> Path:
        root = parent / "cc-fuzzer"
        shutil.copytree(REPO / "scripts", root / "scripts",
                        ignore=shutil.ignore_patterns("__pycache__"))
        (root / "STATE_SCHEMA.md").write_text("# schema\n")
        return root

    def _integrity(self, root: Path) -> str:
        r = subprocess.run(["bash", str(root / "scripts/integrity-check.sh")], env=_env(),
                           capture_output=True, text=True, timeout=120)
        self.assertEqual(r.returncode, 0, r.stderr)
        return r.stdout

    def test_generated_manifest_is_clean_and_detects_drift(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = self._plugin_copy(Path(tmp))
            r = subprocess.run([sys.executable, "-m", "cc_fuzzer_core", "manifest", "write", "--root", str(root)],
                               env=_env(), capture_output=True, text=True, timeout=60)
            self.assertEqual(r.returncode, 0, r.stderr)
            self.assertEqual(self._integrity(root).strip(), "ok")
            (root / "scripts/is-crash.sh").write_text("# tampered\n")
            out = self._integrity(root)
            self.assertIn("1 file(s) modified", out)
            self.assertIn("MODIFIED: scripts/is-crash.sh", out)

    def test_site_packages_install_is_skipped(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = self._plugin_copy(Path(tmp) / "lib/python3.12/site-packages")
            self.assertEqual(self._integrity(root).strip(), "ok")  # no MANIFEST.md5 at all

    def test_gen_manifest_shim_check(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = self._plugin_copy(Path(tmp))
            shutil.copytree(REPO / "src", root / "src", ignore=shutil.ignore_patterns("__pycache__"))
            gen = root / "scripts/gen-manifest.sh"
            r = subprocess.run(["bash", str(gen)], env=_env(), capture_output=True, text=True, timeout=60)
            self.assertEqual(r.returncode, 0, r.stderr)
            self.assertEqual(r.stdout.strip(), str(root / "MANIFEST.md5"))
            r = subprocess.run(["bash", str(gen), "--check"], env=_env(), capture_output=True, text=True, timeout=60)
            self.assertEqual((r.returncode, r.stdout.strip()), (0, "ok"))
            self.assertIn("src/cc_fuzzer_core/manifest.py", (root / "MANIFEST.md5").read_text())


if __name__ == "__main__":
    unittest.main()
