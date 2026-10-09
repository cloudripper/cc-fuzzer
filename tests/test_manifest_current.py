"""MANIFEST.md5 matches the tree it fingerprints.

Every plugin session runs integrity-check.sh against MANIFEST.md5 at
SessionStart. 0.36.4 to 0.38.0 shipped without regenerating it, so every
session opened with "DRIFT DETECTED". Run scripts/gen-manifest.sh before
committing a change to a tracked file; this test fails until you do.
"""
from __future__ import annotations

import subprocess
import sys
import unittest
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
INCLUDES = ["--include", ".claude-plugin", "--include", "agents", "--include", "skills"]


class ManifestTest(unittest.TestCase):
    def test_manifest_is_current(self):
        p = subprocess.run([sys.executable, "-m", "cc_fuzzer_core", "manifest", "check",
                            "--root", str(REPO), *INCLUDES], capture_output=True, text=True)
        self.assertEqual(p.returncode, 0, "MANIFEST.md5 is stale: run scripts/gen-manifest.sh\n"
                         + (p.stdout + p.stderr)[-2000:])


if __name__ == "__main__":
    unittest.main()
