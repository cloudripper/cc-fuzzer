"""Patch validation (cc_fuzzer_core.patch).

A CRS is scored on patches too, and a patch is wrong in ways that look alike
from outside: it does not stop the PoV, it stops the PoV by breaking the
program, or it applies to a finding that was never reproducing in the first
place. These tests build a real vulnerable program, write real diffs, and run
a real build and test command, because every one of those failure modes is
about what actually happens when you run it.

The `before` gate is the one worth keeping honest: without it, "patch applied,
PoV no longer crashes" is indistinguishable from "the PoV never crashed".
"""
from __future__ import annotations

import json
import os
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path

from cc_fuzzer_core import patch

HAVE_CLANG = shutil.which("clang") is not None
HAVE_GIT = shutil.which("git") is not None

PARSER = r'''
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
int parse(const uint8_t *b, size_t n) {
  for (size_t i = 0; i + 4 <= n; i++) {
    if (!memcmp(b + i, "BOOM", 4)) {
      fprintf(stderr,"==1==ERROR: AddressSanitizer: heap-buffer-overflow on address 0x602\n");
      fprintf(stderr,"    #0 0x4f1 in parse /src/parser.c:8:13\n");
      fprintf(stderr,"SUMMARY: AddressSanitizer: heap-buffer-overflow /src/parser.c:8:13 in parse\n");
      abort();
    }
  }
  return (int)n;
}
int main(int argc,char**argv){ if(argc<2)return 0; FILE*f=fopen(argv[1],"rb"); if(!f)return 1;
 static uint8_t b[65536]; size_t n=fread(b,1,sizeof b,f); fclose(f); parse(b,n); return 0; }
'''

BUILD = "#!/bin/sh\nclang -O1 -g parser.c -o bin/parser_fuzzer_verify\n"
TEST = """#!/bin/sh
printf 'hello' > clean.bin
./bin/parser_fuzzer_verify clean.bin || { echo "regression: clean input fails"; exit 1; }
exit 0
"""


class ScopeTest(unittest.TestCase):
    DIFF = ("--- a/src/x.c\n+++ b/src/x.c\n@@\n-old line\n+new line\n+another\n"
            "--- a/src/y.c\n+++ b/src/y.c\n@@\n-gone\n")

    def test_counts_files_and_lines(self):
        s = patch.scope_of(self.DIFF)
        self.assertEqual(s.files, 2)
        self.assertEqual((s.added, s.removed), (2, 2))
        self.assertIn("src/x.c", s.paths)

    def test_a_deletion_only_patch_is_flagged(self):
        """Fixing by deleting the path that reaches the bug is the failure
        mode nothing else catches."""
        s = patch.scope_of("--- a/x.c\n+++ b/x.c\n@@\n-a\n-b\n-c\n")
        self.assertTrue(any("removes code" in c for c in s.concerns()))

    def test_a_large_patch_is_flagged(self):
        big = "--- a/x.c\n+++ b/x.c\n@@\n" + "+line\n" * 300
        self.assertTrue(any("changed lines" in c for c in patch.scope_of(big).concerns()))

    def test_a_small_focused_patch_has_no_concerns(self):
        s = patch.scope_of("--- a/x.c\n+++ b/x.c\n@@\n-bad\n+good\n")
        self.assertEqual(s.concerns(), [])


class CommandTest(unittest.TestCase):
    def test_command_prefix_is_optional_and_placeholders_fill(self):
        self.assertEqual(patch._command("command:git apply {patch}", patch="p.diff"),
                         ["git", "apply", "p.diff"])
        self.assertEqual(patch._command("./build.sh"), ["./build.sh"])

    def test_an_unconfigured_step_is_skipped_not_failed(self):
        s = patch.run_step("build", [], cwd=".", timeout=5)
        self.assertTrue(s.ok)
        self.assertIn("not configured", s.detail)


@unittest.skipUnless(HAVE_CLANG and HAVE_GIT, "needs clang and git")
class RealPatchTest(unittest.TestCase):
    """Real program, real diffs, real build and test commands."""

    def setUp(self):
        self.td = tempfile.TemporaryDirectory()
        self.addCleanup(self.td.cleanup)
        self.root = Path(self.td.name)
        (self.root / "bin").mkdir()
        (self.root / "parser.c").write_text(PARSER)
        for name, body in (("build.sh", BUILD), ("test.sh", TEST)):
            p = self.root / name
            p.write_text(body)
            p.chmod(0o755)
        self._git("init", "-q", ".")
        self._git("add", "-A")
        self._git("-c", "user.email=t@t", "-c", "user.name=t", "commit", "-qm", "base")
        subprocess.run(["./build.sh"], cwd=self.root, check=True, capture_output=True)
        self.pov = self.root / "pov.bin"
        self.pov.write_bytes(b"AAAABOOMZZZZ")
        self.record = {"verify_binary": str(self.root / "bin" / "parser_fuzzer_verify")}
        self.cfg = {"patch": {"apply": "command:git apply {patch}",
                              "build": "command:./build.sh",
                              "test": "command:./test.sh",
                              "revert": "command:git checkout -- .",
                              "timeout_s": 120}}

    def _git(self, *args):
        return subprocess.run(["git", *args], cwd=self.root, capture_output=True, text=True)

    def _diff_from(self, edit) -> str:
        """Make a real diff by editing the tree and asking git."""
        src = self.root / "parser.c"
        original = src.read_text()
        src.write_text(edit(original))
        out = self._git("diff").stdout
        src.write_text(original)
        p = self.root / "p.diff"
        p.write_text(out)
        return str(p)

    def _validate(self, diff, pov=None):
        return patch.validate(self.record, diff, str(pov or self.pov),
                              project_root=self.root, config=self.cfg, harness="parser")

    FIX = 'continue;  /* bounds checked: the marker is data, not a trigger */'

    def _fix(self, s: str) -> str:
        """Remove the whole crashing body. (The fake sanitizer report IS those
        fprintf lines, so leaving them would still read as a crash.)"""
        start = s.index('      fprintf(stderr,"==1==ERROR')
        end = s.index("      abort();\n") + len("      abort();\n")
        return s[:start] + "      " + self.FIX + "\n" + s[end:]

    def test_a_real_fix_validates(self):
        diff = self._diff_from(self._fix)
        v = self._validate(diff)
        self.assertEqual(v.status, patch.FIXES, v.reason)
        self.assertTrue(v.validated)
        self.assertEqual([s.name for s in v.steps if s.name in patch.STEPS],
                         list(patch.STEPS))

    def test_a_patch_that_does_not_fix_is_caught(self):
        diff = self._diff_from(lambda s: s.replace(
            "  return (int)n;", "  /* reviewed */\n  return (int)n;"))
        v = self._validate(diff)
        self.assertEqual(v.status, patch.DOES_NOT_FIX)
        self.assertFalse(v.validated)

    def test_a_patch_that_breaks_the_tests_is_caught(self):
        """It stops the PoV -- by breaking the program. Only the test step
        tells these apart."""
        diff = self._diff_from(lambda s: s.replace(
            "fclose(f); parse(b,n); return 0; }", "fclose(f); (void)n; return 3; }"))
        v = self._validate(diff)
        self.assertEqual(v.status, patch.BREAKS_TESTS)
        after = [s for s in v.steps if s.name == "after"][0]
        self.assertTrue(after.ok, "the PoV did stop reproducing")

    def test_a_pov_that_never_reproduced_is_stale_not_fixed(self):
        """THE gate. Without `before`, this reads as success."""
        stale = self.root / "stale.bin"
        stale.write_bytes(b"harmless")
        diff = self._diff_from(self._fix)
        v = self._validate(diff, pov=stale)
        self.assertEqual(v.status, patch.STALE)
        self.assertFalse(v.validated)
        self.assertEqual([s.name for s in v.steps], ["before"],
                         "nothing after `before` should have run")

    def test_a_build_failure_is_not_a_fix(self):
        diff = self._diff_from(lambda s: s.replace("  return (int)n;", "  return nonsense;"))
        v = self._validate(diff)
        self.assertEqual(v.status, patch.BUILD_FAILED)

    def test_an_unapplyable_patch_is_reported_as_such(self):
        bad = self.root / "bad.diff"
        bad.write_text("--- a/nope.c\n+++ b/nope.c\n@@ -1 +1 @@\n-x\n+y\n")
        v = self._validate(str(bad))
        self.assertEqual(v.status, patch.APPLY_FAILED)

    def test_the_tree_is_reverted_after_every_outcome(self):
        before = (self.root / "parser.c").read_text()
        for edit in (self._fix,
                     lambda s: s.replace("  return (int)n;", "  return nonsense;")):
            with self.subTest():
                self._validate(self._diff_from(edit))
                self.assertEqual((self.root / "parser.c").read_text(), before,
                                 "the working tree was left patched")

    def test_the_verdict_serialises(self):
        diff = self._diff_from(self._fix)
        d = self._validate(diff).as_dict()
        self.assertEqual(json.loads(json.dumps(d))["schema"], patch.VERDICT_SCHEMA)

    def test_a_missing_patch_or_pov_is_an_error(self):
        with self.assertRaises(patch.PatchError):
            self._validate("/nonexistent.diff")
        with self.assertRaises(patch.PatchError):
            patch.validate(self.record, str(self.root / "build.sh"), "/nonexistent.bin",
                           project_root=self.root, config=self.cfg)


if __name__ == "__main__":
    unittest.main()
