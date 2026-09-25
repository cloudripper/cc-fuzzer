"""UPDATE_ROADMAP.md §4 stage 2: replay becomes deterministic, in the core.

The triager used to do this by hand -- export ASAN_OPTIONS, run the reproducer
three times, read the output, and type the stack hash into a shell pipeline it
built from frames it had chosen. Three things could differ run to run: the
binary, the sanitizer environment, and which frames went into the hash.

These tests run REAL binaries (built with clang here) rather than mocking the
subprocess, because what is under test is precisely the behaviour of running
something three times.
"""
from __future__ import annotations

import json
import os
import shutil
import subprocess
import tempfile
import textwrap
import unittest
from pathlib import Path

from cc_fuzzer_core import variants
from cc_fuzzer_core.crash import replay as R
from tests.support.golden import REPO

HAVE_CLANG = shutil.which("clang") is not None

CRASHER = r'''
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
static void parse_exif(const uint8_t *d, size_t n) {
  if (n >= 4 && !memcmp(d, "BOOM", 4)) {
    fprintf(stderr, "==1==ERROR: AddressSanitizer: heap-buffer-overflow on address 0x60200000eff4\n");
    fprintf(stderr, "    #0 0x4f1234 in parse_exif /src/target/src/parser.c:25:13\n");
    fprintf(stderr, "    #1 0x4f2345 in read_chunk /src/target/src/parser.c:61:5\n");
    fprintf(stderr, "SUMMARY: AddressSanitizer: heap-buffer-overflow /src/target/src/parser.c:25:13 in parse_exif\n");
    abort();
  }
}
int main(int argc, char **argv) {
  if (argc < 2) return 0;
  FILE *f = fopen(argv[1], "rb"); if (!f) return 1;
  static uint8_t b[4096]; size_t n = fread(b, 1, sizeof b, f); fclose(f);
  parse_exif(b, n);
  return 0;
}
'''

# Crashes on every other run, via a counter file: a real intermittent binary,
# which is the only honest way to test the flaky verdict.
FLAKY = r'''
#include <stdio.h>
#include <stdlib.h>
int main(int argc, char **argv) {
  (void)argc; (void)argv;
  FILE *c = fopen(COUNTER, "a+"); if (!c) return 0;
  fprintf(c, "x"); long n = ftell(c); fclose(c);
  if (n % 2 == 1) {
    fprintf(stderr, "==1==ERROR: AddressSanitizer: SEGV on unknown address\n");
    fprintf(stderr, "    #0 0x4f1 in flaky_fn /src/t.c:9:3\n");
    fprintf(stderr, "SUMMARY: AddressSanitizer: SEGV /src/t.c:9:3 in flaky_fn\n");
    abort();
  }
  return 0;
}
'''


def compile_c(src: str, out: Path, defines=()) -> Path:
    with tempfile.NamedTemporaryFile("w", suffix=".c", delete=False) as f:
        f.write(src)
        path = f.name
    cmd = ["clang", "-O1", "-g", *[f"-D{d}" for d in defines], path, "-o", str(out)]
    p = subprocess.run(cmd, capture_output=True, text=True)
    os.unlink(path)
    if p.returncode != 0:
        raise AssertionError(f"fixture build failed:\n{p.stderr}")
    return out


class StackHashTest(unittest.TestCase):
    OUT = ("==1==ERROR: AddressSanitizer: heap-buffer-overflow\n"
           "    #0 0x1 in parse_exif /src/parser.c:25:13\n"
           "    #1 0x2 in read_chunk /src/parser.c:61:5\n"
           "    #2 0x3 in decode /src/parser.c:88:2\n"
           "SUMMARY: AddressSanitizer: heap-buffer-overflow /src/parser.c:25:13 in parse_exif\n")

    def test_same_crash_hashes_the_same(self):
        self.assertEqual(R.stack_hash(self.OUT), R.stack_hash(self.OUT))

    def test_a_different_crash_site_hashes_differently(self):
        other = self.OUT.replace("parse_exif", "parse_icc")
        self.assertNotEqual(R.stack_hash(self.OUT), R.stack_hash(other))

    def test_the_hash_ignores_frames_below_the_ones_it_uses(self):
        """Only HASH_FRAMES frames count, so an unrelated caller deeper in the
        stack cannot split one bug into two findings."""
        noisy = (self.OUT.replace("SUMMARY", "    #3 0x9 in main /src/main.c:3:1\nSUMMARY")
                 + "shadow bytes: ...\n")
        self.assertEqual(R.stack_hash(self.OUT), R.stack_hash(noisy))

    def test_hash_is_hex_and_fixed_width(self):
        h = R.stack_hash(self.OUT)
        self.assertEqual(len(h), R.STACK_HASH_LEN)
        int(h, 16)

    def test_output_with_no_frames_still_hashes(self):
        h = R.stack_hash("no frames here", category="timeout")
        self.assertEqual(len(h), R.STACK_HASH_LEN)


class SelectionTest(unittest.TestCase):
    def test_replay_refuses_an_instrumented_binary(self):
        rec = {"cmplog_binary": "/b/x_cmplog", "coverage_binary": "/b/x_cov"}
        with self.assertRaises(variants.SelectionError):
            R.replay(rec, __file__, harness="parser")

    def test_a_missing_reproducer_is_an_error(self):
        with self.assertRaises(R.ReplayError):
            R.replay({"verify_binary": "/bin/true"}, "/nope/missing.bin")

    def test_a_non_executable_binary_is_an_error(self):
        with tempfile.TemporaryDirectory() as td:
            b = Path(td) / "not_exec"
            b.write_text("")
            r = Path(td) / "in.bin"
            r.write_bytes(b"x")
            with self.assertRaises(R.ReplayError) as cm:
                R.replay({"verify_binary": str(b)}, str(r))
            self.assertIn("not executable", str(cm.exception))


@unittest.skipUnless(HAVE_CLANG, "needs clang")
class RealBinaryTest(unittest.TestCase):
    def setUp(self):
        self.td = tempfile.TemporaryDirectory()
        self.addCleanup(self.td.cleanup)
        self.d = Path(self.td.name)
        self.crash = self.d / "crash.bin"
        self.crash.write_bytes(b"BOOMxxxx")
        self.safe = self.d / "safe.bin"
        self.safe.write_bytes(b"safe")

    def _verify_binary(self) -> str:
        return str(compile_c(CRASHER, self.d / "parser_fuzzer_verify"))

    def test_a_real_crash_replays_deterministically(self):
        rec = {"verify_binary": self._verify_binary()}
        r = R.replay(rec, str(self.crash), harness="parser")
        self.assertEqual(r.verdict, R.CRASH)
        self.assertEqual((r.crashes, r.attempts), (3, 3))
        self.assertTrue(r.deterministic)
        self.assertEqual(r.category, "heap-buffer-overflow")
        self.assertIn("parse_exif", r.top_frame)
        self.assertEqual(r.evidence_grade, variants.STRONG)

    def test_the_hash_is_stable_across_separate_replays(self):
        rec = {"verify_binary": self._verify_binary()}
        a = R.replay(rec, str(self.crash), harness="parser")
        b = R.replay(rec, str(self.crash), harness="parser")
        self.assertEqual(a.stack_hash, b.stack_hash)
        self.assertTrue(a.stack_hash)

    def test_a_non_crashing_input_is_no_crash(self):
        rec = {"verify_binary": self._verify_binary()}
        r = R.replay(rec, str(self.safe), harness="parser")
        self.assertEqual(r.verdict, R.NO_CRASH)
        self.assertEqual(r.crashes, 0)
        self.assertEqual(r.stack_hash, "")

    def test_an_intermittent_crash_is_flaky_not_absent(self):
        """A bug that reproduces 2 times in 3 is real but unreliable. Calling
        that `no-crash` would drop it; calling it `crash` would put an
        unreliable reproducer behind a finding."""
        counter = self.d / "counter"
        binary = compile_c(FLAKY, self.d / "parser_fuzzer",
                           defines=[f'COUNTER="{counter}"'])
        r = R.replay({"harness_binary": str(binary)}, str(self.crash), harness="parser")
        self.assertEqual(r.verdict, R.FLAKY)
        self.assertNotIn(r.crashes, (0, r.attempts))
        self.assertFalse(r.deterministic)

    def test_falling_back_to_the_fuzzing_binary_is_recorded_as_weak(self):
        rec = {"harness_binary": self._verify_binary()}
        r = R.replay(rec, str(self.crash), harness="parser")
        self.assertEqual(r.verdict, R.CRASH)
        self.assertEqual(r.variant, "fuzzer")
        self.assertEqual(r.evidence_grade, variants.WEAK)
        self.assertIn("no verify_binary", r.reason)

    def test_every_attempt_is_reported(self):
        rec = {"verify_binary": self._verify_binary()}
        r = R.replay(rec, str(self.crash), harness="parser")
        self.assertEqual([a.n for a in r.runs], [1, 2, 3])
        self.assertTrue(all(a.is_crash for a in r.runs))
        self.assertEqual(json.loads(json.dumps(r.as_dict()))["runs"][0]["attempt"], 1)

    def test_the_environment_is_pinned_not_inherited(self):
        """Two attempts must not differ because of the ASAN_OPTIONS the caller
        happened to have exported."""
        rec = {"verify_binary": self._verify_binary()}
        a = R.replay(rec, str(self.crash), harness="parser",
                     env={**os.environ, "ASAN_OPTIONS": "detect_leaks=0:abort_on_error=0"})
        self.assertEqual(a.verdict, R.CRASH)

    def test_a_timeout_counts_as_an_attempt_not_a_crash(self):
        hang = compile_c("int main(void){ for(;;); }", self.d / "parser_fuzzer_verify2")
        r = R.replay({"verify_binary": str(hang)}, str(self.crash), harness="parser",
                     attempts=1, timeout=1)
        self.assertEqual(r.attempts, 1)
        self.assertEqual(r.runs[0].exit_code, 124)


if __name__ == "__main__":
    unittest.main()
