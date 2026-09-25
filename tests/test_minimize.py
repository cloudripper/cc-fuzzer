"""Crash-input minimization that preserves WHICH bug (cc_fuzzer_core.minimize).

A fuzzer's reproducer is whatever buffer happened to trip the bug. The short
form is worth more than convenience: it is what makes the essential cause
legible, and two long inputs that look like separate findings often minimize
to the same few bytes.

The hazard these tests exist for: delta debugging will happily shrink an input
until it crashes SOMEWHERE ELSE. That is a smaller input and a different
finding, and a minimizer that accepts it has swapped the bug out from under
the report. `two_bugs` below is that case, built as a real binary.
"""
from __future__ import annotations

import os
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path

from cc_fuzzer_core import minimize
from cc_fuzzer_core.crash import replay

HAVE_CLANG = shutil.which("clang") is not None

# Crashes wherever it finds the marker.
SCANNER = r'''
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
int main(int argc, char **argv) {
  if (argc < 2) return 0;
  FILE *f = fopen(argv[1], "rb"); if (!f) return 1;
  static uint8_t b[65536]; size_t n = fread(b, 1, sizeof b, f); fclose(f);
  for (size_t i = 0; i + 4 <= n; i++) if (!memcmp(b + i, "BOOM", 4)) {
    fprintf(stderr, "==1==ERROR: AddressSanitizer: heap-buffer-overflow on address 0x602\n");
    fprintf(stderr, "    #0 0x4f1 in parse_chunk /src/parser.c:25:13\n");
    fprintf(stderr, "SUMMARY: AddressSanitizer: heap-buffer-overflow /src/parser.c:25:13 in parse_chunk\n");
    abort();
  }
  return 0;
}
'''

# TWO bugs, and the decoy fires only on SHORT inputs -- exactly the shape that
# tempts a minimizer into the wrong finding.
TWO_BUGS = r'''
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
static void die(const char *fn, int line) {
  fprintf(stderr, "==1==ERROR: AddressSanitizer: heap-buffer-overflow on address 0x602\n");
  fprintf(stderr, "    #0 0x4f1 in %s /src/parser.c:%d:13\n", fn, line);
  fprintf(stderr, "SUMMARY: AddressSanitizer: heap-buffer-overflow /src/parser.c:%d:13 in %s\n", line, fn);
  abort();
}
int main(int argc, char **argv) {
  if (argc < 2) return 0;
  FILE *f = fopen(argv[1], "rb"); if (!f) return 1;
  static uint8_t b[65536]; size_t n = fread(b, 1, sizeof b, f); fclose(f);
  for (size_t i = 0; i + 4 <= n; i++) if (!memcmp(b + i, "BOOM", 4)) die("parse_chunk", 25);
  if (n <= 8) die("parse_header", 99);
  return 0;
}
'''


def compile_c(src: str, out: Path) -> str:
    with tempfile.NamedTemporaryFile("w", suffix=".c", delete=False) as f:
        f.write(src)
        path = f.name
    p = subprocess.run(["clang", "-O1", "-g", path, "-o", str(out)],
                       capture_output=True, text=True)
    os.unlink(path)
    if p.returncode != 0:
        raise AssertionError(f"fixture build failed:\n{p.stderr}")
    return str(out)


class DdminTest(unittest.TestCase):
    """The reduction itself, with a pure predicate."""

    def test_reduces_to_the_marker(self):
        data = b"x" * 200 + b"BOOM" + b"y" * 200
        out, _ = minimize.ddmin(data, lambda d: b"BOOM" in d)
        self.assertEqual(out, b"BOOM")

    def test_keeps_what_the_predicate_needs(self):
        out, _ = minimize.ddmin(b"abcdefghij", lambda d: b"a" in d and b"j" in d)
        self.assertIn(b"a", out)
        self.assertIn(b"j", out)

    def test_a_predicate_nothing_satisfies_leaves_the_input(self):
        data = b"abcdef"
        out, _ = minimize.ddmin(data, lambda d: False)
        self.assertEqual(out, data)

    def test_rounds_are_bounded(self):
        _, rounds = minimize.ddmin(b"x" * 500, lambda d: True, max_rounds=3)
        self.assertLessEqual(rounds, 3)


@unittest.skipUnless(HAVE_CLANG, "needs clang")
class RealBinaryTest(unittest.TestCase):
    def setUp(self):
        self.td = tempfile.TemporaryDirectory()
        self.addCleanup(self.td.cleanup)
        self.d = Path(self.td.name)
        self.scanner = {"verify_binary": compile_c(SCANNER, self.d / "scanner_verify")}
        self.big = self.d / "big.bin"
        payload = bytearray(b"\xab" * 4096)
        payload[2000:2004] = b"BOOM"
        self.big.write_bytes(bytes(payload))

    def test_a_4kb_input_reduces_to_the_trigger(self):
        r = minimize.minimize(self.scanner, str(self.big), harness="parser")
        self.assertEqual(bytes(r.data), b"BOOM")
        self.assertEqual(r.original_size, 4096)
        self.assertLess(r.ratio, 0.01)

    def test_the_bug_is_preserved(self):
        base = replay.replay(self.scanner, str(self.big), harness="parser", attempts=1)
        r = minimize.minimize(self.scanner, str(self.big), harness="parser")
        self.assertEqual(r.stack_hash, base.stack_hash)

    def test_the_minimized_input_still_reproduces(self):
        r = minimize.minimize(self.scanner, str(self.big), harness="parser")
        out = self.d / "min.bin"
        minimize.write(r, out)
        again = replay.replay(self.scanner, str(out), harness="parser", attempts=1)
        self.assertEqual(again.verdict, replay.CRASH)
        self.assertEqual(again.stack_hash, r.stack_hash)

    def test_it_is_deterministic(self):
        """A minimized PoV is evidence, so it must not depend on when it ran."""
        a = minimize.minimize(self.scanner, str(self.big), harness="parser")
        b = minimize.minimize(self.scanner, str(self.big), harness="parser")
        self.assertEqual(bytes(a.data), bytes(b.data))
        self.assertEqual(a.probes, b.probes)

    def test_it_will_not_minimize_into_a_different_bug(self):
        """THE test. The decoy crashes on any input of 8 bytes or fewer, so
        "still crashes" would reduce this to a byte or two -- smaller, and the
        wrong finding."""
        rec = {"verify_binary": compile_c(TWO_BUGS, self.d / "two_bugs_verify")}
        base = replay.replay(rec, str(self.big), harness="parser", attempts=1)
        self.assertIn("parse_chunk", base.top_frame)

        r = minimize.minimize(rec, str(self.big), harness="parser")
        self.assertEqual(r.stack_hash, base.stack_hash,
                         "minimized into a different bug")
        self.assertEqual(bytes(r.data), b"BOOM")

        # and prove the decoy really was reachable by shrinking
        tiny = self.d / "tiny.bin"
        tiny.write_bytes(b"\x00")
        decoy = replay.replay(rec, str(tiny), harness="parser", attempts=1)
        self.assertEqual(decoy.verdict, replay.CRASH)
        self.assertNotEqual(decoy.stack_hash, base.stack_hash)

    def test_an_input_that_does_not_crash_is_refused(self):
        clean = self.d / "clean.bin"
        clean.write_bytes(b"nothing here")
        with self.assertRaises(minimize.MinimizeError) as cm:
            minimize.minimize(self.scanner, str(clean), harness="parser")
        self.assertIn("does not reproduce", str(cm.exception))

    def test_an_empty_input_is_refused(self):
        empty = self.d / "empty.bin"
        empty.write_bytes(b"")
        with self.assertRaises(minimize.MinimizeError):
            minimize.minimize(self.scanner, str(empty), harness="parser")

    def test_a_pinned_hash_can_be_supplied(self):
        base = replay.replay(self.scanner, str(self.big), harness="parser", attempts=1)
        r = minimize.minimize(self.scanner, str(self.big), harness="parser",
                              stack_hash=base.stack_hash)
        self.assertEqual(r.stack_hash, base.stack_hash)

    def test_the_probe_budget_is_honoured_and_reported(self):
        r = minimize.minimize(self.scanner, str(self.big), harness="parser",
                              max_probes=3)
        self.assertLessEqual(r.probes, 3)
        self.assertIn("budget", r.reason)

    def test_a_truncated_search_never_returns_an_unchecked_input(self):
        """Running out of budget must not ship a smaller input nobody
        verified."""
        for budget in (1, 2, 3, 5, 8):
            with self.subTest(max_probes=budget):
                r = minimize.minimize(self.scanner, str(self.big), harness="parser",
                                      max_probes=budget)
                out = self.d / f"b{budget}.bin"
                minimize.write(r, out)
                again = replay.replay(self.scanner, str(out), harness="parser", attempts=1)
                self.assertEqual(again.stack_hash, r.stack_hash)

    def test_it_refuses_an_instrumented_binary(self):
        rec = {"cmplog_binary": self.scanner["verify_binary"]}
        from cc_fuzzer_core import variants
        with self.assertRaises(variants.SelectionError):
            minimize.minimize(rec, str(self.big), harness="parser")


if __name__ == "__main__":
    unittest.main()
