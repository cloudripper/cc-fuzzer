"""Which bytes of a PoV decide the bug (cc_fuzzer_core.minimize.sensitivity).

ddmin gives the shortest input that shows the bug. That input is still a mix
of framing the parser needs to get anywhere and the few bytes that decide the
faulting operand; the patch author needs the second set. These tests build a
real binary with every kind of byte in it -- a magic, a length that only has
to exceed a bound, an opcode one bit away from a different bug, and filler --
and check the map tells them apart.
"""
from __future__ import annotations

import json
import shutil
import tempfile
import unittest
from pathlib import Path

from cc_fuzzer_core import minimize as m
from tests.test_minimize import compile_c

HAVE_CLANG = shutil.which("clang") is not None

# "PX" magic, a length byte, an opcode, then anything.
#   len > 8 with op 'W' overflows in write_chunk (the bug under test)
#   op 'V' -- one bit away from 'W' -- overflows in verify_chunk instead
FRAMED = r'''
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
static void die(const char *fn, int line) {
  fprintf(stderr, "==1==ERROR: AddressSanitizer: heap-buffer-overflow on address 0x602\n");
  fprintf(stderr, "    #0 0x4f1 in %s /src/framed.c:%d:13\n", fn, line);
  fprintf(stderr, "SUMMARY: AddressSanitizer: heap-buffer-overflow /src/framed.c:%d:13 in %s\n", line, fn);
  abort();
}
int main(int argc, char **argv) {
  if (argc < 2) return 0;
  FILE *f = fopen(argv[1], "rb"); if (!f) return 1;
  static uint8_t b[4096]; size_t n = fread(b, 1, sizeof b, f); fclose(f);
  if (n < 4 || b[0] != 'P' || b[1] != 'X') return 0;
  if (b[3] == 'V') die("verify_chunk", 40);
  if (b[3] == 'W' && b[2] > 8) die("write_chunk", 25);
  return 0;
}
'''
POV = b"PX\x09Wzzzz"
#        ##~#....


class ClassifyByteTest(unittest.TestCase):
    def test_classes(self):
        self.assertEqual(m.classify_byte([m.NONE, m.OTHER]), m.LOAD_BEARING)
        self.assertEqual(m.classify_byte([m.SAME, m.NONE]), m.CONSTRAINED)
        self.assertEqual(m.classify_byte([m.SAME, m.SAME]), m.FREE)
        self.assertEqual(m.classify_byte([m.SAME, None]), m.UNKNOWN)

    def test_mutations_always_change_the_byte(self):
        for b in range(256):
            for x in m.MUTATIONS:
                self.assertNotEqual(b ^ x, b)


@unittest.skipUnless(HAVE_CLANG, "needs clang")
class SensitivityTest(unittest.TestCase):
    def setUp(self):
        self.td = tempfile.TemporaryDirectory()
        self.addCleanup(self.td.cleanup)
        self.d = Path(self.td.name)
        self.record = {"verify_binary": compile_c(FRAMED, self.d / "framed_verify")}
        self.pov = self.d / "pov.bin"
        self.pov.write_bytes(POV)

    def _map(self, **kw):
        return m.sensitivity(self.record, str(self.pov), harness="framed", **kw)

    def test_the_map_separates_every_kind_of_byte(self):
        s = self._map()
        self.assertEqual(s.mask, "##~#....")
        self.assertTrue(s.complete)
        self.assertEqual(s.probes, 2 * len(POV))

    def test_a_range_check_is_constrained_not_load_bearing(self):
        """The length only has to exceed 8: a big change keeps the bug, a
        one-bit change (9 -> 8) loses it. That is the check the patch adds."""
        self.assertEqual(self._map().offsets(m.CONSTRAINED), [2])

    def test_a_neighbouring_bug_is_reported_not_counted_as_the_same(self):
        s = self._map()
        self.assertEqual(len(s.neighbours), 1)
        n = s.neighbours[0]
        self.assertEqual(n["offsets"], [3])
        self.assertNotEqual(n["stack_hash"], s.stack_hash)

    def test_spans_carry_the_bytes(self):
        spans = [(sp.start, sp.end, sp.cls, sp.hex) for sp in self._map().spans]
        self.assertEqual(spans, [(0, 2, m.LOAD_BEARING, "5058"),
                                 (2, 3, m.CONSTRAINED, "09"),
                                 (3, 4, m.LOAD_BEARING, "57"),
                                 (4, 8, m.FREE, "7a7a7a7a")])

    def test_it_is_deterministic(self):
        self.assertEqual(self._map().as_dict()["mask"], self._map().as_dict()["mask"])

    def test_a_spent_budget_reports_unknown_rather_than_guessing(self):
        s = self._map(max_probes=5)
        self.assertEqual(s.mask, "##??????")
        self.assertFalse(s.complete)
        self.assertIn("budget", s.reason)

    def test_a_pinned_bug_the_input_does_not_show_is_refused(self):
        with self.assertRaises(m.MinimizeError):
            self._map(stack_hash="0" * 16)

    def test_a_non_crashing_input_is_refused(self):
        self.pov.write_bytes(b"PX\x01Wzzzz")
        with self.assertRaises(m.MinimizeError):
            self._map()

    def test_the_result_serialises(self):
        d = json.loads(json.dumps(self._map().as_dict()))
        self.assertEqual(d["schema"], m.SENSITIVITY_SCHEMA)
        self.assertEqual(d["counts"], {m.LOAD_BEARING: 3, m.CONSTRAINED: 1,
                                       m.FREE: 4, m.UNKNOWN: 0})

    def test_render_puts_the_mask_under_the_bytes(self):
        out = m.render(self._map(), POV).splitlines()
        self.assertTrue(out[0].startswith("00000000  50 58 09 57"))
        self.assertIn(" #  #  ~  #  .", out[1])


@unittest.skipUnless(HAVE_CLANG, "needs clang")
class AfterMinimizeTest(unittest.TestCase):
    """The intended order: minimize, then map what is left."""

    def test_minimize_then_map(self):
        with tempfile.TemporaryDirectory() as td:
            d = Path(td)
            rec = {"verify_binary": compile_c(FRAMED, d / "framed_verify")}
            big = d / "big.bin"
            big.write_bytes(b"PX\x09W" + b"\xcd" * 2000)
            r = m.minimize(rec, str(big), harness="framed")
            small = m.write(r, d / "big.bin.min")
            s = m.sensitivity(rec, str(small), harness="framed", stack_hash=r.stack_hash)
            self.assertEqual(s.mask[:4], "##~#")
            self.assertEqual(s.size, r.size)


if __name__ == "__main__":
    unittest.main()
