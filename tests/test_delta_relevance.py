"""Delta relevance: does a crash land in what the diff changed? (delta.relevance)

Every delta-mode consumer needs this and each was rebuilding it. It is
REPORTED, never used to filter: a crash far from the diff can still be the
diff's fault through data flow, so the decision belongs to the policy hook.
"""
from __future__ import annotations

import shutil
import tempfile
import unittest
from pathlib import Path

from cc_fuzzer_core import crs, delta

GIT_DIFF = """diff --git a/src/parser.c b/src/parser.c
index 1..2 100644
--- a/src/parser.c
+++ b/src/parser.c
@@ -22,0 +23,4 @@ static int parse_chunk(const uint8_t *b, size_t n)
+  if (len > cap)
+    return -1;
+  memcpy(dst, b, len);
+  return 0;
"""
PLAIN_DIFF = """--- a/lib/util.c\t2026-01-01
+++ b/lib/util.c\t2026-01-02
@@ -10,2 +10,3 @@ int helper(int x)
-  return x;
+  if (x < 0) return 0;
+  return x;
"""


LIBCUE_DIFF = """diff --git a/cd.c b/cd.c
--- a/cd.c
+++ b/cd.c
@@ -339,7 +339,7 @@ track_get_rem(const Track* track)
 
 void track_set_index(Track *track, int i, long ind)
 {
-\tif (i < 0 || i > MAXINDEX) {
+\tif (i > MAXINDEX) {
 \t\tfprintf(stderr, "too many indexes\\n");
                 return;
         }
"""


class HunkFunctionTest(unittest.TestCase):
    """AIxCC libcue delta: the hunk header names the function BEFORE the hunk
    (track_get_rem); the removed check is in track_set_index, and the crash
    at cd.c:347 is two lines past the hunk."""

    def test_changed_lines_are_attributed_to_their_own_function(self):
        t = delta.parse_diff(LIBCUE_DIFF)
        self.assertEqual(t[0]["function_context"], "track_get_rem(const Track* track)")
        self.assertEqual(t[0]["functions"], ["track_set_index"])

    def test_a_crash_just_past_the_hunk_in_the_changed_function_touches_the_diff(self):
        r = delta.relevance(["track_set_index @ /src/libcue/cd.c:347"],
                            delta.parse_diff(LIBCUE_DIFF))
        self.assertTrue(r["touches_diff"], r)
        self.assertEqual(r["functions_in_diff"], ["track_set_index @ /src/libcue/cd.c:347"])

    def test_an_added_function_counts_as_changed(self):
        d = ("--- a/x.c\n+++ b/x.c\n@@ -10,0 +11,3 @@ int other(void)\n"
             "+static int added(int v)\n+{\n+  return v;\n")
        self.assertEqual(delta.parse_diff(d)[0]["functions"], ["added"])


class ParseTest(unittest.TestCase):
    def test_a_plain_unified_diff_names_its_file(self):
        t = delta.parse_diff(PLAIN_DIFF)
        self.assertEqual([(x["file"], x["lines_changed"]) for x in t],
                         [("lib/util.c", [10, 12])])

    def test_a_git_diff_is_parsed_as_before(self):
        t = delta.parse_diff(GIT_DIFF)
        self.assertEqual((t[0]["file"], t[0]["lines_changed"]), ("src/parser.c", [23, 26]))


class RelevanceTest(unittest.TestCase):
    T = delta.parse_diff(GIT_DIFF)

    def test_delta_relevance(self):
        """Frames inside and outside the diff are both reported."""
        r = delta.relevance(["parse_chunk @ /src/proj/src/parser.c:25",
                             "main @ /src/proj/src/main.c:9"], self.T)
        self.assertTrue(r["touches_diff"])
        self.assertEqual(r["frames_in_diff"], ["parse_chunk @ /src/proj/src/parser.c:25"])
        self.assertEqual(r["nearest_frame_distance"], 0)

    def test_distance_to_the_nearest_hunk(self):
        r = delta.relevance(["read_hdr @ /src/proj/src/parser.c:40"], self.T)
        self.assertFalse(r["touches_diff"])
        self.assertEqual(r["nearest_frame_distance"], 14)

    def test_a_frame_in_a_changed_function_touches_the_diff(self):
        r = delta.relevance(["parse_chunk @ /src/proj/src/parser.c:90"], self.T)
        self.assertTrue(r["touches_diff"])
        self.assertEqual(r["functions_in_diff"], ["parse_chunk @ /src/proj/src/parser.c:90"])

    def test_a_build_time_symbol_prefix_still_names_the_changed_function(self):
        """libpng under OSS-Fuzz: PNG_PREFIX=OSS_FUZZ_ renames png_handle_iCCP."""
        r = delta.relevance(["OSS_FUZZ_parse_chunk @ /src/proj/src/parser.c:90"], self.T)
        self.assertTrue(r["touches_diff"])
        for fn in ("myparse_chunk", "Xparse_chunk", "oss_fuzz_parse_chunk", "parse_chunk2"):
            r = delta.relevance([f"{fn} @ /src/proj/src/parser.c:90"], self.T)
            self.assertFalse(r["touches_diff"], fn)

    def test_paths_match_on_whole_components(self):
        r = delta.relevance(["f @ /src/proj/src/myparser.c:25"], self.T)
        self.assertIsNone(r["nearest_frame_distance"], "myparser.c is not parser.c")

    def test_no_frames_in_changed_files(self):
        r = delta.relevance(["main @ /x/main.c:1"], self.T)
        self.assertEqual((r["touches_diff"], r["nearest_frame_distance"]), (False, None))


class AllocationStackTest(unittest.TestCase):
    """A use-after-free whose diff is in the allocating function: that frame
    is only in the "previously allocated by" stack, past the 12 report frames."""

    def test_the_allocation_stack_counts_for_relevance(self):
        from cc_fuzzer_core.crs import TriageResult, _delta_relevance
        report = "\n".join(
            ["==1==ERROR: AddressSanitizer: heap-use-after-free on address 0x1"]
            + [f"    #{i} 0x1 in cleanup_{i} /src/proj/src/other.c:{i + 1}:1" for i in range(14)]
            + ["previously allocated by thread T0 here:",
               "    #0 0x1 in malloc (/out/h+0x1)",
               "    #1 0x1 in parse_chunk /src/proj/src/parser.c:90:3",
               "SUMMARY: AddressSanitizer: heap-use-after-free"])
        r = TriageResult(status="confirmed",
                         frames=tuple(f"cleanup_{i} @ /src/proj/src/other.c:{i + 1}"
                                      for i in range(12)),
                         sanitizer_excerpt=report)
        rel = _delta_relevance(r, GIT_DIFF, None)
        self.assertTrue(rel["touches_diff"], rel)
        self.assertEqual(rel["functions_in_diff"], ["parse_chunk @ /src/proj/src/parser.c:90"])


@unittest.skipUnless(shutil.which("clang"), "needs clang")
class TriageTest(unittest.TestCase):
    """SCANNER's report puts parse_chunk at /src/parser.c:25."""

    def setUp(self):
        from tests.test_crs import ORACLE_OK
        from tests.test_minimize import SCANNER, compile_c
        self.td = tempfile.TemporaryDirectory()
        self.addCleanup(self.td.cleanup)
        self.d = Path(self.td.name)
        self.record = {"verify_binary": compile_c(SCANNER, self.d / "scanner_verify")}
        self.crash = self.d / "crash.bin"
        self.crash.write_bytes(b"zzBOOMzz")
        o = self.d / "oracle.sh"
        o.write_text(ORACLE_OK)
        o.chmod(0o755)
        self.cfg = {"verification": {"final_step": f"command:{o}"}}

    def _triage(self, diff_text):
        p = self.d / "ref.diff"
        p.write_text(diff_text)
        return crs.triage(self.record, str(self.crash), harness="p", config=self.cfg,
                          delta_range=str(p), do_sensitivity=False)

    def test_a_crash_in_the_diff(self):
        r = self._triage(GIT_DIFF)
        self.assertTrue(r.delta_relevance["touches_diff"])
        self.assertEqual(r.as_dict()["delta_relevance"]["schema"], "delta-relevance/v1")

    def test_nothing_is_filtered(self):
        r = self._triage(PLAIN_DIFF)
        self.assertFalse(r.delta_relevance["touches_diff"])
        self.assertEqual(r.status, crs.CONFIRMED)
        self.assertTrue(r.should_submit)

    def test_the_policy_can_use_it(self):
        import sys
        import types
        mod = types.ModuleType("delta_policy_mod")
        mod.decide = lambda res, ctx: res["delta_relevance"].get("touches_diff", False)
        sys.modules["delta_policy_mod"] = mod
        self.addCleanup(sys.modules.pop, "delta_policy_mod")
        self.cfg["submission"] = {"policy": "python:delta_policy_mod:decide"}
        self.assertTrue(self._triage(GIT_DIFF).should_submit)
        self.assertFalse(self._triage(PLAIN_DIFF).should_submit)

    def test_an_unreadable_range_is_reported_not_raised(self):
        r = crs.triage(self.record, str(self.crash), harness="p", config=self.cfg,
                       delta_range="main..HEAD", do_sensitivity=False)
        self.assertIn("error", r.delta_relevance)
        self.assertEqual(r.status, crs.CONFIRMED)


if __name__ == "__main__":
    unittest.main()
