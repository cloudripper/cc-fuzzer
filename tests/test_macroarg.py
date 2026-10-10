"""macroarg: function-like macro calls with expression arguments (sweep macro-arg).

The motivating miss (finals Q38): a bounds-check macro called with `6+8+4`,
whose body subtracts the argument without parentheses. The agent reached the
line and marked it safe as "a pure refactor"; it never expanded the macro.
"""
from __future__ import annotations

import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from cc_fuzzer_core import macroarg, sweep

CHECK_DEFINE = ("#define CHECKOVERFLOW(offset,datasize,structsize) (( offset >= datasize) || "
                "(structsize > datasize) || (offset > datasize - structsize ))\n")

DIFF = """diff --git a/lib/mnote.c b/lib/mnote.c
--- a/lib/mnote.c
+++ b/lib/mnote.c
@@ -160,7 +160,7 @@ mnote_load (Data *n, const unsigned char *buf, unsigned int buf_size)
 \t\treturn;
 \t}
-\tif (CHECKOVERFLOW(datao, buf_size, 12)) {
+\tif (CHECKOVERFLOW(n->offset, buf_size, 6+8+4)) {
 \t\treturn;
 \t}
 \tc = get_short (buf + datao);
"""


def tree(files: dict) -> Path:
    root = Path(tempfile.mkdtemp())
    for rel, text in files.items():
        (root / rel).parent.mkdir(parents=True, exist_ok=True)
        (root / rel).write_text(text)
    return root


class CallsTest(unittest.TestCase):
    def test_expression_arguments_only(self):
        self.assertEqual(macroarg.calls("if (CHECKOVERFLOW(n->offset, buf_size, 6+8+4)) {"),
                         [("CHECKOVERFLOW", ["n->offset", "buf_size", "6+8+4"])])
        self.assertEqual(macroarg.calls("if (CHECKOVERFLOW(n->offset, buf_size, 8)) {"), [])   # constants
        self.assertEqual(macroarg.calls("CHECK(a->b, c.d, -1)"), [])                          # no binary op
        self.assertEqual(macroarg.calls("y = ARRAY_SIZE(t) * 2;"), [])                       # op outside
        self.assertEqual(macroarg.calls("v = Min(a+b, c);"), [])                             # not ALL-CAPS

    def test_names_inside_string_literals_are_not_calls(self):
        """freerdp delta-03: `"... WBT_FRAME_END (0x%x)"` read as a call with `0x % x`."""
        self.assertEqual(macroarg.calls('WLog_Print(log, WLOG_ERROR, "wants WBT_FRAME_END (0x%x)", *p);'), [])
        self.assertEqual(macroarg.calls("MAX('%', a+b)"), [("MAX", ['""', "a+b"])])

    def test_nested_calls_and_parentheses(self):
        got = macroarg.calls("x = AVIF_CLAMP(Cr - AVIF_CLAMP(Cr,minCr,maxCr),0.0f,1.0f);")
        self.assertEqual(got[0], ("AVIF_CLAMP", ["Cr - AVIF_CLAMP(Cr,minCr,maxCr)", "0.0f", "1.0f"]))
        self.assertEqual(macroarg.calls("v[MIN (maxlen-1, size)] = 0;"), [("MIN", ["maxlen-1", "size"])])


class CheckTest(unittest.TestCase):
    P3 = ["offset", "datasize", "structsize"]
    BODY = CHECK_DEFINE.split(")", 1)[1].strip()

    def test_the_subtracted_sum(self):
        self.assertEqual(macroarg.check(self.P3, self.BODY, ["n->offset", "buf_size", "6+8+4"]),
                         ["`datasize - structsize` becomes `datasize - 6 + 8 + 4`"])
        # `6+8+4 > datasize` groups as the call reads: only the subtraction is reported
        self.assertEqual(len(macroarg.check(self.P3, self.BODY, ["a", "b", "6+8+4"])), 1)
        self.assertEqual(macroarg.check(self.P3, self.BODY, ["n->offset", "buf_size", "18"]), [])

    def test_precedence_cases(self):
        cases = [
            (["a", "b"], "((a) * (b))", ["x+1", "y"], False),      # parenthesised: safe
            (["a", "b"], "(a * b)", ["x+1", "y"], True),           # x + 1*b
            (["a", "b"], "(a < b ? a : b)", ["x+1", "y-2"], False),
            (["x"], "(-x)", ["a-b"], True),                        # unary minus
            (["x"], "((size_t)x)", ["a+b"], True),                 # cast binds first
            (["x"], "(x + 1)", ["a+b"], False),
            (["x"], "(1 + x)", ["a+b"], False),                    # + is associative
            (["x"], "(1 - x)", ["a+b"], True),
            (["x"], "(x << 2)", ["a+b"], False),                   # + binds tighter than <<
            (["x"], "(x == 0)", ["a&b"], True),                    # the a & b == 0 trap
            (["x"], "#x", ["a+b"], False),                         # stringified
            (["x", "y"], "x ## y", ["a+b", "c"], False),           # pasted
            (["x"], "f(x, 2)", ["a+b"], False),                    # a function argument
            (["x"], "(2 * x)", ["a*b"], False),                    # * is associative
            (["x"], "(2 / x)", ["a*b"], True),
        ]
        for params, body, args, bad in cases:
            self.assertEqual(bool(macroarg.check(params, body, args)), bad, (body, args))

    def test_arity_mismatch_and_expand(self):
        self.assertEqual(macroarg.check(["a", "b"], "(a-b)", ["x+1"]), [])               # variadic etc.
        self.assertEqual(macroarg.expand(["a", "ab"], "(a - ab)", ["x+1", "y"]), "(x+1 - y)")


class FindDefineTest(unittest.TestCase):
    def test_the_calling_file_wins_then_headers_anywhere(self):
        root = tree({"lib/mnote.c": "int x;\n" + CHECK_DEFINE,
                     "include/other.h": "#define CHECKOVERFLOW(a,b,c) ((a)+(b)+(c))\n",
                     "include/deep/m.h": "#define SPAN(lo, \\\n   hi) \\\n  (hi - lo)\n"})
        params, body, where, line = macroarg.find_define("CHECKOVERFLOW", root, near="lib/mnote.c")
        self.assertEqual((params, where, line), (["offset", "datasize", "structsize"], "lib/mnote.c", 2))
        params, body, where, _ = macroarg.find_define("SPAN", root, near="lib/mnote.c")
        self.assertEqual((params, body, where), (["lo", "hi"], "(hi - lo)", "include/deep/m.h"))
        self.assertIsNone(macroarg.find_define("NOPE", root, near="lib/mnote.c"))
        self.assertIsNone(macroarg.find_define("CHECKOVERFLOW", root / "missing"))


    def test_diff_paths_resolve_one_directory_down(self):
        """OSS-Fuzz layout: the finder's source dir is /src and the diff's
        paths are relative to /src/<project>; a dependency beside it is not
        searched."""
        root = tree({"proj/lib/mnote.c": CHECK_DEFINE,
                     "dep/include/x.h": "#define OTHER(a) (a)\n"})
        self.assertEqual(macroarg.repo_root(root, "lib/mnote.c"), root / "proj")
        self.assertEqual(macroarg.find_define("CHECKOVERFLOW", root, near="lib/mnote.c")[2], "lib/mnote.c")
        self.assertIsNone(macroarg.find_define("OTHER", root, near="lib/mnote.c"))
        self.assertEqual(macroarg.repo_root(root, "nope.c"), root)
        doc = sweep.build(DIFF, src_root=root)
        self.assertTrue(any("macro-precedence" in r["classes"] for r in sweep.required(doc)))


class SweepTest(unittest.TestCase):
    def test_with_the_source_the_item_carries_the_expansion_and_goes_first(self):
        root = tree({"lib/mnote.c": CHECK_DEFINE})
        doc = sweep.build(DIFF, src_root=root)
        req = sweep.required(doc)
        item = next(r for r in req if "macro-arg" in r["classes"])
        self.assertEqual(item["classes"][:2], ["macro-precedence", "macro-arg"])
        self.assertIn("buf_size - 6+8+4", item["note"])
        self.assertIn("`datasize - structsize` becomes `datasize - 6 + 8 + 4`", item["note"])
        shown = sweep.show(doc).splitlines()
        self.assertIn("macro-precedence", shown[1])                   # first item
        self.assertIn("expands to", shown[2])

    def test_without_the_source_or_the_define_it_says_to_expand_it(self):
        doc = sweep.build(DIFF)
        item = next(r for r in sweep.required(doc) if "macro-arg" in r["classes"])
        self.assertEqual(item["class"], "macro-arg")
        self.assertIn("expand it", item["note"])
        doc = sweep.build(DIFF, src_root=tree({"lib/other.c": "int y;\n"}))
        item = next(r for r in sweep.required(doc) if "macro-arg" in r["classes"])
        self.assertIn("no #define found", item["note"])

    def test_a_safe_macro_is_an_item_with_its_expansion_but_sorts_last(self):
        root = tree({"lib/mnote.c": "#define CHECKOVERFLOW(o,d,s) (((o) >= (d)) || ((o) > (d) - (s)))\n"})
        diff = DIFF.replace("-\tif (CHECKOVERFLOW(datao, buf_size, 12)) {\n", "") \
                   .replace(" \tc = get_short (buf + datao);", "+\tmemcpy(dst, buf + datao, c);")
        doc = sweep.build(diff, src_root=root)
        req = sorted(sweep.open_items(doc), key=lambda r: sweep._ORDER.get(r["class"], 99))
        self.assertEqual([r["class"] for r in req], ["copy", "macro-arg"])
        self.assertNotIn("precedence", req[1]["note"])
        self.assertIn("expands to", req[1]["note"])

    def test_cli_init_takes_the_source_tree(self):
        root = tree({"lib/mnote.c": CHECK_DEFINE})
        d = Path(tempfile.mkdtemp())
        (d / "ref.diff").write_text(DIFF)
        out = subprocess.run([sys.executable, "-m", "cc_fuzzer_core", "sweep", "init", str(d / "ref.diff"),
                              "--file", str(d / "s.json"), "--src", str(root)],
                             capture_output=True, text=True)
        self.assertEqual(out.returncode, 0, out.stderr)
        self.assertIn("macro-precedence", out.stdout)
        self.assertTrue(any(s.get("note") for it in json.loads((d / "s.json").read_text())["items"]
                            for s in it["sinks"]))


if __name__ == "__main__":
    unittest.main()
