"""Delta sweep (cc_fuzzer_core.sweep): a verdict for every risky changed line."""
from __future__ import annotations

import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from cc_fuzzer_core import sweep as S

REPO = Path(__file__).resolve().parents[1]

DIFF = """diff --git a/lib/proto.c b/lib/proto.c
--- a/lib/proto.c
+++ b/lib/proto.c
@@ -200,6 +200,16 @@ static int handle_auth(struct conn *c)
   log_msgf(c, "auth start");
+  char *resp = malloc(1024);
+  size_t n = read_reply(c, resp + 1024 * c->count, 1024);
+  char *sp = strchr(resp, ' ');
+  strcpy(combined, c->user);
+  log_msgf(c, sp);
+  log_msgf(c,
+           "multi-line call %s", sp);
+  snprintf(c->msg, sizeof(c->msg), sp);
+  /* printf(x) in a comment */
+  free(resp);
   return 0;
diff --git a/docs/NOTES.md b/docs/NOTES.md
--- a/docs/NOTES.md
+++ b/docs/NOTES.md
@@ -1,1 +1,2 @@
 notes
+more notes
diff --git a/lib/plain.c b/lib/plain.c
--- a/lib/plain.c
+++ b/lib/plain.c
@@ -10,2 +10,3 @@ void f(void)
 {
+  g();
 }
"""


def _by_line(doc):
    return {s["line"]: s["classes"] for it in doc["items"] for s in it["sinks"]}


class SinksTest(unittest.TestCase):
    def test_classes(self):
        self.assertEqual(S.sinks_of("snprintf(buf, sizeof(buf), user);"), ["format-string"])
        self.assertEqual(S.sinks_of('snprintf(buf, sizeof(buf), "%s", user);'), [])
        self.assertIn("copy", S.sinks_of("strcpy(dst, src);"))
        self.assertEqual(S.sinks_of("x = read(fd, buf + off * n, len);"), ["ptr-arith"])
        self.assertEqual(S.sinks_of("strcpy(dst, c->user);"), ["copy"])     # -> is not a minus
        self.assertIn("scan", S.sinks_of("p = strchr(buf, ' ');"))
        self.assertEqual(S.sinks_of("int16_t len = h->len;"), ["int-type"])
        self.assertEqual(S.sinks_of("char *p = q;"), [])                      # a pointer, not an int
        self.assertEqual(S.sinks_of("// strcpy(a, b);"), [])

    def test_wrappers_come_from_the_diff(self):
        self.assertEqual(S.format_wrappers(DIFF), {"log_msgf"})
        self.assertEqual(S.sinks_of("log_msgf(c, sp);", {"log_msgf"}), ["format-string"])
        self.assertEqual(S.sinks_of("log_msgf(c, sp);"), [])
        self.assertEqual(S.sinks_of("log_msgf(c,", {"log_msgf"}), [])        # call continues


class BuildTest(unittest.TestCase):
    def setUp(self):
        self.doc = S.build(DIFF, source="t.diff")

    def test_items_and_lines(self):
        lines = _by_line(self.doc)
        self.assertEqual(lines[202], ["ptr-arith", "int-type"])
        self.assertEqual(lines[203], ["scan"])
        self.assertEqual(lines[205], ["format-string"])                      # the wrapper call
        self.assertEqual(lines[208], ["format-string"])
        self.assertNotIn(201, lines)                                          # char *resp
        self.assertNotIn(206, lines)                                          # call continues
        self.assertNotIn(209, lines)                                          # comment
        self.assertEqual(self.doc["verdicts"]["h2"]["verdict"], "not-code")   # docs/

    def test_required_and_order(self):
        req = {r["id"]: r for r in S.required(self.doc)}
        self.assertIn("h3", req)                                              # a code hunk with no sink
        self.assertEqual(req["h3"]["class"], "hunk")
        self.assertNotIn("h2", req)
        first = S.show(self.doc).splitlines()[1]
        self.assertIn("format-string", first)


class MarkAndGateTest(unittest.TestCase):
    def setUp(self):
        self.doc = S.build(DIFF)
        self.td = tempfile.TemporaryDirectory()
        self.addCleanup(self.td.cleanup)
        self.pov = Path(self.td.name) / "pov.bin"
        self.pov.write_bytes(b"x")

    def _open(self):
        return [r["id"] for r in S.open_items(self.doc)]

    def test_mark_rules(self):
        some = self._open()[0]
        with self.assertRaises(S.SweepError):
            S.mark(self.doc, "h9.s9", "safe", "a long enough reason")
        with self.assertRaises(S.SweepError):
            S.mark(self.doc, some, "safe", "short")
        with self.assertRaises(S.SweepError):
            S.mark(self.doc, some, "reached", "ran it and nothing happened")    # no --input
        with self.assertRaises(S.SweepError):
            S.mark(self.doc, some, "crash", "it crashed hard", input_path="/nope")
        S.mark(self.doc, some, "crash", "it crashed hard", input_path=str(self.pov))
        self.assertNotIn(some, self._open())

    def test_a_hunk_verdict_closes_its_sinks(self):
        S.mark(self.doc, "h1", "unreachable", "the harness never authenticates")
        self.assertEqual(self._open(), ["h3"])

    def test_gate_blocks_with_progress_only_and_gives_up(self):
        block, msg = S.gate(self.doc)
        self.assertTrue(block)
        self.assertIn("format-string", msg)
        # continuing for the hook with no progress: let it end
        self.assertFalse(S.gate(self.doc, stop_hook_active=True)[0])
        S.mark(self.doc, "h3", "safe", "only a call with no arguments")
        self.assertTrue(S.gate(self.doc, stop_hook_active=True)[0])          # progress
        self.assertTrue(S.gate(self.doc)[0])
        self.assertFalse(S.gate(self.doc)[0])                                # MAX_BLOCKS reached
        self.assertEqual(self.doc["gate"]["blocks"], S.MAX_BLOCKS)

    def test_complete_never_blocks(self):
        S.mark(self.doc, "h1", "safe", "all bounded by the length check")
        S.mark(self.doc, "h3", "safe", "only a call with no arguments")
        self.assertEqual(S.gate(self.doc), (False, "delta sweep complete"))


class CliTest(unittest.TestCase):
    def _run(self, *args, stdin=None):
        return subprocess.run([sys.executable, "-m", "cc_fuzzer_core", "sweep", *args],
                              input=stdin, capture_output=True, text=True,
                              env={**os.environ, "PYTHONPATH": str(REPO / "src")})

    def test_init_mark_and_hook(self):
        with tempfile.TemporaryDirectory() as d:
            diff, f = Path(d) / "x.diff", Path(d) / "sweep.json"
            diff.write_text(DIFF)
            r = self._run("init", str(diff), "--file", str(f))
            self.assertEqual(r.returncode, 0, r.stderr)
            self.assertEqual(self._run("init", str(diff), "--file", str(f)).returncode, 2)  # exists
            self.assertEqual(self._run("gate", "--file", str(f)).returncode, 1)
            hook = self._run("gate", "--hook", "--file", str(f), stdin='{"stop_hook_active": false}')
            self.assertEqual(hook.returncode, 0)
            self.assertEqual(json.loads(hook.stdout)["decision"], "block")
            self.assertEqual(self._run("mark", "h1", "safe", "every write is bounded", "--file",
                                       str(f)).returncode, 0)
            self.assertEqual(self._run("mark", "h3", "safe", "only a call with no args", "--file",
                                       str(f)).returncode, 0)
            self.assertEqual(self._run("gate", "--file", str(f)).returncode, 0)
            hook = self._run("gate", "--hook", "--file", str(f), stdin="{}")
            self.assertEqual((hook.returncode, hook.stdout), (0, ""))

    def test_the_file_can_come_from_the_environment(self):
        with tempfile.TemporaryDirectory() as d:
            diff, f = Path(d) / "x.diff", Path(d) / "env-sweep.json"
            diff.write_text(DIFF)
            env = {**os.environ, "PYTHONPATH": str(REPO / "src"), S.SWEEP_FILE_ENV: str(f)}
            r = subprocess.run([sys.executable, "-m", "cc_fuzzer_core", "sweep", "init", str(diff)],
                               capture_output=True, text=True, env=env, cwd=d)
            self.assertEqual(r.returncode, 0, r.stderr)
            self.assertTrue(f.is_file())

    def test_the_skill_ships_in_the_wheel(self):
        text = (REPO / "pyproject.toml").read_text()
        self.assertIn('"skills/delta-sweep" = "cc_fuzzer_core/data/skills/delta-sweep"', text)
        self.assertTrue((REPO / "skills" / "delta-sweep" / "SKILL.md").is_file())

    def test_hook_without_a_sweep_allows(self):
        with tempfile.TemporaryDirectory() as d:
            r = self._run("gate", "--hook", "--file", str(Path(d) / "none.json"), stdin="{}")
            self.assertEqual((r.returncode, r.stdout), (0, ""))


if __name__ == "__main__":
    unittest.main()
