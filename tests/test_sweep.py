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

    def test_more_classes(self):
        for line, cls in (("*(unsigned int *)res = 0;", "cast-deref"),
                          ("content_len += header_len;", "len-arith"),
                          ("b = proj_copy(b, d, n);", "copy"),
                          ("proj_free(r->x);", "free"),
                          ("p = proj_alloc(MAX_SIZE, log);", "alloc"),
                          ("rev[j] = buf[i];", "index-write"),
                          ("abort();", "abort"),
                          ("r3 = r1 / r2;", "div"),
                          ("if (++w->count == w->count_max) {", "eq-bound")):
            with self.subTest(line=line):
                self.assertIn(cls, S.sinks_of(line))
        self.assertEqual(S.sinks_of('printf("%d/%s", a, b);'), [])           # not a division
        self.assertEqual(S.sinks_of("if (i == n) {"), [])

    def test_removed_checks_and_changed_constants(self):
        diff = ("--- a/x.c\n+++ b/x.c\n@@ -10,6 +10,5 @@ int f(char *p, int n)\n"
                "   int a = 0;\n"
                "-  if (n > 16) return -1;\n"
                "-  char buf[32];\n"
                "+  char buf[16];\n"
                "   /* (offset 3, length 6). */\n"
                "-  /* (offset 2, length 6). */\n"
                "   return 0;\n")
        doc = S.build(diff)
        got = {s["text"]: s["classes"] for s in doc["items"][0]["sinks"]}
        self.assertEqual(got["removed: if (n > 16) return -1;"], ["removed-check"])
        self.assertIn("const-change", got["char buf[16];"])
        self.assertFalse(any("offset" in t for t in got))                    # comments are not items

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


@unittest.skipUnless(__import__("tests.support.claude_driver", fromlist=["x"]).claude_binary(),
                     "no Claude Code binary cached")
class LiveGateTest(unittest.TestCase):
    """Real Claude Code, scripted model: the Stop hook holds the turn open once
    and lets it end when the agent makes no progress."""

    def test_the_gate_blocks_then_lets_go(self):
        from tests.support import claude_driver
        with tempfile.TemporaryDirectory() as d:
            diff, f = Path(d) / "x.diff", Path(d) / "sweep.json"
            diff.write_text(DIFF)
            S.save(S.build(DIFF), f)
            hook = {"type": "command", "command": f"{REPO / 'hooks' / 'sweep-gate.sh'} --file {f}"}
            res, final = claude_driver.run([{"text": "finished"}, {"text": "still finished"}],
                                           settings={"hooks": {"Stop": [{"hooks": [hook]}]}})
            self.assertEqual(final.get("subtype"), "success")
            reqs = claude_driver.last_requests
            self.assertEqual(len(reqs), 2)                        # blocked once, then allowed
            blocked = json.dumps(reqs[1]["messages"][-1])
            self.assertIn("delta sweep", blocked)
            self.assertEqual(S.load(f)["gate"]["blocks"], 1)


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
            gate = self._run("gate", "--json", "--file", str(f))
            self.assertEqual(gate.returncode, 0)
            self.assertEqual(json.loads(gate.stdout)["decision"], "block")
            hook = subprocess.run([str(REPO / "hooks" / "sweep-gate.sh"), "--file", str(f)],
                                  input='{"stop_hook_active": false}', capture_output=True, text=True)
            self.assertEqual(json.loads(hook.stdout)["decision"], "block")
            self.assertEqual(self._run("mark", "h1", "safe", "every write is bounded", "--file",
                                       str(f)).returncode, 0)
            self.assertEqual(self._run("mark", "h3", "safe", "only a call with no args", "--file",
                                       str(f)).returncode, 0)
            self.assertEqual(self._run("gate", "--file", str(f)).returncode, 0)
            gate = self._run("gate", "--json", "--file", str(f))
            self.assertEqual(json.loads(gate.stdout)["decision"], "allow")

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

    def test_a_missing_sweep_allows(self):
        with tempfile.TemporaryDirectory() as d:
            r = self._run("gate", "--json", "--file", str(Path(d) / "none.json"))
            self.assertEqual(json.loads(r.stdout)["decision"], "allow")
            h = subprocess.run([str(REPO / "hooks" / "sweep-gate.sh"), "--file", str(Path(d) / "none.json")],
                               input="{}", capture_output=True, text=True)
            self.assertEqual((h.returncode, h.stdout), (0, ""))


if __name__ == "__main__":
    unittest.main()
