"""Tool-call hygiene (cc_fuzzer_core.hygiene): a call repeated within one response runs once."""
from __future__ import annotations

import json
import os
import subprocess
import sys
import tempfile
import threading
import unittest
from pathlib import Path

from cc_fuzzer_core import hygiene as H
from tests.support import claude_driver

REPO = Path(__file__).resolve().parents[1]


def _call(tid, session="s", prompt="p", tool="Read", inp=None, now=None):
    return H.call(session, prompt, tid, tool, inp if inp is not None else {"file_path": "/x.c"}, now=now)


class HygieneTest(unittest.TestCase):
    def setUp(self):
        self.td = tempfile.TemporaryDirectory()
        self.addCleanup(self.td.cleanup)
        os.environ[H.STATE_ENV] = self.td.name
        self.addCleanup(os.environ.pop, H.STATE_ENV, None)

    def test_a_duplicate_in_one_response_is_denied_once(self):
        self.assertIsNone(_call("a"))
        self.assertIn("Duplicate", _call("b"))
        self.assertIsNone(_call("c"))       # asked again: allowed

    def test_a_copy_with_the_same_call_id_is_a_duplicate(self):
        """The qualification duplicates all repeated the original's id."""
        self.assertIsNone(_call("same"))
        self.assertIn("Duplicate", _call("same"))

    def test_different_input_or_tool_is_not_a_duplicate(self):
        self.assertIsNone(_call("a"))
        self.assertIsNone(_call("b", inp={"file_path": "/y.c"}))
        self.assertIsNone(_call("c", tool="Bash", inp={"file_path": "/x.c"}))

    def test_the_batch_ends_with_the_response(self):
        self.assertIsNone(_call("a"))
        H.batch_end("s")
        self.assertIsNone(_call("b"))       # the next response

    def test_sessions_prompts_and_age_separate_batches(self):
        self.assertIsNone(_call("a"))
        self.assertIsNone(_call("b", session="other"))
        self.assertIsNone(_call("c", prompt="p2"))
        self.assertIsNone(_call("d", prompt="p2", now=__import__("time").time() + H.MAX_AGE_S + 1))

    def test_concurrent_copies_run_once(self):
        denied = []

        def one(i):
            if _call(f"id{i}"):
                denied.append(i)
        ts = [threading.Thread(target=one, args=(i,)) for i in range(2)]
        for t in ts:
            t.start()
        for t in ts:
            t.join()
        self.assertEqual(len(denied), 1)

    def test_cli_decides_and_never_fails(self):
        env = {**os.environ, "PYTHONPATH": str(REPO / "src")}
        run = lambda tid, stdin: json.loads(subprocess.run(
            [sys.executable, "-m", "cc_fuzzer_core", "hygiene", "call", "--session", "s",
             "--prompt", "p", "--id", tid, "--tool", "Read"],
            input=stdin, capture_output=True, text=True, env=env).stdout)
        self.assertEqual(run("a", '{"file_path": "/x.c"}')["decision"], "allow")
        self.assertEqual(run("b", '{"file_path": "/x.c"}')["decision"], "deny")
        self.assertEqual(run("c", "not json")["decision"], "allow")

    def test_the_plugin_hook_translates(self):
        env = {**os.environ, H.STATE_ENV: self.td.name}
        hook = lambda ev: subprocess.run([str(REPO / "hooks" / "dedup-calls.sh")], input=json.dumps(ev),
                                         capture_output=True, text=True, env=env).stdout
        ev = {"hook_event_name": "PreToolUse", "session_id": "h", "prompt_id": "p", "tool_name": "Read",
              "tool_input": {"file_path": "/x.c"}}
        self.assertEqual(hook({**ev, "tool_use_id": "1"}), "")
        out = json.loads(hook({**ev, "tool_use_id": "2"}))
        self.assertEqual(out["hookSpecificOutput"]["permissionDecision"], "deny")
        hook({"hook_event_name": "PostToolBatch", "session_id": "h"})
        self.assertEqual(hook({**ev, "tool_use_id": "3"}), "")

    def test_registered_in_the_plugin(self):
        hooks = json.loads((REPO / "hooks" / "hooks.json").read_text())["hooks"]
        cmd = "${CLAUDE_PLUGIN_ROOT}/hooks/dedup-calls.sh"
        self.assertTrue(any(h["command"] == cmd for m in hooks["PreToolUse"] for h in m["hooks"]))
        self.assertTrue(any(h["command"] == cmd for m in hooks["PostToolBatch"] for h in m["hooks"]))


@unittest.skipUnless(claude_driver.claude_binary(), "no Claude Code binary cached "
                     "(scripts/claude-code-contract.py fetch <version>)")
class LiveHygieneTest(unittest.TestCase):
    """Real Claude Code, scripted model: duplicates in one response run once."""

    def test_against_the_cli(self):
        with tempfile.TemporaryDirectory() as d:
            work = Path(d) / "w"
            work.mkdir()
            (work / "a.c").write_text("int a;\n" * 50)
            hook = {"type": "command", "command": str(REPO / "hooks" / "dedup-calls.sh")}
            settings = {"hooks": {"PreToolUse": [{"matcher": "Read|Bash", "hooks": [hook]}],
                                  "PostToolBatch": [{"hooks": [hook]}]}}
            read = {"tool": "Read", "input": {"file_path": str(work / "a.c")}}
            bash = {"tool": "Bash", "input": {"command": "echo ran >> runs.txt", "description": "r"}}
            res, final = claude_driver.run(
                [{"tools": [read, read, bash, bash]}, bash, {"tools": [bash, bash], "same_id": True},
                 {"text": "done"}],
                settings=settings, workdir=work, env={H.STATE_ENV: str(Path(d) / "state")})
            self.assertEqual(final.get("subtype"), "success")
            errs = [r["is_error"] for r in res]
            # which of two concurrent copies is denied is a race: exactly one per pair
            self.assertEqual((sum(errs[0:2]), sum(errs[2:4]), errs[4], sum(errs[5:7])),
                             (1, 1, False, 1), errs)
            self.assertIn("Duplicate", next(r["text"] for r in res if r["is_error"]))
            self.assertEqual((work / "runs.txt").read_text().count("ran"), 3)


if __name__ == "__main__":
    unittest.main()
