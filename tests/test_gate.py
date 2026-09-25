"""UPDATE_ROADMAP.md §12: which binary an action runs on is a core decision.

A crash reproduced on an instrumented binary (cmplog, symcc, coverage) is not
evidence about the target -- it is evidence about the instrumentation. Under
time pressure a triager reaches for whichever binary is already built, so the
rule is enforced twice and both layers ask the same code:

  - variants.select() / check_binary() refuse at the API
  - hooks/gate-verify-build.sh refuses earlier, via `cc-fuzzer gate`

These tests cover both, and the seam between them -- a hook that fails open is
worse than no hook, because it reads as enforcement.
"""
from __future__ import annotations

import json
import os
import subprocess
import tempfile
import unittest
from pathlib import Path

from cc_fuzzer_core import gate, variants
from tests.support.golden import REPO, core

HOOK = REPO / "hooks" / "gate-verify-build.sh"

FULL = {
    "harness_binary": "/b/parser_fuzzer",
    "verify_binary": "/b/parser_fuzzer_verify",
    "coverage_binary": "/b/parser_fuzzer_cov",
    "cmplog_binary": "/b/parser_fuzzer_cmplog",
    "symcc_binary": "/b/parser_fuzzer_symcc",
}
NO_VERIFY = {k: v for k, v in FULL.items() if k != "verify_binary"}


def run_cli(*args, stdin=""):
    env = dict(os.environ)
    env.update({"PYTHONPATH": str(REPO / "src"), "CC_FUZZER_ROOT": str(REPO)})
    return subprocess.run(core(*args), input=stdin, capture_output=True, text=True, env=env)


class SelectTest(unittest.TestCase):
    def test_evidence_actions_use_the_verify_binary(self):
        for action in (variants.A_REPLAY, variants.A_VERIFY, variants.A_POC):
            with self.subTest(action=action):
                sel = variants.select(FULL, action, harness="parser")
                self.assertEqual(sel.variant, "verify")
                self.assertEqual(sel.evidence_grade, variants.STRONG)

    def test_evidence_actions_never_reach_an_instrumented_binary(self):
        """Even when the verify binary is the only one missing, replay must not
        silently land on cmplog/symcc/coverage."""
        only_instrumented = {"cmplog_binary": "/b/c", "symcc_binary": "/b/s",
                             "coverage_binary": "/b/cov"}
        for action in (variants.A_REPLAY, variants.A_VERIFY, variants.A_POC):
            with self.subTest(action=action):
                with self.assertRaises(variants.SelectionError):
                    variants.select(only_instrumented, action, harness="parser")

    def test_replay_falls_back_to_the_fuzzing_binary_as_weak_evidence(self):
        sel = variants.select(NO_VERIFY, variants.A_REPLAY, harness="parser")
        self.assertEqual(sel.variant, "fuzzer")
        self.assertEqual(sel.evidence_grade, variants.WEAK)
        self.assertIn("no verify_binary", sel.reason)

    def test_verify_and_poc_do_not_get_that_fallback(self):
        """replay is allowed to degrade and say so; a finding's verification
        and its PoC are not."""
        for action in (variants.A_VERIFY, variants.A_POC):
            with self.subTest(action=action):
                with self.assertRaises(variants.SelectionError):
                    variants.select(NO_VERIFY, action, harness="parser")

    def test_cmplog_and_concolic_are_launcher_only(self):
        for action in variants.LAUNCHER_ONLY:
            with self.subTest(action=action):
                with self.assertRaises(variants.SelectionError) as cm:
                    variants.select(FULL, action, harness="parser")
                self.assertIn("launcher", str(cm.exception))
                ok = variants.select(FULL, action, caller=variants.LAUNCHER_CALLER,
                                     harness="parser")
                self.assertTrue(ok.binary)

    def test_check_binary_refuses_a_substitute(self):
        with self.assertRaises(variants.SelectionError) as cm:
            variants.check_binary(FULL, variants.A_REPLAY, "/b/parser_fuzzer_cmplog")
        self.assertIn("parser_fuzzer_verify", str(cm.exception))

    def test_check_binary_accepts_the_selected_one(self):
        sel = variants.check_binary(FULL, variants.A_REPLAY, "/b/parser_fuzzer_verify")
        self.assertEqual(sel.variant, "verify")

    def test_unknown_action_is_refused(self):
        with self.assertRaises(variants.SelectionError):
            variants.select(FULL, "exploit")

    def test_a_missing_binary_names_what_it_wanted(self):
        with self.assertRaises(variants.SelectionError) as cm:
            variants.select({}, variants.A_FUZZ, harness="parser")
        self.assertIn("harness_binary", str(cm.exception))
        self.assertIn("parser", str(cm.exception))


class ClassifyCommandTest(unittest.TestCase):
    def test_running_an_instrumented_binary_is_denied(self):
        for name in ("parser_fuzzer_cmplog", "parser_fuzzer_symcc", "parser_fuzzer_cov"):
            with self.subTest(binary=name):
                v = gate.classify_command(f"./{name} input.bin", record=FULL, harness="parser")
                self.assertFalse(v.allowed)
                self.assertIn(name, v.reason)
                self.assertTrue(v.suggestion)

    def test_the_launcher_may_use_them(self):
        v = gate.classify_command(
            "bash scripts/launch-fuzzer-slot.sh --harness parser --binary ./parser_fuzzer_cmplog",
            record=FULL, harness="parser")
        self.assertTrue(v.allowed)

    def test_replaying_a_crash_on_the_fuzzing_binary_is_denied(self):
        v = gate.classify_command(
            "/b/parser_fuzzer fuzz/crashes/new/parser__abc.bin", record=FULL, harness="parser")
        self.assertFalse(v.allowed)
        self.assertIn("parser_fuzzer_verify", v.reason)

    def test_replaying_on_the_verify_binary_is_allowed(self):
        v = gate.classify_command(
            "/b/parser_fuzzer_verify fuzz/crashes/new/parser__abc.bin",
            record=FULL, harness="parser")
        self.assertTrue(v.allowed)

    def test_unrelated_commands_are_untouched(self):
        for cmd in ("ls fuzz/crashes/new/", "git status", "python3 -m pytest", ""):
            with self.subTest(cmd=cmd):
                self.assertTrue(gate.classify_command(cmd, record=FULL).allowed)

    def test_a_crash_path_without_a_known_binary_is_allowed(self):
        """The gate refuses the wrong BUILD; it does not police every command
        that mentions a crash file."""
        self.assertTrue(gate.classify_command(
            "cp fuzz/crashes/new/parser__abc.bin /tmp/", record=FULL).allowed)

    def test_variants_are_read_from_the_declarations(self):
        """The suffix table comes from variants, so a new instrumented variant
        cannot leave a hole here."""
        for name in variants.forbidden_for_evidence():
            self.assertEqual(gate.variant_of(f"x{variants.BINARY_SUFFIX[name]}"), name)


class GateCliTest(unittest.TestCase):
    def test_deny_exits_1_and_explains(self):
        r = run_cli("gate", "classify-command", "--command", "./parser_fuzzer_cmplog in.bin")
        self.assertEqual(r.returncode, 1)
        self.assertIn("cmplog", r.stderr)

    def test_allow_exits_0(self):
        r = run_cli("gate", "classify-command", "--command", "ls")
        self.assertEqual(r.returncode, 0)

    def test_json_carries_the_decision(self):
        r = run_cli("gate", "classify-command", "--json",
                    "--command", "./parser_fuzzer_cov x.bin")
        doc = json.loads(r.stdout)
        self.assertEqual(doc["decision"], "deny")
        self.assertEqual(doc["variant"], "coverage")

    def test_reads_stdin(self):
        r = run_cli("gate", "classify-command", "--json", stdin="./parser_fuzzer_symcc x")
        self.assertEqual(json.loads(r.stdout)["decision"], "deny")


class HookTest(unittest.TestCase):
    """The hook must translate the core's verdict and nothing else."""

    def _run(self, command, tool="Bash", cwd=None):
        payload = json.dumps({"hook_event_name": "PreToolUse", "tool_name": tool,
                              "cwd": cwd or str(REPO),
                              "tool_input": {"command": command}})
        env = dict(os.environ)
        env.update({"PYTHONPATH": str(REPO / "src"), "CC_FUZZER_ROOT": str(REPO)})
        return subprocess.run(["bash", str(HOOK)], input=payload,
                              capture_output=True, text=True, env=env)

    def test_denies_an_instrumented_binary_with_a_way_forward(self):
        r = self._run("./parser_fuzzer_cmplog fuzz/crashes/new/x.bin")
        self.assertEqual(r.returncode, 0, r.stderr)
        doc = json.loads(r.stdout)["hookSpecificOutput"]
        self.assertEqual(doc["permissionDecision"], "deny")
        self.assertIn("cmplog", doc["permissionDecisionReason"])
        self.assertIn("Run instead:", doc["permissionDecisionReason"])

    def test_a_denial_is_never_reported_as_an_allow(self):
        """`gate classify-command` exits 1 to MEAN deny. A `|| allow` on that
        exit status turns every refusal into a silent allow -- the one failure
        this hook exists to prevent, and it did exactly that once."""
        r = self._run("./parser_fuzzer_symcc x.bin")
        self.assertTrue(r.stdout.strip(), "hook produced no verdict for a denied command")
        self.assertIn("deny", r.stdout)

    def test_allows_an_ordinary_command_silently(self):
        r = self._run("ls fuzz/state")
        self.assertEqual(r.returncode, 0)
        self.assertEqual(r.stdout.strip(), "")

    def test_ignores_other_tools(self):
        r = self._run("./parser_fuzzer_cmplog x", tool="Write")
        self.assertEqual(r.stdout.strip(), "")

    def test_malformed_input_fails_open(self):
        env = dict(os.environ)
        env.update({"PYTHONPATH": str(REPO / "src"), "CC_FUZZER_ROOT": str(REPO)})
        for payload in ("", "not json", "[]", "{}"):
            with self.subTest(payload=payload):
                r = subprocess.run(["bash", str(HOOK)], input=payload,
                                   capture_output=True, text=True, env=env)
                self.assertEqual(r.returncode, 0)
                self.assertEqual(r.stdout.strip(), "")

    def test_registered_on_pretooluse_for_bash(self):
        doc = json.loads((REPO / "hooks" / "hooks.json").read_text())
        entry = doc["hooks"]["PreToolUse"][0]
        self.assertEqual(entry["matcher"], "Bash")
        self.assertIn("gate-verify-build.sh", entry["hooks"][0]["command"])


class ConsumerTest(unittest.TestCase):
    """The callers that pick a binary must go through select()."""

    def test_findings_verify_uses_the_selector(self):
        src = (REPO / "src" / "cc_fuzzer_core" / "findings.py").read_text()
        self.assertIn("_verify_binary(c, harness)", src)
        self.assertIn("A_VERIFY", src)

    def test_launcher_declares_itself_as_the_launcher(self):
        src = (REPO / "src" / "cc_fuzzer_core" / "slots" / "launcher.py").read_text()
        self.assertIn("LAUNCHER_CALLER", src)
        self.assertIn("A_CMPLOG", src)


if __name__ == "__main__":
    unittest.main()
