"""UPDATE_ROADMAP.md §4 stage 3 + §11: the swappable verifier, and the gate.

§4: what counts as FINAL confirmation is not universal, so it is configured.
    The downstream contract is the point -- `command:<path>` lets a host plug
    its own oracle in without the core knowing anything about it.

§11: nothing enters fuzz/findings/ unless the promote path put it there after
    a verifier confirmed it, and the directory carries a marker saying so. The
    roadmap's own acceptance test is that a forced unverified promotion is
    refused BOTH at the API and by the hook, so both are exercised here.
"""
from __future__ import annotations

import json
import os
import subprocess
import tempfile
import textwrap
import unittest
from pathlib import Path

from cc_fuzzer_core import gate
from cc_fuzzer_core.crash import pipeline, verifiers
from cc_fuzzer_core.crash.verifiers import command as cmd_verifier
from tests.support.golden import REPO, core

HOOK = REPO / "hooks" / "gate-findings.sh"

ORACLE = textwrap.dedent('''\
    #!/usr/bin/env bash
    req="$(cat)"
    repro=$(printf '%s' "$req" | python3 -c 'import json,sys; print(json.load(sys.stdin)["reproducer"])')
    if [ -s "$repro" ] && head -c4 "$repro" | grep -q BOOM; then
      printf '{"schema":"verify-verdict/v1","status":"confirmed","reason":"oracle reproduced it","evidence":["%s"]}\\n' "$repro"
    else
      printf '{"schema":"verify-verdict/v1","status":"rejected","reason":"no repro"}\\n'
    fi
''')


class FakeCampaign:
    def __init__(self, root: Path):
        self.project_root = root
        self.fuzz_root = root / "fuzz"


def run_cli(*args, stdin=""):
    env = dict(os.environ)
    env.update({"PYTHONPATH": str(REPO / "src"), "CC_FUZZER_ROOT": str(REPO)})
    return subprocess.run(core(*args), input=stdin, capture_output=True, text=True, env=env)


class ResolveTest(unittest.TestCase):
    def test_default_is_poc_realism(self):
        self.assertEqual(verifiers.step_of({}), "poc-realism")
        self.assertEqual(verifiers.step_of(None), "poc-realism")

    def test_config_selects_the_step(self):
        cfg = {"verification": {"final_step": "command:/bin/true", "timeout_s": 5}}
        self.assertEqual(verifiers.step_of(cfg), "command:/bin/true")
        self.assertEqual(verifiers.timeout_of(cfg), 5)

    def test_only_poc_realism_is_agent_backed(self):
        """The loop must dispatch an agent for poc-realism and call the
        verifier inline for everything else."""
        self.assertTrue(verifiers.is_agent_backed("poc-realism"))
        self.assertFalse(verifiers.is_agent_backed("command:/x"))
        self.assertFalse(verifiers.is_agent_backed("python:m:f"))

    def test_python_verifier_resolves(self):
        fn = verifiers.resolve("python:json:dumps")
        self.assertTrue(callable(fn))

    def test_unknown_step_names_the_alternatives(self):
        with self.assertRaises(verifiers.VerifierError) as cm:
            verifiers.resolve("magic")
        for needle in ("poc-realism", "command:", "python:"):
            self.assertIn(needle, str(cm.exception))

    def test_bad_python_spec_is_refused(self):
        for spec in ("python:nomodule", "python:json:nope", "python::f"):
            with self.subTest(spec=spec):
                with self.assertRaises(verifiers.VerifierError):
                    verifiers.resolve(spec)

    def test_a_bad_verdict_status_is_refused(self):
        with self.assertRaises(verifiers.VerifierError):
            verifiers.Verdict("maybe")
        with self.assertRaises(verifiers.VerifierError):
            verifiers.Verdict.from_dict({"status": "ok"})


class CommandVerifierTest(unittest.TestCase):
    """The downstream contract: JSON in, JSON out, and no way to turn an
    oracle malfunction into a rejected finding."""

    def setUp(self):
        self.td = tempfile.TemporaryDirectory()
        self.addCleanup(self.td.cleanup)
        self.d = Path(self.td.name)
        self.oracle = self.d / "oracle.sh"
        self.oracle.write_text(ORACLE)
        self.oracle.chmod(0o755)
        self.crash = self.d / "crash.bin"
        self.crash.write_bytes(b"BOOMxxxx")
        self.safe = self.d / "safe.bin"
        self.safe.write_bytes(b"safe")

    def _cfg(self, step=None):
        return {"verification": {"final_step": step or f"command:{self.oracle}",
                                 "timeout_s": 30}}

    def test_the_oracle_confirms(self):
        v = verifiers.verify({"id": "f001"},
                             {"reproducer": str(self.crash)}, config=self._cfg())
        self.assertEqual(v.status, verifiers.CONFIRMED)
        self.assertEqual(list(v.evidence), [str(self.crash)])

    def test_the_oracle_rejects(self):
        v = verifiers.verify({"id": "f002"},
                             {"reproducer": str(self.safe)}, config=self._cfg())
        self.assertEqual(v.status, verifiers.REJECTED)

    def test_the_request_carries_what_the_oracle_needs(self):
        req = verifiers.request({"id": "f1", "stack_hash": "abc"},
                                {"harness": "parser", "reproducer": "/r.bin",
                                 "binaries": {"verify_binary": "/b/v"},
                                 "replay": {"verdict": "crash"}})
        self.assertEqual(req["schema"], verifiers.REQUEST_SCHEMA)
        self.assertEqual(req["finding"]["stack_hash"], "abc")
        self.assertEqual(req["binaries"]["verify_binary"], "/b/v")
        self.assertEqual(req["replay"]["verdict"], "crash")
        self.assertEqual(json.loads(json.dumps(req)), req)

    def test_a_broken_oracle_is_inconclusive_never_rejected(self):
        """Every way of failing to reach a verdict must be distinguishable
        from the oracle saying no -- otherwise a bad day for the oracle
        silently discards real findings."""
        cases = {
            "missing": "command:/nonexistent-oracle-xyz",
            "no output": "command:/bin/false",
        }
        bad_json = self.d / "bad.sh"
        bad_json.write_text("#!/usr/bin/env bash\necho 'not json'\n")
        bad_json.chmod(0o755)
        cases["bad json"] = f"command:{bad_json}"
        bad_status = self.d / "badstatus.sh"
        bad_status.write_text('#!/usr/bin/env bash\necho \'{"status":"probably"}\'\n')
        bad_status.chmod(0o755)
        cases["bad status"] = f"command:{bad_status}"
        for label, step in cases.items():
            with self.subTest(case=label):
                v = verifiers.verify({"id": "f"}, {"reproducer": str(self.crash)},
                                     config=self._cfg(step))
                self.assertEqual(v.status, verifiers.INCONCLUSIVE, v.reason)

    def test_a_hanging_oracle_times_out_as_inconclusive(self):
        hang = self.d / "hang.sh"
        hang.write_text("#!/usr/bin/env bash\ncat >/dev/null\nsleep 30\n")
        hang.chmod(0o755)
        v = verifiers.verify({"id": "f"}, {"reproducer": str(self.crash)},
                             config={"verification": {"final_step": f"command:{hang}",
                                                      "timeout_s": 1}})
        self.assertEqual(v.status, verifiers.INCONCLUSIVE)
        self.assertIn("timed out", v.reason)


class RealismVerifierTest(unittest.TestCase):
    def setUp(self):
        self.td = tempfile.TemporaryDirectory()
        self.addCleanup(self.td.cleanup)
        self.d = Path(self.td.name)
        for n in ("driver.sh", "verifier.sh"):
            (self.d / n).write_text("#!/bin/sh\nexit 0\n")

    def _att(self, **over):
        att = {"driver": "driver.sh", "verifier": "verifier.sh", "boundary": "b",
               "precondition": "p", "projected_vs_demonstrated": "pv"}
        att.update(over)
        return att

    def test_no_attestation_is_inconclusive_not_rejected(self):
        """The PoC bundle has not been built yet; the answer is to dispatch
        poc-builder, not to drop the finding."""
        v = verifiers.verify({"id": "f"}, {"project_root": str(self.d)}, config={})
        self.assertEqual(v.status, verifiers.INCONCLUSIVE)
        self.assertIn("poc-builder", v.reason)

    def test_a_complete_attestation_confirms(self):
        v = verifiers.verify({"realism_attestation": self._att()},
                             {"project_root": str(self.d)}, config={})
        self.assertEqual(v.status, verifiers.CONFIRMED)

    def test_missing_statements_are_rejected(self):
        v = verifiers.verify({"realism_attestation": self._att(boundary="")},
                             {"project_root": str(self.d)}, config={})
        self.assertEqual(v.status, verifiers.REJECTED)
        self.assertIn("boundary", v.reason)

    def test_an_attested_file_that_does_not_exist_is_rejected(self):
        v = verifiers.verify({"realism_attestation": self._att(driver="nope.sh")},
                             {"project_root": str(self.d)}, config={})
        self.assertEqual(v.status, verifiers.REJECTED)
        self.assertIn("nope.sh", v.reason)


class MarkerTest(unittest.TestCase):
    def setUp(self):
        self.td = tempfile.TemporaryDirectory()
        self.addCleanup(self.td.cleanup)
        self.root = Path(self.td.name)
        self.repro = self.root / "crash.bin"
        self.repro.write_bytes(b"BOOMxxxx")
        self.binary = self.root / "parser_fuzzer_verify"
        self.binary.write_bytes(b"\x7fELF fake")
        self.record = {"verify_binary": str(self.binary)}

    def _finalize(self, status=verifiers.CONFIRMED, fid="f001"):
        c = FakeCampaign(self.root)
        return pipeline.finalize(
            c, fid, {"id": fid, "stack_hash": "abc123"}, record=self.record,
            reproducer=str(self.repro), harness="parser",
            replay_result={"verdict": "crash", "stack_hash": "abc123"},
            verify_fn=lambda f, ctx: verifiers.Verdict(status, "test"))

    def test_a_confirmed_finding_gets_a_directory_and_a_marker(self):
        r = self._finalize()
        self.assertTrue(r.confirmed)
        self.assertTrue(Path(r.marker).is_file())
        doc = json.loads(Path(r.marker).read_text())
        self.assertEqual(doc["schema"], pipeline.MARKER_SCHEMA)
        self.assertEqual(doc["status"], verifiers.CONFIRMED)
        self.assertEqual(doc["stack_hash"], "abc123")
        self.assertTrue(pipeline.verified(r.directory))

    def test_a_rejected_finding_creates_nothing(self):
        """No half-made directory to be mistaken for a finding later."""
        r = self._finalize(status=verifiers.REJECTED, fid="f002")
        self.assertFalse(r.confirmed)
        self.assertEqual(r.directory, "")
        self.assertFalse((self.root / "fuzz" / "findings" / "f002").exists())

    def test_an_inconclusive_finding_creates_nothing(self):
        r = self._finalize(status=verifiers.INCONCLUSIVE, fid="f003")
        self.assertEqual(r.directory, "")
        self.assertFalse((self.root / "fuzz" / "findings" / "f003").exists())

    def test_a_directory_without_a_marker_is_not_verified(self):
        d = self.root / "fuzz" / "findings" / "hand-made"
        d.mkdir(parents=True)
        (d / "poc.c").write_text("int main(){}")
        problems = pipeline.marker_problems(d)
        self.assertTrue(problems)
        self.assertIn("no .verified", problems[0])

    def test_a_changed_reproducer_invalidates_the_marker(self):
        """The marker records what was verified. If the reproducer changed
        afterwards, the claim no longer describes what is on disk."""
        r = self._finalize()
        self.repro.write_bytes(b"DIFFERENT")
        problems = pipeline.marker_problems(r.directory)
        self.assertTrue(any("reproducer changed" in p for p in problems))

    def test_a_changed_binary_invalidates_the_marker(self):
        r = self._finalize()
        self.binary.write_bytes(b"\x7fELF other")
        problems = pipeline.marker_problems(r.directory)
        self.assertTrue(any("binary changed" in p for p in problems), problems)
        self.assertFalse(pipeline.verified(r.directory))

    def test_a_forged_marker_status_is_rejected(self):
        r = self._finalize()
        doc = json.loads(Path(r.marker).read_text())
        doc["status"] = "rejected"
        Path(r.marker).write_text(json.dumps(doc))
        self.assertFalse(pipeline.verified(r.directory))

    def test_the_marker_is_written_last(self):
        """Interrupting a promotion must leave something that reads as
        unverified, not as a finding."""
        c = FakeCampaign(self.root)
        with self.assertRaises(RuntimeError):
            pipeline.finalize(c, "f009", {"id": "f009"}, record=self.record,
                              reproducer=str(self.repro), harness="parser",
                              verify_fn=lambda f, ctx: (_ for _ in ()).throw(
                                  RuntimeError("verifier exploded")))
        self.assertFalse((self.root / "fuzz" / "findings" / "f009" /
                          pipeline.MARKER_NAME).exists())


class ApiAndHookTest(unittest.TestCase):
    """The roadmap's §11 acceptance test: a forced unverified promotion is
    refused at the API AND by the hook."""

    WRITES = (
        ("Bash", "cp /tmp/exploit.c fuzz/findings/f001/exploit.c", ""),
        ("Bash", "mkdir -p fuzz/findings/f001", ""),
        ("Bash", "echo done > fuzz/findings/f001/notes.md", ""),
        ("Bash", "tee fuzz/findings/f001/out.log", ""),
        ("Write", "", "fuzz/findings/f001/poc.c"),
        ("Edit", "", "/abs/path/fuzz/findings/f001/poc.c"),
    )

    def test_the_api_refuses_every_hand_write(self):
        for tool, cmd, path in self.WRITES:
            with self.subTest(tool=tool, target=cmd or path):
                v = gate.classify_finding_write(cmd, tool=tool, path=path)
                self.assertFalse(v.allowed)
                self.assertIn("promote", v.suggestion)

    def test_the_api_allows_the_promote_path_and_reads(self):
        for tool, cmd, path in (
                ("Bash", "cc-fuzzer findings promote f001 --driver d --verifier v", ""),
                ("Bash", "ls fuzz/findings/", ""),
                ("Bash", "cat fuzz/findings/f001/.verified", ""),
                ("Write", "", "fuzz/state/notes.md")):
            with self.subTest(target=cmd or path):
                self.assertTrue(gate.classify_finding_write(cmd, tool=tool, path=path).allowed)

    def _hook(self, payload):
        env = dict(os.environ)
        env.update({"PYTHONPATH": str(REPO / "src"), "CC_FUZZER_ROOT": str(REPO)})
        return subprocess.run(["bash", str(HOOK)], input=json.dumps(payload),
                              capture_output=True, text=True, env=env)

    def test_the_hook_refuses_every_hand_write(self):
        for tool, cmd, path in self.WRITES:
            with self.subTest(tool=tool, target=cmd or path):
                ti = {"command": cmd} if tool == "Bash" else {"file_path": path}
                r = self._hook({"tool_name": tool, "tool_input": ti})
                self.assertTrue(r.stdout.strip(), "hook produced no verdict")
                doc = json.loads(r.stdout)["hookSpecificOutput"]
                self.assertEqual(doc["permissionDecision"], "deny")
                self.assertIn("Run instead:", doc["permissionDecisionReason"])

    def test_the_hook_allows_the_promote_path(self):
        r = self._hook({"tool_name": "Bash", "tool_input": {
            "command": "cc-fuzzer findings promote f001 --driver d --verifier v"}})
        self.assertEqual(r.stdout.strip(), "")

    def test_the_hook_fails_open_on_junk(self):
        env = dict(os.environ)
        env.update({"PYTHONPATH": str(REPO / "src"), "CC_FUZZER_ROOT": str(REPO)})
        for payload in ("", "not json", "[]", "{}"):
            with self.subTest(payload=payload):
                r = subprocess.run(["bash", str(HOOK)], input=payload,
                                   capture_output=True, text=True, env=env)
                self.assertEqual(r.returncode, 0)
                self.assertEqual(r.stdout.strip(), "")

    def test_registered_for_the_writing_tools(self):
        doc = json.loads((REPO / "hooks" / "hooks.json").read_text())
        entry = [e for e in doc["hooks"]["PreToolUse"]
                 if "gate-findings.sh" in json.dumps(e)][0]
        for tool in ("Write", "Edit", "MultiEdit", "Bash"):
            self.assertIn(tool, entry["matcher"])

    def test_cli_check_finding(self):
        with tempfile.TemporaryDirectory() as td:
            d = Path(td) / "f001"
            d.mkdir()
            r = run_cli("gate", "check-finding", str(d))
            self.assertEqual(r.returncode, 1)
            self.assertIn(".verified", r.stderr)


if __name__ == "__main__":
    unittest.main()
