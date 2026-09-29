"""Determinism knobs: in config, and echoed into every result (cc_fuzzer_core.determinism)."""
from __future__ import annotations

import json
import os
import shutil
import tempfile
import unittest
from pathlib import Path

from cc_fuzzer_core import crs, determinism, patch


class ResolveTest(unittest.TestCase):
    def test_defaults_are_the_module_constants(self):
        from cc_fuzzer_core import minimize
        from cc_fuzzer_core.crash import replay
        d = determinism.resolve({})
        self.assertEqual((d["replay_attempts"], d["minimize_max_probes"]),
                         (replay.ATTEMPTS, minimize.MAX_PROBES))

    def test_explicit_beats_config_beats_default(self):
        cfg = {"determinism": {"replay_attempts": 5, "fuzzer_seed": 1337}}
        d = determinism.resolve(cfg, replay_attempts=2)
        self.assertEqual((d["replay_attempts"], d["fuzzer_seed"]), (2, 1337))

    def test_bad_knobs_are_refused(self):
        for block in ({"replay_attemps": 3}, {"replay_attempts": 0},
                      {"minimize_max_probes": -1}, {"fuzzer_seed": "1"}, {"fuzzer_seed": True}):
            with self.subTest(block=block), self.assertRaises(determinism.DeterminismError):
                determinism.resolve({"determinism": block})

    def test_the_echo_is_schema_tagged_and_complete(self):
        e = determinism.echo(determinism.resolve({}))
        self.assertEqual(e["schema"], "determinism/v1")
        self.assertEqual(set(e) - {"schema"}, set(determinism.KNOBS))


@unittest.skipUnless(shutil.which("clang"), "needs clang")
class EchoTest(unittest.TestCase):
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
        self.cfg = {"verification": {"final_step": f"command:{o}"},
                    "determinism": {"replay_attempts": 2, "fuzzer_seed": 1337,
                                    "sensitivity_max_probes": 6}}

    def test_triage_uses_and_echoes_the_config(self):
        r = crs.triage(self.record, str(self.crash), harness="p", config=self.cfg)
        self.assertEqual(r.replay["attempts"], 2, "the knob was used, not just echoed")
        self.assertEqual(r.determinism["replay_attempts"], 2)
        self.assertEqual(r.determinism["fuzzer_seed"], 1337)
        self.assertEqual(r.sensitivity["probes"], 6)
        self.assertEqual(r.as_dict()["determinism"]["schema"], "determinism/v1")

    def test_an_argument_still_wins(self):
        r = crs.triage(self.record, str(self.crash), harness="p", config=self.cfg, attempts=1)
        self.assertEqual((r.replay["attempts"], r.determinism["replay_attempts"]), (1, 1))


class PatchEchoTest(unittest.TestCase):
    def test_the_verdict_echoes_and_gates_get_the_seed(self):
        with tempfile.TemporaryDirectory() as td:
            d = Path(td)
            (d / "p.diff").write_text("--- a/x\n+++ b/x\n@@\n-a\n+b\n")
            (d / "a.bin").write_bytes(b"x")
            g = d / "g.sh"
            g.write_text(f'#!/bin/sh\necho "$CC_FUZZER_FUZZER_SEED" > {d}/seed\n')
            g.chmod(0o755)
            cfg = {"determinism": {"fuzzer_seed": 42},
                   "patch": {"extra_gates": [{"name": "g", "command": f"command:{g}"}]}}
            v = patch.validate({}, str(d / "p.diff"), str(d / "a.bin"), project_root=d,
                               config=cfg,
                               replay_fn=lambda p, ph, b: patch.PovRun(ph == "before", "h"))
            self.assertEqual(v.status, patch.FIXES, v.reason)
            self.assertEqual(v.determinism["fuzzer_seed"], 42)
            self.assertEqual((d / "seed").read_text().strip(), "42")

    def test_robust_fuzz_passes_the_seed_to_libfuzzer(self):
        with tempfile.TemporaryDirectory() as td:
            d = Path(td)
            stub = d / "fuzzer"
            stub.write_text(f'#!/bin/sh\necho "$@" >> {d}/argv\nexit 0\n')
            stub.chmod(0o755)
            (d / "pov").write_bytes(b"x")
            r = patch.robust_fuzz(str(stub), str(d / "pov"), 1, seed=1337)
            self.assertTrue(r["ok"])
            self.assertIn("-seed=1337", (d / "argv").read_text())


if __name__ == "__main__":
    unittest.main()
