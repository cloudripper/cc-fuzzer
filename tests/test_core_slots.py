"""UPDATE_ROADMAP.md §2 row 5: slot launcher and liveness ported into
cc_fuzzer_core.slots, plus core.tools.which.

  - parity: `cc-fuzzer slots launch|liveness` reproduce the launch-fuzzer-slot
    and check-slot-liveness goldens (Stage 0 + tests/support/cases.py)
  - fixes: no $CONFIG/$MANIFEST interpolation into Python source (paths with
    quotes work); liveness events carry their fields (the events.sh flag bug)
  - tools.which: $CC_FUZZER_TOOL_<NAME> > nix-env.json pin > PATH, no host scans
  - the scripts are shims; _lib/launch_slot.py is gone
"""
from __future__ import annotations

import json
import os
import shutil
import stat
import subprocess
import tempfile
import unittest
from pathlib import Path

from cc_fuzzer_core import events, tools
from cc_fuzzer_core.paths import Campaign
from cc_fuzzer_core.slots import launcher, liveness
from tests.support.cases import ROW5_CASES, assert_core_case
from tests.support.golden import FROZEN_NOW, REPO, GoldenTestCase, Sandbox, bash, core


class TestRow5Parity(GoldenTestCase):
    def test_extra_cases(self):
        for case in ROW5_CASES:
            with self.subTest(case=case.name):
                assert_core_case(self, case)

    def test_stage0_liveness(self):
        from tests.test_golden_bash import TestCheckSlotLiveness

        # Re-run each Stage 0 scenario (same setup, same golden) with the core
        # CLI in place of the script.
        orig_run = Sandbox.run

        def run_core(sb, argv, **kw):
            argv = list(argv)
            if argv[:2] == ["bash", str(REPO / "scripts/check-slot-liveness.sh")]:
                argv = core("slots", "liveness", *argv[2:])
            return orig_run(sb, argv, **kw)

        for name in ("test_no_manifest", "test_dry_run_all_dead", "test_dry_run_one_alive",
                     "test_deadlocked_and_missing_binary", "test_slot_without_harness_binding"):
            with self.subTest(test=name):
                t = TestCheckSlotLiveness(name)
                Sandbox.run = run_core
                try:
                    t.setUp()
                    getattr(t, name)()
                finally:
                    Sandbox.run = orig_run
                    t.doCleanups()


def _campaign(tmp: Path, name="proj") -> Campaign:
    root = tmp / name
    (root / "fuzz" / "state").mkdir(parents=True)
    return Campaign(root, root / "fuzz", root / "fuzz" / "state")


class TestLiveness(unittest.TestCase):
    def test_quoted_paths(self):
        # check-slot-liveness.sh pasted $CONFIG / $MANIFEST into Python source,
        # so a project path with a quote broke the slot plan.
        with tempfile.TemporaryDirectory() as d:
            c = _campaign(Path(d), "it's here")
            (c.state_dir / "fuzz-config.json").write_text(json.dumps(
                {"fuzzer_slots": [{"slot": "s1", "engine": "libfuzzer", "harness": "h"}]}))
            (c.state_dir / "fuzzers.json").write_text(json.dumps(
                {"schema": "fuzzers/v2", "slots": [{"slot": "s1", "pid": "2147480001", "restart_count": 2}]}))
            r = liveness.check(c, dry_run=True)
            self.assertEqual(r.lines, ["slot=s1 engine=libfuzzer state=dead would_restart=1 restart_count=2 harness=h"])

    def test_throttled(self):
        self.assertTrue(liveness.throttled("3", "2026-09-21T14:13:00Z", now=FROZEN_NOW))
        self.assertFalse(liveness.throttled("3", "2026-09-21T14:10:00Z", now=FROZEN_NOW))
        self.assertFalse(liveness.throttled("2", "2026-09-21T14:13:00Z", now=FROZEN_NOW))
        self.assertFalse(liveness.throttled("x", "2026-09-21T14:13:00Z", now=FROZEN_NOW))
        self.assertFalse(liveness.throttled("5", "", now=FROZEN_NOW))

    def test_events_have_fields(self):
        with tempfile.TemporaryDirectory() as d:
            c = _campaign(Path(d))
            events.append(c.state_dir, "tick", branch="b")
            row = events.append(c.state_dir, "error", error_message="boom")
            self.assertEqual((row["tick"], row["error_message"], row["schema"]), (1, "boom", "event/v1"))


class TestLauncherApi(unittest.TestCase):
    def test_update_manifest_restart(self):
        with tempfile.TemporaryDirectory() as d:
            mf = Path(d) / "fuzzers.json"
            base = dict(slot="s", engine="aflpp", binary="b", pid="1", pgid="1", started_at="T1",
                        log_file="l", pid_file="p", engine_file="e", role=None, afl_power_schedule=None,
                        harness="h")
            launcher.update_manifest(mf, dict(base))
            e = launcher.update_manifest(mf, dict(base, started_at="T2"), restart_of="s")
            self.assertEqual((e["restart_count"], e["last_restart_at"], list(e)[-1]), (1, "T2", "harness"))
            e = launcher.update_manifest(mf, dict(base, started_at="T3"))
            self.assertEqual((e["restart_count"], e["last_restart_at"]), (1, "T2"))
            self.assertEqual(len(json.loads(mf.read_text())["slots"]), 1)
            with self.assertRaises(ValueError):
                launcher.update_manifest(mf, dict(base, engine="honggfuzz"))

    def test_dict_files(self):
        self.assertEqual(launcher._dict_files(["a", "", "b"]), ["a", "b"])
        self.assertEqual(launcher._dict_files("one.dict"), ["one.dict"])
        self.assertEqual(launcher._dict_files(None), [])
        self.assertEqual(launcher._dict_files("[broken"), [])


def _exe(path: Path, body="#!/bin/sh\nexit 0\n"):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(body)
    path.chmod(path.stat().st_mode | stat.S_IXUSR)
    return path


class TestToolsWhich(unittest.TestCase):
    def test_env_var_name(self):
        self.assertEqual(tools.env_var("llvm-cov"), "CC_FUZZER_TOOL_LLVM_COV")
        self.assertEqual(tools.env_var("afl-fuzz"), "CC_FUZZER_TOOL_AFL_FUZZ")

    def test_order(self):
        with tempfile.TemporaryDirectory() as d:
            d = Path(d)
            c = _campaign(d)
            on_path = _exe(d / "bin" / "mytool")
            pinned = _exe(d / "nix" / "mytool")
            override = _exe(d / "override" / "mytool")
            env = {"PATH": str(d / "bin")}
            self.assertEqual(tools.which("mytool", c, env=env), str(on_path))
            (c.state_dir / "nix-env.json").write_text(json.dumps({"tools": {"mytool": str(pinned)}}))
            self.assertEqual(tools.which("mytool", c, env=env), str(pinned))
            env["CC_FUZZER_TOOL_MYTOOL"] = str(override)
            self.assertEqual(tools.which("mytool", c, env=env), str(override))
            # a non-executable override / pin is skipped
            env["CC_FUZZER_TOOL_MYTOOL"] = str(d / "nope")
            (c.state_dir / "nix-env.json").write_text(json.dumps({"tools": {"mytool": str(d / "nope")}}))
            self.assertEqual(tools.which("mytool", c, env=env), str(on_path))
            self.assertIsNone(tools.which("absent-tool", c, env=env))

    def test_no_host_scans_in_core(self):
        src = (REPO / "src" / "cc_fuzzer_core").rglob("*.py")
        hits = [str(p) for p in src if "/usr/lib/llvm" in p.read_text() or "/nix/store" in p.read_text()]
        self.assertEqual(hits, [])

    def test_cli_and_nix_tools_provider(self):
        with tempfile.TemporaryDirectory() as d:
            d = Path(d)
            t = _exe(d / "t" / "fancy-tool")
            env = dict(os.environ, PYTHONPATH=str(REPO / "src"), CC_FUZZER_TOOL_FANCY_TOOL=str(t))
            r = subprocess.run(core("tool", "which", "fancy-tool"), cwd=d, env=env, capture_output=True, text=True)
            self.assertEqual((r.returncode, r.stdout.strip()), (0, str(t)))
            r = subprocess.run(core("tool", "which", "no-such-tool-x"), cwd=d, env=env, capture_output=True, text=True)
            self.assertEqual((r.returncode, r.stdout), (1, ""))
            sh = (f'. "{REPO}/scripts/_lib/nix-tools.sh"; nix_tool fancy-tool; '
                  f'nix_tool no-such-tool-x || echo missing')
            r = subprocess.run(["bash", "-c", sh], cwd=d, env=env, capture_output=True, text=True)
            self.assertEqual(r.stdout.split(), [str(t), "missing"])


class TestShims(unittest.TestCase):
    def test_scripts_are_shims(self):
        for script, verb in (("launch-fuzzer-slot.sh", "slots launch"),
                             ("check-slot-liveness.sh", "slots liveness")):
            text = (REPO / "scripts" / script).read_text()
            self.assertIn(f"python3 -m cc_fuzzer_core {verb}", text)
            self.assertNotIn("python3 -", text.replace(f"python3 -m cc_fuzzer_core {verb}", ""))
        self.assertFalse((REPO / "scripts" / "_lib" / "launch_slot.py").exists())


if __name__ == "__main__":
    unittest.main()
