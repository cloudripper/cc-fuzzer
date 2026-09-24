"""Golden snapshots of the current bash entry points (UPDATE_ROADMAP.md Stage 0).

Each test runs one plugin entry point against a copy of a fixture campaign and
asserts the full capture (stdout, stderr, exit code, written/deleted files)
matches tests/golden/<entry>/<case>.json. These goldens are the contract the
Python ports are held to: a port's test reruns the same case through
`core(...)` and asserts the same golden / assertSameBehaviour.

Re-record after an intentional behaviour change:
    CC_FUZZER_UPDATE_GOLDEN=1 PYTHONPATH=src python3 -m unittest tests.test_golden_bash
"""
from __future__ import annotations

import shutil
import subprocess
import unittest

from tests.support.cases import ALL_CASES, run_case
from tests.support.golden import (FIXTURES, FROZEN_NOW, GoldenTestCase, bash,
                                  python_script, require_tools)

N = FROZEN_NOW
LOGS = FIXTURES / "sanitizer-logs"


def _awk_is_gawk() -> bool:
    try:
        out = subprocess.run(["awk", "--version"], capture_output=True, text=True, timeout=5)
    except (OSError, subprocess.TimeoutExpired):
        return False
    return "GNU Awk" in out.stdout


# ---------------------------------------------------------------------------
# validate-state.sh
# ---------------------------------------------------------------------------

class TestValidateState(GoldenTestCase):
    def _run(self, fixture, case, setup=None, env=None):
        sb = self.sandbox(fixture)
        if setup:
            setup(sb)
        self.assertGolden(f"validate-state/{case}", sb.run(bash("scripts/validate-state.sh"), env=env))

    def test_cold(self):
        self._run("campaign-cold", "cold")

    def test_warm(self):
        self._run("campaign-warm", "warm")

    def test_plateau(self):
        self._run("campaign-plateau", "plateau")

    def test_crashes(self):
        self._run("campaign-crashes", "crashes")

    def test_no_campaign(self):
        sb = self.sandbox(None)
        (sb.project / "fuzz").mkdir()
        self.assertGolden("validate-state/no-state", sb.run(bash("scripts/validate-state.sh")))

    def test_not_a_project(self):
        sb = self.sandbox(None)
        self.assertGolden("validate-state/not-a-project", sb.run(bash("scripts/validate-state.sh")))

    def test_broken(self):
        def breakit(sb):
            sb.path("fuzz/state/harnesses.json").unlink()
            sb.write("fuzz/state/schema-version", "v11\n")
            sb.write("fuzz/state/coverage-parser-123.json", "{}\n")
            sb.write("fuzz/crashes/new/unknown__0123456789abcdef.bin", b"x")
            sb.write("fuzz/crashes/known/bogus/repro.bin", b"x")
            sb.edit_json("fuzz/state/current.json", lambda d: d.update(active_harness="nope"))
            with open(sb.path("fuzz/state/findings.jsonl"), "a") as f:
                f.write('{"schema":"finding/v2","id":"bad"}\n')
        self._run("campaign-crashes", "broken", setup=breakit)

    def test_state_dir_override(self):
        # State moved to a non-default dir named by FUZZ_STATE_DIR (relative
        # to the project root) and given a wrong schema-version. Before §1,
        # validate-state.sh ignored FUZZ_STATE_DIR (saw no state: "ok"); it
        # now validates the named dir and reports the mismatch.
        def move(sb):
            shutil.move(str(sb.path("fuzz/state")), str(sb.path("fuzz/alt-state")))
            sb.write("fuzz/alt-state/schema-version", "v11\n")
        self._run("campaign-warm", "state-dir-override", setup=move,
                  env={"FUZZ_STATE_DIR": "fuzz/alt-state"})

    def test_from_inside_fuzz_dir(self):
        sb = self.sandbox("campaign-cold")
        self.assertGolden("validate-state/cwd-inside-fuzz",
                          sb.run(bash("scripts/validate-state.sh"), cwd="fuzz/state"))

    def test_recursive_fuzz_refused(self):
        sb = self.sandbox("campaign-cold")
        (sb.project / "fuzz" / "fuzz").mkdir()
        self.assertGolden("validate-state/recursive-fuzz", sb.run(bash("scripts/validate-state.sh")))


# ---------------------------------------------------------------------------
# update-current.sh (-> current.json) and derive-tick-state.py
# ---------------------------------------------------------------------------

class TestUpdateCurrent(GoldenTestCase):
    def _run(self, fixture, case, setup=None):
        sb = self.sandbox(fixture)
        if setup:
            setup(sb)
        self.assertGolden(f"update-current/{case}", sb.run(bash("scripts/update-current.sh")))

    def test_cold(self):
        self._run("campaign-cold", "cold")

    def test_warm(self):
        self._run("campaign-warm", "warm")

    def test_plateau(self):
        self._run("campaign-plateau", "plateau")

    def test_crashes(self):
        self._run("campaign-crashes", "crashes")

    def test_warm_live_slot(self):
        # One live slot (a real sleeping process) flips restart_fuzzer off for
        # that harness.
        proc = subprocess.Popen(["sleep", "300"])
        self.addCleanup(proc.wait)
        self.addCleanup(proc.kill)

        def live(sb):
            sb.add_sub(f'"{proc.pid}"', '"<PID>"')
            sb.add_sub(f"pid={proc.pid}", "pid=<PID>")

            def set_pid(doc):
                doc["slots"][0]["pid"] = str(proc.pid)
                doc["slots"][0]["pgid"] = str(proc.pid)
            sb.edit_json("fuzz/state/fuzzers.json", set_pid)
        self._run("campaign-warm", "warm-live-slot", setup=live)


class TestDeriveTickState(GoldenTestCase):
    DERIVED = ("tick_coverage", "consult_state", "yolo_state")

    def _run(self, fixture, case):
        sb = self.sandbox(fixture)
        sb.edit_json("fuzz/state/current.json",
                     lambda d: [d.pop(k, None) for k in self.DERIVED] and None)
        self.assertGolden(f"derive-tick-state/{case}",
                          sb.run(python_script("scripts/_lib/derive-tick-state.py",
                                               "fuzz/state/current.json")))

    def test_warm(self):
        self._run("campaign-warm", "warm")

    def test_plateau(self):
        self._run("campaign-plateau", "plateau")

    def test_crashes(self):
        self._run("campaign-crashes", "crashes")

    def test_missing_file(self):
        sb = self.sandbox("campaign-cold")
        self.assertGolden("derive-tick-state/missing",
                          sb.run(python_script("scripts/_lib/derive-tick-state.py",
                                               "fuzz/state/current.json")))


# ---------------------------------------------------------------------------
# yolo-state.sh next-tick
# ---------------------------------------------------------------------------

class TestYoloNextTick(GoldenTestCase):
    def _run(self, fixture, case, setup=None):
        sb = self.sandbox(fixture)
        if setup:
            setup(sb)
        self.assertGolden(f"yolo-next-tick/{case}", sb.run(bash("scripts/yolo-state.sh", "next-tick")))

    def test_no_current(self):
        self._run("campaign-cold", "no-current")

    def test_inactive(self):
        self._run("campaign-warm", "inactive")

    def test_schedule(self):
        self._run("campaign-plateau", "schedule")

    def test_halt_disables_yolo(self):
        def halt(sb):
            def h(doc):
                doc["yolo_state"]["halt_triggered"] = True
                doc["yolo_state"]["halt_reason"] = 'no_progress: ladder stage 3 ("consult" returned nothing)'
            sb.edit_json("fuzz/state/current.json", h)
        self._run("campaign-plateau", "halt", setup=halt)


# ---------------------------------------------------------------------------
# is-crash.sh
# ---------------------------------------------------------------------------

@unittest.skipUnless(_awk_is_gawk(),
                     "is-crash.sh goldens were recorded with GNU awk; its top-frame "
                     "awk program uses `func`, a gawk keyword, so output is awk-dependent")
class TestIsCrash(GoldenTestCase):
    def _log(self, name, *args):
        sb = self.sandbox(None)
        return sb.run(bash("scripts/is-crash.sh", *args, str(LOGS / name)))

    def test_every_log_as_path(self):
        for log in sorted(p.name for p in LOGS.glob("*.log")):
            with self.subTest(log=log):
                self.assertGolden(f"is-crash/{log[:-4]}", self._log(log))

    def test_stdin_with_exit_code(self):
        sb = self.sandbox(None)
        text = (LOGS / "clean.log").read_text()
        for code in ("0", "134", "137", "139"):
            with self.subTest(code=code):
                self.assertGolden(f"is-crash/stdin-exit-{code}",
                                  sb.run(bash("scripts/is-crash.sh", "--exit-code", code), stdin=text))

    def test_usage_errors(self):
        sb = self.sandbox(None)
        self.assertGolden("is-crash/unknown-flag", sb.run(bash("scripts/is-crash.sh", "--bogus")))
        self.assertGolden("is-crash/unreadable", sb.run(bash("scripts/is-crash.sh", "/nonexistent.log")))
        self.assertGolden("is-crash/two-paths", sb.run(bash("scripts/is-crash.sh", "a", "b")))


# ---------------------------------------------------------------------------
# find-delta-targets.sh (fixture git repo built per test)
# ---------------------------------------------------------------------------

@require_tools("git")
class TestFindDeltaTargets(GoldenTestCase):
    def _repo(self):
        sb = self.sandbox("campaign-warm")
        sb.write(".gitignore", "fuzz/\n")
        sb.git("init", "-q", "-b", "main")
        sb.git("add", ".gitignore", "src")
        sb.git("commit", "-q", "-m", "base")
        sb.git("checkout", "-q", "-b", "feature")
        parser = sb.path("src/parser.c").read_text()
        sb.write("src/parser.c", parser.replace("i <= len", "i < len").replace(
            '"exif entries: %u"', '"exif entries=%u"'))
        sb.git("commit", "-q", "-am", "fix off-by-one")
        sb.write("src/lookup.c", "int lookup(int k) {\n    return k * 2;\n}\n")
        encoder = sb.path("src/encoder.c").read_text()
        sb.write("src/encoder.c", encoder.replace("    *out = buf;\n", ""))
        sb.git("add", "src")
        sb.git("commit", "-q", "-m", "add lookup, drop assignment")
        return sb

    def test_auto_range_feature_branch(self):
        sb = self._repo()
        self.assertGolden("find-delta-targets/auto-main", sb.run(bash("scripts/find-delta-targets.sh")))

    def test_explicit_range(self):
        sb = self._repo()
        self.assertGolden("find-delta-targets/explicit-range",
                          sb.run(bash("scripts/find-delta-targets.sh", "--range", "HEAD~1..HEAD")))

    def test_bad_range(self):
        sb = self._repo()
        self.assertGolden("find-delta-targets/bad-range",
                          sb.run(bash("scripts/find-delta-targets.sh", "--range=nope..HEAD")))

    def test_not_git(self):
        sb = self.sandbox("campaign-cold")
        self.assertGolden("find-delta-targets/not-git", sb.run(bash("scripts/find-delta-targets.sh")))


# ---------------------------------------------------------------------------
# extract-cmplog-dict.sh
# ---------------------------------------------------------------------------

class TestExtractCmplogDict(GoldenTestCase):
    def test_all_harnesses(self):
        sb = self.sandbox("campaign-warm")
        self.assertGolden("extract-cmplog-dict/all-harnesses", sb.run(bash("scripts/extract-cmplog-dict.sh")))

    def test_one_harness_custom_output(self):
        sb = self.sandbox("campaign-warm")
        self.assertGolden("extract-cmplog-dict/encoder-custom-output",
                          sb.run(bash("scripts/extract-cmplog-dict.sh", "--harness", "encoder",
                                      "--output", "fuzz/dicts/encoder.dict")))

    def test_explicit_instance_dir(self):
        sb = self.sandbox("campaign-warm")
        self.assertGolden("extract-cmplog-dict/explicit-aflpp-out",
                          sb.run(bash("scripts/extract-cmplog-dict.sh", "--aflpp-out",
                                      "fuzz/harnesses/encoder/aflpp-out/encoder-afl")))

    def test_no_afl_output(self):
        sb = self.sandbox("campaign-cold")
        self.assertGolden("extract-cmplog-dict/no-afl-output", sb.run(bash("scripts/extract-cmplog-dict.sh")))

    def test_state_dir_override(self):
        # Dicts land in $FUZZ_STATE_DIR (ignored before §1: fuzz/state/).
        sb = self.sandbox("campaign-warm")
        shutil.move(str(sb.path("fuzz/state")), str(sb.path("alt-state")))
        self.assertGolden("extract-cmplog-dict/state-dir-override",
                          sb.run(bash("scripts/extract-cmplog-dict.sh", "--harness", "encoder"),
                                 env={"FUZZ_STATE_DIR": "alt-state"}))

    def test_unknown_arg(self):
        sb = self.sandbox("campaign-cold")
        self.assertGolden("extract-cmplog-dict/unknown-arg",
                          sb.run(bash("scripts/extract-cmplog-dict.sh", "--bogus")))


# ---------------------------------------------------------------------------
# corpus-quarantine.sh (fixture stub harness)
# ---------------------------------------------------------------------------

class TestCorpusQuarantine(GoldenTestCase):
    def test_process_quarantine_dir(self):
        sb = self.sandbox("campaign-cold")
        self.assertGolden("corpus-quarantine/all",
                          sb.run(bash("scripts/corpus-quarantine.sh", "--harness", "parser")))

    def test_explicit_file(self):
        sb = self.sandbox("campaign-cold")
        self.assertGolden("corpus-quarantine/explicit-file",
                          sb.run(bash("scripts/corpus-quarantine.sh", "--harness", "parser",
                                      "fuzz/harnesses/parser/corpus-quarantine/seed-a.bin")))

    def test_active_harness_fallback(self):
        sb = self.sandbox("campaign-crashes")
        sb.write("fuzz/harnesses/parser/corpus-quarantine/new-seed.bin", "eXIf\x01\x00\x00\x00z")
        self.assertGolden("corpus-quarantine/active-harness-fallback",
                          sb.run(bash("scripts/corpus-quarantine.sh")))

    def test_state_dir_override(self):
        # The active-harness fallback reads $FUZZ_STATE_DIR/current.json
        # (ignored before §1, which read fuzz/state/ and found nothing).
        sb = self.sandbox("campaign-crashes")
        shutil.move(str(sb.path("fuzz/state")), str(sb.path("fuzz/alt-state")))
        sb.write("fuzz/harnesses/parser/corpus-quarantine/new-seed.bin", "eXIf\x01\x00\x00\x00z")
        self.assertGolden("corpus-quarantine/state-dir-override",
                          sb.run(bash("scripts/corpus-quarantine.sh"),
                                 env={"FUZZ_STATE_DIR": "fuzz/alt-state"}))

    def test_nothing_to_do(self):
        sb = self.sandbox("campaign-crashes")
        self.assertGolden("corpus-quarantine/empty",
                          sb.run(bash("scripts/corpus-quarantine.sh", "--harness", "parser")))

    def test_unknown_harness(self):
        sb = self.sandbox("campaign-cold")
        self.assertGolden("corpus-quarantine/unknown-harness",
                          sb.run(bash("scripts/corpus-quarantine.sh", "--harness", "nope")))

    def test_missing_binary(self):
        sb = self.sandbox("campaign-cold")
        sb.path("fuzz/harnesses/parser/harness/parser_fuzzer").unlink()
        self.assertGolden("corpus-quarantine/missing-binary",
                          sb.run(bash("scripts/corpus-quarantine.sh", "--harness", "parser")))


# ---------------------------------------------------------------------------
# check-slot-liveness.sh (fake PIDs; never lets a real relaunch happen)
# ---------------------------------------------------------------------------

class TestCheckSlotLiveness(GoldenTestCase):
    def _live_proc(self, sb):
        proc = subprocess.Popen(["sleep", "300"])
        self.addCleanup(proc.wait)
        self.addCleanup(proc.kill)
        sb.add_sub(f"pid={proc.pid}", "pid=<PID>")
        return proc

    def test_no_manifest(self):
        sb = self.sandbox("campaign-cold")
        self.assertGolden("check-slot-liveness/no-manifest", sb.run(bash("scripts/check-slot-liveness.sh")))

    def test_dry_run_all_dead(self):
        sb = self.sandbox("campaign-warm")
        self.assertGolden("check-slot-liveness/dry-run-dead",
                          sb.run(bash("scripts/check-slot-liveness.sh", "--dry-run")))

    def test_dry_run_one_alive(self):
        sb = self.sandbox("campaign-warm")
        proc = self._live_proc(sb)
        sb.edit_json("fuzz/state/fuzzers.json",
                     lambda d: d["slots"][0].update(pid=str(proc.pid), pgid=str(proc.pid)))
        self.assertGolden("check-slot-liveness/dry-run-one-alive",
                          sb.run(bash("scripts/check-slot-liveness.sh", "--dry-run")))

    def test_deadlocked_and_missing_binary(self):
        # parser-main: 3 restarts 10s ago -> deadlocked (emits an error event).
        # encoder-afl: harness binary removed -> launch_failed, no relaunch.
        sb = self.sandbox("campaign-warm")
        import time as _t
        recent = _t.strftime("%Y-%m-%dT%H:%M:%SZ", _t.gmtime(N - 10))
        sb.edit_json("fuzz/state/fuzzers.json",
                     lambda d: d["slots"][0].update(restart_count=3, last_restart_at=recent))
        sb.path("fuzz/harnesses/encoder/harness/encoder_fuzzer").unlink()
        self.assertGolden("check-slot-liveness/deadlocked-and-missing-binary",
                          sb.run(bash("scripts/check-slot-liveness.sh")))

    def test_slot_without_harness_binding(self):
        sb = self.sandbox("campaign-warm")

        def unbind(doc):
            doc["fuzzer_slots"] = [dict(s, harness="") for s in doc["fuzzer_slots"]]
        sb.edit_json("fuzz/state/fuzz-config.json", unbind)
        self.assertGolden("check-slot-liveness/no-harness-binding",
                          sb.run(bash("scripts/check-slot-liveness.sh")))


# ---------------------------------------------------------------------------
# code-review-run.sh (Tier-1 prescan)
# ---------------------------------------------------------------------------

class TestCodeReviewPrescan(GoldenTestCase):
    def _run(self, fixture, case, *args):
        sb = self.sandbox(fixture)
        self.assertGolden(f"code-review-prescan/{case}", sb.run(bash("scripts/code-review-run.sh", *args)))

    def test_warm_config_defaults_no_sast(self):
        self._run("campaign-warm", "warm-no-sast", "--sast", "off")

    def test_sweep(self):
        self._run("campaign-warm", "warm-sweep", "--sweep", "--batch-size", "2", "--no-sast")

    def test_cold_explicit_root(self):
        self._run("campaign-cold", "cold-explicit-root", "--target-root", "src",
                  "--max-functions", "2", "--no-sast", "--no-cve-context")

    @unittest.skipIf(shutil.which("semgrep") or shutil.which("codeql"),
                     "golden records the 'no analyzer on PATH' SAST skip")
    def test_sast_auto_without_analyzers(self):
        self._run("campaign-crashes", "crashes-sast-auto", "--sast", "auto")

    def test_bad_arg(self):
        self._run("campaign-cold", "bad-arg", "--bogus")

    def test_rerun_is_fresh(self):
        # A second run over an unchanged tree: records the stale-hash reuse path.
        sb = self.sandbox("campaign-warm")
        first = sb.run(bash("scripts/code-review-run.sh", "--no-sast"))
        self.assertEqual(first.exit_code, 0, first.stderr)
        self.assertGolden("code-review-prescan/warm-rerun",
                          sb.run(bash("scripts/code-review-run.sh", "--no-sast")))


# ---------------------------------------------------------------------------
# Extra cases for the §2 ports (tests/support/cases.py): fuzz-config.sh,
# enums.py, validate-state.sh, yolo-state.sh, tick-coverage-roundup.sh,
# ceiling-probe.sh, derive-tick-state.py, update-current.sh. Recorded from the
# pre-port implementations; the ports are held to the same goldens by
# tests/test_core_*.py.
# ---------------------------------------------------------------------------

class TestExtraCases(GoldenTestCase):
    def test_bash_entry_points(self):
        for case in ALL_CASES:
            with self.subTest(case=case.name):
                self.assertGolden(case.name, run_case(self, case, case.bash_argv))


if __name__ == "__main__":
    unittest.main()
