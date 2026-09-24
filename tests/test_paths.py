"""UPDATE_ROADMAP.md §1: root path from one env var.

  - cc_fuzzer_core.paths: plugin_root()/data(), campaign(), HarnessLayout
  - scripts/_lib/root.sh: the one bash resolver every script sources first
  - parity: path-anchor.sh vs `cc-fuzzer paths campaign`, and the sourced
    harness-path.sh functions vs `cc-fuzzer paths <verb>` (and its CLI shim)
  - sweep: no script still resolves its root any other way
"""
from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from cc_fuzzer_core import paths
from tests.support.golden import REPO, GoldenTestCase, Sandbox, core

SCRIPTS = REPO / "scripts"
ROOT_SH = SCRIPTS / "_lib" / "root.sh"


def _env(**extra):
    env = {k: v for k, v in os.environ.items()
           if not k.startswith(("CLAUDE", "CC_FUZZER_", "PYTHON", "FUZZ_")) and k != "PROJECT_ROOT"}
    env["PYTHONDONTWRITEBYTECODE"] = "1"
    for k, v in extra.items():
        if v is not None:
            env[k] = str(v)
    return env


def _bash(script: str, cwd, **env):
    return subprocess.run(["bash", "-c", script], cwd=cwd, env=_env(**env),
                          capture_output=True, text=True, timeout=60)


# ---------------------------------------------------------------------------
# plugin_root / data
# ---------------------------------------------------------------------------

class TestPluginRoot(unittest.TestCase):
    def test_env_wins(self):
        self.assertEqual(paths.plugin_root({"CC_FUZZER_ROOT": "/x/y"}), Path("/x/y"))

    def test_host_variable_is_not_read(self):
        # The core never consults the plugin host's variable; only root.sh does.
        env = {"CLAUDE_PLUGIN_ROOT": "/elsewhere"}
        self.assertEqual(paths.plugin_root(env), REPO)

    def test_checkout_fallback(self):
        self.assertEqual(paths.plugin_root({}), REPO)
        self.assertEqual(paths.data("rules", env={}), REPO / "rules")
        self.assertTrue(paths.data("STATE_SCHEMA.md", env={}).is_file())

    def _installed_copy(self, tmp: Path, with_data: bool) -> Path:
        site = tmp / "site-packages"
        shutil.copytree(REPO / "src" / "cc_fuzzer_core", site / "cc_fuzzer_core",
                        ignore=shutil.ignore_patterns("__pycache__"))
        if with_data:
            (site / "cc_fuzzer_core" / "data").mkdir()
            (site / "cc_fuzzer_core" / "data" / "STATE_SCHEMA.md").write_text("# schema\n")
        return site

    def test_package_data_fallback(self):
        with tempfile.TemporaryDirectory() as tmp:
            site = self._installed_copy(Path(tmp), with_data=True)
            r = subprocess.run([sys.executable, "-m", "cc_fuzzer_core", "paths", "root"], cwd=tmp,
                               env=_env(PYTHONPATH=site), capture_output=True, text=True, timeout=60)
            self.assertEqual(r.returncode, 0, r.stderr)
            self.assertEqual(r.stdout.strip(), str(site / "cc_fuzzer_core" / "data"))

    def test_no_root_anywhere(self):
        with tempfile.TemporaryDirectory() as tmp:
            site = self._installed_copy(Path(tmp), with_data=False)
            r = subprocess.run([sys.executable, "-m", "cc_fuzzer_core", "paths", "data", "rules"], cwd=tmp,
                               env=_env(PYTHONPATH=site), capture_output=True, text=True, timeout=60)
            self.assertEqual(r.returncode, 1)
            self.assertIn("CC_FUZZER_ROOT", r.stderr)


# ---------------------------------------------------------------------------
# campaign()
# ---------------------------------------------------------------------------

class TestCampaign(unittest.TestCase):
    def setUp(self):
        self.sb = Sandbox("campaign-warm")
        self.addCleanup(self.sb.cleanup)
        self.p = self.sb.project

    def test_walks_up_without_cd(self):
        cwd = os.getcwd()
        c = paths.campaign(self.p / "fuzz" / "state" / "snapshots", env={})
        self.assertEqual(os.getcwd(), cwd)
        self.assertEqual(c, paths.Campaign(self.p, self.p / "fuzz", self.p / "fuzz" / "state"))
        self.assertEqual(c.snapshots_dir, self.p / "fuzz/state/snapshots")
        self.assertEqual(c.harnesses_dir, self.p / "fuzz/harnesses")
        self.assertEqual(c.crashes_dir, self.p / "fuzz/crashes")

    def test_project_root_override(self):
        c = paths.campaign("/", env={"PROJECT_ROOT": str(self.p)})
        self.assertEqual(c.project_root, self.p)
        c = paths.campaign("/", project_root=self.p, env={"PROJECT_ROOT": "/nope"})
        self.assertEqual(c.project_root, self.p)
        with self.assertRaises(paths.CampaignError) as cm:
            paths.campaign(env={"PROJECT_ROOT": str(self.p / "src")})
        self.assertEqual(cm.exception.code, 2)
        self.assertIn("does not contain fuzz/", str(cm.exception))

    def test_not_a_project(self):
        with tempfile.TemporaryDirectory() as tmp:
            with self.assertRaises(paths.CampaignError) as cm:
                paths.campaign(tmp, env={})
        self.assertIn("not inside a cc-fuzzer project", str(cm.exception))

    def test_recursive_fuzz(self):
        (self.p / "fuzz" / "fuzz").mkdir()
        with self.assertRaises(paths.CampaignError) as cm:
            paths.campaign(self.p, env={})
        self.assertIn("recursive fuzz/fuzz/", str(cm.exception))
        self.assertEqual(paths.campaign(self.p, env={}, strict=False).project_root, self.p)

    def test_state_dir_override(self):
        rel = paths.campaign(self.p, env={"FUZZ_STATE_DIR": "alt/state"})
        self.assertEqual(rel.state_dir, self.p / "alt" / "state")
        ab = paths.campaign(self.p, env={"FUZZ_STATE_DIR": "/abs/state"})
        self.assertEqual(ab.state_dir, Path("/abs/state"))
        self.assertEqual(ab.snapshots_dir, Path("/abs/state/snapshots"))


# ---------------------------------------------------------------------------
# HarnessLayout
# ---------------------------------------------------------------------------

class TestHarnessLayout(unittest.TestCase):
    def setUp(self):
        self.sb = Sandbox("campaign-warm")
        self.addCleanup(self.sb.cleanup)
        self.lay = paths.campaign(self.sb.project, env={}).layout()

    def test_declared(self):
        self.assertEqual(self.lay.declared_harnesses(), ["parser", "encoder"])
        self.assertTrue(self.lay.is_known_harness("encoder"))
        self.assertFalse(self.lay.is_known_harness("nope"))
        self.assertEqual(self.lay.default_harness(), "parser")

    def test_cache_and_invalidate(self):
        self.lay.declared_harnesses()
        self.sb.edit_json("fuzz/state/fuzz-config.json", lambda d: d.update(harnesses=d["harnesses"][:1]))
        self.assertEqual(self.lay.declared_harnesses(), ["parser", "encoder"])
        self.lay.invalidate()
        self.assertEqual(self.lay.declared_harnesses(), ["parser"])

    def test_dirs_and_names(self):
        fr = self.sb.project / "fuzz"
        self.assertEqual(self.lay.corpus_dir("parser"), fr / "harnesses/parser/corpus")
        self.assertEqual(self.lay.quarantine_dir("parser"), fr / "harnesses/parser/corpus-quarantine")
        self.assertEqual(paths.HarnessLayout.gaps_snapshot_name("parser", 12), "gaps-parser-12.json")
        self.assertEqual(paths.HarnessLayout.crash_filename("parser", "ab12"), "parser__ab12.bin")
        self.assertEqual(paths.HarnessLayout.parse_crash_filename("x/parser__ab12.bin"), ("parser", "ab12"))
        self.assertIsNone(paths.HarnessLayout.parse_crash_filename("x/Parser__ab12.bin"))
        self.assertIsNone(paths.HarnessLayout.parse_crash_filename("x/parser_ab12.bin"))

    def test_records(self):
        self.assertEqual(self.lay.harness_binary("encoder"), "fuzz/harnesses/encoder/harness/encoder_fuzzer")
        self.assertIs(self.lay.harness_field("encoder", "cmplog_enabled"), True)
        self.assertIsNone(self.lay.harness_field("nope", "harness_binary"))
        self.assertEqual(self.lay.slot_to_harness("encoder-afl"), "encoder")
        self.assertIsNone(self.lay.slot_to_harness("nope"))

    def test_afl_instances(self):
        out = self.sb.project / "fuzz/harnesses/encoder/aflpp-out"
        (out / "default" / "queue").mkdir(parents=True)
        (out / "zz-not-an-instance").mkdir()
        self.assertEqual(paths.HarnessLayout.afl_instances(out), [out / "default", out / "encoder-afl"])
        self.assertEqual(paths.HarnessLayout.afl_instances(""), [])
        self.assertEqual(paths.HarnessLayout.afl_instances(out / "missing"), [])


# ---------------------------------------------------------------------------
# Parity with the bash implementations
# ---------------------------------------------------------------------------

_ANCHOR_PROBE = r'''
. "$CC_FUZZER_ROOT/scripts/_lib/path-anchor.sh"
echo "PROJECT_ROOT=$PROJECT_ROOT"
echo "FUZZ_ROOT=$FUZZ_ROOT"
sd="${FUZZ_STATE_DIR:-$FUZZ_ROOT/state}"
case "$sd" in /*) ;; *) sd="$PWD/$sd" ;; esac
echo "STATE_DIR=$sd"
'''


class TestPathAnchorParity(GoldenTestCase):
    """path-anchor.sh (sourced) and paths.campaign() agree on every outcome."""

    CASES = [
        ("project root", "", {}),
        ("nested dir", "src", {}),
        ("inside fuzz/", "fuzz/state/snapshots", {}),
        ("relative state override", "", {"FUZZ_STATE_DIR": "fuzz/alt"}),
        ("absolute state override", "src", {"FUZZ_STATE_DIR": "/var/tmp/ccf-state"}),
        ("PROJECT_ROOT env", "/", {"PROJECT_ROOT": "<PROJECT>"}),
        ("bad PROJECT_ROOT", "", {"PROJECT_ROOT": "<PROJECT>/src"}),
        ("not a project", "/", {}),
    ]

    def test_parity(self):
        for label, cwd, env in self.CASES:
            with self.subTest(label):
                sb = self.sandbox("campaign-warm")
                env = {k: v.replace("<PROJECT>", str(sb.project)) for k, v in env.items()}
                where = cwd or None
                b = sb.run(["bash", "-c", _ANCHOR_PROBE], cwd=where, env=env)
                p = sb.run(core("paths", "campaign"), cwd=where, env=env)
                self.assertEqual((b.exit_code, b.stdout, b.stderr), (p.exit_code, p.stdout, p.stderr))

    def test_recursive_refusal_parity(self):
        sb = self.sandbox("campaign-warm")
        (sb.project / "fuzz" / "fuzz").mkdir()
        b = sb.run(["bash", "-c", _ANCHOR_PROBE])
        p = sb.run(core("paths", "campaign"))
        self.assertEqual(b.exit_code, 2)
        self.assertEqual((b.exit_code, b.stderr), (p.exit_code, p.stderr))
        lenient = sb.run(core("paths", "campaign", "--lenient", "--format", "json"))
        self.assertEqual(json.loads(lenient.stdout)["project_root"], "<PROJECT>")

    def test_sh_format_evals(self):
        sb = self.sandbox("campaign-warm")
        spaced = sb.tmp / "with space"
        shutil.move(str(sb.project), str(spaced))
        sb.project.mkdir()
        r = sb.run(["bash", "-c", 'eval "$(python3 -m cc_fuzzer_core paths campaign --format sh)"; '
                                  'printf "%s|%s\\n" "$PROJECT_ROOT" "$STATE_DIR"'], cwd=spaced / "src")
        self.assertEqual(r.stdout.strip(), f"{spaced}|{spaced}/fuzz/state".replace(str(sb.tmp), "<TMP>"))

    def test_missing_ok(self):
        sb = self.sandbox(None)
        r = sb.run(core("paths", "campaign", "--missing-ok"))
        self.assertEqual((r.exit_code, r.stdout, r.stderr), (1, "", ""))


class TestHarnessPathParity(GoldenTestCase):
    """Sourced harness-path.sh functions == `cc-fuzzer paths <verb>` ==
    harness-path.sh CLI (now a shim onto the former)."""

    CALLS = [
        ("is_multi",), ("declared_harnesses",), ("default_harness",),
        ("is_known_harness", "parser"), ("is_known_harness", "nope"),
        ("harness_root", "encoder"), ("harness_dir", "encoder"), ("corpus_dir", "parser"),
        ("quarantine_dir", "parser"), ("coverage_dir", "parser"),
        ("coverage_snapshot_name", "parser", "1790000000"), ("gaps_snapshot_name", "parser", "1"),
        ("concolic_snapshot_name", "encoder", "2"), ("cmplog_dict_name", "encoder", "3"),
        ("crash_filename", "parser", "deadbeef"),
        ("parse_crash_filename", "fuzz/crashes/new/parser__deadbeefcafe0001.bin"),
        ("parse_crash_filename", "fuzz/crashes/new/nonconforming.bin"),
        ("harness_field", "encoder", "sanitizers"), ("harness_field", "encoder", "cmplog_enabled"),
        ("harness_field", "parser", "cmplog_binary"), ("harness_field", "parser", "harness_attempts"),
        ("harness_field", "nope", "name"),
        ("harness_binary", "parser"), ("slot_to_harness", "encoder-afl"), ("slot_to_harness", "nope"),
        ("afl_instances", "fuzz/harnesses/encoder/aflpp-out"), ("afl_instances", "fuzz/missing"),
    ]

    @staticmethod
    def _sourced(call):
        fn, *args = call
        quoted = " ".join(f"'{a}'" for a in args)
        if fn == "is_known_harness":
            body = f'{fn} {quoted} && echo yes || {{ echo no; exit 1; }}'
        elif fn == "is_multi":
            body = 'is_multi && echo multi'
        else:
            body = f"{fn} {quoted}"
        return ["bash", "-c", f'. "$CC_FUZZER_ROOT/scripts/_lib/harness-path.sh"; {body}']

    def _check(self, env=None, setup=None):
        sb = self.sandbox("campaign-warm")
        if setup:
            setup(sb)
        for call in self.CALLS:
            with self.subTest(call=call, env=env):
                src = sb.run(self._sourced(call), env=env)
                py = sb.run(core("paths", *call), env=env)
                cli = sb.run(["bash", str(SCRIPTS / "_lib/harness-path.sh"), *call], env=env)
                self.assertEqual((src.exit_code, src.stdout), (py.exit_code, py.stdout))
                self.assertEqual((cli.exit_code, cli.stdout), (py.exit_code, py.stdout))

    def test_default_layout(self):
        self._check()

    def test_env_layout(self):
        def move(sb):
            shutil.move(str(sb.path("fuzz/state")), str(sb.path("alt-state")))
        self._check(env={"FUZZ_ROOT": "fuzz", "FUZZ_STATE_DIR": "alt-state"}, setup=move)

    def test_cli_help_and_unknown(self):
        sb = self.sandbox("campaign-warm")
        for argv in ([], ["help"], ["bogus-verb"]):
            r = sb.run(["bash", str(SCRIPTS / "_lib/harness-path.sh"), *argv])
            self.assertEqual(r.exit_code, 0)
            self.assertIn("per-harness path resolver", r.stdout)


# ---------------------------------------------------------------------------
# root.sh
# ---------------------------------------------------------------------------

class TestRootSh(unittest.TestCase):
    PROBE = 'set -euo pipefail; . "{root_sh}"; echo "$CC_FUZZER_ROOT"; echo "${{PYTHONPATH:-}}"'

    def _probe(self, root_sh=ROOT_SH, **env):
        return _bash(self.PROBE.format(root_sh=root_sh), "/", **env)

    def test_falls_back_to_own_location(self):
        r = self._probe()
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertEqual(r.stdout.splitlines(), [str(REPO), str(REPO / "src")])
        self.assertEqual(r.stderr, "")

    def test_cc_fuzzer_root_wins(self):
        with tempfile.TemporaryDirectory() as tmp:
            other = Path(tmp) / "other"
            shutil.copytree(REPO / "scripts" / "_lib", other / "scripts" / "_lib")
            r = self._probe(CC_FUZZER_ROOT=other, CLAUDE_PLUGIN_ROOT=REPO)
            self.assertEqual(r.stdout.splitlines()[0], str(other))
            # no src/ in that tree => PYTHONPATH untouched
            self.assertEqual(r.stdout.splitlines()[1], "")

    def test_host_variable_is_the_compat_fallback(self):
        with tempfile.TemporaryDirectory() as tmp:
            other = Path(tmp) / "other"
            shutil.copytree(REPO / "scripts" / "_lib", other / "scripts" / "_lib")
            r = self._probe(CLAUDE_PLUGIN_ROOT=other)
            self.assertEqual(r.stdout.splitlines()[0], str(other))

    def test_bogus_candidate_is_ignored_loudly(self):
        r = self._probe(CC_FUZZER_ROOT="/nonexistent/root")
        self.assertEqual(r.returncode, 0)
        self.assertEqual(r.stdout.splitlines()[0], str(REPO))
        self.assertIn("ignoring root '/nonexistent/root'", r.stderr)

    def test_pythonpath_prepended_once(self):
        r = _bash(f'. "{ROOT_SH}"; . "{ROOT_SH}"; echo "$PYTHONPATH"', "/", PYTHONPATH="/keep/me")
        self.assertEqual(r.stdout.strip(), f"{REPO / 'src'}:/keep/me")

    def test_relative_invocation(self):
        r = _bash('. scripts/_lib/root.sh; echo "$CC_FUZZER_ROOT"', REPO)
        self.assertEqual(r.stdout.strip(), str(REPO))


class TestBinCcFuzzer(unittest.TestCase):
    def test_runs_from_anywhere_with_clean_env(self):
        with tempfile.TemporaryDirectory() as tmp:
            link = Path(tmp) / "cc-fuzzer"
            link.symlink_to(REPO / "bin" / "cc-fuzzer")
            for exe in (REPO / "bin" / "cc-fuzzer", link):
                r = subprocess.run([str(exe), "paths", "data", "rules"], cwd=tmp, env=_env(),
                                   capture_output=True, text=True, timeout=60)
                self.assertEqual(r.returncode, 0, r.stderr)
                self.assertEqual(r.stdout.strip(), str(REPO / "rules"))


# ---------------------------------------------------------------------------
# Sweep: the six old mechanisms are gone
# ---------------------------------------------------------------------------

class TestRootMechanismSweep(unittest.TestCase):
    def _scripts(self):
        return sorted(SCRIPTS.glob("*.sh"))

    def test_every_script_sources_root_sh_first(self):
        bad = []
        for p in self._scripts():
            code = [ln for ln in p.read_text().splitlines() if ln.strip() and not ln.lstrip().startswith("#")]
            first_source = next((ln for ln in code if re.match(r"\s*(\.|source)\s", ln)), "")
            if "_lib/root.sh" not in first_source:
                bad.append(f"{p.name}: first sourced file is {first_source.strip()!r}")
        self.assertEqual(bad, [])

    def test_no_self_located_script_dir(self):
        hits = [f"{p.relative_to(REPO)}:{i}" for p in self._scripts() + sorted((SCRIPTS / "_lib").glob("*.sh"))
                for i, ln in enumerate(p.read_text().splitlines(), 1)
                if "SCRIPT_DIR=" in ln and "CC_FUZZER_ROOT" not in ln]
        self.assertEqual(hits, [])

    def test_host_root_only_read_by_root_sh(self):
        # An assignment or env lookup of the host variable (user-facing message
        # text that merely mentions it is fine until §3 rewrites it).
        pat = re.compile(r'^\s*(export\s+)?[A-Za-z_]+=[^(]*CLAUDE_PLUGIN_ROOT|environ(\.get\(|\[)[^\n]*CLAUDE_PLUGIN_ROOT')
        hits = []
        for p in sorted(SCRIPTS.rglob("*")):
            if p.is_file() and p != ROOT_SH and p.suffix in (".sh", ".py"):
                for i, ln in enumerate(p.read_text().splitlines(), 1):
                    if pat.search(ln):
                        hits.append(f"{p.relative_to(REPO)}:{i}: {ln.strip()}")
        self.assertEqual(hits, [])

    def test_no_sys_path_insert_in_lib(self):
        hits = [f"{p.name}:{i}" for p in sorted((SCRIPTS / "_lib").glob("*.py"))
                for i, ln in enumerate(p.read_text().splitlines(), 1) if "sys.path.insert" in ln]
        self.assertEqual(hits, [])

    def test_no_ccfuzzer_src(self):
        for rel in ("flake.nix", "scripts/campaign-init.sh", "templates/project-flake.nix"):
            self.assertNotIn("CCFUZZER_SRC", (REPO / rel).read_text(), rel)
        self.assertIn('export CC_FUZZER_ROOT="${self}"', (REPO / "flake.nix").read_text())


if __name__ == "__main__":
    unittest.main()
