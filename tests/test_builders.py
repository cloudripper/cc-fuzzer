"""UPDATE_ROADMAP.md §6: one build-spec/v1, several toolchains.

  - the clang flag table lives in ONE place and reproduces nix-build.sh's
    variant block flag for flag (that parity is the whole safety argument for
    letting nix-build.sh stop carrying its own copy)
  - the script builder passes the spec through the environment, so a project's
    own build.sh can finally be ASKED for a particular variant
  - the OSS-Fuzz builder maps needs to $SANITIZER/$FUZZING_ENGINE, and reports
    SymCC `unsupported` rather than silently skipping it
  - the clang builder actually compiles: plan -> binaries that run
  - the cov_main.c declaration links against a C++ harness (it did not)
"""
from __future__ import annotations

import json
import os
import shutil
import subprocess
import tempfile
import textwrap
import unittest
from pathlib import Path

from cc_fuzzer_core import builders, variants
from cc_fuzzer_core.builders import clang as clang_builder
from cc_fuzzer_core.builders import ossfuzz, script, toolchain
from tests.support.golden import REPO, core

NIX_BUILD = REPO / "scripts" / "nix-build.sh"
HAVE_CLANG = shutil.which("clang++") is not None


def run_cli(*args):
    env = dict(os.environ)
    env.update({"PYTHONPATH": str(REPO / "src"), "CC_FUZZER_ROOT": str(REPO)})
    return subprocess.run(core(*args), capture_output=True, text=True, env=env)


def all_on_spec(harness="parser"):
    return variants.spec({"variants": {"cmplog": {"enabled": True},
                                       "symcc": {"enabled": True}}}, harness)


class NixParityTest(unittest.TestCase):
    """The core's table must equal what nix-build.sh compiles with today."""

    EXPECTED = {
        "fuzzer":   ("clang++", ["-g", "-O1", "-fno-omit-frame-pointer",
                                 "-fsanitize=address,undefined,fuzzer"], {}),
        "coverage": ("clang++", ["-g", "-O0", "-fprofile-instr-generate",
                                 "-fcoverage-mapping"], {}),
        "verify":   ("clang++", ["-g", "-O1", "-fno-omit-frame-pointer",
                                 "-fsanitize=address,undefined"], {}),
        "cmplog":   ("afl-clang-fast++", ["-g", "-O1", "-fno-omit-frame-pointer"],
                     {"AFL_LLVM_CMPLOG": "1"}),
        "symcc":    ("sym++", ["-g", "-O1"], {}),
    }

    def test_every_variant_matches_nix_build(self):
        plan = builders.plan(all_on_spec(), "nix", harness="parser")
        got = {s["variant"]: (s["compiler"], s["cflags"], s["env"]) for s in plan["steps"]}
        self.assertEqual(got, self.EXPECTED)

    # EXPECTED above is transcribed from the variant block nix-build.sh
    # carried before §6 (see the commit that removed it). It is the record of
    # what the builds produced then, so a change to the core's table that
    # would silently change every campaign's binaries fails here.

    def test_nix_build_no_longer_carries_its_own_flag_table(self):
        """The parity above is only worth anything if there is now ONE table.
        nix-build.sh must ask the core rather than keep a second copy."""
        text = NIX_BUILD.read_text()
        self.assertIn("from cc_fuzzer_core import builders", text)
        block = text[text.index("# Variants:"):text.index("# Mock derivations")]
        for stale in ("-fsanitize=", "-fprofile-instr-generate", "-fno-omit-frame-pointer",
                      "afl-clang-fast++", "sym++"):
            self.assertNotIn(stale, block, f"nix-build.sh still hard-codes {stale}")

    def test_nix_is_delegated_not_run(self):
        for s in builders.plan(all_on_spec(), "nix", harness="parser")["steps"]:
            self.assertEqual(s["status"], builders.DELEGATED)

    def test_install_names_match_the_state_schema(self):
        got = {s["variant"]: s["install_as"]
               for s in builders.plan(all_on_spec(), "nix", harness="parser")["steps"]}
        self.assertEqual(got, {"fuzzer": "parser_fuzzer", "coverage": "parser_fuzzer_cov",
                               "verify": "parser_fuzzer_verify",
                               "cmplog": "parser_fuzzer_cmplog",
                               "symcc": "parser_fuzzer_symcc"})


class ScriptBuilderTest(unittest.TestCase):
    def test_spec_reaches_build_sh_through_the_environment(self):
        step = script.step(variants.default("verify").as_dict(), harness="parser")
        env = step["env"]
        self.assertEqual(env["CC_FUZZER_VARIANT"], "verify")
        self.assertEqual(env["CC_FUZZER_PURPOSE"], "verify")
        self.assertEqual(env["CC_FUZZER_SANITIZERS"], "address,undefined")
        self.assertEqual(env["CC_FUZZER_OUTPUT"], "parser_fuzzer_verify")
        self.assertIn("-fsanitize=address,undefined", env["CC_FUZZER_CFLAGS"])

    def test_cmplog_carries_the_compiler_environment_too(self):
        env = script.step(variants.default("cmplog").as_dict(), harness="p")["env"]
        self.assertEqual(env["AFL_LLVM_CMPLOG"], "1")
        self.assertEqual(env["CC_FUZZER_COMPILER"], "afl-clang-fast++")

    def test_required_is_stated_so_a_script_can_fail_loudly(self):
        self.assertEqual(script.step(variants.default("fuzzer").as_dict())["env"]["CC_FUZZER_REQUIRED"], "1")
        self.assertEqual(script.step(variants.default("verify").as_dict())["env"]["CC_FUZZER_REQUIRED"], "0")


class OssFuzzBuilderTest(unittest.TestCase):
    def test_purpose_maps_to_sanitizer_and_engine(self):
        steps = {s["variant"]: s for s in
                 builders.plan(all_on_spec(), "oss-fuzz", harness="parser",
                               out_dir="/out")["steps"]}
        self.assertEqual(steps["fuzzer"]["env"],
                         {"SANITIZER": "address", "FUZZING_ENGINE": "libfuzzer"})
        self.assertEqual(steps["verify"]["env"],
                         {"SANITIZER": "undefined", "FUZZING_ENGINE": "none"})
        self.assertEqual(steps["coverage"]["env"],
                         {"SANITIZER": "coverage", "FUZZING_ENGINE": "libfuzzer"})
        self.assertEqual(steps["cmplog"]["env"]["FUZZING_ENGINE"], "afl")
        self.assertEqual(steps["cmplog"]["env"]["AFL_LLVM_CMPLOG"], "1")

    def test_symcc_is_unsupported_not_skipped(self):
        """`skipped` means the campaign turned it off; `unsupported` means it
        asked and the image cannot. §12 must tell those apart."""
        steps = {s["variant"]: s for s in
                 builders.plan(all_on_spec(), "oss-fuzz", harness="p")["steps"]}
        self.assertEqual(steps["symcc"]["status"], builders.UNSUPPORTED)
        self.assertIn("SymCC", steps["symcc"]["reason"])
        self.assertNotIn("symcc", all_on_spec()["skipped"])

    def test_binaries_come_from_out(self):
        s = builders.plan(variants.spec({}, "parser"), "oss-fuzz", harness="parser",
                          env={"OUT": "/somewhere/out"})["steps"][0]
        self.assertTrue(s["output"].startswith("/somewhere/out/"))

    def test_out_defaults_when_unset(self):
        self.assertEqual(ossfuzz.out_dir({}), "/out")


class ResultTest(unittest.TestCase):
    def test_a_bad_status_is_refused(self):
        with self.assertRaises(builders.BuildError):
            builders.result("p", "clang", {"fuzzer": {"status": "done"}})

    def test_failed_required_separates_degraded_from_failed(self):
        spec = variants.spec({}, "parser")
        degraded = builders.result("parser", "clang", {
            "fuzzer": {"status": builders.OK, "binary": "b"},
            "coverage": {"status": builders.FAILED, "reason": "no profile runtime"}})
        self.assertEqual(builders.failed_required(spec, degraded), [])
        broken = builders.result("parser", "clang", {
            "fuzzer": {"status": builders.FAILED, "reason": "boom"}})
        self.assertEqual(builders.failed_required(spec, broken), ["fuzzer"])


class CovMainLinkageTest(unittest.TestCase):
    """Regression: the shipped cov_main.c declared LLVMFuzzerTestOneInput with
    no linkage guard. clang++ compiles a .c input as C++, so the declaration
    mangled as C++ while the harness defines the symbol extern "C" -- the
    verify and coverage binaries could not link at all for a C++ harness."""

    HARNESS = textwrap.dedent('''
        #include <stdint.h>
        #include <stddef.h>
        extern "C" int LLVMFuzzerTestOneInput(const uint8_t *d, size_t n) {
          (void)d; return (int)n;
        }
    ''')

    def _cov_main_from_prompt(self) -> str:
        """The template exactly as the harness-writer prompt ships it."""
        text = (REPO / "prompts" / "harness-writer.md").read_text()
        start = text.index("Write `fuzz/harnesses/<name>/harness/cov_main.c`")
        block = text[text.index("```c", start) + 4:]
        return textwrap.dedent(block[:block.index("```")])

    def test_the_template_declares_c_linkage(self):
        src = self._cov_main_from_prompt()
        self.assertIn("__cplusplus", src)
        self.assertIn('extern "C"', src)

    @unittest.skipUnless(HAVE_CLANG, "needs clang++")
    def test_the_template_links_against_a_cpp_harness(self):
        with tempfile.TemporaryDirectory() as td:
            d = Path(td)
            (d / "h.cc").write_text(self.HARNESS)
            (d / "cov_main.c").write_text(self._cov_main_from_prompt())
            out = d / "t"
            p = subprocess.run(["clang++", "-g", "-O1", str(d / "h.cc"),
                                str(d / "cov_main.c"), "-o", str(out)],
                               capture_output=True, text=True)
            self.assertEqual(p.returncode, 0,
                             f"cov_main.c does not link:\n{p.stderr}")
            self.assertTrue(out.exists())


@unittest.skipUnless(HAVE_CLANG, "needs clang++")
class ClangBuildTest(unittest.TestCase):
    """The spec really does produce binaries. Sanitizers are overridden off
    because this container's clang ships no compiler-rt runtimes; what is under
    test is plan -> compile -> a binary that runs, not the sanitizers."""

    NO_RT = {"variants": {
        "fuzzer": {"sanitizers": [], "instrumentation": "none",
                   "link_mode": "standalone-main"},
        "verify": {"sanitizers": []},
        "coverage": {"enabled": False}}}

    def _tree(self, d: Path):
        (d / "parser_fuzzer.cc").write_text(CovMainLinkageTest.HARNESS)
        cov = (REPO / "prompts" / "harness-writer.md").read_text()
        start = cov.index("Write `fuzz/harnesses/<name>/harness/cov_main.c`")
        block = cov[cov.index("```c", start) + 4:]
        (d / "cov_main.c").write_text(textwrap.dedent(block[:block.index("```")]))

    def test_plan_builds_runnable_binaries(self):
        with tempfile.TemporaryDirectory() as td:
            d = Path(td)
            self._tree(d)
            spec = variants.spec(self.NO_RT, "parser")
            plan = builders.plan(spec, "clang", harness="parser",
                                 sources=[str(d / "parser_fuzzer.cc")],
                                 main_source=str(d / "cov_main.c"),
                                 out_dir=str(d / "out"))
            res = clang_builder.build(plan)
            self.assertEqual(builders.failed_required(spec, res), [],
                             json.dumps(res["variants"], indent=2))
            for name, row in res["variants"].items():
                with self.subTest(variant=name):
                    self.assertEqual(row["status"], builders.OK, row.get("reason"))
                    self.assertTrue(os.access(row["binary"], os.X_OK))
            binary = res["variants"]["verify"]["binary"]
            seed = d / "seed.bin"
            seed.write_bytes(b"abcd")
            p = subprocess.run([binary, str(seed)], capture_output=True)
            self.assertEqual(p.returncode, 0)

    def test_a_missing_compiler_is_unsupported_and_names_the_tool(self):
        with tempfile.TemporaryDirectory() as td:
            d = Path(td)
            self._tree(d)
            spec = variants.spec({"variants": {"cmplog": {"enabled": True}}}, "parser")
            plan = builders.plan(spec, "clang", harness="parser",
                                 sources=[str(d / "parser_fuzzer.cc")],
                                 main_source=str(d / "cov_main.c"),
                                 out_dir=str(d / "out"))
            cmplog = [s for s in plan["steps"] if s["variant"] == "cmplog"][0]
            # pin it unavailable by name, so this test does not quietly depend
            # on AFL being absent from the machine running it
            from cc_fuzzer_core import tools
            row = clang_builder.run_step(
                cmplog, env={**os.environ, tools.env_var("afl-clang-fast++"): ""})
            self.assertEqual(row["status"], builders.UNSUPPORTED)
            self.assertIn("afl-clang-fast++", row["reason"])


class RecordArgsTest(unittest.TestCase):
    """build-result/v1 -> the flags write-harness-built already understands."""

    def _res(self, **rows):
        return builders.result("parser", "clang", rows)

    def test_paths_become_binary_flags(self):
        args = builders.record_args(self._res(
            fuzzer={"status": "ok", "binary": "b/f"},
            coverage={"status": "ok", "binary": "b/c"},
            verify={"status": "ok", "binary": "b/v"}))
        self.assertEqual(args[:2], ["--build-backend", "clang"])
        for flag, path in (("--harness-binary", "b/f"), ("--coverage-binary", "b/c"),
                           ("--verify-binary", "b/v")):
            self.assertEqual(args[args.index(flag) + 1], path)

    def test_a_missing_variant_is_disabled_with_a_reason(self):
        args = builders.record_args(self._res(fuzzer={"status": "ok", "binary": "b/f"}))
        self.assertIn("--no-coverage", args)
        self.assertEqual(args[args.index("--coverage-disabled-reason") + 1],
                         "not requested for this harness")

    def test_unsupported_keeps_the_builder_s_own_reason(self):
        args = builders.record_args(self._res(
            fuzzer={"status": "ok", "binary": "b/f"},
            cmplog={"status": "unsupported", "reason": "no AFL in this image"}))
        self.assertEqual(args[args.index("--cmplog-disabled-reason") + 1],
                         "no AFL in this image")

    def test_a_failed_build_keeps_its_error(self):
        args = builders.record_args(self._res(
            fuzzer={"status": "ok", "binary": "b/f"},
            coverage={"status": "failed", "reason": "no profile runtime"}))
        self.assertEqual(args[args.index("--coverage-disabled-reason") + 1],
                         "no profile runtime")

    def test_a_missing_fuzzing_binary_is_an_error_not_a_record(self):
        """A harness record without its fuzzing binary is a failed build, not
        a degraded one -- writing it down would make the campaign look ready."""
        with self.assertRaises(builders.BuildError) as cm:
            builders.record_args(self._res(fuzzer={"status": "failed", "reason": "boom"}))
        self.assertIn("boom", str(cm.exception))

    def test_required_is_checked_against_the_spec(self):
        spec = variants.spec({}, "parser")
        with self.assertRaises(builders.BuildError):
            builders.record_args(self._res(coverage={"status": "ok", "binary": "b/c"}),
                                 spec=spec)

    def test_a_foreign_document_is_refused(self):
        with self.assertRaises(builders.BuildError):
            builders.record_args({"schema": "build-plan/v1"})

    def test_cli_emits_the_flags(self):
        with tempfile.TemporaryDirectory() as td:
            f = Path(td) / "r.json"
            f.write_text(json.dumps(self._res(
                fuzzer={"status": "ok", "binary": "b/f"},
                verify={"status": "ok", "binary": "b/v"})))
            r = run_cli("build", "record-args", "--result", str(f))
            self.assertEqual(r.returncode, 0, r.stderr)
            self.assertIn("--verify-binary", r.stdout.split("\n"))

    def test_cli_refuses_a_result_missing_the_required_variant(self):
        with tempfile.TemporaryDirectory() as td:
            f = Path(td) / "r.json"
            f.write_text(json.dumps(self._res(
                coverage={"status": "ok", "binary": "b/c"})))
            r = run_cli("build", "record-args", "--result", str(f))
            self.assertEqual(r.returncode, 2)


class CliTest(unittest.TestCase):
    def test_backends(self):
        r = run_cli("build", "backends")
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertEqual(r.stdout.split(), list(builders.BACKENDS))

    def test_plan_json(self):
        r = run_cli("build", "plan", "--harness", "parser", "--backend", "nix")
        self.assertEqual(r.returncode, 0, r.stderr)
        doc = json.loads(r.stdout)
        self.assertEqual(doc["schema"], builders.PLAN_SCHEMA)
        self.assertEqual([s["variant"] for s in doc["steps"]],
                         ["fuzzer", "coverage", "verify"])

    def test_unknown_backend_is_refused(self):
        r = run_cli("build", "plan", "--backend", "bazel")
        self.assertEqual(r.returncode, 2)


if __name__ == "__main__":
    unittest.main()
