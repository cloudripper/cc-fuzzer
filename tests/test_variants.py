"""UPDATE_ROADMAP.md §6: build variants declared as needs, not clang flags.

  - the defaults reproduce nix-build.sh's variant block (fuzzer/coverage/verify
    on, cmplog/symcc opt-in), so today's behaviour is unchanged
  - a variant states its NEED (purpose, sanitizers, instrumentation, link mode)
    so a non-clang builder has something to translate
  - fuzz-config.json overrides it per harness, and a bad override is refused
    with a message naming the field rather than being silently ignored
  - verify carries neither the fuzzer sanitizer nor coverage instrumentation:
    that is what makes it usable as evidence (§12 selects it for replay)
"""
from __future__ import annotations

import json
import os
import subprocess
import unittest

from cc_fuzzer_core import enums, variants
from tests.support.golden import REPO, core


def run_cli(*args):
    env = dict(os.environ)
    env.update({"PYTHONPATH": str(REPO / "src"), "CC_FUZZER_ROOT": str(REPO)})
    return subprocess.run(core(*args), capture_output=True, text=True, env=env)


class DefaultsTest(unittest.TestCase):
    def test_the_three_always_built(self):
        on = [v.name for v in variants.enabled()]
        self.assertEqual(on, ["fuzzer", "coverage", "verify"])

    def test_cmplog_and_symcc_are_opt_in(self):
        off = [v.name for v in variants.resolve() if not v.enabled]
        self.assertEqual(off, ["cmplog", "symcc"])

    def test_only_the_fuzzing_binary_is_required(self):
        self.assertEqual([v.name for v in variants.resolve() if v.required], ["fuzzer"])

    def test_fuzzer_matches_nix_build_defaults(self):
        v = variants.default("fuzzer")
        self.assertEqual(v.sanitizers, ("address", "undefined", "fuzzer"))
        self.assertEqual(v.instrumentation, variants.LIBFUZZER)
        self.assertEqual(v.link_mode, variants.FUZZER_MAIN)

    def test_verify_is_clean_enough_to_be_evidence(self):
        """A crash that only reproduces under the fuzzer's own instrumentation
        is evidence about the instrumentation (§12 replays on this one)."""
        v = variants.default("verify")
        self.assertNotIn("fuzzer", v.sanitizers)
        self.assertEqual(v.instrumentation, variants.NONE)
        self.assertEqual(v.link_mode, variants.STANDALONE_MAIN)

    def test_coverage_carries_no_sanitizer(self):
        v = variants.default("coverage")
        self.assertEqual(v.sanitizers, ())
        self.assertEqual(v.instrumentation, variants.SOURCE_COVERAGE)

    def test_binary_fields_and_suffixes_match_the_state_schema(self):
        # nix-build.sh's out_suffix table and harness-built/v7's field names
        self.assertEqual(
            {v.name: (v.binary_field(), v.binary_suffix()) for v in variants.DEFAULTS},
            {"fuzzer": ("harness_binary", ""),
             "coverage": ("coverage_binary", "_cov"),
             "verify": ("verify_binary", "_verify"),
             "cmplog": ("cmplog_binary", "_cmplog"),
             "symcc": ("symcc_binary", "_symcc")})

    def test_unknown_variant_is_refused(self):
        with self.assertRaises(variants.VariantError):
            variants.default("asan")


class OverrideTest(unittest.TestCase):
    def test_per_harness_override_enables_cmplog(self):
        cfg = {"harnesses": [{"name": "parser", "variants": {"cmplog": {"enabled": True}}}]}
        names = [v["name"] for v in variants.spec(cfg, "parser")["variants"]]
        self.assertIn("cmplog", names)

    def test_an_override_is_scoped_to_its_harness(self):
        cfg = {"harnesses": [{"name": "parser", "variants": {"cmplog": {"enabled": True}}}]}
        self.assertNotIn("cmplog", [v["name"] for v in variants.spec(cfg, "encoder")["variants"]])

    def test_campaign_wide_block_applies_to_every_harness(self):
        cfg = {"variants": {"symcc": {"enabled": True}}}
        for h in ("parser", "encoder"):
            self.assertIn("symcc", [v["name"] for v in variants.spec(cfg, h)["variants"]])

    def test_per_harness_wins_over_campaign_wide(self):
        cfg = {"variants": {"cmplog": {"enabled": True}},
               "harnesses": [{"name": "parser", "variants": {"cmplog": {"enabled": False}}}]}
        self.assertNotIn("cmplog", [v["name"] for v in variants.spec(cfg, "parser")["variants"]])
        self.assertIn("cmplog", [v["name"] for v in variants.spec(cfg, "other")["variants"]])

    def test_sanitizers_can_be_replaced(self):
        got = variants.apply_override(variants.default("verify"), {"sanitizers": ["memory"]})
        self.assertEqual(got.sanitizers, ("memory",))

    def test_a_bad_field_names_itself(self):
        for over, needle in (({"enabled": "yes"}, "true or false"),
                             ({"link_mode": "static"}, "link_mode"),
                             ({"sanitizers": "address"}, "list of strings"),
                             ({"purpose": "profit"}, "purpose"),
                             ({"santiizers": []}, "not a known field")):
            with self.subTest(over=over):
                with self.assertRaises(variants.VariantError) as cm:
                    variants.apply_override(variants.default("verify"), over)
                self.assertIn(needle, str(cm.exception))

    def test_an_unknown_variant_in_config_is_refused(self):
        with self.assertRaises(variants.VariantError):
            variants.resolve({"asan": {"enabled": True}})


class SpecTest(unittest.TestCase):
    def test_spec_is_serialisable_and_labelled(self):
        s = variants.spec({}, "parser")
        self.assertEqual(s["schema"], variants.SPEC_SCHEMA)
        self.assertEqual(s["harness"], "parser")
        self.assertEqual(json.loads(json.dumps(s)), s)

    def test_spec_lists_what_was_skipped(self):
        self.assertEqual(variants.spec({}, "parser")["skipped"], ["cmplog", "symcc"])

    def test_every_spec_entry_carries_its_needs(self):
        for v in variants.spec({}, "parser")["variants"]:
            self.assertIn(v["purpose"], variants.PURPOSES)
            self.assertIn(v["instrumentation"], variants.INSTRUMENTATION)
            self.assertIn(v["link_mode"], variants.LINK_MODES)
            self.assertIsInstance(v["sanitizers"], list)


class BackendEnumTest(unittest.TestCase):
    def test_backends_include_the_new_builders(self):
        self.assertEqual(sorted(enums.BUILD_BACKEND),
                         ["legacy", "nix", "oss-fuzz", "script"])

    def test_backend_enum_is_registered(self):
        r = run_cli("enums", "print", "build_backend")
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertIn("oss-fuzz", r.stdout)


class CliTest(unittest.TestCase):
    def test_list(self):
        r = run_cli("variants", "list")
        self.assertEqual(r.returncode, 0, r.stderr)
        for name in variants.NAMES:
            self.assertIn(name, r.stdout)

    def test_show_json(self):
        r = run_cli("variants", "show", "verify")
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertEqual(json.loads(r.stdout)["purpose"], "verify")

    def test_spec_reads_a_config_file(self):
        import tempfile
        from pathlib import Path
        with tempfile.TemporaryDirectory() as td:
            cfg = Path(td) / "fuzz-config.json"
            cfg.write_text(json.dumps(
                {"harnesses": [{"name": "parser", "variants": {"symcc": {"enabled": True}}}]}))
            r = run_cli("variants", "spec", "--harness", "parser", "--config", str(cfg))
            self.assertEqual(r.returncode, 0, r.stderr)
            self.assertIn("symcc", [v["name"] for v in json.loads(r.stdout)["variants"]])

    def test_show_rejects_an_unknown_variant(self):
        r = run_cli("variants", "show", "asan")
        self.assertEqual(r.returncode, 2)


if __name__ == "__main__":
    unittest.main()
