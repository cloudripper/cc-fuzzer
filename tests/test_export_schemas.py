"""Versioned export schemas: triage-export/v1 and patch-export/v1.

A consumer in another container (a patcher reading a finder's records) keys
on these documents. Their SHAPE is the contract: these goldens pin it, and a
change that breaks them is a new schema version, not an edit.

Regenerate only on a deliberate version bump:
    CC_FUZZER_WRITE_EXPORT_GOLDENS=1 python3 -m pytest tests/test_export_schemas.py
"""
from __future__ import annotations

import json
import os
import tempfile
import unittest
from pathlib import Path

from cc_fuzzer_core import crs, determinism, patch

GOLDEN = Path(__file__).resolve().parent / "golden" / "exports"
# Fixed values, so changing a DEFAULT does not read as a schema change.
KNOBS = determinism.echo({"replay_attempts": 3, "replay_timeout_s": 30,
                          "minimize_max_probes": 400, "minimize_max_rounds": 40,
                          "sensitivity_max_probes": 1024, "fuzzer_seed": 1337})


def triage_fixture() -> crs.TriageResult:
    return crs.TriageResult(
        status=crs.CONFIRMED, reason="oracle reproduced it", pov="/work/pov.min",
        original_pov="/work/pov", pov_sha256="a" * 64, original_sha256="b" * 64,
        stack_hash="c481acca1f401bf7", category="heap-buffer-overflow",
        top_frame="write_chunk @ /src/framed.c:25", sanitizer="address",
        frames=("write_chunk @ /src/framed.c:25", "main @ /src/framed.c:40"),
        sanitizer_excerpt="==1==ERROR: AddressSanitizer: heap-buffer-overflow\n"
                          "SUMMARY: AddressSanitizer: heap-buffer-overflow",
        binary="/out/framed_verify", variant="verify", evidence_grade="strong",
        evidence_source="replay", replay_grade="strong", verdict_step="command:/opt/oracle",
        original_size=2004, size=4,
        replay={"schema": "crash-replay/v1", "verdict": "crash"},
        minimized={"schema": "minimized-input/v1", "size": 4},
        sensitivity={"schema": "input-sensitivity/v1", "mask": "##~#"},
        policy_verdict={"schema": "policy-verdict/v1", "policy": "builtin:any-confirmed",
                        "verdict": "accept", "reason": "confirmed"},
        delta_relevance={"schema": "delta-relevance/v1", "touches_diff": True,
                         "frames_in_diff": ["write_chunk @ /src/framed.c:25"],
                         "functions_in_diff": [], "nearest_frame_distance": 0,
                         "files_changed": 1},
        determinism=KNOBS)


def patch_fixture() -> patch.PatchVerdict:
    steps = (patch.Step("before", True, policy=""),
             patch.Step("build", True, value="rb-7", policy="required"),
             patch.Step("after", True),
             patch.Step("tests", True, "no test script", ran=False, policy="preferred"),
             patch.Step("gate:neighbours", True, "8 variants, none reproduce the bug",
                        policy="required"))
    povs = (patch.PovResult("/work/pov.min", "c481acca1f401bf7", "crash", "no-crash"),)
    return patch.PatchVerdict(
        status=patch.FIXES, reason="PoV no longer reproduces and the tests still pass",
        steps=steps, scope=patch.Scope(1, 2, 0, ("src/framed.c",), ("write_chunk",)),
        pov="/work/pov.min", stack_hash="c481acca1f401bf7", seconds=0.0, povs=povs,
        build="rb-7", unverified_steps=("tests",),
        determinism=KNOBS)


class ExportGoldenTest(unittest.TestCase):
    def _check(self, name, doc):
        path = GOLDEN / f"{name}.json"
        text = json.dumps(doc, indent=2, sort_keys=True) + "\n"
        if os.environ.get("CC_FUZZER_WRITE_EXPORT_GOLDENS") == "1":
            path.write_text(text)
        self.assertEqual(json.loads(text), json.loads(path.read_text()),
                         f"{name} changed shape: that is a new schema version")

    def test_export_schemas(self):
        self._check("triage-export-v1", triage_fixture().as_dict())
        self._check("patch-export-v1", patch_fixture().as_dict())

    def test_the_schema_names_are_versioned(self):
        self.assertEqual(crs.TRIAGE_SCHEMA, "triage-export/v1")
        self.assertEqual(patch.VERDICT_SCHEMA, "patch-export/v1")

    def test_notable_fields_are_present(self):
        t = triage_fixture().as_dict()
        for k in ("status", "policy_verdict", "stack_hash", "category", "sanitizer",
                  "frames", "sanitizer_excerpt", "pov_sha256", "original_sha256",
                  "evidence_grade", "evidence_source", "sensitivity", "delta_relevance"):
            self.assertIn(k, t)
        p = patch_fixture().as_dict()
        for k in ("verdict", "steps", "unverified_steps", "povs", "scope"):
            self.assertIn(k, p)
        self.assertIn("ran", p["steps"][0])
        self.assertIn("concerns", p["scope"])
        self.assertIn("before", p["povs"][0])


class LiveShapeTest(unittest.TestCase):
    """What the code emits for real has exactly the golden's keys."""

    def _keys(self, name):
        return set(json.loads((GOLDEN / f"{name}.json").read_text()))

    def test_a_real_patch_verdict(self):
        with tempfile.TemporaryDirectory() as td:
            d = Path(td)
            (d / "p.diff").write_text("--- a/x\n+++ b/x\n@@\n-a\n+b\n")
            (d / "a.bin").write_bytes(b"x")
            v = patch.validate({}, str(d / "p.diff"), str(d / "a.bin"), project_root=d,
                               replay_fn=lambda p, ph, b: patch.PovRun(ph == "before", "h"))
        self.assertEqual(set(v.as_dict()), self._keys("patch-export-v1"))

    def test_a_real_triage_result(self):
        r = crs.TriageResult(crs.NOT_A_CRASH)
        self.assertEqual(set(r.as_dict()), self._keys("triage-export-v1"))


if __name__ == "__main__":
    unittest.main()
