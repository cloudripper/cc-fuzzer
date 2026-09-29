"""SARIF in and out (prescan.sast_scan.normalize_sarif / export_sarif)."""
from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from cc_fuzzer_core.prescan import sast_scan

FINDINGS = [
    {"tool": "cc-fuzzer", "rule_id": "qp-unchecked-length", "severity": "high",
     "cwe": ["CWE-787"], "path": "src/parser.c", "line": 88, "end_line": 90,
     "message": "parse_chunk passes len to memcpy with no comparison on it"},
    {"tool": "cc-fuzzer", "rule_id": "qp-callers", "severity": "low", "cwe": [],
     "path": "src/main.c", "line": 12, "end_line": 12, "message": "call to parse_chunk"},
]


class SarifTest(unittest.TestCase):
    def test_export_is_sarif_2_1_0(self):
        doc = sast_scan.export_sarif(FINDINGS, tool_version="9.9")
        self.assertEqual(doc["version"], "2.1.0")
        run = doc["runs"][0]
        self.assertEqual(run["tool"]["driver"]["name"], "cc-fuzzer")
        self.assertEqual(run["tool"]["driver"]["version"], "9.9")
        self.assertEqual(run["results"][0]["level"], "error")
        self.assertEqual(run["tool"]["driver"]["rules"][0]["properties"]["tags"],
                         ["external/cwe/cwe-787"])

    def test_round_trip(self):
        """normalize(export(f)) == f for normalized findings."""
        back = sast_scan.normalize_sarif(sast_scan.export_sarif(FINDINGS), Path("/src"))
        self.assertEqual(back, FINDINGS)

    def test_rules_are_deduplicated(self):
        doc = sast_scan.export_sarif(FINDINGS + [dict(FINDINGS[0], line=120)])
        self.assertEqual(len(doc["runs"][0]["tool"]["driver"]["rules"]), 2)
        self.assertEqual(len(doc["runs"][0]["results"]), 3)

    def test_query_hits_export_too(self):
        doc = sast_scan.export_sarif([{"file": "a.c", "line": 3, "message": "m",
                                       "rule_id": "r"}])
        loc = doc["runs"][0]["results"][0]["locations"][0]["physicalLocation"]
        self.assertEqual((loc["artifactLocation"]["uri"], loc["region"]["startLine"]),
                         ("a.c", 3))

    def test_normalize_takes_a_path_a_string_or_a_dict(self):
        doc = sast_scan.export_sarif(FINDINGS)
        with tempfile.TemporaryDirectory() as td:
            p = Path(td) / "x.sarif"
            p.write_text(json.dumps(doc))
            for src in (p, str(p), json.dumps(doc), doc):
                with self.subTest(kind=type(src).__name__):
                    self.assertEqual(len(sast_scan.normalize_sarif(src, Path(td))), 2)

    def test_absolute_and_file_uris_become_relative_to_the_root(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            doc = sast_scan.export_sarif([dict(FINDINGS[0], path=str(root / "lib" / "x.c"))])
            self.assertEqual(sast_scan.normalize_sarif(doc, root)[0]["path"], "lib/x.c")
            doc["runs"][0]["results"][0]["locations"][0]["physicalLocation"][
                "artifactLocation"]["uri"] = (root / "lib" / "y.c").as_uri()
            self.assertEqual(sast_scan.normalize_sarif(doc, root)[0]["path"], "lib/y.c")

    def test_garbage_is_no_findings(self):
        self.assertEqual(sast_scan.normalize_sarif("/nonexistent.sarif", Path("/")), [])


if __name__ == "__main__":
    unittest.main()
