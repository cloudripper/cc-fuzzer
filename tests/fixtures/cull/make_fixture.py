"""Regenerate bug-candidates.sarif with cull's own writer.

    pip install -e <cull checkout>      # cull 0.3.0, evidence 1.8.0
    python tests/fixtures/cull/make_fixture.py tests/fixtures/cull/bug-candidates.sarif

The records are hand-made; everything cull derives from them (the cull/v1
bag, candidate_id, position, confidence, input_hints' value/encoding/hex)
comes from cull's code, so the fixture is what a real scan emits. Not run by
the test suite: cull is not a dependency of cc-fuzzer.
"""
import json
import sys

from cull import evidence_record as EV
from cull import hints as H
from cull import report as R


def rec(path, line, fn, cwe, verdict, tier, triage, reach=None, access="write", steps=None,
        mech="memcpy", why="the length is not bounded by the destination", extra=None,
        rtier=None, chain=None, storage="heap", prox=None):
    r = {"path": path, "line": line, "col": 5, "function": fn, "function_line": line - 10,
         "function_end_line": line + 20, "verdict": verdict, "triage_tier_name": tier,
         "triage": triage, "triage_rank": None, "mechanism": mech, "why": why,
         "sink_expr": "memcpy(dst, src, len)",
         "flow": {"candidates": [{"reachability": reach}] if reach else []},
         "flow_steps": steps or [],
         "state": {"cwe": cwe, "bounds_checks_on_path": [{"stmt": "if (len > 64)", "holds_as": "false"}],
                   "extraction": {"model": {"operation": "memcpy", "access": access,
                                            "dest_object": "hdr->buf", "cap_bytes": 64, "storage": storage,
                                            "write_bytes": "len",
                                            "deciding_operands": [{"role": "length", "expr": "len"}]},
                                  "refusal": []}}}
    r["reach_tier"] = rtier
    r["call_chain"] = chain
    r["diff_proximity"] = prox
    r.update(extra or {})
    return r


steps = [{"reachability": "input", "operand": "len", "source": "fread",
          "steps": [{"uri": "src/io.c", "start_line": 40, "start_column": 3, "message": "fread(buf, 1, n, f)"},
                    {"uri": "src/parse.c", "start_line": 88, "start_column": 9, "message": "len = hdr->size"}]}]
recs = [
    rec("src/parse.c", 120, "parse_chunk", "CWE-787", "UNDETERMINED", "wrap-prone", 0.91, "input", steps=steps,
        rtier="harness", chain=["LLVMFuzzerTestOneInput", "parse", "parse_chunk"], storage="stack",
        why="the length read from the header is not bounded by the 64-byte buffer",
        prox={"label": "changed-file", "hops": None}),
    rec("src/parse.c", 60, "read_header", "CWE-125", "UNDETERMINED", "unbounded-extent", 0.72, "entry-point",
        access="read", rtier="indirect", chain=["LLVMFuzzerTestOneInput", "dispatch", "read_header"],
        prox={"label": "in-diff", "hops": None}),
    rec("src/free.c", 30, "drop_node", "CWE-416", "UNDETERMINED", "freed-on-some-path", 0.55, "harness",
        rtier="harness", chain=["LLVMFuzzerTestOneInput", "drop_node"],
        why="the node may be freed on the error path before this use",
        prox={"label": "changed-function", "hops": None}),
    rec("src/util.c", 12, "copy_name", "CWE-787", "REPORT", "proven", 1.0, None, rtier="none-found",
        storage="global", why="the copy writes 72 bytes into a 64-byte buffer",
        prox={"label": "near-change", "hops": 1}),
    rec("src/tbl.c", 99, "lookup", "CWE-476", "UNDETERMINED", "null-on-some-path", 0.40, None,
        rtier="none-found", why="a null literal reaches the dereference on one path",
        prox={"label": "diff-flow", "hops": None}),
    rec("src/misc.c", 7, "fmt_path", "CWE-22", "UNDETERMINED", None, 0.10, None,
        extra={"external": {"stage": "security-extended", "rule": "cpp/path-injection",
                            "name": "Path injection", "severity": 7.5, "precision": "high",
                            "cwes": ["CWE-22"]}}),
]
# what InputHints.ql reports; cull.hints turns it into each record's input_hints
hint_objs = [
    {"role": "input-hint", "function": "parse", "path": "src/parse.c", "line": 88,
     "kind": "text", "value": "IHDR", "tainted": True},
    {"role": "input-hint", "function": "parse", "path": "src/parse.c", "line": 90,
     "kind": "int", "value": str(0x474E5089), "width": 4, "tainted": True},
    {"role": "input-hint", "function": "read_header", "path": "src/parse.c", "line": 55,
     "kind": "text", "value": 'a"b\\c', "tainted": False},
]
H.annotate(recs, H.by_function(hint_objs))
recs[-1]["input_hints"] = None          # an alert: the input-hints stage says nothing

meta = {"version": "0.3.0", "root_uri": "file:///work/proj/",
        "run_provenance": {"cull_version": "0.3.0", "codeql_version": "2.25.6",
                           "pack_sha256": "a" * 64, "db_sha256": "b" * 64, "diff_sha256": "c" * 64,
                           "entry": ["LLVMFuzzerTestOneInput"],
                           "classes": ["memory-safety", "null", "integer-memory"],
                           "evidence_version": EV.EVIDENCE_VERSION, "escalate": 0,
                           "dropped": 3, "degraded": False, "score_version": 1,
                           "reach_tiers": {"harness": 2, "indirect": 1, "none-found": 2, "null": 1},
                           "stage_timeout": 1800.0, "seconds": 12.5},
        "analysis_stages": [{"family": "CWE-787", "stage": "write-evidence", "fate": "landed"}]}

if __name__ == "__main__":
    text = R.render_sarif_bug_candidates(recs, meta)
    doc = json.loads(text)
    problems = R.check_bug_candidates(doc)
    if problems:
        sys.exit("cull's checker refused the fixture: %s" % problems)
    open(sys.argv[1], "w").write(text)
    for r in doc["runs"][0]["results"]:
        print(r["ruleId"], r["properties"]["cull/v1"])
