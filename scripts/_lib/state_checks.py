#!/usr/bin/env python3
"""state_checks.py — shim onto cc_fuzzer_core.schema.checks.

The content-validation primitives moved into the core package (UPDATE_ROADMAP.md
§2 row 2; validate-state.sh is now `cc-fuzzer schema validate`). This keeps the
old subcommand CLI for the remaining callers (findings.sh uses `field`), with
the same environment-variable inputs and output.

Subcommands:
  config-harness-names   CFG                      -> harness names, one per line
  validate-json          FILE SCHEMA REQUIRED ALLOWED LENIENT -> OK | "WARN: ..." | error line
  field        <file> <dotted.path> [default]     -> single field value
  hash-check   <file>                             -> "<key>=<val>" for bad hashes
  harnesses-mirror       HARNESSES_PATH MIRROR_PATH DECLARED REQUIRED_V6 ALLOWED_V6 [EXPECTED_HARNESS_SCHEMA]
  slots                  DECLARED CFG
  fuzzers-manifest       DECLARED MANIFEST_PATH
  findings               DECLARED FINDINGS
  code-review            FILE
  jsonl-corrections      HCS
  jsonl-dropped          DROPS
  jsonl-events           EVENTS
  snapshot-multi         SNAPS_DIR DECLARED
  harness-bins           HS_PATH
Relative paths inside state files resolve against the cwd, as before.
"""
import os
import sys

from cc_fuzzer_core.schema import checks as C
from cc_fuzzer_core.schema import fields as F

E = os.environ


def _declared():
    return [n for n in E.get("DECLARED", "").splitlines() if n.strip()]


def _csv(name):
    v = E.get(name, "")
    return v.split(",") if v else []


DISPATCH = {
    "config-harness-names": lambda: C.config_harness_names(E["CFG"]),
    "validate-json": lambda: [C.validate_json(E["FILE"], E["SCHEMA"], _csv("REQUIRED"), _csv("ALLOWED"),
                                              E.get("LENIENT", "strict") == "lenient")],
    "harnesses-mirror": lambda: C.harnesses_mirror(
        E["HARNESSES_PATH"], E["MIRROR_PATH"], _declared(), _csv("REQUIRED_V6"), _csv("ALLOWED_V6"),
        E.get("EXPECTED_HARNESS_SCHEMA", F.HARNESS_BUILT_SCHEMA)),
    "slots": lambda: C.slots(E["CFG"], _declared()),
    "fuzzers-manifest": lambda: C.fuzzers_manifest(E["MANIFEST_PATH"], _declared()),
    "findings": lambda: C.findings(E["FINDINGS"], _declared()),
    "code-review": lambda: C.code_review(E["FILE"]),
    "jsonl-corrections": lambda: C.jsonl_corrections(E["HCS"]),
    "jsonl-dropped": lambda: C.jsonl_dropped(E["DROPS"]),
    "jsonl-events": lambda: C.jsonl_events(E["EVENTS"]),
    "snapshot-multi": lambda: C.snapshot_multi(E["SNAPS_DIR"], _declared()),
    "harness-bins": lambda: C.harness_bins(E["HS_PATH"]),
}


def main(argv):
    if not argv:
        print("usage: state_checks.py <subcommand> [args]", file=sys.stderr)
        return 2
    sub, rest = argv[0], argv[1:]
    if sub == "field":
        print(C.field(rest[0], rest[1], rest[2] if len(rest) > 2 else ""))
        return 0
    if sub == "hash-check":
        lines = C.hash_check(rest[0])
    elif sub in DISPATCH:
        lines = DISPATCH[sub]()
    else:
        print(f"unknown subcommand: {sub}", file=sys.stderr)
        return 2
    for ln in lines:
        print(ln)
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
