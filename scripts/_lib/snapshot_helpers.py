#!/usr/bin/env python3
"""snapshot_helpers.py — small JSON helpers for snapshot-coverage.sh.

snapshot-coverage.sh drives llvm-cov / AFL stat parsing and writes the coverage
snapshot; these are the bits that were inline python — a fuzzers.json slot
lookup (used twice, for log_file and pid_file) and three stdin→JSON transforms
over llvm-cov output and file lists.

Subcommands:
  slot-field <field>   env MF H -> <field> of the first libfuzzer slot bound to
                       harness H (matches the old per-field heredocs)
  cov-summary          stdin: llvm-cov --summary-only JSON -> "covered total pct"
                       (pct as %.2f; "0 0 0" on any parse error)
  lines-to-json        stdin -> JSON array of stripped non-empty lines
  unreached-funcs      stdin: llvm-cov export JSON -> JSON array of up to 15
                       function names with count == 0
"""
import json
import os
import sys


def cmd_slot_field(argv):
    field = argv[0]
    try:
        doc = json.load(open(os.environ["MF"]))
        for s in doc.get("slots", []):
            if s.get("engine") == "libfuzzer" and s.get("harness") == os.environ["H"]:
                print(s.get(field, ""))
                break
    except Exception:
        pass


def cmd_cov_summary():
    try:
        d = json.load(sys.stdin)
        totals = d["data"][0]["totals"]
        lines = totals["lines"]
        covered = lines.get("covered", 0)
        total = lines.get("count", 0)
        pct = (covered / total * 100) if total else 0
        print(covered, total, f"{pct:.2f}")
    except Exception:
        print(0, 0, 0)


def cmd_lines_to_json():
    print(json.dumps([line.strip() for line in sys.stdin if line.strip()]))


def cmd_unreached_funcs():
    try:
        d = json.load(sys.stdin)
        funcs = d["data"][0].get("functions", [])
        unreached = [f["name"] for f in funcs if f.get("count", 0) == 0]
        print(json.dumps(unreached[:15]))
    except Exception:
        print("[]")


def main(argv):
    if not argv:
        print("usage: snapshot_helpers.py <subcommand> [args]", file=sys.stderr)
        return 2
    sub, rest = argv[0], argv[1:]
    if sub == "slot-field":
        cmd_slot_field(rest)
    elif sub == "cov-summary":
        cmd_cov_summary()
    elif sub == "lines-to-json":
        cmd_lines_to_json()
    elif sub == "unreached-funcs":
        cmd_unreached_funcs()
    else:
        print(f"unknown subcommand: {sub}", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
