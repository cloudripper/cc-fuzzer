#!/usr/bin/env python3
"""findings_ops.py — JSONL transforms for findings.sh.

findings.sh is the ONLY sanctioned writer of findings.jsonl; it owns the CLI,
the enum validation, the two-stage reproducer verification, and the atomic
.tmp+mv discipline. The per-record JSON construction and the in-place rewrites
used to be inline `python3 <<PY` heredocs — several of which interpolated shell
values straight into Python source. They live here now, one subcommand each,
reading their inputs from the environment (and stdin where the original piped).

All JSON is emitted compact (separators=(',',':')) to match the original
on-disk format. Rewrite subcommands print the full rewritten file to stdout;
the caller redirects to a .tmp and mv's it into place.

Subcommands:
  harnesses-txt        FINDINGS ID                 -> sorted unique harnesses, one/line
  build-finding   <location> <root_cause> <reproducer> <excerpt>
                       env: NEW_ID STACK_HASH CATEGORY EXPLOITABILITY
                            BUILD_HASH NOW IS_MULTI HARNESS   -> one finding line
  dedup                FINDINGS STACK_HASH NOW HARNESS_APPEND -> rewritten file
  add-harness          FINDINGS APPEND_ID APPEND_HARNESS      -> rewritten file
  stale-mark           FINDINGS ID CURRENT_BUILD              -> rewritten file
  drop-record          TS CRASH STAGE REASON HASH PRINCIPLE EVIDENCE -> one record line
  field-stdin   <key>  read one JSON line from stdin -> .get(key,'')
  dedup-info           read one JSON line from stdin -> "<id> <dedup_count>"
"""
import json
import os
import sys


def _compact(d):
    return json.dumps(d, separators=(",", ":"))


def _iter_lines(path):
    with open(path) as f:
        for line in f:
            yield line.strip()


# ---------------------------------------------------------------------------
def cmd_harnesses_txt():
    target = os.environ["ID"]
    for line in _iter_lines(os.environ["FINDINGS"]):
        if not line:
            continue
        try:
            d = json.loads(line)
        except Exception:
            continue
        if d.get("id") == target:
            for h in sorted(set(d.get("harnesses") or [])):
                print(h)
            break


# ---------------------------------------------------------------------------
def cmd_build_finding(argv):
    location, root_cause, reproducer, excerpt = argv[0], argv[1], argv[2], argv[3]
    is_multi = os.environ.get("IS_MULTI", "0") == "1"
    d = {
        "schema": "finding/v2" if is_multi else "finding/v1",
        "id": os.environ["NEW_ID"],
        "stack_hash": os.environ["STACK_HASH"],
        "category": os.environ["CATEGORY"],
        "location": location,
        "exploitability": os.environ["EXPLOITABILITY"],
        "root_cause": root_cause,
        "reproducer": reproducer,
        "verified_against_build": os.environ.get("BUILD_HASH", ""),
        "first_seen": os.environ["NOW"],
        "last_seen": os.environ["NOW"],
        "dedup_count": 1,
    }
    if is_multi:
        d["harnesses"] = [os.environ["HARNESS"]]
    # Oracle-driven (logic) findings carry the oracle type and a divergence
    # record instead of a sanitizer-only narrative. ORACLE_TYPE defaults to
    # "crash" (omitted for back-compat); a non-crash oracle adds the fields.
    # DIVERGENCE is a JSON object string the triager assembled. See
    # STATE_SCHEMA "Oracle-Driven Fuzzing".
    oracle_type = os.environ.get("ORACLE_TYPE", "") or ""
    if oracle_type and oracle_type != "crash":
        d["oracle_type"] = oracle_type
        div_raw = os.environ.get("DIVERGENCE", "") or ""
        if div_raw:
            try:
                d["divergence"] = json.loads(div_raw)
            except Exception:
                # Malformed divergence JSON must not corrupt the record; record
                # the raw string so the triager can repair it rather than lose it.
                d["divergence"] = {"_raw": div_raw, "_parse_error": True}
    if excerpt:
        d["sanitizer_report_excerpt"] = excerpt
    print(_compact(d))


# ---------------------------------------------------------------------------
def cmd_dedup():
    target = os.environ["STACK_HASH"]
    now = os.environ["NOW"]
    append_harness = os.environ.get("HARNESS_APPEND", "")
    for line in _iter_lines(os.environ["FINDINGS"]):
        if not line:
            continue
        try:
            d = json.loads(line)
        except Exception:
            print(line)
            continue
        if d.get("stack_hash") == target:
            d["dedup_count"] = d.get("dedup_count", 1) + 1
            d["last_seen"] = now
            if append_harness:
                hs = d.get("harnesses") or []
                if append_harness not in hs:
                    hs.append(append_harness)
                    d["harnesses"] = hs
        print(_compact(d))


# ---------------------------------------------------------------------------
def cmd_add_harness():
    target = os.environ["APPEND_ID"]
    harness = os.environ["APPEND_HARNESS"]
    appended = False
    for line in _iter_lines(os.environ["FINDINGS"]):
        if not line:
            continue
        try:
            d = json.loads(line)
        except Exception:
            print(line)
            continue
        if d.get("id") == target:
            hs = d.get("harnesses") or []
            if harness not in hs:
                hs.append(harness)
                d["harnesses"] = hs
                appended = True
        print(_compact(d))
    sys.stderr.write("appended\n" if appended else "noop\n")


# ---------------------------------------------------------------------------
def cmd_stale_mark():
    target = os.environ["ID"]
    current_build = os.environ["CURRENT_BUILD"]
    for line in _iter_lines(os.environ["FINDINGS"]):
        if not line:
            continue
        try:
            d = json.loads(line)
        except Exception:
            print(line)
            continue
        if d.get("id") == target:
            d["status"] = "stale"
            d["stale_against_build"] = current_build
            d["reproducer"] = d.get("reproducer", "").replace("crashes/known/", "crashes/stale/")
        print(_compact(d))


# ---------------------------------------------------------------------------
def cmd_drop_record():
    record = {
        "schema": "dropped-crash/v1",
        "ts": os.environ["TS"],
        "crash_file": os.environ["CRASH"],
        "stage": os.environ["STAGE"],
        "reason": os.environ["REASON"],
    }
    hash_ = os.environ.get("HASH", "")
    if hash_:
        record["stack_hash_partial"] = hash_
    principle = os.environ.get("PRINCIPLE", "")
    record["principle"] = principle if principle else None
    evidence = os.environ.get("EVIDENCE", "")
    if evidence:
        record["evidence"] = evidence
    print(_compact(record))


# ---------------------------------------------------------------------------
def cmd_field_stdin(argv):
    key = argv[0]
    try:
        d = json.loads(sys.stdin.read())
        print(d.get(key, ""))
    except Exception:
        print("")


def cmd_dedup_info():
    for line in sys.stdin:
        line = line.strip()
        if not line:
            continue
        d = json.loads(line)
        print(d.get("id", ""), d.get("dedup_count", 0))
        break


DISPATCH = {
    "harnesses-txt": cmd_harnesses_txt,
    "dedup": cmd_dedup,
    "add-harness": cmd_add_harness,
    "stale-mark": cmd_stale_mark,
    "drop-record": cmd_drop_record,
    "dedup-info": cmd_dedup_info,
}


def main(argv):
    if not argv:
        print("usage: findings_ops.py <subcommand> [args]", file=sys.stderr)
        return 2
    sub, rest = argv[0], argv[1:]
    if sub == "build-finding":
        cmd_build_finding(rest)
        return 0
    if sub == "field-stdin":
        cmd_field_stdin(rest)
        return 0
    fn = DISPATCH.get(sub)
    if fn is None:
        print(f"unknown subcommand: {sub}", file=sys.stderr)
        return 2
    fn()
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
