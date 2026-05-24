#!/usr/bin/env python3
"""write_harness_built.py — emit harness-built.json (and, in multi mode,
update harnesses.json) from the environment prepared by write-harness-built.sh.

The bash wrapper does all argument parsing, validation, and hash computation,
then exports the resolved values and calls this with one positional argument:
the temp path to write the (singular file | multi-mode mirror) into.

Singular: write the harness-built/v5 doc straight to argv[1].
Multi:    upsert the harness-built/v6 doc (adds `name`) into harnesses.json by
          name, atomically, then mirror harnesses[0] into argv[1] so v8-era
          readers of harness-built.json keep working.
"""
import json
import os
import sys


def tri_bool(s):
    return s == "true"


def opt(v):
    return v if v else None


def build_doc():
    df_raw = os.environ.get("DICT_FILES_PY", "")
    dict_files = [line for line in df_raw.splitlines() if line] if df_raw else []
    sanitizers = [s for s in os.environ["SANITIZERS_PY"].split(",") if s]
    is_multi = os.environ.get("IS_MULTI_WRITE", "0") == "1"

    doc = {
        "schema": "harness-built/v6" if is_multi else "harness-built/v5",
        "harness_source": os.environ["HARNESS_SOURCE"],
        "harness_binary": os.environ["HARNESS_BINARY"],
        "coverage_binary": opt(os.environ.get("COVERAGE_BIN_JSON", "")),
        "coverage_tracking": tri_bool(os.environ["COVERAGE_TRACKING"]),
        "verify_binary": opt(os.environ.get("VERIFY_BIN_JSON", "")),
        "cmplog_binary": opt(os.environ.get("CMPLOG_BIN_JSON", "")),
        "cmplog_enabled": tri_bool(os.environ["CMPLOG_ENABLED"]),
        "symcc_binary": opt(os.environ.get("SYMCC_BINARY", "")),
        "build_script": os.environ["BUILD_SCRIPT"],
        "entry_function": os.environ["ENTRY_FUNCTION"],
        "input_encoding": os.environ["INPUT_ENCODING"],
        "sanitizers": sanitizers,
        "fuzzing_mode": os.environ["FUZZING_MODE"],
        "dict_files": dict_files,
        "target_source": os.environ["TARGET_SOURCE"],
        "target_source_hash": os.environ["TARGET_HASH"],
        "build_command_hash": os.environ["BUILD_HASH"],
        "harness_attempts": int(os.environ.get("ATTEMPTS", "1") or "1"),
        "built_at": os.environ["BUILT_AT"],
    }

    if is_multi:
        doc["name"] = os.environ["HARNESS_NAME"]

    # Conditional fields per spec: reason fields must appear when their tracking
    # field is false, must NOT appear when tracking is true.
    if not doc["coverage_tracking"]:
        doc["coverage_disabled_reason"] = os.environ.get("COVERAGE_REASON_JSON", "")
    if not doc["cmplog_enabled"]:
        doc["cmplog_disabled_reason"] = os.environ.get("CMPLOG_REASON_JSON", "")

    bc = os.environ.get("BUILD_COMMAND", "")
    if bc:
        doc["build_command"] = bc

    return doc, is_multi


def main(argv):
    if len(argv) < 1:
        print("usage: write_harness_built.py <tmp-out-path>", file=sys.stderr)
        return 2
    out_path = argv[0]
    doc, is_multi = build_doc()

    # Singular path: write doc straight to the harness-built.json TMP.
    if not is_multi:
        with open(out_path, "w") as f:
            json.dump(doc, f, indent=2)
        return 0

    # Multi path: upsert into harnesses.json, then mirror harnesses[0].
    hs_path = os.path.join(os.environ["STATE_DIR"], "harnesses.json")
    try:
        hset = json.load(open(hs_path))
        if hset.get("schema") != "harness-set/v1":
            hset = {"schema": "harness-set/v1", "harnesses": []}
    except Exception:
        hset = {"schema": "harness-set/v1", "harnesses": []}

    name = os.environ["HARNESS_NAME"]
    hs = hset.setdefault("harnesses", [])
    idx = next((i for i, h in enumerate(hs) if isinstance(h, dict) and h.get("name") == name), None)
    if idx is None:
        hs.append(doc)
    else:
        hs[idx] = doc

    hs_tmp = hs_path + ".tmp"
    with open(hs_tmp, "w") as f:
        json.dump(hset, f, indent=2)
    os.replace(hs_tmp, hs_path)

    # Mirror harnesses[0] into harness-built.json so v8-era readers keep working.
    with open(out_path, "w") as f:
        json.dump(hs[0], f, indent=2)
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
