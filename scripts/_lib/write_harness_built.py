#!/usr/bin/env python3
"""write_harness_built.py — upsert the harness record into harnesses.json and
mirror harnesses[0] into harness-built.json, from the environment prepared by
write-harness-built.sh.

The bash wrapper does all argument parsing, validation, and hash computation,
then exports the resolved values and calls this with one positional argument:
the temp path to write the harness-built.json mirror into.

Every campaign is multi-harness since v0.30. This upserts the harness-built/v7
doc (with `name`, `build_backend`) into harnesses.json by name, atomically, then
mirrors harnesses[0] into argv[1] so readers of harness-built.json keep working.
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

    build_backend = os.environ.get("BUILD_BACKEND", "legacy") or "legacy"
    doc = {
        "schema": "harness-built/v7",
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

    doc["name"] = os.environ["HARNESS_NAME"]
    doc["build_backend"] = build_backend
    import datetime as _dt
    doc["build_backend_decided_at"] = _dt.datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ")
    doc["build_backend_decided_by"] = "write-harness-built"

    # Instrumented shared objects whose coverage mapping llvm-cov must also read
    # (a monolithic / Nix-DSO-linked harness has its coverage data in the .so,
    # not the harness binary). Additive-optional: only present when non-empty.
    dso_raw = os.environ.get("COVERAGE_DSO_PY", "")
    coverage_dso = [line for line in dso_raw.splitlines() if line] if dso_raw else []
    if coverage_dso:
        doc["coverage_dso"] = coverage_dso

    # Conditional fields per spec: reason fields must appear when their tracking
    # field is false, must NOT appear when tracking is true.
    if not doc["coverage_tracking"]:
        doc["coverage_disabled_reason"] = os.environ.get("COVERAGE_REASON_JSON", "")
    if not doc["cmplog_enabled"]:
        doc["cmplog_disabled_reason"] = os.environ.get("CMPLOG_REASON_JSON", "")

    bc = os.environ.get("BUILD_COMMAND", "")
    if bc:
        doc["build_command"] = bc

    # Oracle config (oracle-driven fuzzing). Additive-optional: absent ⇒ the
    # implicit crash oracle (sanitizer/abort), the historical behavior. When the
    # harness compiles in an invariant / round-trip / differential oracle, the
    # harness-writer passes a JSON blob via ORACLE_JSON. See STATE_SCHEMA
    # "Oracle-Driven Fuzzing".
    oracle_raw = os.environ.get("ORACLE_JSON", "")
    if oracle_raw:
        try:
            doc["oracle"] = json.loads(oracle_raw)
        except Exception:
            doc["oracle"] = {"type": "crash", "_parse_error": True, "_raw": oracle_raw}

    return doc


def main(argv):
    if len(argv) < 1:
        print("usage: write_harness_built.py <tmp-out-path>", file=sys.stderr)
        return 2
    out_path = argv[0]
    doc = build_doc()

    # Upsert into harnesses.json, then mirror harnesses[0].
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

    # Mirror harnesses[0] into harness-built.json so readers of the flat
    # harness-built.json (the read-only mirror) keep working.
    with open(out_path, "w") as f:
        json.dump(hs[0], f, indent=2)
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
