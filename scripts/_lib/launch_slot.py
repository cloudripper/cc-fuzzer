#!/usr/bin/env python3
"""launch_slot.py — JSON helpers for launch-fuzzer-slot.sh.

launch-fuzzer-slot.sh owns the engine launch (nohup libFuzzer/AFL++, PID
capture, per-slot files). The two pieces that were inline python — parsing the
dict_files JSON out of the per-harness record, and the atomic read-modify-write
of fuzzers.json after launch — live here as subcommands, fed from the
environment the wrapper already exports.

Subcommands:
  parse-dict-json   env DJ                 -> each dict-file path, one per line
  update-manifest   env MANIFEST SLOT ENGINE BIN PID PGID STARTED_AT
                        LOG_FILE PID_FILE ENGINE_FILE ROLE POWER_SCHEDULE
                        RESTART_OF HARNESS
                    upsert this slot's entry into fuzzers.json (fuzzers/v2, atomic)
"""
import json
import os
import sys
from pathlib import Path

# SSOT for all state enums. Same sibling-import pattern as cve-context-builder.py.
sys.path.insert(0, str(Path(__file__).resolve().parent))
import enums  # type: ignore  # noqa: E402


def cmd_parse_dict_json():
    """DICT_FILES may be a JSON array (multi-element dict_files) or a bare
    string (single dict). Emit each non-empty entry on its own line."""
    try:
        val = os.environ["DJ"]
        arr = json.loads(val) if val.startswith("[") else [val]
        for f in arr:
            if f:
                print(f)
    except Exception:
        pass


def cmd_update_manifest():
    mf = os.environ["MANIFEST"]
    slot = os.environ["SLOT"]
    restart_of = os.environ.get("RESTART_OF", "")
    # Engine is validated against the SSOT here (writer of record); the bash
    # launcher also validates before reaching this point.
    engine = os.environ["ENGINE"]
    if engine not in enums.ENGINES:
        sys.stderr.write(
            "launch_slot: invalid engine '%s' (expected one of: %s)\n"
            % (engine, ", ".join(sorted(enums.ENGINES)))
        )
        sys.exit(2)
    # Multi-harness is the only mode (schema v12): every slot carries a harness
    # binding and fuzzers.json is fuzzers/v2.
    harness = os.environ.get("HARNESS", "")
    expected_schema = "fuzzers/v2"

    try:
        doc = json.load(open(mf))
        if doc.get("schema") != expected_schema:
            doc = {"schema": expected_schema, "slots": []}
    except Exception:
        doc = {"schema": expected_schema, "slots": []}

    # Find or insert
    idx = next((i for i, s in enumerate(doc["slots"]) if s.get("slot") == slot), None)
    restart_count = 0
    last_restart_at = None
    if idx is not None:
        prev = doc["slots"][idx]
        restart_count = int(prev.get("restart_count", 0))
        if restart_of:
            restart_count += 1
            last_restart_at = os.environ["STARTED_AT"]
        else:
            last_restart_at = prev.get("last_restart_at")

    entry = {
        "slot":           slot,
        "engine":         engine,
        "binary":         os.environ["BIN"],
        "pid":            os.environ["PID"],
        "pgid":           os.environ["PGID"],
        "started_at":     os.environ["STARTED_AT"],
        "log_file":       os.environ["LOG_FILE"],
        "pid_file":       os.environ["PID_FILE"],
        "engine_file":    os.environ["ENGINE_FILE"],
        "role":           os.environ.get("ROLE") or None,
        "afl_power_schedule": os.environ.get("POWER_SCHEDULE") or None,
        "restart_count":  restart_count,
        "last_restart_at": last_restart_at,
    }
    entry["harness"] = harness

    if idx is None:
        doc["slots"].append(entry)
    else:
        doc["slots"][idx] = entry

    with open(mf + ".tmp", "w") as f:
        json.dump(doc, f, indent=2)
    os.replace(mf + ".tmp", mf)


DISPATCH = {
    "parse-dict-json": cmd_parse_dict_json,
    "update-manifest": cmd_update_manifest,
}


def main(argv):
    if not argv or argv[0] not in DISPATCH:
        print("usage: launch_slot.py {parse-dict-json|update-manifest}", file=sys.stderr)
        return 2
    DISPATCH[argv[0]]()
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
