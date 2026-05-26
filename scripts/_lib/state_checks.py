#!/usr/bin/env python3
"""state_checks.py — content-validation primitives for validate-state.sh.

validate-state.sh is the strict state gate; its exit code drives
check-campaign-state.sh. It is fundamentally a bash orchestrator — directory
layout, globbing, mode detection on the filesystem, BASH_REMATCH on filenames —
but the per-file *content* validation used to be ~400 lines of inline
`python3 <<PY` heredocs interleaved through the script. Those live here now,
one subcommand per former heredoc, so the logic is testable in isolation and the
driver stays readable.

Each subcommand prints problem lines to stdout (one per line); the caller turns
them into err()/warn() entries. Exit status is NOT used to signal problems
(always 0 unless a usage error) — the presence of output is the signal, matching
the original heredocs, which were captured with `$(... 2>&1)`.

Inputs are passed via environment variables (documented per subcommand) to avoid
interpolating shell values into Python source the way the old heredocs did.

Subcommands:
  config-harness-names   CFG                      -> harness names, one per line
  validate-json          FILE SCHEMA REQ ALLOW LEN-> OK | "WARN: ..." | error line
  field        <file> <dotted.path> [default]     -> single field value
  hash-check   <file>                             -> "<key>=<val>" for bad hashes
  harnesses-mirror       HARNESSES_PATH MIRROR_PATH DECLARED REQUIRED_V6 ALLOWED_V6 [EXPECTED_HARNESS_SCHEMA]
  slots                  MODE DECLARED CFG
  fuzzers-manifest       MODE DECLARED MANIFEST_PATH
  findings               MODE DECLARED FINDINGS
  jsonl-corrections      HCS
  jsonl-dropped          DROPS
  jsonl-events           EVENTS
  snapshot-multi         SNAPS_DIR DECLARED
  harness-bins           HS_PATH
"""
from __future__ import annotations
import glob
import json
import os
import re
import sys


def _env_set(name):
    """Newline-delimited env var -> set of non-empty values."""
    return {n for n in os.environ.get(name, "").splitlines() if n.strip()}


# ---------------------------------------------------------------------------
# mode detection: harness names declared in fuzz-config.json
# ---------------------------------------------------------------------------
def cmd_config_harness_names():
    try:
        d = json.load(open(os.environ["CFG"]))
        hs = d.get("harnesses") or []
        if isinstance(hs, list):
            for h in hs:
                if isinstance(h, dict) and h.get("name"):
                    print(h["name"])
    except Exception:
        pass


# ---------------------------------------------------------------------------
# the generic JSON schema validator (former validate_json() heredoc)
# ---------------------------------------------------------------------------
def cmd_validate_json():
    file = os.environ["FILE"]
    expected_schema = os.environ["SCHEMA"]
    required_str = os.environ.get("REQUIRED", "")
    allowed_str = os.environ.get("ALLOWED", "")
    lenient = os.environ.get("LENIENT", "strict") == "lenient"

    try:
        with open(file) as f:
            d = json.load(f)
    except json.JSONDecodeError as e:
        print(f"PARSE_ERROR: {e}")
        return
    except Exception as e:
        print(f"READ_ERROR: {e}")
        return

    if not isinstance(d, dict):
        print(f"NOT_OBJECT: top-level must be a JSON object, got {type(d).__name__}")
        return

    schema = d.get("schema")
    if schema != expected_schema:
        print(f"WRONG_SCHEMA: expected '{expected_schema}', got '{schema}'")
        return

    required = set(required_str.split(",")) if required_str else set()
    allowed = set(allowed_str.split(",")) if allowed_str else set()
    allowed.add("schema")

    actual = set(d.keys())
    missing = required - actual
    unrecognized = actual - allowed

    if missing:
        print(f"MISSING_FIELDS: {sorted(missing)}")
        return
    if unrecognized:
        # In lenient mode the validator still surfaces the extra fields, but as
        # a warning so old snapshots don't block the campaign. The "WARN:"
        # prefix is interpreted by the caller.
        prefix = "WARN: " if lenient else ""
        print(f"{prefix}UNRECOGNIZED_FIELDS: {sorted(unrecognized)}")
        return

    print("OK")


# ---------------------------------------------------------------------------
# field readers (former `python3 -c` one-liners)
# ---------------------------------------------------------------------------
def cmd_field(argv):
    """field <file> <dotted.path> [default]

    Traverses a dotted path into a JSON object. Prints the value (Python str:
    booleans render as True/False), or the default if any key is missing or the
    value is null. Mirrors the old `.get(...) or ''` / `.get(..., False)`
    one-liners; on read error prints the default."""
    file = argv[0]
    dotted = argv[1]
    default = argv[2] if len(argv) > 2 else ""
    try:
        cur = json.load(open(file))
    except Exception:
        print(default)
        return
    for key in dotted.split("."):
        if isinstance(cur, dict) and key in cur:
            cur = cur[key]
        else:
            cur = None
            break
    print(default if cur is None else cur)


def cmd_hash_check(argv):
    """hash-check <file> -> '<key>=<val>' lines for non-16-hex hash fields."""
    file = argv[0]
    try:
        d = json.load(open(file))
    except Exception as e:
        print(f"parse_error={e}")
        return
    for k in ("target_source_hash", "build_command_hash"):
        v = d.get(k, "")
        if not re.match(r"^[0-9a-f]{16}$", v or ""):
            print(f"{k}={v}")


# ---------------------------------------------------------------------------
# harnesses.json structural check + mirror-drift invariant
# ---------------------------------------------------------------------------
def cmd_harnesses_mirror():
    SLUG = re.compile(r"^[a-z0-9][a-z0-9_-]{0,31}$")
    required = set(os.environ["REQUIRED_V6"].split(",")) | {"schema"}
    allowed = set(os.environ["ALLOWED_V6"].split(",")) | {"schema"}
    declared = [n for n in os.environ["DECLARED"].splitlines() if n.strip()]
    expected_schema = os.environ.get("EXPECTED_HARNESS_SCHEMA", "harness-built/v7")

    try:
        doc = json.load(open(os.environ["HARNESSES_PATH"]))
    except Exception as e:
        print(f"harnesses.json: parse error: {e}")
        return

    hs = doc.get("harnesses") or []
    if not hs:
        print("harnesses.json: harnesses[] is empty (multi mode requires at least one entry)")
        return

    seen = set()
    for i, h in enumerate(hs):
        if not isinstance(h, dict):
            print(f"harnesses.json: harnesses[{i}] is not an object")
            continue
        if h.get("schema") != expected_schema:
            print(f"harnesses.json: harnesses[{i}].schema is '{h.get('schema')}' (expected {expected_schema})")
        name = h.get("name", "")
        if not SLUG.match(name or ""):
            print(f"harnesses.json: harnesses[{i}].name '{name}' invalid (regex ^[a-z0-9][a-z0-9_-]{{0,31}}$)")
        if name in seen:
            print(f"harnesses.json: duplicate harness name '{name}'")
        seen.add(name)
        keys = set(h.keys())
        missing = required - keys
        unrec = keys - allowed
        if missing:
            print(f"harnesses.json: harnesses[{i}] ({name!r}) missing fields {sorted(missing)}")
        if unrec:
            print(f"harnesses.json: harnesses[{i}] ({name!r}) unrecognized fields {sorted(unrec)}")

    # Cross-ref: harnesses.json names must equal fuzz-config.json:harnesses[] names
    config_names = set(declared)
    hs_names = {h.get("name") for h in hs if isinstance(h, dict)}
    extra_in_hs = hs_names - config_names
    missing_in_hs = config_names - hs_names
    if extra_in_hs:
        print(f"harnesses.json declares {sorted(extra_in_hs)} not in fuzz-config.json:harnesses[]")
    if missing_in_hs:
        print(f"fuzz-config.json:harnesses[] declares {sorted(missing_in_hs)} not in harnesses.json")

    # Mirror invariant: state/harness-built.json must equal harnesses[0] field-by-field
    mirror_path = os.environ["MIRROR_PATH"]
    if os.path.isfile(mirror_path) and hs:
        try:
            mirror = json.load(open(mirror_path))
        except Exception as e:
            print(f"harness-built.json: parse error reading mirror: {e}")
        else:
            head = hs[0]
            all_keys = set(mirror.keys()) | set(head.keys())
            drift = [k for k in all_keys if mirror.get(k) != head.get(k)]
            if drift:
                print(f"harness-built.json: MIRROR DRIFT vs harnesses.json[0] on fields {sorted(drift)} (mirror file is read-only; writes must go to harnesses.json)")


# ---------------------------------------------------------------------------
# fuzz-config.json: fuzzer_slots[] + (multi) harnesses[]
# ---------------------------------------------------------------------------
def cmd_slots():
    mode = os.environ.get("MODE", "singular")
    declared = _env_set("DECLARED")
    try:
        d = json.load(open(os.environ["CFG"]))
    except Exception:
        return
    slots = d.get("fuzzer_slots") or []
    if not isinstance(slots, list):
        print("fuzz-config.json: fuzzer_slots must be a list")
        return
    slot_re = re.compile(r"^[a-z0-9-]{1,32}$")
    seen = set()
    for i, s in enumerate(slots):
        if not isinstance(s, dict):
            print(f"fuzz-config.json: fuzzer_slots[{i}] is not an object")
            continue
        name = s.get("slot", "")
        if not slot_re.match(name):
            print(f'fuzz-config.json: fuzzer_slots[{i}].slot "{name}" invalid (regex ^[a-z0-9-]{{1,32}}$)')
        if name in seen:
            print(f'fuzz-config.json: duplicate slot name "{name}"')
        seen.add(name)
        engine = s.get("engine", "")
        if engine not in ("libfuzzer", "aflpp"):
            print(f'fuzz-config.json: fuzzer_slots[{i}].engine "{engine}" must be libfuzzer or aflpp')
        role = s.get("role")
        if role is not None and role not in ("master", "secondary"):
            print(f'fuzz-config.json: fuzzer_slots[{i}].role "{role}" must be master, secondary, or null')
        sched = s.get("afl_power_schedule")
        if sched is not None and sched not in ("explore", "exploit", "fast", "coe", "quad", "lin", "seek", "rare"):
            print(f'fuzz-config.json: fuzzer_slots[{i}].afl_power_schedule "{sched}" not a valid AFL++ schedule')
        if mode == "multi":
            h = s.get("harness", "")
            if not h:
                print(f"fuzz-config.json: fuzzer_slots[{i}] ({name!r}) missing required field harness (multi mode)")
            elif h not in declared:
                print(f'fuzz-config.json: fuzzer_slots[{i}] ({name!r}) references undeclared harness "{h}"')

    if mode == "multi":
        hs = d.get("harnesses") or []
        if not isinstance(hs, list) or not hs:
            print("fuzz-config.json: multi mode requires non-empty harnesses[]")
        else:
            slug = re.compile(r"^[a-z0-9][a-z0-9_-]{0,31}$")
            names = set()
            for i, h in enumerate(hs):
                if not isinstance(h, dict):
                    print(f"fuzz-config.json: harnesses[{i}] is not an object")
                    continue
                n = h.get("name", "")
                if not slug.match(n or ""):
                    print(f'fuzz-config.json: harnesses[{i}].name "{n}" invalid (regex ^[a-z0-9][a-z0-9_-]{{0,31}}$)')
                if n in names:
                    print(f'fuzz-config.json: duplicate harness name "{n}"')
                names.add(n)
                if not h.get("entry_function"):
                    print(f"fuzz-config.json: harnesses[{i}] ({n!r}) missing entry_function")


# ---------------------------------------------------------------------------
# fuzzers.json live manifest
# ---------------------------------------------------------------------------
def cmd_fuzzers_manifest():
    mode = os.environ.get("MODE", "singular")
    declared = _env_set("DECLARED")
    required_base = {"slot", "engine", "binary", "pid", "pgid", "started_at", "log_file", "pid_file", "engine_file", "restart_count"}
    required = required_base | ({"harness"} if mode == "multi" else set())
    try:
        d = json.load(open(os.environ["MANIFEST_PATH"]))
    except Exception:
        return
    slots = d.get("slots") or []
    for i, s in enumerate(slots):
        if not isinstance(s, dict):
            print(f"fuzzers.json: slots[{i}] is not an object")
            continue
        missing = required - set(s.keys())
        if missing:
            slot_name = s.get("slot", "?")
            print(f"fuzzers.json: slots[{i}] ({slot_name!r}) missing fields {sorted(missing)}")
        if mode == "multi":
            h = s.get("harness", "")
            if h and h not in declared:
                slot_name = s.get("slot", "?")
                print(f'fuzzers.json: slots[{i}] ({slot_name!r}) harness "{h}" not declared in fuzz-config.json')


# ---------------------------------------------------------------------------
# findings.jsonl per-line validation
# ---------------------------------------------------------------------------
def cmd_findings():
    mode = os.environ.get("MODE", "singular")
    declared = _env_set("DECLARED")

    # v0.18 additive fields (verification pipeline + maintainer-facing report).
    # Optional on existing schemas; some will become required at the next
    # schema-version bump (WS-G).
    V018_OPTIONAL = {
        "poc_kind", "poc_path",
        "cvss_v3_1", "cwe_id",
        "principles_audit", "verification",
        "disclosure_state",
        "weaponization",
    }

    if mode == "singular":
        expected_schema = "finding/v1"
        required = {"schema", "id", "stack_hash", "category", "location", "exploitability", "root_cause", "reproducer", "first_seen", "last_seen", "dedup_count"}
        allowed = required | {"subcategory", "sanitizer_report_excerpt", "verified_against_build", "status", "stale_against_build"} | V018_OPTIONAL
    else:
        expected_schema = "finding/v2"
        required = {"schema", "id", "stack_hash", "category", "location", "exploitability", "root_cause", "reproducer", "first_seen", "last_seen", "dedup_count", "harnesses"}
        allowed = required | {"subcategory", "sanitizer_report_excerpt", "verified_against_build", "status", "stale_against_build"} | V018_OPTIONAL

    allowed_categories = {"heap-buffer-overflow", "heap-use-after-free", "stack-buffer-overflow", "global-buffer-overflow", "stack-overflow", "null-deref", "assertion-failure", "oom", "timeout", "flaky", "harness-artifact"}
    allowed_exploitability = {"likely", "medium", "unlikely", "harness-artifact"}
    ID_RE = re.compile(r"^f[0-9]{3,}$")

    seen_hashes = {}
    seen_ids = set()

    with open(os.environ["FINDINGS"]) as f:
        for ln, line in enumerate(f, 1):
            line = line.strip()
            if not line:
                continue
            try:
                d = json.loads(line)
            except Exception as e:
                print(f"findings.jsonl line {ln}: parse error: {e}")
                continue
            if d.get("schema") != expected_schema:
                print(f"findings.jsonl line {ln}: wrong schema '{d.get('schema')}' (expected {expected_schema})")
                continue
            keys = set(d.keys())
            missing = required - keys
            unrec = keys - allowed
            if missing:
                print(f"findings.jsonl line {ln}: missing fields {sorted(missing)}")
            if unrec:
                print(f"findings.jsonl line {ln}: unrecognized fields {sorted(unrec)}")

            fid = d.get("id", "")
            if fid and not ID_RE.match(fid):
                print(f"findings.jsonl line {ln}: invalid id format '{fid}' (must match ^f[0-9]{{3,}}$)")
            if fid in seen_ids:
                print(f"findings.jsonl line {ln}: duplicate id '{fid}'")
            seen_ids.add(fid)

            cat = d.get("category", "")
            if cat and cat not in allowed_categories and not cat.startswith("ubsan-"):
                print(f"findings.jsonl line {ln}: invalid category '{cat}'")

            expl = d.get("exploitability", "")
            if expl and expl not in allowed_exploitability:
                print(f"findings.jsonl line {ln}: invalid exploitability '{expl}'")

            sh = d.get("stack_hash", "")
            if sh:
                if sh in seen_hashes and seen_hashes[sh] != fid:
                    print(f"findings.jsonl line {ln}: stack_hash '{sh}' already used by {seen_hashes[sh]} (use findings.sh dedup)")
                seen_hashes[sh] = fid

            rep = d.get("reproducer", "")
            status = d.get("status", "")
            if rep and fid:
                if status == "stale":
                    expected = f"fuzz/crashes/stale/{fid}/repro.bin"
                else:
                    expected = f"fuzz/crashes/known/{fid}/repro.bin"
                if rep != expected:
                    print(f"findings.jsonl line {ln}: reproducer '{rep}' should be '{expected}'")
            if rep and not os.path.isfile(rep):
                print(f"findings.jsonl line {ln}: reproducer file does not exist: {rep}")

            if mode == "multi":
                hs = d.get("harnesses")
                if not isinstance(hs, list) or not hs:
                    print(f"findings.jsonl line {ln}: harnesses[] is empty (multi mode requires >=1 source harness)")
                else:
                    for h in hs:
                        if h not in declared:
                            print(f"findings.jsonl line {ln}: harnesses[] contains undeclared harness '{h}'")


# ---------------------------------------------------------------------------
# harness-corrections.jsonl (v0.18 triager -> harness-writer feedback)
# ---------------------------------------------------------------------------
def cmd_jsonl_corrections():
    required = {"schema", "ts", "finding_id", "stack_hash", "principle", "suggested_fix"}
    principles = {"harness_correctness", "api_contract", "public_api_reachability", "entry_point_currency"}
    with open(os.environ["HCS"]) as f:
        for ln, line in enumerate(f, 1):
            line = line.strip()
            if not line:
                continue
            try:
                d = json.loads(line)
            except Exception as e:
                print(f"harness-corrections.jsonl line {ln}: parse error: {e}")
                continue
            if d.get("schema") != "harness-correction/v1":
                print(f"harness-corrections.jsonl line {ln}: wrong schema '{d.get('schema')}'")
                continue
            missing = required - set(d.keys())
            if missing:
                print(f"harness-corrections.jsonl line {ln}: missing {sorted(missing)}")
            if d.get("principle") not in principles:
                print(f"harness-corrections.jsonl line {ln}: invalid principle '{d.get('principle')}'")


# ---------------------------------------------------------------------------
# dropped_crashes.jsonl (v0.18 transparency log)
# ---------------------------------------------------------------------------
def cmd_jsonl_dropped():
    required = {"schema", "ts", "crash_file", "stage", "reason"}
    stages = {"artifact_filter", "deterministic_replay", "target_realistic_reproducer"}
    principles = {None, "", "harness_correctness", "api_contract", "public_api_reachability", "entry_point_currency"}
    with open(os.environ["DROPS"]) as f:
        for ln, line in enumerate(f, 1):
            line = line.strip()
            if not line:
                continue
            try:
                d = json.loads(line)
            except Exception as e:
                print(f"dropped_crashes.jsonl line {ln}: parse error: {e}")
                continue
            if d.get("schema") != "dropped-crash/v1":
                print(f"dropped_crashes.jsonl line {ln}: wrong schema '{d.get('schema')}' (expected dropped-crash/v1)")
                continue
            missing = required - set(d.keys())
            if missing:
                print(f"dropped_crashes.jsonl line {ln}: missing fields {sorted(missing)}")
            if d.get("stage") not in stages:
                print(f"dropped_crashes.jsonl line {ln}: invalid stage '{d.get('stage')}'")
            if d.get("stage") == "artifact_filter":
                if d.get("principle") not in (principles - {None, ""}):
                    print(f"dropped_crashes.jsonl line {ln}: artifact_filter requires a valid principle (got {d.get('principle')!r})")
            else:
                if d.get("principle") not in (None, "", "null") and d.get("principle") not in principles:
                    print(f"dropped_crashes.jsonl line {ln}: principle field present but invalid for stage '{d.get('stage')}'")


# ---------------------------------------------------------------------------
# events.jsonl lightweight check
# ---------------------------------------------------------------------------
def cmd_jsonl_events():
    required_base = {"schema", "ts", "tick", "event"}
    with open(os.environ["EVENTS"]) as f:
        for ln, line in enumerate(f, 1):
            line = line.strip()
            if not line:
                continue
            try:
                d = json.loads(line)
            except Exception as e:
                print(f"events.jsonl line {ln}: parse error: {e}")
                continue
            if d.get("schema") != "event/v1":
                print(f"events.jsonl line {ln}: wrong schema")
                continue
            missing = required_base - set(d.keys())
            if missing:
                print(f"events.jsonl line {ln}: missing {sorted(missing)}")


# ---------------------------------------------------------------------------
# multi-mode snapshot filename/harness-field consistency
# ---------------------------------------------------------------------------
def cmd_snapshot_multi():
    declared = _env_set("DECLARED")
    patterns = [
        ("coverage", re.compile(r"^coverage-([a-z0-9][a-z0-9_-]{0,31})-(\d+)\.json$")),
        ("gaps", re.compile(r"^gaps-([a-z0-9][a-z0-9_-]{0,31})-(\d+)\.json$")),
        ("concolic", re.compile(r"^concolic-([a-z0-9][a-z0-9_-]{0,31})-(\d+)\.json$")),
    ]
    singular_re = re.compile(r"^(coverage|gaps|concolic)-\d+\.json$")
    for path in sorted(glob.glob(os.path.join(os.environ["SNAPS_DIR"], "*.json"))):
        base = os.path.basename(path)
        if base.startswith("plan-") or base.startswith("delta-"):
            continue
        matched = False
        for kind, pat in patterns:
            m = pat.match(base)
            if not m:
                continue
            matched = True
            harness = m.group(1)
            if harness not in declared:
                print(f'snapshots/{base}: filename prefix references undeclared harness "{harness}"')
                break
            try:
                d = json.load(open(path))
            except Exception:
                break
            h_field = d.get("harness")
            if h_field is None:
                print(f'snapshots/{base}: multi-mode snapshot must carry top-level "harness" field')
            elif h_field != harness:
                print(f'snapshots/{base}: harness field "{h_field}" disagrees with filename prefix "{harness}"')
            break
        if not matched and singular_re.match(base):
            print(f"snapshots/{base}: singular-mode filename in multi mode (the upgrade should have renamed it to include a harness prefix)")


# ---------------------------------------------------------------------------
# multi-mode harness binary executability
# ---------------------------------------------------------------------------
def cmd_harness_bins():
    try:
        doc = json.load(open(os.environ["HS_PATH"]))
    except Exception:
        return
    for h in doc.get("harnesses", []):
        name = h.get("name", "?")
        b = h.get("harness_binary", "")
        if b and not (os.path.isfile(b) and os.access(b, os.X_OK)):
            print(f'harness "{name}" binary not executable: {b}')


DISPATCH = {
    "config-harness-names": cmd_config_harness_names,
    "validate-json": cmd_validate_json,
    "harnesses-mirror": cmd_harnesses_mirror,
    "slots": cmd_slots,
    "fuzzers-manifest": cmd_fuzzers_manifest,
    "findings": cmd_findings,
    "jsonl-corrections": cmd_jsonl_corrections,
    "jsonl-dropped": cmd_jsonl_dropped,
    "jsonl-events": cmd_jsonl_events,
    "snapshot-multi": cmd_snapshot_multi,
    "harness-bins": cmd_harness_bins,
}


def main(argv):
    if not argv:
        print("usage: state_checks.py <subcommand> [args]", file=sys.stderr)
        return 2
    sub = argv[0]
    rest = argv[1:]
    if sub == "field":
        cmd_field(rest)
        return 0
    if sub == "hash-check":
        cmd_hash_check(rest)
        return 0
    fn = DISPATCH.get(sub)
    if fn is None:
        print(f"unknown subcommand: {sub}", file=sys.stderr)
        return 2
    fn()
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
