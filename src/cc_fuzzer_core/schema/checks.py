"""Content-validation primitives (lifted from scripts/_lib/state_checks.py).

One function per former state_checks.py subcommand. Each returns the problem
lines that subcommand printed (the validator turns them into errors/warnings);
inputs are explicit arguments instead of environment variables. Relative
paths inside state files (reproducers, binaries) are resolved against `base`
(the project root) — the old helpers relied on validate-state.sh having cd'd
there.

Messages are byte-identical to the old helpers: they are the contract
validate-state.sh's output (and its goldens) is built from.
"""
from __future__ import annotations

import glob
import json
import os
import re
from pathlib import Path
from typing import Iterable

from cc_fuzzer_core import enums
from cc_fuzzer_core.schema import fields as F

SLUG_RE = re.compile(r"^[a-z0-9][a-z0-9_-]{0,31}$")
_SLOT_RE = re.compile(r"^[a-z0-9-]{1,32}$")
_HEX16 = re.compile(r"^[0-9a-f]{16}$")
_FINDING_ID_RE = re.compile(r"^f[0-9]{3,}$")
_CR_ID_RE = re.compile(r"^cr[0-9]{3,}$")


def _resolve(base, p) -> str:
    """p as the old cwd-relative checks saw it: relative => under base."""
    return p if base is None or os.path.isabs(p) else os.path.join(base, p)


def _load(path):
    with open(path) as f:
        return json.load(f)


# ---------------------------------------------------------------------------
# declared harnesses (fuzz-config.json harnesses[].name)
# ---------------------------------------------------------------------------

def config_harness_names(cfg_path) -> list[str]:
    """Declared harness names in fuzz-config.json order; [] on any problem."""
    try:
        d = _load(cfg_path)
        hs = d.get("harnesses") or []
        out = []
        if isinstance(hs, list):
            for h in hs:
                if isinstance(h, dict) and h.get("name"):
                    out.append(str(h["name"]))
        return out
    except Exception:
        return []


# ---------------------------------------------------------------------------
# the generic JSON schema validator
# ---------------------------------------------------------------------------

def validate_json(file, schema: str, required: Iterable[str], allowed: Iterable[str],
                  lenient: bool = False) -> str:
    """"OK" | "WARN: ..." (lenient unrecognized fields) | an error line."""
    try:
        with open(file) as f:
            d = json.load(f)
    except json.JSONDecodeError as e:
        return f"PARSE_ERROR: {e}"
    except Exception as e:
        return f"READ_ERROR: {e}"

    if not isinstance(d, dict):
        return f"NOT_OBJECT: top-level must be a JSON object, got {type(d).__name__}"

    got = d.get("schema")
    if got != schema:
        return f"WRONG_SCHEMA: expected '{schema}', got '{got}'"

    required = {r for r in required if r}
    allowed = {a for a in allowed if a} | {"schema"}
    actual = set(d.keys())
    missing = required - actual
    unrecognized = actual - allowed
    if missing:
        return f"MISSING_FIELDS: {sorted(missing)}"
    if unrecognized:
        # Lenient: still surfaced, but as a warning so old snapshots don't
        # block the campaign.
        return f"{'WARN: ' if lenient else ''}UNRECOGNIZED_FIELDS: {sorted(unrecognized)}"
    return "OK"


def validate_file(file, fs: F.FileSchema) -> str:
    return validate_json(file, fs.schema, fs.required, fs.allowed, fs.lenient)


# ---------------------------------------------------------------------------
# field readers
# ---------------------------------------------------------------------------

def field(file, dotted: str, default: str = "") -> str:
    """A dotted path into a JSON object, rendered the way the old `field`
    subcommand printed it (Python str: booleans are True/False); the default
    when any key is missing, the value is null, or the file is unreadable."""
    try:
        cur = _load(file)
    except Exception:
        return default
    for key in dotted.split("."):
        if isinstance(cur, dict) and key in cur:
            cur = cur[key]
        else:
            cur = None
            break
    return default if cur is None else str(cur)


def hash_check(file) -> list[str]:
    """'<key>=<val>' for build hashes that are not 16-char lowercase hex."""
    try:
        d = _load(file)
    except Exception as e:
        return [f"parse_error={e}"]
    out = []
    if not isinstance(d, dict):
        return out
    for k in ("target_source_hash", "build_command_hash"):
        v = d.get(k, "")
        s = v or ""
        if not isinstance(s, str):
            break  # the old helper raised here (non-string hash), ending the check
        if not re.match(r"^[0-9a-f]{16}$", s):
            out.append(f"{k}={v}")
    return out


# ---------------------------------------------------------------------------
# harnesses.json structural check + mirror-drift invariant
# ---------------------------------------------------------------------------

def harnesses_mirror(harnesses_path, mirror_path, declared: list[str],
                     required=F.HARNESS_BUILT_REQUIRED_V7, allowed=F.HARNESS_BUILT_ALLOWED_V7,
                     expected_schema=F.HARNESS_BUILT_SCHEMA) -> list[str]:
    out = []
    required = set(required) | {"schema"}
    allowed = set(allowed) | {"schema"}
    try:
        doc = _load(harnesses_path)
    except Exception as e:
        return [f"harnesses.json: parse error: {e}"]
    if not isinstance(doc, dict):
        return out  # validate_json already reported NOT_OBJECT

    hs = doc.get("harnesses") or []
    if not hs:
        return ["harnesses.json: harnesses[] is empty (multi mode requires at least one entry)"]
    if not isinstance(hs, list):
        return ["harnesses.json: harnesses must be a list"]

    seen = set()
    for i, h in enumerate(hs):
        if not isinstance(h, dict):
            out.append(f"harnesses.json: harnesses[{i}] is not an object")
            continue
        if h.get("schema") != expected_schema:
            out.append(f"harnesses.json: harnesses[{i}].schema is '{h.get('schema')}' (expected {expected_schema})")
        name = h.get("name", "")
        if not (isinstance(name or "", str) and SLUG_RE.match(name or "")):
            out.append(f"harnesses.json: harnesses[{i}].name '{name}' invalid (regex ^[a-z0-9][a-z0-9_-]{{0,31}}$)")
        key = name if isinstance(name, (str, int, float, bool, type(None))) else repr(name)
        if key in seen:
            out.append(f"harnesses.json: duplicate harness name '{name}'")
        seen.add(key)
        keys = set(h.keys())
        missing = required - keys
        unrec = keys - allowed
        if missing:
            out.append(f"harnesses.json: harnesses[{i}] ({name!r}) missing fields {sorted(missing)}")
        if unrec:
            out.append(f"harnesses.json: harnesses[{i}] ({name!r}) unrecognized fields {sorted(unrec)}")

    # harnesses.json names must equal fuzz-config.json:harnesses[] names.
    config_names = set(declared)
    hs_names = {h.get("name") for h in hs if isinstance(h, dict) and not isinstance(h.get("name"), (dict, list))}
    extra_in_hs = hs_names - config_names
    missing_in_hs = config_names - hs_names
    if extra_in_hs:
        out.append(f"harnesses.json declares {sorted(extra_in_hs, key=str)} not in fuzz-config.json:harnesses[]")
    if missing_in_hs:
        out.append(f"fuzz-config.json:harnesses[] declares {sorted(missing_in_hs)} not in harnesses.json")

    # Mirror invariant: harness-built.json must equal harnesses[0] field-by-field.
    if os.path.isfile(mirror_path) and hs:
        try:
            mirror = _load(mirror_path)
        except Exception as e:
            out.append(f"harness-built.json: parse error reading mirror: {e}")
        else:
            head = hs[0]
            if isinstance(mirror, dict) and isinstance(head, dict):
                all_keys = set(mirror.keys()) | set(head.keys())
                drift = [k for k in all_keys if mirror.get(k) != head.get(k)]
                if drift:
                    out.append(f"harness-built.json: MIRROR DRIFT vs harnesses.json[0] on fields {sorted(drift)} "
                               "(mirror file is read-only; writes must go to harnesses.json)")
    return out


# ---------------------------------------------------------------------------
# fuzz-config.json: fuzzer_slots[] + harnesses[]
# ---------------------------------------------------------------------------

def slots(cfg_path, declared) -> list[str]:
    declared = set(declared)
    out = []
    try:
        d = _load(cfg_path)
    except Exception:
        return out
    if not isinstance(d, dict):
        return out
    sl = d.get("fuzzer_slots") or []
    if not isinstance(sl, list):
        return ["fuzz-config.json: fuzzer_slots must be a list"]
    seen = set()
    for i, s in enumerate(sl):
        if not isinstance(s, dict):
            out.append(f"fuzz-config.json: fuzzer_slots[{i}] is not an object")
            continue
        name = s.get("slot", "")
        if not (isinstance(name, str) and _SLOT_RE.match(name)):
            out.append(f'fuzz-config.json: fuzzer_slots[{i}].slot "{name}" invalid (regex ^[a-z0-9-]{{1,32}}$)')
        hkey = name if not isinstance(name, (dict, list)) else repr(name)
        if hkey in seen:
            out.append(f'fuzz-config.json: duplicate slot name "{name}"')
        seen.add(hkey)
        engine = s.get("engine", "")
        if engine not in F.SLOT_ENGINES:
            out.append(f'fuzz-config.json: fuzzer_slots[{i}].engine "{engine}" must be libfuzzer or aflpp')
        role = s.get("role")
        if role is not None and role not in F.SLOT_ROLES:
            out.append(f'fuzz-config.json: fuzzer_slots[{i}].role "{role}" must be master, secondary, or null')
        sched = s.get("afl_power_schedule")
        if sched is not None and sched not in F.AFL_POWER_SCHEDULES:
            out.append(f'fuzz-config.json: fuzzer_slots[{i}].afl_power_schedule "{sched}" not a valid AFL++ schedule')
        h = s.get("harness", "")
        if not h:
            out.append(f"fuzz-config.json: fuzzer_slots[{i}] ({name!r}) missing required field harness (multi mode)")
        elif isinstance(h, (dict, list)) or h not in declared:
            out.append(f'fuzz-config.json: fuzzer_slots[{i}] ({name!r}) references undeclared harness "{h}"')

    hs = d.get("harnesses") or []
    if not isinstance(hs, list) or not hs:
        out.append("fuzz-config.json: multi mode requires non-empty harnesses[]")
    else:
        names = set()
        for i, h in enumerate(hs):
            if not isinstance(h, dict):
                out.append(f"fuzz-config.json: harnesses[{i}] is not an object")
                continue
            n = h.get("name", "")
            if not (isinstance(n or "", str) and SLUG_RE.match(n or "")):
                out.append(f'fuzz-config.json: harnesses[{i}].name "{n}" invalid (regex ^[a-z0-9][a-z0-9_-]{{0,31}}$)')
            nkey = n if not isinstance(n, (dict, list)) else repr(n)
            if nkey in names:
                out.append(f'fuzz-config.json: duplicate harness name "{n}"')
            names.add(nkey)
            if not h.get("entry_function"):
                out.append(f"fuzz-config.json: harnesses[{i}] ({n!r}) missing entry_function")
    return out


def features_block(cfg_path) -> list[str]:
    """fuzz-config.json `features` (§9): known flag names, bool values."""
    from cc_fuzzer_core import features
    try:
        d = _load(cfg_path)
    except Exception:
        return []
    return features.block_problems(d.get("features")) if isinstance(d, dict) else []


# ---------------------------------------------------------------------------
# fuzzers.json live manifest
# ---------------------------------------------------------------------------

def fuzzers_manifest(manifest_path, declared) -> list[str]:
    declared = set(declared)
    required = F.FUZZERS_SLOT_REQUIRED | {"harness"}
    out = []
    try:
        d = _load(manifest_path)
    except Exception:
        return out
    if not isinstance(d, dict):
        return out
    sl = d.get("slots") or []
    if not isinstance(sl, list):
        return out
    for i, s in enumerate(sl):
        if not isinstance(s, dict):
            out.append(f"fuzzers.json: slots[{i}] is not an object")
            continue
        missing = required - set(s.keys())
        if missing:
            out.append(f"fuzzers.json: slots[{i}] ({s.get('slot', '?')!r}) missing fields {sorted(missing)}")
        h = s.get("harness", "")
        if h and (isinstance(h, (dict, list)) or h not in declared):
            out.append(f'fuzzers.json: slots[{i}] ({s.get("slot", "?")!r}) harness "{h}" not declared in fuzz-config.json')
    return out


# ---------------------------------------------------------------------------
# jsonl ledgers
# ---------------------------------------------------------------------------

def _jsonl(path):
    """(line_number, parsed | Exception) for every non-blank line; the same
    line numbering as iterating the file in text mode."""
    with open(path) as f:
        for ln, line in enumerate(f, 1):
            line = line.strip()
            if not line:
                continue
            try:
                yield ln, json.loads(line)
            except Exception as e:
                yield ln, e


def _get(d, k, default=None):
    return d.get(k, default) if isinstance(d, dict) else default


def findings(findings_path, declared, base=None) -> list[str]:
    """findings.jsonl per-line validation (finding/v2)."""
    declared = set(declared)
    out = []
    seen_hashes = {}
    seen_ids = set()
    for ln, d in _jsonl(findings_path):
        if isinstance(d, Exception):
            out.append(f"findings.jsonl line {ln}: parse error: {d}")
            continue
        if _get(d, "schema") != F.FINDING_SCHEMA:
            out.append(f"findings.jsonl line {ln}: wrong schema '{_get(d, 'schema')}' (expected {F.FINDING_SCHEMA})")
            continue
        keys = set(d.keys())
        is_cr = d.get("source") == "code_review"
        required = F.FINDING_CR_REQUIRED if is_cr else F.FINDING_CRASH_REQUIRED
        missing = required - keys
        unrec = keys - F.FINDING_ALLOWED
        if missing:
            out.append(f"findings.jsonl line {ln}: missing fields {sorted(missing)}")
        if unrec:
            out.append(f"findings.jsonl line {ln}: unrecognized fields {sorted(unrec)}")

        fid = d.get("id", "")
        fid_s = fid if isinstance(fid, str) else str(fid)
        if fid and not _FINDING_ID_RE.match(fid_s):
            out.append(f"findings.jsonl line {ln}: invalid id format '{fid}' (must match ^f[0-9]{{3,}}$)")
        fkey = fid if not isinstance(fid, (dict, list)) else repr(fid)
        if fkey in seen_ids:
            out.append(f"findings.jsonl line {ln}: duplicate id '{fid}'")
        seen_ids.add(fkey)

        cat = d.get("category", "")
        if cat and cat not in enums.CATEGORIES and not (isinstance(cat, str) and cat.startswith("ubsan-")):
            out.append(f"findings.jsonl line {ln}: invalid category '{cat}'")

        expl = d.get("exploitability", "")
        if expl and (isinstance(expl, (dict, list)) or expl not in enums.EXPLOITABILITY):
            out.append(f"findings.jsonl line {ln}: invalid exploitability '{expl}'")

        sh = d.get("stack_hash", "")
        if sh and not isinstance(sh, (dict, list)):
            if sh in seen_hashes and seen_hashes[sh] != fid:
                out.append(f"findings.jsonl line {ln}: stack_hash '{sh}' already used by {seen_hashes[sh]} (use findings.sh dedup)")
            seen_hashes[sh] = fid

        rep = d.get("reproducer", "")
        status = d.get("status", "")
        # A promoted (status==finding) record MUST carry its promotion receipt.
        if status == "finding" and "realism_attestation" not in keys:
            out.append(f"findings.jsonl line {ln}: status 'finding' requires field 'realism_attestation'")
        if rep and fid:
            if status == "stale":
                expected = f"fuzz/crashes/stale/{fid}/repro.bin"
            else:
                expected = f"fuzz/crashes/known/{fid}/repro.bin"
            if rep != expected:
                out.append(f"findings.jsonl line {ln}: reproducer '{rep}' should be '{expected}'")
        if rep and not (isinstance(rep, str) and os.path.isfile(_resolve(base, rep))):
            out.append(f"findings.jsonl line {ln}: reproducer file does not exist: {rep}")

        hs = d.get("harnesses")
        if not isinstance(hs, list) or not hs:
            out.append(f"findings.jsonl line {ln}: harnesses[] is empty (finding/v2 requires >=1 source harness)")
        else:
            for h in hs:
                if isinstance(h, (dict, list)) or h not in declared:
                    out.append(f"findings.jsonl line {ln}: harnesses[] contains undeclared harness '{h}'")
    return out


def code_review(file) -> list[str]:
    """code-review/v1 per-finding validation (required set + enum membership)."""
    base = os.path.basename(file)
    try:
        doc = _load(file)
    except Exception as e:
        return [f"{base}: parse error: {e}"]
    out = []
    if not isinstance(doc, dict):
        return out

    # Loud-coverage scope fields: present-and-wrong is an error, absent is fine.
    scope = doc.get("scope")
    if isinstance(scope, dict):
        smode = scope.get("mode")
        if smode is not None and (isinstance(smode, (dict, list)) or smode not in enums.CR_REVIEW_MODE):
            out.append(f"{base}: scope.mode '{smode}' invalid (expected one of {sorted(enums.CR_REVIEW_MODE)})")
        for k in ("functions_inventoried", "candidates_reviewed", "not_reviewed"):
            v = scope.get(k)
            if v is not None and not isinstance(v, int):
                out.append(f"{base}: scope.{k} must be an int, got {type(v).__name__}")
        cc = scope.get("coverage_complete")
        if cc is not None and not isinstance(cc, bool):
            out.append(f"{base}: scope.coverage_complete must be a boolean, got {type(cc).__name__}")

    fs = doc.get("findings")
    if fs is None:
        return out
    if not isinstance(fs, list):
        out.append(f"{base}: findings must be a list")
        return out

    def bad(v, members):
        return v is not None and (isinstance(v, (dict, list)) or v not in members)

    for i, f in enumerate(fs):
        if not isinstance(f, dict):
            out.append(f"{base}: findings[{i}] is not an object")
            continue
        missing = F.CR_FINDING_REQUIRED - set(f.keys())
        if missing:
            out.append(f"{base}: findings[{i}] ({f.get('id', '?')!r}) missing fields {sorted(missing)}")
        fid = f.get("id", "")
        if fid and not _CR_ID_RE.match(fid if isinstance(fid, str) else str(fid)):
            out.append(f"{base}: findings[{i}] invalid id '{fid}' (must match ^cr[0-9]{{3,}}$)")
        crh = f.get("cr_hash", "")
        if crh and not _HEX16.match(crh if isinstance(crh, str) else str(crh)):
            out.append(f"{base}: findings[{i}] ({fid!r}) cr_hash '{crh}' is not 16-char lowercase hex")
        status = f.get("status")
        if bad(status, enums.CR_STATUS):
            out.append(f"{base}: findings[{i}] ({fid!r}) invalid status '{status}' (expected one of {sorted(enums.CR_STATUS)})")
        pattern = f.get("pattern")
        if bad(pattern, enums.CR_PATTERN_CLASSES):
            out.append(f"{base}: findings[{i}] ({fid!r}) invalid pattern '{pattern}'")
        conf = f.get("confidence")
        if bad(conf, enums.CONFIDENCE):
            out.append(f"{base}: findings[{i}] ({fid!r}) invalid confidence '{conf}' (expected one of {sorted(enums.CONFIDENCE)})")
        ok = f.get("oracle_kind")
        if bad(ok, enums.ORACLE_KIND):
            out.append(f"{base}: findings[{i}] ({fid!r}) invalid oracle_kind '{ok}' (expected one of {sorted(enums.ORACLE_KIND)})")
        tier = f.get("tier_classified")
        if bad(tier, ("sonnet", "opus")):
            out.append(f"{base}: findings[{i}] ({fid!r}) invalid tier_classified '{tier}' (expected sonnet or opus)")
        ndp = f.get("needs_deep_pass")
        if ndp is not None and not isinstance(ndp, bool):
            out.append(f"{base}: findings[{i}] ({fid!r}) needs_deep_pass must be a boolean, got {type(ndp).__name__}")
    return out


def jsonl_corrections(path) -> list[str]:
    """harness-corrections.jsonl (v0.18 triager -> harness-writer feedback)."""
    out = []
    for ln, d in _jsonl(path):
        if isinstance(d, Exception):
            out.append(f"harness-corrections.jsonl line {ln}: parse error: {d}")
            continue
        if _get(d, "schema") != F.CORRECTION_SCHEMA:
            out.append(f"harness-corrections.jsonl line {ln}: wrong schema '{_get(d, 'schema')}'")
            continue
        missing = F.CORRECTION_REQUIRED - set(d.keys())
        if missing:
            out.append(f"harness-corrections.jsonl line {ln}: missing {sorted(missing)}")
        p = d.get("principle")
        if isinstance(p, (dict, list)) or p not in F.PRINCIPLES:
            out.append(f"harness-corrections.jsonl line {ln}: invalid principle '{p}'")
    return out


def jsonl_dropped(path) -> list[str]:
    """dropped_crashes.jsonl (v0.18 transparency log)."""
    out = []
    for ln, d in _jsonl(path):
        if isinstance(d, Exception):
            out.append(f"dropped_crashes.jsonl line {ln}: parse error: {d}")
            continue
        if _get(d, "schema") != F.DROPPED_SCHEMA:
            out.append(f"dropped_crashes.jsonl line {ln}: wrong schema '{_get(d, 'schema')}' (expected {F.DROPPED_SCHEMA})")
            continue
        missing = F.DROPPED_REQUIRED - set(d.keys())
        if missing:
            out.append(f"dropped_crashes.jsonl line {ln}: missing fields {sorted(missing)}")
        stage = d.get("stage")
        hashable = not isinstance(stage, (dict, list))
        if not hashable or stage not in F.DROPPED_STAGES:
            out.append(f"dropped_crashes.jsonl line {ln}: invalid stage '{stage}'")
        p = d.get("principle")
        p_ok = not isinstance(p, (dict, list)) and p in F.PRINCIPLES
        if stage == "artifact_filter":
            if not p_ok:
                out.append(f"dropped_crashes.jsonl line {ln}: artifact_filter requires a valid principle (got {p!r})")
        elif p not in (None, "", "null") and not p_ok:
            out.append(f"dropped_crashes.jsonl line {ln}: principle field present but invalid for stage '{stage}'")
    return out


def jsonl_events(path) -> list[str]:
    out = []
    for ln, d in _jsonl(path):
        if isinstance(d, Exception):
            out.append(f"events.jsonl line {ln}: parse error: {d}")
            continue
        if _get(d, "schema") != F.EVENT_SCHEMA:
            out.append(f"events.jsonl line {ln}: wrong schema")
            continue
        missing = F.EVENT_REQUIRED - set(d.keys())
        if missing:
            out.append(f"events.jsonl line {ln}: missing {sorted(missing)}")
        if d.get("event") == "agent_call" and "source" in d:
            src = d.get("source")
            if src not in enums.LEDGER_SOURCE:
                out.append(f"events.jsonl line {ln}: agent_call source {src!r} not one of "
                           f"{', '.join(sorted(enums.LEDGER_SOURCE))}")
            elif src in enums.LEDGER_HOST_SOURCES and not d.get("call_id"):
                out.append(f"events.jsonl line {ln}: {src} agent_call without call_id")
    return out


# ---------------------------------------------------------------------------
# snapshots: filename prefix <-> harness field
# ---------------------------------------------------------------------------

_SNAPSHOT_PATTERNS = [
    ("coverage", re.compile(r"^coverage-([a-z0-9][a-z0-9_-]{0,31})-(\d+)\.json$")),
    ("gaps", re.compile(r"^gaps-([a-z0-9][a-z0-9_-]{0,31})-(\d+)\.json$")),
    ("concolic", re.compile(r"^concolic-([a-z0-9][a-z0-9_-]{0,31})-(\d+)\.json$")),
]
# A snapshot without a <harness> prefix is a retired singular-layout name.
_LEGACY_SINGULAR_RE = re.compile(r"^(coverage|gaps|concolic)-\d+\.json$")


def snapshot_multi(snaps_dir, declared) -> list[str]:
    declared = set(declared)
    out = []
    for path in sorted(glob.glob(os.path.join(glob.escape(str(snaps_dir)), "*.json"))):
        base = os.path.basename(path)
        if base.startswith("plan-") or base.startswith("delta-"):
            continue
        matched = False
        for _kind, pat in _SNAPSHOT_PATTERNS:
            m = pat.match(base)
            if not m:
                continue
            matched = True
            harness = m.group(1)
            if harness not in declared:
                out.append(f'snapshots/{base}: filename prefix references undeclared harness "{harness}"')
                break
            try:
                d = _load(path)
            except Exception:
                break
            h_field = _get(d, "harness")
            if h_field is None:
                out.append(f'snapshots/{base}: multi-mode snapshot must carry top-level "harness" field')
            elif h_field != harness:
                out.append(f'snapshots/{base}: harness field "{h_field}" disagrees with filename prefix "{harness}"')
            break
        if not matched and _LEGACY_SINGULAR_RE.match(base):
            out.append(f"snapshots/{base}: retired singular-layout snapshot name (no <harness> prefix). "
                       "v0.30 is multi-harness only; remove the stray file or rename it with a harness prefix.")
    return out


def harness_bins(harnesses_path, base=None) -> list[str]:
    """Declared harness binaries that are not executable (warnings)."""
    try:
        doc = _load(harnesses_path)
    except Exception:
        return []
    out = []
    hs = doc.get("harnesses", []) if isinstance(doc, dict) else []
    for h in hs if isinstance(hs, list) else []:
        if not isinstance(h, dict):
            continue
        name = h.get("name", "?")
        b = h.get("harness_binary", "")
        if b and not (isinstance(b, str) and os.path.isfile(_resolve(base, b))
                      and os.access(_resolve(base, b), os.X_OK)):
            out.append(f'harness "{name}" binary not executable: {b}')
    return out


def nix_environment_issues(path) -> list[tuple[str, str]]:
    """(severity, message) per nix-environment-issues.json issue:
    severity "error" => error, anything else => warning."""
    try:
        doc = _load(path)
    except Exception:
        return []
    out = []
    issues = (doc.get("issues") if isinstance(doc, dict) else None) or []
    for iss in issues if isinstance(issues, list) else []:
        if not isinstance(iss, dict):
            continue
        sev = iss.get("severity", "warning")
        rem = iss.get("remediation") or {}
        hint = rem.get("human_message", "") if isinstance(rem, dict) else ""
        msg = f"nix-environment ({iss.get('code', '?')}): {iss.get('summary', '')}"
        if hint:
            msg += f" — {hint}"
        out.append(("error" if sev == "error" else "warning", msg))
    return out


def resolve_path(base, p) -> Path:
    return Path(_resolve(None if base is None else str(base), p))
