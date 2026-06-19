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
                            BUILD_HASH NOW HARNESS   -> one finding/v2 line
  dedup                FINDINGS STACK_HASH NOW HARNESS_APPEND -> rewritten file
  add-harness          FINDINGS APPEND_ID APPEND_HARNESS      -> rewritten file
  stale-mark           FINDINGS ID CURRENT_BUILD              -> rewritten file
  drop-record          TS CRASH STAGE REASON HASH PRINCIPLE EVIDENCE -> one record line
  field-stdin   <key>  read one JSON line from stdin -> .get(key,'')
  dedup-info           read one JSON line from stdin -> "<id> <dedup_count>"
  import-cr            FINDINGS SNAPSHOT NOW NEXT_NUM HARNESS
                       -> source:code_review candidate lines (dedup on cr_ref)
"""
import json
import os
import sys
from pathlib import Path

# SSOT for all state enums. Same sibling-import pattern as cve-context-builder.py.
sys.path.insert(0, str(Path(__file__).resolve().parent))
import enums  # type: ignore  # noqa: E402


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
    d = {
        "schema": "finding/v2",
        "id": os.environ["NEW_ID"],
        # v0.30 (schema v12): every new entry lands as a CANDIDATE. Only
        # `findings.sh --promote` flips it to "finding" after the poc-builder
        # passes the 3-point realism gate (driver + verifier against real
        # target + boundary/precondition/projected_vs_demonstrated). This
        # field is REQUIRED on every entry in schema v12 — readers that don't
        # understand it should treat any missing value as `candidate`.
        "status": "candidate",
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
    # finding/v2 requires a non-empty harnesses[] (multi is the only mode).
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
def cmd_promote():
    """Flip an existing candidate to status=finding, attaching the
    realism_attestation block built by findings.sh from the operator's flags
    or env. The attestation is REQUIRED (schema v12); findings.sh refuses to
    call this subcommand without all the gate fields.

    Env:
      FINDINGS                 - path to findings.jsonl
      PROMOTE_ID               - finding id (e.g. f005)
      ATTEST_DRIVER            - path to mechanical reproducer (fuzzer driver)
      ATTEST_VERIFIER          - path to the CLI-style verify-*.sh
      ATTEST_BOUNDARY          - boundary crossed (string)
      ATTEST_PRECONDITION      - attacker precondition (string)
      ATTEST_PROJECTED         - projected_vs_demonstrated narrative (string)
      ATTEST_VERIFIER_LINES    - soft line count from the verifier (int as str)
      ATTEST_VERIFIER_TOOLS    - soft distinct-binary count from the verifier (int as str)
      NOW                      - ISO 8601 timestamp for promoted_at
    """
    target = os.environ["PROMOTE_ID"]
    now = os.environ["NOW"]
    attestation = {
        "driver": os.environ["ATTEST_DRIVER"],
        "verifier": os.environ["ATTEST_VERIFIER"],
        "boundary": os.environ["ATTEST_BOUNDARY"],
        "precondition": os.environ["ATTEST_PRECONDITION"],
        "projected_vs_demonstrated": os.environ["ATTEST_PROJECTED"],
        "verifier_lines": int(os.environ.get("ATTEST_VERIFIER_LINES") or 0),
        "verifier_tools": int(os.environ.get("ATTEST_VERIFIER_TOOLS") or 0),
        "promoted_at": now,
    }
    found = False
    for line in _iter_lines(os.environ["FINDINGS"]):
        if not line:
            continue
        try:
            d = json.loads(line)
        except Exception:
            print(line)
            continue
        if d.get("id") == target:
            d["status"] = "finding"
            d["realism_attestation"] = attestation
            d["last_seen"] = now
            found = True
        print(_compact(d))
    sys.stderr.write("promoted\n" if found else "not_found\n")


def cmd_list_candidates():
    """Print one line per entry currently in candidate status.

    Output: <id>\t<category>\t<location>\t<first_seen>
    """
    for line in _iter_lines(os.environ["FINDINGS"]):
        if not line:
            continue
        try:
            d = json.loads(line)
        except Exception:
            continue
        # schema v12: every entry has `status` set explicitly by build-finding.
        status = d.get("status")
        if status == "candidate":
            print(
                "{id}\t{category}\t{location}\t{first_seen}".format(
                    id=d.get("id", ""),
                    category=d.get("category", ""),
                    location=d.get("location", ""),
                    first_seen=d.get("first_seen", ""),
                )
            )


# ---------------------------------------------------------------------------
def _cr_to_category(pattern):
    """Map a code-review/v1 `pattern` to a findings.jsonl `category`.

    Thin shim over enums.cr_to_category — the CR_TO_CATEGORY map is the SSOT's,
    so the cr-pattern vocabulary and the category enum can never drift apart.
    Unrecognized patterns fall back to `logic-error`.
    """
    return enums.cr_to_category(pattern)


def cmd_import_cr(argv):
    """Ingest high/medium-confidence code-review/v1 findings into findings.jsonl
    as source:code_review candidates, deduping on cr_ref (the cr_hash).

    Env:
      FINDINGS     - path to findings.jsonl
      SNAPSHOT     - path to a code-review-<ts>.json snapshot
      HARNESS      - harness name for the harnesses[] entry
      NOW          - ISO 8601 timestamp
      NEXT_NUM     - the next free f<NNN> number (int as str) the caller computed

    Reads the snapshot, selects findings with confidence in {high, medium},
    skips any whose cr_hash already appears as a cr_ref in findings.jsonl, and
    APPENDS one candidate line per new cr finding to stdout (the caller >> 's
    them onto findings.jsonl). Prints a one-line summary to stderr.
    """
    findings_path = os.environ["FINDINGS"]
    snapshot_path = os.environ["SNAPSHOT"]
    harness = os.environ.get("HARNESS", "")
    now = os.environ["NOW"]
    next_num = int(os.environ.get("NEXT_NUM") or 1)

    # Existing cr_refs already in the ledger — dedup key.
    existing_refs = set()
    try:
        for line in _iter_lines(findings_path):
            if not line:
                continue
            try:
                d = json.loads(line)
            except Exception:
                continue
            ref = d.get("cr_ref")
            if ref:
                existing_refs.add(ref)
    except FileNotFoundError:
        pass

    try:
        with open(snapshot_path) as f:
            snap = json.load(f)
    except Exception as e:
        sys.stderr.write("import-cr: cannot read snapshot %s: %s\n" % (snapshot_path, e))
        return

    imported = 0
    skipped = 0
    # Import high/medium-confidence findings. needs_deep_pass is a SEPARATE
    # boolean flag now (not a confidence value), so a high/medium finding that
    # also carries needs_deep_pass=true still imports here — the flag only tells
    # the deep pass what to investigate, it does not gate importability.
    _importable_conf = {"high", "medium"} & enums.CONFIDENCE
    for cr in snap.get("findings") or []:
        if cr.get("confidence") not in _importable_conf:
            continue
        cr_hash = cr.get("cr_hash")
        if not cr_hash:
            skipped += 1
            continue
        if cr_hash in existing_refs:
            skipped += 1
            continue
        existing_refs.add(cr_hash)

        line_range = cr.get("line_range") or []
        loc_line = line_range[0] if line_range else "?"
        location = "{fn}@{file}:{ln}".format(
            fn=cr.get("function", "?"),
            file=cr.get("file", "?"),
            ln=loc_line,
        )
        evidence = cr.get("evidence", "")
        root_cause = "[code-review {pat}] {ev}".format(
            pat=cr.get("pattern", "?"), ev=evidence
        ).strip()

        new_id = "f%03d" % next_num
        next_num += 1
        d = {
            "schema": "finding/v2",
            "id": new_id,
            "status": "candidate",
            "source": "code_review",
            "cr_ref": cr_hash,
            "category": _cr_to_category(cr.get("pattern", "")),
            "location": location,
            "exploitability": "medium",
            "root_cause": root_cause,
            "first_seen": now,
            "last_seen": now,
            "dedup_count": 1,
        }
        # Carry the cr's oracle framing through so poc-builder can shape the
        # verifier around the boundary crossing, not a crash.
        oracle_kind = cr.get("oracle_kind")
        if oracle_kind:
            d["oracle_kind"] = oracle_kind
        if cr.get("trust_boundary_crossed"):
            d["trust_boundary_crossed"] = cr["trust_boundary_crossed"]
        if cr.get("precondition"):
            d["precondition"] = cr["precondition"]
        if evidence:
            d["code_review_evidence"] = evidence
        if harness:
            d["harnesses"] = [harness]
        print(_compact(d))
        imported += 1

    sys.stderr.write("import-cr: imported=%d skipped=%d (snapshot=%s)\n"
                     % (imported, skipped, snapshot_path))


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
    "promote": cmd_promote,
    "list-candidates": cmd_list_candidates,
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
    if sub == "import-cr":
        cmd_import_cr(rest)
        return 0
    fn = DISPATCH.get(sub)
    if fn is None:
        print(f"unknown subcommand: {sub}", file=sys.stderr)
        return 2
    fn()
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
