"""The strict state validator: validate(campaign) -> [Problem].

A port of scripts/validate-state.sh (now a shim onto `cc-fuzzer schema
validate`): the filesystem layout checks, the schema-version gate, per-file
JSON schema validation, content checks (schema/checks.py) and the
cross-reference checks, in the same order and with the same messages, so the
rendered report and exit code are unchanged.

Strictness rules (STATE_SCHEMA.md):
  - every JSON file must carry a `schema` matching a known schema/version
  - every required field must be present
  - unrecognized fields are an ERROR (a WARNING for immutable snapshots)
  - file locations must match STATE_SCHEMA.md exactly

Multi-harness only (schema v12): a campaign with state present MUST declare a
non-empty fuzz-config.json:harnesses[]; there is no singular fallback.
"""
from __future__ import annotations

import fnmatch
import glob
import json
import os
import re
import sys
from dataclasses import asdict, dataclass
from pathlib import Path

from cc_fuzzer_core import enums
from cc_fuzzer_core.paths import Campaign, CampaignError, campaign as _campaign
from cc_fuzzer_core.schema import checks as C
from cc_fuzzer_core.schema import fields as F

ERROR, WARNING, INFO = "error", "warning", "info"

_CRASH_DIR_RE = re.compile(r"^f[0-9]{3,}$")
_NEW_CRASH_RE = re.compile(r"^([a-z0-9][a-z0-9_-]{0,31})__[0-9a-f]{16,64}\.bin$")


@dataclass(frozen=True)
class Problem:
    severity: str   # error | warning | info
    message: str


def _as_campaign(c) -> Campaign:
    """Accept a Campaign, or a state dir (<project>/fuzz/state layout)."""
    if isinstance(c, Campaign):
        return c
    state = Path(os.path.abspath(c))
    return Campaign(state.parent.parent, state.parent, state)


def _sorted_glob(d: Path, pattern: str) -> list[Path]:
    return [Path(p) for p in sorted(glob.glob(os.path.join(glob.escape(str(d)), pattern)))]


class _Collector:
    def __init__(self):
        self.problems: list[Problem] = []

    def add(self, sev, msg):
        self.problems.append(Problem(sev, msg))

    def err(self, msg):
        self.add(ERROR, msg)

    def warn(self, msg):
        self.add(WARNING, msg)

    def lines(self, sev, lines):
        """Helper output -> one problem per non-empty line (a message that
        contains newlines splits, exactly as `while read -r line` did)."""
        for ln in "\n".join(lines).split("\n"):
            if ln:
                self.add(sev, ln)

    def json_file(self, file: Path, fs: F.FileSchema):
        if not file.is_file():
            self.err(f"missing required file: {file}")
            return
        result = C.validate_file(file, fs)
        if result == "OK":
            return
        if result.startswith("WARN:"):
            self.warn(f"{file}: {result[len('WARN: '):] if result.startswith('WARN: ') else result}")
        else:
            self.err(f"{file}: {result}")


def validate(c) -> list[Problem]:
    """All problems with a campaign's state, in report order within each
    severity. An empty list means valid. `c` is a Campaign or a state dir."""
    c = _as_campaign(c)
    fuzz, state = c.fuzz_root, c.state_dir
    snaps, harnesses_dir, crashes = state / "snapshots", fuzz / "harnesses", fuzz / "crashes"
    out = _Collector()

    # -- declared harnesses (fuzz-config.json harnesses[].name) -------------
    cfg = state / "fuzz-config.json"
    declared: list[str] = []
    if cfg.is_file():
        text = "\n".join(C.config_harness_names(cfg))
        declared = [n for n in text.split("\n") if n]
    names_ok = bool(declared)
    known = set(declared)

    # -- Step 1: filesystem layout -------------------------------------------
    if not fuzz.is_dir():
        return [Problem(INFO, f"no campaign: {fuzz} does not exist")]

    have_state = state.is_dir()
    if have_state:
        for d in (state, snaps, crashes, crashes / "new", crashes / "known", crashes / "flaky"):
            if not d.is_dir():
                out.warn(f"missing required directory: {d} (will be created)")

    if have_state and not names_ok:
        if not cfg.is_file():
            out.err(f"state exists but {cfg} is missing. v0.30 is multi-harness only — run "
                    "'harness-set.sh init --entry <fn>' (or /cc-fuzzer:campaign) to declare a harness set.")
        else:
            out.err("fuzz-config.json declares no harnesses[] (or could not be read). v0.30 is multi-harness "
                    "only; the singular flat layout was retired. Declare a harness set with 'harness-set.sh "
                    "init --entry <fn>', or /fuzz-reset and start fresh.")

    if names_ok:
        if not harnesses_dir.is_dir():
            out.err(f"harnesses[] declared in fuzz-config.json but {harnesses_dir}/ does not exist")
        else:
            for name in declared:
                bundle = harnesses_dir / name
                if not bundle.is_dir():
                    out.warn(f"declared harness '{name}' has no bundle at {bundle} "
                             "(run /cc-fuzzer:campaign or harness-writer to build)")
                for sub in ("harness", "corpus", "coverage"):
                    if not (bundle / sub).is_dir():
                        out.warn(f"missing {bundle}/{sub}/")

    # Retired singular top-level paths must NOT exist.
    for legacy in (fuzz / "harness", fuzz / "corpus"):
        if legacy.is_dir() and not legacy.is_symlink():
            out.err(f"retired singular path {legacy}/ still exists. v0.30 is multi-harness only; per-harness "
                    f"state lives under {harnesses_dir}/<name>/. Remove the stray directory (or /fuzz-reset "
                    "and start fresh).")

    # Forbidden legacy paths (bug-magnets: the triager has been known to write
    # to fuzz/state/crashes/ instead of fuzz/crashes/new/).
    for shown, real in ((str(fuzz / "known-crashes"), fuzz / "known-crashes"),
                        (str(fuzz / "known_crashes"), fuzz / "known_crashes"),
                        (str(state / "crashes"), state / "crashes"),
                        (str(state / "harnesses"), state / "harnesses"),
                        ("out/default/crashes", c.project_root / "out" / "default" / "crashes")):
        if real.is_dir():
            out.err(f"legacy/forbidden path exists: {shown}")

    # Timestamped files must be in snapshots/, not the state root.
    if have_state:
        for pat in ("coverage-*.json", "gaps-*.json", "concolic-*.json"):
            for stray in _sorted_glob(state, pat):
                if stray.is_file():
                    out.err(f"timestamped file in wrong location: {stray} (must be in {snaps}/)")

    # FINDINGS-REPORT-<target>.md is rewritable; warn when none exists.
    if have_state and not _sorted_glob(state, "FINDINGS-REPORT-*.md"):
        out.warn(f"no FINDINGS-REPORT-*.md in {state} (run /cc-fuzzer:report to generate)")

    known_dirs = [p for p in _sorted_glob(crashes / "known", "*") if p.is_dir()] \
        if (crashes / "known").is_dir() else []
    for d in known_dirs:
        if not _CRASH_DIR_RE.match(d.name):
            out.err(f"non-conforming crash directory name: {crashes}/known/{d.name} (must match ^f\\d{{3,}}$)")

    # -- Step 2: schema-version -----------------------------------------------
    sv = state / "schema-version"
    if have_state and not sv.is_file():
        out.err(f"missing {sv}. v0.30 requires schema {F.SCHEMA_VERSION}; older campaigns cannot be migrated. "
                "Start a fresh campaign with /cc-fuzzer:campaign.")
    elif sv.is_file():
        with open(sv, "rb") as f:
            first = f.readline()
        actual = first.decode("utf-8", "replace").replace(" ", "").replace("\n", "")
        if actual != F.SCHEMA_VERSION:
            out.err(f"schema version mismatch: state has '{actual}', plugin requires '{F.SCHEMA_VERSION}'. "
                    f"v0.30 requires schema {F.SCHEMA_VERSION}; older campaigns cannot be migrated. "
                    "Start a fresh campaign with /cc-fuzzer:campaign.")

    # -- Step 3: JSON schema validation ---------------------------------------
    base = c.project_root
    hb = state / "harness-built.json"
    if hb.is_file():
        out.json_file(hb, F.HARNESS_BUILT)
        _harness_built_crosschecks(out, hb, base)

    hs_path = state / "harnesses.json"
    if names_ok:
        if not hs_path.is_file():
            out.err(f"harnesses[] declared but {hs_path} is missing")
        else:
            out.json_file(hs_path, F.HARNESS_SET)
            out.lines(ERROR, C.harnesses_mirror(hs_path, hb, declared))

    cur = state / "current.json"
    if cur.is_file():
        out.json_file(cur, F.CURRENT)
        active = C.field(cur, "active_harness").rstrip("\n")
        if active and active not in known:
            out.err(f"current.json: active_harness '{active}' is not a declared harness")
        rec_h = C.field(cur, "recommendation.harness").rstrip("\n")
        if rec_h and rec_h not in known:
            out.err(f"current.json: recommendation.harness '{rec_h}' is not a declared harness")
        branch = C.field(cur, "recommendation.branch").rstrip("\n")
        if branch and branch not in enums.REC_BRANCHES:
            out.err(f"current.json: invalid recommendation.branch '{branch}'")

    if (state / "budget.json").is_file():
        out.json_file(state / "budget.json", F.BUDGET)

    if cfg.is_file():
        out.json_file(cfg, F.FUZZ_CONFIG)
        out.lines(ERROR, C.slots(cfg, declared))
        out.lines(ERROR, C.features_block(cfg))

    if (state / "fuzzers.json").is_file():
        out.json_file(state / "fuzzers.json", F.FUZZERS)
        out.lines(ERROR, C.fuzzers_manifest(state / "fuzzers.json", declared))

    for fname, fn in (("findings.jsonl", lambda p: C.findings(p, declared, base)),
                      ("harness-corrections.jsonl", C.jsonl_corrections),
                      ("dropped_crashes.jsonl", C.jsonl_dropped),
                      ("events.jsonl", C.jsonl_events)):
        if (state / fname).is_file():
            out.lines(ERROR, fn(state / fname))

    if snaps.is_dir():
        _snapshots(out, snaps, declared)

    # -- Step 4: cross-reference checks ---------------------------------------
    if hs_path.is_file():
        out.lines(WARNING, C.harness_bins(hs_path, base))

    for d in known_dirs:
        if not (d / "repro.bin").is_file():
            out.err(f"missing canonical reproducer: {d}//repro.bin")
        if not (d / "harnesses.txt").is_file():
            out.err(f"missing {d}/harnesses.txt (one harness name per line, must mirror finding.harnesses[])")

    if (crashes / "new").is_dir():
        for f in _sorted_glob(crashes / "new", "*"):
            if not f.is_file():
                continue
            m = _NEW_CRASH_RE.match(f.name)
            if not m:
                out.err(f"crashes/new/{f.name}: multi-mode filename must match <harness>__<hash>.bin")
            elif m.group(1) not in known:
                out.err(f"crashes/new/{f.name}: prefix references undeclared harness '{m.group(1)}'")

    # nix-environment-issues.json (written by nix-env-reconcile.sh): severity
    # error issues are hard errors so the preflight gate catches them here too.
    nix = state / "nix-environment-issues.json"
    if nix.is_file():
        for sev, msg in C.nix_environment_issues(nix):
            first, *_rest = msg.split("\n")  # continuation lines carried no ERR:/WARN: tag
            out.add(ERROR if sev == "error" else WARNING, first)
    return out.problems


def _harness_built_crosschecks(out: _Collector, hb: Path, base: Path):
    """Coverage / cmplog / fuzzing_mode / build-hash checks on harness-built.json."""
    def fld(key, default=""):
        return C.field(hb, key, default).rstrip("\n")

    def executable(p):
        q = C.resolve_path(base, p)
        return q.exists() and os.access(q, os.X_OK)

    if fld("coverage_tracking", "False") == "True":
        cov = fld("coverage_binary")
        if not cov:
            out.err("harness-built.json: coverage_tracking=true but coverage_binary is null/missing")
        elif not executable(cov):
            out.err(f"harness-built.json: coverage_binary not executable: {cov}")
    elif not fld("coverage_disabled_reason"):
        out.warn("harness-built.json: coverage_tracking=false but no coverage_disabled_reason set. "
                 "Rebuild with /cc-fuzzer:campaign --reset to enable coverage.")

    if fld("cmplog_enabled", "False") == "True":
        cmp = fld("cmplog_binary")
        if not cmp:
            out.err("harness-built.json: cmplog_enabled=true but cmplog_binary is null/missing")
        elif not executable(cmp):
            out.warn(f"harness-built.json: cmplog_binary not executable: {cmp} "
                     "(run-fuzzer.sh will continue without -c)")
    elif not fld("cmplog_disabled_reason"):
        out.warn("harness-built.json: cmplog_enabled=false but no cmplog_disabled_reason set.")

    mode = fld("fuzzing_mode")
    if mode == "":
        out.err("harness-built.json: fuzzing_mode missing — rebuild with /cc-fuzzer:campaign --reset")
    elif mode not in F.FUZZING_MODES:
        out.err(f"harness-built.json: invalid fuzzing_mode '{mode}' (expected in_process or process_based)")

    for line in "\n".join(C.hash_check(hb)).split("\n"):
        if line:
            out.err(f"harness-built.json: {line} is not 16-char lowercase hex (placeholder stub?). Rebuild via "
                    "/cc-fuzzer:campaign --reset, or run scripts/write-harness-built.sh to repair.")


def _snapshots(out: _Collector, snaps: Path, declared: list[str]):
    """Snapshot files are immutable historical artifacts: validated leniently
    (unknown fields warn), plus the per-finding code-review check and the
    filename-prefix <-> harness-field consistency check."""
    for pattern, fs in F.SNAPSHOTS:
        for f in _sorted_glob(snaps, pattern):
            if f.is_file():
                out.json_file(f, fs)
    for f in _sorted_glob(snaps, "code-review-*.json"):
        if fnmatch.fnmatchcase(f.name, "code-review-prescan-*.json"):
            continue
        window = fnmatch.fnmatchcase(f.name, F.CODE_REVIEW_WINDOW_GLOB)
        if not window and not f.is_file():
            continue
        out.json_file(f, F.CODE_REVIEW_WINDOW if window else F.CODE_REVIEW)
        out.lines(ERROR, C.code_review(f))
    out.lines(ERROR, C.snapshot_multi(snaps, declared))


# ---------------------------------------------------------------------------
# report rendering (validate-state.sh's output)
# ---------------------------------------------------------------------------

def render(problems: list[Problem]) -> tuple[str, int]:
    """(report text, exit code) exactly as validate-state.sh printed them."""
    infos = [p.message for p in problems if p.severity == INFO]
    if infos:
        return "".join(f"{m}\n" for m in infos) + "ok\n", 0
    warnings = [p.message for p in problems if p.severity == WARNING]
    errors = [p.message for p in problems if p.severity == ERROR]
    lines = []
    if warnings:
        lines.append(f"WARNINGS ({len(warnings)}):")
        lines += [f"  {w}" for w in warnings]
    if errors:
        lines += ["", f"ERRORS ({len(errors)}):"]
        lines += [f"  {e}" for e in errors]
        lines += ["", "FAIL: state validation failed. See errors above.",
                  "  - Run '/fuzz-reset' to wipe state and start over (v0.30 requires schema v12; "
                  "older state cannot be migrated)",
                  "  - Or fix individual issues manually"]
        return "\n".join(lines) + "\n", 1
    lines.append("ok")
    return "\n".join(lines) + "\n", 0


# ---------------------------------------------------------------------------
# CLI: cc-fuzzer schema <verb>
# ---------------------------------------------------------------------------

def _cmd_validate(a):
    try:
        c = _campaign()
    except CampaignError as e:
        sys.stderr.write(f"{e}\n")
        return e.code
    problems = validate(c)
    text, rc = render(problems)
    if a.json:
        print(json.dumps({"ok": rc == 0, "problems": [asdict(p) for p in problems]}, indent=2))
    else:
        sys.stdout.write(text)
    return rc


def _cmd_version(_a):
    print(F.SCHEMA_VERSION)
    return 0


def _cmd_field(a):
    print(C.field(a.file, a.path, a.default))
    return 0


def register_cli(subparsers):
    from cc_fuzzer_core.cli import add_subsystem

    _p, verbs = add_subsystem(subparsers, "schema", "state schema validation (port of validate-state.sh)")
    v = verbs.add_parser("validate", help="validate the campaign's state (exit 1 on errors)")
    v.add_argument("--json", action="store_true", help="machine-readable problems list")
    v.set_defaults(func=_cmd_validate)
    v = verbs.add_parser("version", help="print the supported state schema version")
    v.set_defaults(func=_cmd_version)
    v = verbs.add_parser("field", help="print a dotted field of a JSON file (True/False for booleans)")
    v.add_argument("file")
    v.add_argument("path")
    v.add_argument("default", nargs="?", default="")
    v.set_defaults(func=_cmd_field)
