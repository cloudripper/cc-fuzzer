"""The findings ledger (UPDATE_ROADMAP.md §2 row 8): findings.sh's subcommands
plus _lib/findings_ops.py's JSONL transforms.

findings.jsonl (finding/v2, one compact JSON object per line) has ONE writer:
this module (findings.sh is a shim onto `cc-fuzzer findings`). New entries are
appended; existing ones are only rewritten whole-file through .tmp + rename.

    count(c) / lines(c) / find_by_hash(c, h)       readers
    add(c, stack_hash, category, ...) -> AddResult  two-stage reproducer check
                                                    (harness binary, then the
                                                    standalone verify binary),
                                                    then append a candidate
    dedup(c, h) / add_harness(c, id, harness)       in-place dedup_count/harnesses[]
    verify(c, id=None) -> [(id, status)]            re-verify after a rebuild
    stale_mark(c, id) / remove(c, id)               backup-safe moves (fuzz/.trash/)
    list_candidates(c)                              status=candidate entries
    promote(c, id, driver=..., ...) -> PromoteResult
                                                    the realism gate: the ONLY way
                                                    an entry becomes status=finding
    drop(c, crash_file, stage, reason, ...)         dropped_crashes.jsonl record
    import_cr(c, snapshot=None)                     code-review candidates in

Errors raise FindingsError(message, code) with findings.sh's messages and exit
codes. Progress / warning lines go to `log` (a callable taking one line; the
CLI passes stderr). Ledger lines are matched on the raw text, whitespace
tolerant ("key": "value" or "key":"value"), as findings.sh's greps did; the
value is matched literally.

Paths given by the caller (reproducers, drivers, crash files, snapshots)
resolve against the project root; messages show them as given.
"""
from __future__ import annotations

import fnmatch
import hashlib
import json
import os
import re
import shutil
import subprocess
import sys
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable

from cc_fuzzer_core import enums
from cc_fuzzer_core.paths import Campaign, CampaignError, HarnessLayout, campaign as _campaign, state_dir_text

LEDGER = "findings.jsonl"
DROPS = "dropped_crashes.jsonl"
DEDUP_THRESHOLD = 5
VERIFY_ATTEMPTS = 3
VERIFY_TIMEOUT_S = 30
# Sanitizer settings for every reproducer run (stage 2 of `verify` omits
# detect_leaks, as before).
ASAN_OPTIONS = "symbolize=1:abort_on_error=1:halt_on_error=1:print_stacktrace=1:detect_leaks=1"
ASAN_OPTIONS_NO_LEAKS = "symbolize=1:abort_on_error=1:halt_on_error=1:print_stacktrace=1"
UBSAN_OPTIONS = "halt_on_error=1:print_stacktrace=1:abort_on_error=1"
DROP_STAGES = ("artifact_filter", "deterministic_replay", "target_realistic_reproducer")
DROP_PRINCIPLES = ("harness_correctness", "api_contract", "public_api_reachability", "entry_point_currency")
VERIFIER_SOFT_MAX_LINES = 200
VERIFIER_SOFT_MAX_TOOLS = 6

# A harness run crashed: any of these in its combined output (or rc >= 128).
# libFuzzer's own handlers report a SIGABRT/SIGSEGV as "deadly signal" with
# exit 1; a trap-based oracle prints CCFUZZ_ORACLE_VIOLATION with no SUMMARY;
# UBSan's integer suite prints "runtime error:".
_CRASH_RE = re.compile(
    r"SUMMARY: (AddressSanitizer|UndefinedBehaviorSanitizer|LeakSanitizer|ThreadSanitizer|"
    r"MemorySanitizer|libFuzzer:)|ERROR: libFuzzer:|CCFUZZ_ORACLE_VIOLATION|runtime error:")
_FINDING_V2_RE = re.compile(r'"schema"[ \t\n\r\f\v]*:[ \t\n\r\f\v]*"finding/v2"')
_ID_NUM_RE = re.compile(r'"id"[ \t\n\r\f\v]*:[ \t\n\r\f\v]*"f([0-9]+)"')
_HASH_RE = re.compile(r"[0-9a-fA-F]{12,64}")
# Command-like tokens in a verifier: line start or after | ; & $( .
_TOOL_TOKEN_RE = re.compile(r"(^|[|;&]|\$\()[ \t\n\r\f\v]*[A-Za-z_][A-Za-z0-9_.-]*")
_SHELL_WORDS = frozenset(
    "if then else elif fi for while do done case esac in set local export function return "
    "true false exit echo test cd trap read shift break continue".split())

Log = Callable[[str], None]


class FindingsError(RuntimeError):
    """str(e) is the (possibly multi-line) message, `code` the exit status."""

    def __init__(self, message: str, code: int = 1):
        super().__init__(message)
        self.code = code


def _nolog(_line: str) -> None:
    pass


# ---------------------------------------------------------------------------
# Ledger primitives
# ---------------------------------------------------------------------------

def ledger_path(c: Campaign) -> Path:
    return c.state_dir / LEDGER


def ensure_ledger(c: Campaign) -> Path:
    """`mkdir -p $STATE_DIR; touch findings.jsonl` (every subcommand does it)."""
    c.state_dir.mkdir(parents=True, exist_ok=True)
    p = ledger_path(c)
    if not p.exists():
        p.touch()
    return p


def _read(c: Campaign) -> str:
    try:
        return ledger_path(c).read_text(encoding="utf-8", errors="surrogateescape")
    except OSError:
        return ""


def _raw_lines(text: str) -> list[str]:
    """The file's lines without their terminators (grep's view)."""
    lines = text.split("\n")
    if lines and lines[-1] == "":
        lines.pop()
    return lines


def _field_re(key: str, value: str) -> re.Pattern:
    return re.compile(rf'"{key}"[ \t\n\r\f\v]*:[ \t\n\r\f\v]*"{re.escape(value)}"')


def _matching(c: Campaign, key: str, value: str) -> list[str]:
    pat = _field_re(key, value)
    return [ln for ln in _raw_lines(_read(c)) if pat.search(ln)]


def _compact(d) -> str:
    return json.dumps(d, separators=(",", ":"))


def _rewrite(c: Campaign, fn) -> str:
    """findings_ops.py's rewrite loop: every non-blank line, stripped; JSON
    objects are passed to fn(d) (which may mutate) and re-emitted compact,
    anything else is kept verbatim. Returns the new text (not yet written)."""
    out = []
    for line in _read(c).split("\n"):
        line = line.strip()
        if not line:
            continue
        try:
            d = json.loads(line)
        except Exception:
            out.append(line)
            continue
        if isinstance(d, dict):
            fn(d)
        out.append(_compact(d))
    return "".join(ln + "\n" for ln in out)


def _replace(c: Campaign, text: str, *, empty_error: str | None = None) -> None:
    """Atomic .tmp + rename. With empty_error, an empty result aborts instead."""
    p = ledger_path(c)
    tmp = p.with_name(p.name + ".tmp")
    tmp.write_text(text, encoding="utf-8", errors="surrogateescape")
    if empty_error is not None and not text:
        tmp.unlink()
        raise FindingsError(empty_error, 1)
    os.replace(tmp, p)


def _iter_records(c: Campaign):
    for line in _read(c).split("\n"):
        line = line.strip()
        if not line:
            continue
        try:
            d = json.loads(line)
        except Exception:
            continue
        if isinstance(d, dict):
            yield d


def _next_num(c: Campaign) -> int:
    nums = [int(m) for m in _ID_NUM_RE.findall(_read(c))]
    return (max(nums) if nums else 0) + 1


def _now_iso() -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())


def _trash_ts() -> str:
    return time.strftime("%Y%m%dT%H%M%SZ", time.gmtime())


def _io(c: Campaign, p) -> str:
    p = os.fspath(p)
    return p if os.path.isabs(p) else str(c.project_root / p)


def _field_text(v) -> str:
    """A value as the old helpers printed it (Python str; "" for null)."""
    if v is None:
        return ""
    if isinstance(v, (list, dict)):
        return json.dumps(v)
    return str(v)


def _mirror_field(c: Campaign, key: str) -> str:
    """harness-built.json:<key> the way `state_checks.py field` printed it."""
    try:
        d = json.loads((c.state_dir / "harness-built.json").read_text())
    except Exception:
        return ""
    v = d.get(key) if isinstance(d, dict) else None
    return "" if v is None else str(v)


def _stdin_field(text: str, key: str) -> str:
    """`findings_ops.py field-stdin <key>` on `text`: str(value) ("None" for
    null), "" when absent or when text isn't one JSON object."""
    try:
        v = json.loads(text).get(key, "")
    except Exception:
        return ""
    return str(v)


def _executable(c: Campaign, p: str) -> bool:
    return bool(p) and os.access(_io(c, p), os.X_OK)


def _bash_int(s) -> int | None:
    m = re.fullmatch(r"[ \t\n]*([-+]?[0-9]+)[ \t\n]*", str(s))
    return int(m.group(1)) if m else None


def harness_context(c: Campaign, harness: str | None = None) -> str:
    """The harness a new/deduped entry is attributed to: the given one, else
    the first declared harness (finding/v2 requires a non-empty harnesses[])."""
    return harness or HarnessLayout(c.fuzz_root, c.state_dir).default_harness()


def _harness_field(c: Campaign, harness: str, key: str) -> str:
    v = _field_text(HarnessLayout(c.fuzz_root, c.state_dir).harness_field(harness, key))
    return "" if v == "None" else v


def _write_harnesses_txt(c: Campaign, fid: str) -> None:
    """crashes/known/<id>/harnesses.txt := the entry's harnesses[], sorted
    and unique, one per line (only when that directory exists)."""
    d = c.crashes_dir / "known" / fid
    if not d.is_dir():
        return
    names: list = []
    for rec in _iter_records(c):
        if rec.get("id") == fid:
            names = sorted(set(rec.get("harnesses") or []))
            break
    text = "\n".join(str(n) for n in names).rstrip("\n")
    if text:
        tmp = d / "harnesses.txt.tmp"
        tmp.write_text(text + "\n")
        os.replace(tmp, d / "harnesses.txt")


# ---------------------------------------------------------------------------
# Reproducer runs
# ---------------------------------------------------------------------------

def crashed(rc: int, output: str) -> bool:
    """Did a harness run crash? rc >= 128 (killed by a signal) or a crash
    marker in its combined output (see _CRASH_RE)."""
    return rc >= 128 or bool(_CRASH_RE.search(output))


def run_reproducer(c: Campaign, binary: str, reproducer: str, *, leaks: bool = True,
                   timeout: float = VERIFY_TIMEOUT_S) -> tuple[int, str]:
    """Run `binary reproducer` from the project root under the strict
    sanitizer settings, like `timeout 30 bin repro 2>&1`: returns (rc, combined
    output without trailing newlines). rc is 124 on timeout, 128+N when killed
    by signal N. stdin is /dev/null."""
    env = dict(os.environ, ASAN_OPTIONS=ASAN_OPTIONS if leaks else ASAN_OPTIONS_NO_LEAKS,
               UBSAN_OPTIONS=UBSAN_OPTIONS)
    try:
        p = subprocess.Popen([_io(c, binary), reproducer], cwd=c.project_root, env=env,
                             stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    except OSError as e:
        return 126, f"timeout: failed to run command '{binary}': {e.strerror}"
    try:
        out, _ = p.communicate(timeout=timeout)
        rc = p.returncode
    except subprocess.TimeoutExpired:
        p.terminate()
        out, _ = p.communicate()
        rc = 124
    if rc < 0:
        rc = 128 - rc
    text = out.replace(b"\0", b"").decode("utf-8", "surrogateescape").rstrip("\n")
    return rc, text


def _attempts(c, binary, reproducer, *, stage=None, log_file=None, leaks=True) -> int:
    n = 0
    for i in range(1, VERIFY_ATTEMPTS + 1):
        rc, out = run_reproducer(c, binary, reproducer, leaks=leaks)
        if log_file is not None:
            with open(log_file, "a", encoding="utf-8", errors="surrogateescape") as f:
                f.write(f"=== {stage} attempt {i} rc={rc} ===\n{out}\n")
        if crashed(rc, out):
            n += 1
    return n


def _route_flaky(c: Campaign, reproducer: str, tag: str, stack_hash: str) -> None:
    flaky = c.crashes_dir / "flaky"
    flaky.mkdir(parents=True, exist_ok=True)
    base = os.path.basename(reproducer)
    base = base[:-4] if base.endswith(".bin") else base
    try:
        shutil.copyfile(_io(c, reproducer), flaky / f"{base}-{tag}-{stack_hash[:8]}.bin")
    except OSError:
        pass


# ---------------------------------------------------------------------------
# Readers
# ---------------------------------------------------------------------------

def count(c: Campaign) -> int:
    """Lines carrying "schema": "finding/v2"."""
    return sum(1 for ln in _raw_lines(_read(c)) if _FINDING_V2_RE.search(ln))


def find_by_hash(c: Campaign, stack_hash: str) -> list[str]:
    """The raw ledger lines with this stack_hash."""
    return _matching(c, "stack_hash", stack_hash)


def list_candidates(c: Campaign) -> list[dict]:
    """status=candidate entries, in ledger order."""
    return [d for d in _iter_records(c) if d.get("status") == "candidate"]


# ---------------------------------------------------------------------------
# add
# ---------------------------------------------------------------------------

@dataclass
class AddResult:
    id: str
    record: dict
    stage1: int | None = None       # crashes out of VERIFY_ATTEMPTS (None: skipped)
    stage2: int | None = None


def _check_add_args(stack_hash, category, exploitability) -> None:
    if not _HASH_RE.fullmatch(stack_hash):
        raise FindingsError(f"ERROR: stack_hash '{stack_hash}' must be hex (12-64 chars). "
                            "Did you mix up arg order?", 2)
    # crash classes + logic classes (enums SSOT); ubsan-<kind> by prefix.
    if not category.startswith("ubsan-") and category not in enums.CATEGORIES:
        raise FindingsError(f"ERROR: invalid category '{category}'. See 'findings.sh help'.", 2)
    if exploitability not in enums.EXPLOITABILITY:
        raise FindingsError(f"ERROR: invalid exploitability '{exploitability}' "
                            "(must be likely|medium|unlikely|harness-artifact).", 2)


def _verify_new(c: Campaign, stack_hash: str, reproducer: str, harness: str, log: Log):
    """Stage 1 (harness binary, 2/3 crashes) and stage 2 (standalone verify
    binary, 2/3) before a finding may be created. Returns (harness_bin,
    stage1, stage2|None). A failed stage routes the input to crashes/flaky/
    and raises (exit 3)."""
    state = state_dir_text(c)
    if not os.path.isfile(_io(c, reproducer)):
        raise FindingsError(f"ERROR: reproducer file missing: {reproducer}\n"
                            "       create the file first, then call findings.sh add", 2)
    hbin = _harness_field(c, harness, "harness_binary") or _mirror_field(c, "harness_binary")
    if not hbin or not _executable(c, hbin):
        raise FindingsError(f"ERROR: cannot find harness_binary in {state}/harness-built.json\n"
                            "       set FINDINGS_SKIP_VERIFY=1 to skip verification (not recommended)", 2)

    # Stage 1: the fuzzer harness, 3 runs; 2/3 must crash (deterministic).
    vlog = Path(_io(c, f"{state}/verify-{stack_hash[:12]}.log"))
    vlog.write_text("")
    s1 = _attempts(c, hbin, reproducer, stage="stage1", log_file=vlog)
    if s1 < 2:
        _route_flaky(c, reproducer, "flaky", stack_hash)
        raise FindingsError(
            f"ERROR: Stage 1 (harness) verification failed: {s1}/{VERIFY_ATTEMPTS} attempts crashed\n"
            "       reproducer is non-deterministic or no longer triggers the bug\n"
            f"       full log: {state}/verify-{stack_hash[:12]}.log\n"
            "       routing input to fuzz/crashes/flaky/\n"
            "       to override (not recommended): set FINDINGS_SKIP_VERIFY=1", 3)
    log(f"stage1 ok: {s1}/{VERIFY_ATTEMPTS} harness crashes")

    # Stage 2: the standalone ASan binary (no -fsanitize=fuzzer). A crash that
    # doesn't reproduce here only exists inside libFuzzer: a harness artifact.
    vbin = _harness_field(c, harness, "verify_binary") or _mirror_field(c, "verify_binary")
    s2 = None
    if vbin and _executable(c, vbin):
        s2 = _attempts(c, vbin, reproducer, stage="stage2", log_file=vlog)
        if s2 < 2:
            _route_flaky(c, reproducer, "harness-artifact", stack_hash)
            raise FindingsError(
                f"ERROR: Stage 2 (standalone ASan) verification failed: {s2}/{VERIFY_ATTEMPTS} attempts crashed\n"
                "       crash only reproduces in the fuzzer harness, not in the standalone ASan binary.\n"
                "       This is a harness artifact — the bug is in the libFuzzer wrapper, not in target code.\n"
                f"       full log: {state}/verify-{stack_hash[:12]}.log\n"
                "       routing input to fuzz/crashes/flaky/ (harness-artifact)\n"
                "       to override: set FINDINGS_SKIP_VERIFY=1 (only if you have strong reason to believe\n"
                "       this is a real bug despite not reproducing in the standalone binary)", 3)
        log(f"stage2 ok: {s2}/{VERIFY_ATTEMPTS} standalone ASan crashes — confirmed real target bug")
    else:
        if not vbin:
            log("WARN: verify_binary not set in harness-built.json — cannot cross-verify against standalone binary.")
            log("      This finding may be a harness artifact. Rebuild harness with /cc-fuzzer:harness to enable")
            log("      Stage 2 verification.")
        else:
            log(f"WARN: verify_binary set but not executable: {vbin}")
            log("      Rebuild harness to regenerate it.")
        log("      Proceeding without Stage 2 verification. If exploitability is uncertain, use harness-artifact.")
    log(f"verify ok: stage1={s1}/{VERIFY_ATTEMPTS} stage2={'skipped' if s2 is None else s2}/{VERIFY_ATTEMPTS}")
    return hbin, s1, s2


def build_finding(fid, stack_hash, category, location, exploitability, root_cause, reproducer,
                  excerpt, *, harness, build_hash, now, oracle_type="", divergence="") -> dict:
    """One new finding/v2 entry. Every new entry is a CANDIDATE (schema v12):
    only promote() flips it to "finding"."""
    d = {
        "schema": "finding/v2",
        "id": fid,
        "status": "candidate",
        "stack_hash": stack_hash,
        "category": category,
        "location": location,
        "exploitability": exploitability,
        "root_cause": root_cause,
        "reproducer": reproducer,
        "verified_against_build": build_hash,
        "first_seen": now,
        "last_seen": now,
        "dedup_count": 1,
        "harnesses": [harness],
    }
    # Oracle-driven (logic) findings carry the oracle type and a divergence
    # record. "crash" (the default) is omitted. Malformed divergence JSON is
    # kept raw so the triager can repair it rather than lose it.
    if oracle_type and oracle_type != "crash":
        d["oracle_type"] = oracle_type
        if divergence:
            try:
                d["divergence"] = json.loads(divergence)
            except Exception:
                d["divergence"] = {"_raw": divergence, "_parse_error": True}
    if excerpt:
        d["sanitizer_report_excerpt"] = excerpt
    return d


def add(c: Campaign, stack_hash: str, category: str, location: str, exploitability: str,
        root_cause: str, reproducer: str, excerpt: str = "", *, harness: str | None = None,
        skip_verify: bool = False, oracle_type: str = "", divergence: str = "",
        log: Log = _nolog) -> AddResult:
    """Append a new candidate (see module docstring). Refuses bad enums, an
    existing stack_hash (use dedup), and -- unless skip_verify -- a reproducer
    that doesn't crash 2/3 on the harness binary and 2/3 on the verify binary."""
    ensure_ledger(c)
    harness = harness_context(c, harness)
    _check_add_args(stack_hash, category, exploitability)
    if find_by_hash(c, stack_hash):
        raise FindingsError(f"ERROR: stack_hash {stack_hash} already exists - use 'dedup' instead", 1)
    hbin, s1, s2 = "", None, None
    if not skip_verify:
        hbin, s1, s2 = _verify_new(c, stack_hash, reproducer, harness, log)
    build_hash = _mirror_field(c, "build_command_hash")

    # Keep the harness binary next to the reproducer so the finding can still
    # be reproduced after a rebuild.
    if hbin and _executable(c, hbin) and os.path.isfile(_io(c, reproducer)):
        rdir = Path(_io(c, os.path.dirname(reproducer) or "."))
        rdir.mkdir(parents=True, exist_ok=True)
        if not (rdir / "repro.binary").is_file():
            try:
                shutil.copy(_io(c, hbin), rdir / "repro.binary")
            except OSError:
                pass

    fid = f"f{_next_num(c):03d}"
    rec = build_finding(fid, stack_hash, category, location, exploitability, root_cause, reproducer,
                        excerpt, harness=harness, build_hash=build_hash, now=_now_iso(),
                        oracle_type=oracle_type, divergence=divergence)
    with open(ledger_path(c), "a", encoding="utf-8") as f:
        f.write(_compact(rec) + "\n")
    _write_harnesses_txt(c, fid)
    return AddResult(fid, rec, s1, s2)


# ---------------------------------------------------------------------------
# dedup / add-harness
# ---------------------------------------------------------------------------

@dataclass
class DedupResult:
    id: str
    dedup_count: str
    warning: str = ""           # set when dedup_count reached the threshold


def dedup(c: Campaign, stack_hash: str, *, harness: str | None = None,
          threshold=DEDUP_THRESHOLD) -> DedupResult:
    """dedup_count += 1 and last_seen := now on the entry with this stack_hash;
    the harness (default: the first declared) is appended to its harnesses[].
    result.warning is set once dedup_count reaches `threshold` (the triager
    re-runs the artifact filter on high-dup hashes)."""
    ensure_ledger(c)
    harness = harness_context(c, harness)
    if not find_by_hash(c, stack_hash):
        raise FindingsError(f"ERROR: no finding with stack_hash {stack_hash}", 1)
    now = _now_iso()

    def bump(d):
        if d.get("stack_hash") == stack_hash:
            d["dedup_count"] = d.get("dedup_count", 1) + 1
            d["last_seen"] = now
            if harness:
                hs = d.get("harnesses") or []
                if harness not in hs:
                    hs.append(harness)
                    d["harnesses"] = hs
    _replace(c, _rewrite(c, bump), empty_error="ERROR: dedup produced empty file - aborted")

    fid, cnt = "", ""
    first = find_by_hash(c, stack_hash)
    if first:
        try:
            d = json.loads(first[0])
            tokens = f"{d.get('id', '')} {d.get('dedup_count', 0)}".split()
            fid, cnt = (tokens + ["", ""])[:2]
        except Exception:
            pass
    n, t = _bash_int(cnt), _bash_int(threshold)
    warning = ""
    if n is not None and t is not None and n >= t:
        warning = (f"WARN: dedup_count crossed {threshold} for {fid} (now {cnt}). Triager should re-run the "
                   "four-principle artifact filter on this stack hash before next dedup — high-frequency "
                   "repeats often turn out to be harness artifacts.")
    if harness and fid:
        _write_harnesses_txt(c, fid)
    return DedupResult(fid, cnt, warning)


def add_harness(c: Campaign, fid: str, harness: str) -> bool:
    """Append a harness to an entry's harnesses[] (idempotent). True when it
    was added."""
    ensure_ledger(c)
    if not _matching(c, "id", fid):
        raise FindingsError(f"ERROR: no finding with id {fid}", 1)
    added = []

    def app(d):
        if d.get("id") == fid:
            hs = d.get("harnesses") or []
            if harness not in hs:
                hs.append(harness)
                d["harnesses"] = hs
                added.append(True)
    _replace(c, _rewrite(c, app), empty_error="ERROR: add-harness produced empty file - aborted")
    _write_harnesses_txt(c, fid)
    return bool(added)


# ---------------------------------------------------------------------------
# verify / stale-mark / remove
# ---------------------------------------------------------------------------

def verify(c: Campaign, fid: str | None = None) -> list[tuple[str, str]]:
    """Re-run every (or one) entry's reproducer against harness-built.json's
    binaries: ok | ok-no-stage2 | harness-artifact | stale | missing. The
    ledger is not modified (stale_mark acts on the result)."""
    ensure_ledger(c)
    hbin = _mirror_field(c, "harness_binary")
    if not hbin or not _executable(c, hbin):
        raise FindingsError("ERROR: harness binary not found in harness-built.json", 2)
    vbin = _mirror_field(c, "verify_binary")
    out = []
    # `while read` semantics: an unterminated last line is not read.
    for line in _read(c).split("\n")[:-1]:
        if not line:
            continue
        rid, repro = _stdin_field(line, "id"), _stdin_field(line, "reproducer")
        if not rid or (fid and fid != rid):
            continue
        if not os.path.isfile(_io(c, repro)):
            out.append((rid, "missing"))
            continue
        if _attempts(c, hbin, repro) >= 2:
            if vbin and _executable(c, vbin):
                ok = _attempts(c, vbin, repro, leaks=False) >= 2
                out.append((rid, "ok" if ok else "harness-artifact"))
            else:
                out.append((rid, "ok-no-stage2"))
        else:
            out.append((rid, "stale"))
    return out


def stale_mark(c: Campaign, fid: str, *, log: Log = _nolog) -> tuple[Path, Path]:
    """Move crashes/known/<id>/ to crashes/stale/<id>/ (an existing
    destination is staged to fuzz/.trash/<ts>/ first) and mark the entry
    status=stale + stale_against_build. Returns (old, new) dirs."""
    ensure_ledger(c)
    known = c.crashes_dir / "known" / fid
    stale = c.crashes_dir / "stale" / fid
    if not known.is_dir():
        raise FindingsError(f"ERROR: {known} does not exist", 1)
    build = _mirror_field(c, "build_command_hash")
    stale.parent.mkdir(parents=True, exist_ok=True)
    if os.path.lexists(stale):
        dst = c.fuzz_root / ".trash" / _trash_ts() / "crashes" / "stale" / fid
        dst.parent.mkdir(parents=True, exist_ok=True)
        shutil.move(str(stale), str(dst))
        log(f"stale-mark: prior {stale} staged to {dst} (not hard-deleted)")
    shutil.move(str(known), str(stale))

    def mark(d):
        if d.get("id") == fid:
            d["status"] = "stale"
            d["stale_against_build"] = build
            repro = d.get("reproducer", "")
            if isinstance(repro, str):
                d["reproducer"] = repro.replace("crashes/known/", "crashes/stale/")
    _replace(c, _rewrite(c, mark))
    return known, stale


def remove(c: Campaign, fid: str, *, log: Log = _nolog) -> Path:
    """Backup-safe removal: the entry's line, fuzz/findings/<id>/ and
    crashes/known/<id>/ are staged to fuzz/.trash/<ts>/, never hard-deleted.
    Returns the trash dir."""
    ensure_ledger(c)
    existing = _matching(c, "id", fid)
    if not existing:
        raise FindingsError(f"ERROR: remove: no finding with id {fid}", 1)
    trash = c.fuzz_root / ".trash" / _trash_ts()
    (trash / "state").mkdir(parents=True, exist_ok=True)
    with open(trash / "state" / LEDGER, "a", encoding="utf-8", errors="surrogateescape") as f:
        f.write("\n".join(existing).rstrip("\n") + "\n")
    for sub in (f"findings/{fid}", f"crashes/known/{fid}"):
        src = c.fuzz_root / sub
        if src.is_dir():
            dst = trash / sub
            dst.parent.mkdir(parents=True, exist_ok=True)
            shutil.move(str(src), str(dst))
            log(f"remove: staged {src} -> {dst}")
    pat = _field_re("id", fid)
    _replace(c, "".join(ln + "\n" for ln in _raw_lines(_read(c)) if not pat.search(ln)))
    return trash


# ---------------------------------------------------------------------------
# promote: the realism gate
# ---------------------------------------------------------------------------

@dataclass
class PromoteResult:
    id: str
    attestation: dict
    verifier_lines: int
    verifier_tools: int
    warnings: list = field(default_factory=list)


def verifier_complexity(path) -> tuple[int, int]:
    """(lines, distinct command-like tokens) of a verifier script: the soft
    lean-PoC heuristic (newline count; tokens at a line start or after
    | ; & $( minus shell keywords/builtins)."""
    data = Path(path).read_bytes()
    lines = data.count(b"\n")
    tokens = set()
    for line in data.decode("utf-8", "surrogateescape").split("\n"):
        for m in _TOOL_TOKEN_RE.finditer(line):
            tok = re.sub(r"^[^A-Za-z_]*", "", m.group(0))
            if tok not in _SHELL_WORDS:
                tokens.add(tok)
    return lines, len(tokens)


def _config_get(c: Campaign, dotted: str) -> str:
    try:
        d = json.loads((c.state_dir / "fuzz-config.json").read_text())
    except Exception:
        return ""
    for part in dotted.split("."):
        if isinstance(d, dict) and part in d:
            d = d[part]
        else:
            return ""
    return "" if d in (None, "") else str(d)


def promote(c: Campaign, fid: str, *, driver: str, verifier: str, boundary: str,
            precondition: str, projected: str, log: Log = _nolog) -> PromoteResult:
    """Flip a candidate to status=finding, attaching realism_attestation.

    This is the promotion gate (schema v12): the 3-point realism gate --
    a mechanical reproducer (driver), a CLI-style verifier against the REAL
    target binary that exits 0 only when the trust boundary is crossed, and
    the boundary / precondition / projected_vs_demonstrated statements -- is
    REQUIRED; the verifier's size and tool count are soft-checked (warn only;
    fuzz-config.json poc.verifier_complexity_soft_max_lines / _tools).
    Refuses: missing fields or files, an unknown id, a status other than
    candidate (an existing finding is re-attested with a warning).

    §4/§11 replace this with pipeline.finalize(id) + a verification marker;
    keep every promotion going through this one function until then."""
    ensure_ledger(c)
    missing = "".join(f" {flag}" for flag, v in (
        ("--driver", driver), ("--verifier", verifier), ("--boundary", boundary),
        ("--precondition", precondition), ("--projected", projected)) if not v)
    if missing:
        raise FindingsError(f"ERROR: promote: missing required attestation fields:{missing}\n"
                            "       schema v12 REQUIRES the 3-point realism gate — see\n"
                            "       references/verifier-template.sh and poc-builder.md.", 2)
    if not os.path.isfile(_io(c, driver)):
        raise FindingsError(f"ERROR: promote: --driver path does not exist: {driver}", 2)
    if not os.path.isfile(_io(c, verifier)):
        raise FindingsError(f"ERROR: promote: --verifier path does not exist: {verifier}", 2)

    existing = _matching(c, "id", fid)
    if not existing:
        raise FindingsError(f"ERROR: promote: no finding with id {fid}", 1)
    status = _stdin_field("\n".join(existing), "status")
    warnings = []
    if status == "finding":
        warnings.append(f"WARN: promote: {fid} is already status=finding; re-attesting "
                        "(overwriting realism_attestation)")
        log(warnings[-1])
    elif status and status != "candidate":
        raise FindingsError(f"ERROR: promote: {fid} has status={status} — promotion refused", 1)

    max_lines = _config_get(c, "poc.verifier_complexity_soft_max_lines") or str(VERIFIER_SOFT_MAX_LINES)
    max_tools = _config_get(c, "poc.verifier_complexity_soft_max_tools") or str(VERIFIER_SOFT_MAX_TOOLS)
    v_lines, v_tools = verifier_complexity(_io(c, verifier))
    ml, mt = _bash_int(max_lines), _bash_int(max_tools)
    if ml is not None and v_lines > ml:
        warnings.append(f"WARN: promote: verifier is {v_lines} lines (> soft cap {max_lines}). The "
                        "disclosure PoC should be lean (PLUGIN_ISSUES friction 5); split research "
                        "tooling out under poc-bundle/research/.")
        log(warnings[-1])
    if mt is not None and v_tools > mt:
        warnings.append(f"WARN: promote: verifier shells out to ~{v_tools} distinct binaries (> soft "
                        f"cap {max_tools}). Consider trimming non-essential tools from the reference verifier.")
        log(warnings[-1])

    now = _now_iso()
    attestation = {
        "driver": driver,
        "verifier": verifier,
        "boundary": boundary,
        "precondition": precondition,
        "projected_vs_demonstrated": projected,
        "verifier_lines": v_lines,
        "verifier_tools": v_tools,
        "promoted_at": now,
    }

    def flip(d):
        if d.get("id") == fid:
            d["status"] = "finding"
            d["realism_attestation"] = attestation
            d["last_seen"] = now
    _replace(c, _rewrite(c, flip), empty_error="ERROR: promote produced empty file - aborted")
    return PromoteResult(fid, attestation, v_lines, v_tools, warnings)


# ---------------------------------------------------------------------------
# drop / import-cr
# ---------------------------------------------------------------------------

def drop(c: Campaign, crash_file: str, stage: str, reason: str, *, principle: str = "",
         evidence: str = "") -> dict:
    """Append a dropped-crash/v1 record to dropped_crashes.jsonl (the
    triager's transparency log for every candidate it filters out)."""
    ensure_ledger(c)
    if stage not in DROP_STAGES:
        raise FindingsError(f"ERROR: drop: invalid stage '{stage}'\n"
                            "       valid: artifact_filter | deterministic_replay | target_realistic_reproducer", 2)
    if stage == "artifact_filter" and principle not in DROP_PRINCIPLES:
        raise FindingsError("ERROR: drop: --principle is required when stage=artifact_filter\n"
                            "       valid: harness_correctness | api_contract | public_api_reachability | "
                            "entry_point_currency", 2)
    log_path = c.state_dir / DROPS
    log_path.touch()
    short = ""
    p = _io(c, crash_file)
    if os.path.isfile(p) and os.access(p, os.R_OK):
        try:
            with open(p, "rb") as f:
                short = hashlib.sha256(f.read()).hexdigest()[:8]
        except OSError:
            pass
    rec = {"schema": "dropped-crash/v1", "ts": _now_iso(), "crash_file": crash_file,
           "stage": stage, "reason": reason}
    if short:
        rec["stack_hash_partial"] = short
    rec["principle"] = principle if principle else None
    if evidence:
        rec["evidence"] = evidence
    with open(log_path, "a", encoding="utf-8") as f:
        f.write(_compact(rec) + "\n")
    return rec


def _latest_snapshot(c: Campaign) -> str:
    """`ls -1t $STATE_DIR/snapshots/code-review-*.json | head -1` (newest
    mtime, ties by name; note the glob also matches prescan artifacts and
    window partials)."""
    snaps = f"{state_dir_text(c)}/snapshots"
    cands = []
    try:
        entries = list(os.scandir(_io(c, snaps)))
    except OSError:
        return ""
    for e in entries:
        if fnmatch.fnmatchcase(e.name, "code-review-*.json"):
            try:
                cands.append((-e.stat().st_mtime_ns, e.name))
            except OSError:
                pass
    return f"{snaps}/{min(cands)[1]}" if cands else ""


@dataclass
class ImportResult:
    snapshot: str
    imported: list = field(default_factory=list)   # the new entries
    skipped: int = 0
    error: str = ""                                # unreadable snapshot (nothing imported)


def import_cr(c: Campaign, snapshot: str | None = None, *, harness: str | None = None) -> ImportResult:
    """Bridge high/medium-confidence code-review/v1 findings into the ledger as
    status=candidate, source=code_review, cr_ref=<cr_hash> (dedup on cr_ref).
    They then go through the same list-candidates -> promote gate."""
    ensure_ledger(c)
    harness = harness_context(c, harness)
    if not snapshot:
        snapshot = _latest_snapshot(c)
        if not snapshot:
            raise FindingsError(f"ERROR: import-cr: no code-review snapshot found in {state_dir_text(c)}/snapshots/\n"
                                "       run /cc-fuzzer:fuzz-review first, or pass a snapshot path.", 2)
    if not os.path.isfile(_io(c, snapshot)):
        raise FindingsError(f"ERROR: import-cr: snapshot not found: {snapshot}", 2)
    next_num = _next_num(c)
    res = ImportResult(snapshot)
    try:
        existing = {d.get("cr_ref") for d in _iter_records(c) if d.get("cr_ref")}
        try:
            with open(_io(c, snapshot)) as f:
                snap = json.load(f)
        except Exception as e:
            res.error = f"import-cr: cannot read snapshot {snapshot}: {e}"
            _replace(c, _read(c))
            return res
        # needs_deep_pass is a separate flag, not a confidence: it doesn't gate import.
        importable = {"high", "medium"} & enums.CONFIDENCE
        now = _now_iso()
        for cr in snap.get("findings") or []:
            if cr.get("confidence") not in importable:
                continue
            cr_hash = cr.get("cr_hash")
            if not cr_hash or cr_hash in existing:
                res.skipped += 1
                continue
            existing.add(cr_hash)
            line_range = cr.get("line_range") or []
            location = "{fn}@{file}:{ln}".format(fn=cr.get("function", "?"), file=cr.get("file", "?"),
                                                 ln=line_range[0] if line_range else "?")
            evidence = cr.get("evidence", "")
            d = {
                "schema": "finding/v2",
                "id": "f%03d" % next_num,
                "status": "candidate",
                "source": "code_review",
                "cr_ref": cr_hash,
                "category": enums.cr_to_category(cr.get("pattern", "")),
                "location": location,
                "exploitability": "medium",
                "root_cause": "[code-review {pat}] {ev}".format(pat=cr.get("pattern", "?"), ev=evidence).strip(),
                "first_seen": now,
                "last_seen": now,
                "dedup_count": 1,
            }
            next_num += 1
            # The cr's oracle framing carries through so poc-builder can shape
            # the verifier around the boundary crossing, not a crash.
            if cr.get("oracle_kind"):
                d["oracle_kind"] = cr["oracle_kind"]
            if cr.get("trust_boundary_crossed"):
                d["trust_boundary_crossed"] = cr["trust_boundary_crossed"]
            if cr.get("precondition"):
                d["precondition"] = cr["precondition"]
            if evidence:
                d["code_review_evidence"] = evidence
            if harness:
                d["harnesses"] = [harness]
            res.imported.append(d)
    except Exception:
        raise FindingsError("ERROR: import-cr: helper failed (rc=1)", 1)
    _replace(c, _read(c) + "".join(_compact(d) + "\n" for d in res.imported))
    return res


# ---------------------------------------------------------------------------
# CLI: cc-fuzzer findings <verb> (findings.sh is a shim onto it)
# ---------------------------------------------------------------------------

_ADD_USAGE = r"""usage: findings.sh add <stack_hash> <category> <location> <exploitability> <root_cause> <reproducer> [sanitizer_excerpt]

This is a POSITIONAL-ARGS interface, NOT a flag-style interface.
WRONG: findings.sh add --id f001 --category null-deref --location ...
RIGHT: findings.sh add "abc123def456" "null-deref" "func\@file.c:42" "medium" "off-by-one" "fuzz/crashes/known/f001/repro.bin" ""

The id is allocated by this script - do NOT pass --id. The argument order is:
  1. stack_hash         (16-hex-char sha256-prefix of the crash stack)
  2. category           (crash: heap-buffer-overflow heap-use-after-free stack-buffer-overflow
                                  global-buffer-overflow stack-overflow null-deref assertion-failure
                                  oom timeout harness-artifact, or ubsan-<kind>;
                          logic: invariant-violation roundtrip-mismatch differential-divergence
                                  parser-differential auth-bypass access-control incorrect-validation
                                  canonicalization state-confusion integer-truncation logic-error)
  3. location           (function@file:line of the actual bug, not the libc frame)
  4. exploitability     (one of: likely medium unlikely harness-artifact)
  5. root_cause         (one or two sentences)
  6. reproducer         (path to fuzz/crashes/known/<id>/repro.bin - placeholder until you mkdir+mv)
  7. sanitizer_excerpt  (optional - first ~10 lines of the sanitizer report)

For a LOGIC finding (oracle-driven), additionally set in the ENVIRONMENT (not flags):
  ORACLE_TYPE=invariant|roundtrip|differential   and
  DIVERGENCE='{"property_id":"...","comparison":"...","observed":"...","expected":"..."}'
The stack_hash for a logic finding is the property-divergence hash (sha256 prefix of
oracle_type|property_id|divergence_class) — the dedup machinery is unchanged.
"""

_HELP_TAIL = """
Commands:
  count              Print number of unique findings
  list               Print all findings (jsonl)
  find-by-hash H     Print finding line matching stack_hash H, if any
  add H CAT LOC EXPL ROOTCAUSE REPRODUCER [EXCERPT]
                     Append a new finding with stack_hash H. Allocates next id (f001, f002...).
                     TWO-STAGE VERIFICATION before committing:
                       Stage 1: reproducer crashes harness binary 2/3 times (ASan+fuzzer)
                       Stage 2: reproducer crashes verify_binary 2/3 times (ASan-only, no fuzzer)
                     Stage 2 failure = harness artifact, routed to crashes/flaky/, rejected.
                     Stage 1 failure = non-deterministic, routed to crashes/flaky/, rejected.
                     Set FINDINGS_SKIP_VERIFY=1 to bypass both checks (not recommended).
  verify [id]        Re-verify one or all findings against harness + verify_binary.
                     Output: id<TAB>status, status in {ok, ok-no-stage2, stale, harness-artifact, missing}.
                     ok             = stage1 + stage2 both pass
                     ok-no-stage2   = stage1 passes, verify_binary not available
                     harness-artifact = stage1 passes but stage2 fails (finding reclassifiable)
                     stale          = stage1 fails (no longer reproduces at all)
                     missing        = reproducer file missing
  stale-mark <id>    Move a finding's crashes/known/<id>/ tree to crashes/stale/<id>/
                     and add status=stale + stale_against_build to findings.jsonl.
                     If the destination already exists, it is STAGED to
                     fuzz/.trash/<ts>/ rather than hard-deleted (backup safety).
  import-cr [SNAP]   Bridge code-review findings into the candidate ledger.
                     Ingests high/medium-confidence findings from a code-review
                     snapshot (default: latest fuzz/state/snapshots/code-review-*.json)
                     into findings.jsonl as status=candidate, source=code_review,
                     cr_ref=<cr_hash>. Dedups on cr_ref. The imported candidates
                     flow through the same list-candidates -> promote realism gate.
  list-candidates    Print one line per status=candidate entry. Output:
                     <id><TAB><category><TAB><location><TAB><first_seen>
  promote <id> --driver P --verifier P --boundary S --precondition S --projected S
                     Flip status=candidate -> status=finding, attaching the
                     realism_attestation block. REQUIRED on every promotion
                     (schema v12 / PLUGIN_ISSUES.md recommendation B):
                       --driver       mechanical reproducer path
                       --verifier     CLI-style verify-*.sh against the REAL
                                      target binary (non-ASan, non-coverage);
                                      exit 0 ONLY when the boundary is crossed
                       --boundary     trust/privilege boundary crossed (string)
                       --precondition attacker precondition (string)
                       --projected    projected_vs_demonstrated narrative (string)
                     Soft complexity check on the verifier (WARN not reject):
                       poc.verifier_complexity_soft_max_lines (default 200)
                       poc.verifier_complexity_soft_max_tools (default 6)
                     in fuzz/state/fuzz-config.json.
  remove <id>        Backup-safe finding removal. Stages fuzz/findings/<id>/,
                     fuzz/crashes/known/<id>/, and the JSONL line to
                     fuzz/.trash/<ts>/ instead of hard-deleting.
  dedup H            Increment dedup_count and update last_seen for finding with stack_hash H.
                     Prints the matching finding's id.
  drop CRASH_FILE STAGE REASON [--principle P] [--evidence E]
                     Append a record to fuzz/state/dropped_crashes.jsonl explaining why
                     a crash candidate was filtered out by the triager (transparency log).
                     STAGE in: artifact_filter | deterministic_replay | target_realistic_reproducer.
                     PRINCIPLE required when STAGE=artifact_filter:
                       harness_correctness | api_contract | public_api_reachability | entry_point_currency

Per STATE_SCHEMA.md, this is the ONLY tool that should write to findings.jsonl.
"""

VERBS = ("count", "list", "find-by-hash", "add", "dedup", "add-harness", "verify", "stale-mark",
         "list-candidates", "promote", "remove", "drop", "import-cr", "help")


def _err(line: str) -> None:
    sys.stderr.write(line + "\n")
    sys.stderr.flush()


def _out(line: str) -> None:
    sys.stdout.write(line + "\n")
    sys.stdout.flush()


def _required(args, i, msg):
    """findings.sh's ${N:?msg}: a missing or empty positional is an error (exit 1)."""
    if len(args) <= i or args[i] == "":
        raise FindingsError(f"findings.sh: {msg}", 1)
    return args[i]


def _flags(args, known, verb):
    """--flag value pairs (a trailing flag with no value reads as "")."""
    vals = {k: "" for k in known}
    args = list(args)
    while args:
        a = args.pop(0)
        if a not in known:
            raise FindingsError(f"ERROR: {verb}: unknown flag '{a}'", 2)
        vals[a] = args.pop(0) if args else ""
    return vals


def _v_count(c, args):
    n = count(c)
    # `grep -c ... || echo 0`: grep prints 0 AND fails on no match.
    _out(f"{n}" if n else "0\n0")


def _v_list(c, args):
    data = ledger_path(c).read_bytes()
    sys.stdout.flush()
    sys.stdout.buffer.write(data)
    sys.stdout.buffer.flush()


def _v_find(c, args):
    for ln in find_by_hash(c, _required(args, 0, "stack_hash required")):
        _out(ln)


def _v_add(c, args):
    if len(args) < 6:
        sys.stderr.write(_ADD_USAGE)
        return 2
    for a in args:
        if a.startswith("--"):
            raise FindingsError(f"ERROR: findings.sh uses POSITIONAL args, not flags. Got '{a}'. "
                                "See 'findings.sh help'.", 2)
    r = add(c, *args[:6], args[6] if len(args) > 6 else "",
            harness=os.environ.get("HARNESS") or None,
            skip_verify=os.environ.get("FINDINGS_SKIP_VERIFY", "0") == "1",
            oracle_type=os.environ.get("ORACLE_TYPE", ""), divergence=os.environ.get("DIVERGENCE", ""),
            log=_err)
    _out(r.id)


def _v_dedup(c, args):
    h = _required(args, 0, "stack_hash required")
    r = dedup(c, h, harness=os.environ.get("HARNESS") or None,
              threshold=os.environ.get("FINDINGS_DEDUP_THRESHOLD") or DEDUP_THRESHOLD)
    _out(r.id)
    if r.warning:
        _err(r.warning)


def _v_add_harness(c, args):
    fid = _required(args, 0, "finding id required (e.g. f005)")
    h = _required(args, 1, "harness name required")
    add_harness(c, fid, h)
    _out(fid)


def _v_verify(c, args):
    fid = args[0] if args else ""
    for rid, st in verify(c, fid or None):
        _out(f"{rid}\t{st}")


def _v_stale(c, args):
    fid = _required(args, 0, "finding id required")
    old, new = stale_mark(c, fid, log=_err)
    _out(f"{fid} marked stale (was {old}, now {new})")


def _v_candidates(c, args):
    for d in list_candidates(c):
        _out("{id}\t{category}\t{location}\t{first_seen}".format(
            id=d.get("id", ""), category=d.get("category", ""),
            location=d.get("location", ""), first_seen=d.get("first_seen", "")))


def _v_promote(c, args):
    fid = _required(args, 0, "usage: findings.sh promote <id> --driver P --verifier P --boundary S "
                             "--precondition S --projected S")
    v = _flags(args[1:], ("--driver", "--verifier", "--boundary", "--precondition", "--projected"), "promote")
    r = promote(c, fid, driver=v["--driver"], verifier=v["--verifier"], boundary=v["--boundary"],
                precondition=v["--precondition"], projected=v["--projected"], log=_err)
    _out(f"{fid} promoted to status=finding (verifier={v['--verifier']}, lines={r.verifier_lines}, "
         f"tools={r.verifier_tools})")


def _v_remove(c, args):
    fid = _required(args, 0, "usage: findings.sh remove <id>")
    trash = remove(c, fid, log=_err)
    _out(f"{fid} removed (staged to {trash}, NOT hard-deleted)")


def _v_drop(c, args):
    if len(args) < 3:
        _err("Usage: findings.sh drop <crash_file> <stage> <reason> [--principle <name>] [--evidence <text>]")
        _err("  stage in: artifact_filter | deterministic_replay | target_realistic_reproducer")
        _err("  principle (required only when stage=artifact_filter):")
        _err("    harness_correctness | api_contract | public_api_reachability | entry_point_currency")
        return 2
    v = _flags(args[3:], ("--principle", "--evidence"), "drop")
    drop(c, args[0], args[1], args[2], principle=v["--principle"], evidence=v["--evidence"])
    p = v["--principle"]
    _out(f"dropped: {args[0]} (stage={args[1]}{', principle=' + p if p else ''})")


def _v_import(c, args):
    r = import_cr(c, args[0] if args else None, harness=os.environ.get("HARNESS") or None)
    if r.error:
        _err(r.error)
    else:
        _err("import-cr: imported=%d skipped=%d (snapshot=%s)" % (len(r.imported), r.skipped, r.snapshot))


def _v_help(c, args):
    sys.stdout.write(f"findings.sh - the canonical writer for {state_dir_text(c)}/{LEDGER}\n" + _HELP_TAIL)


_HANDLERS = {"count": _v_count, "list": _v_list, "find-by-hash": _v_find, "add": _v_add,
             "dedup": _v_dedup, "add-harness": _v_add_harness, "verify": _v_verify,
             "stale-mark": _v_stale, "list-candidates": _v_candidates, "promote": _v_promote,
             "remove": _v_remove, "drop": _v_drop, "import-cr": _v_import, "help": _v_help}


def _run(verb):
    def handler(a):
        try:
            c = _campaign()
        except CampaignError as e:
            _err(str(e))
            return e.code
        ensure_ledger(c)
        try:
            rc = _HANDLERS[verb](c, list(a.args))
        except FindingsError as e:
            _err(str(e))
            return e.code
        return 0 if rc is None else rc
    return handler


def register_cli(subparsers):
    from cc_fuzzer_core.cli import add_raw_verb, add_subsystem

    _p, verbs = add_subsystem(subparsers, "findings", "the findings ledger (port of findings.sh; `findings help`)")
    for verb in VERBS:
        add_raw_verb(verbs, "findings", verb, _run(verb), f"findings.sh {verb}")
