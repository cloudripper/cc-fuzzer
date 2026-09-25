"""Per-harness coverage snapshots (port of scripts/snapshot-coverage.sh +
scripts/_lib/snapshot_helpers.py).

snapshot(campaign, harness) -> SnapshotResult writes
<state>/snapshots/coverage-<harness>-<ts>.json (coverage-snapshot/v2) and then
refreshes current.json. Instrumentation must never fail silently: a snapshot
always carries an `instrumentation` block, so "real zero" and "broken zero"
can be told apart.

  1. llvm-cov / llvm-profdata resolve through tools.which (the plugin exports
     CC_FUZZER_TOOL_LLVM_COV / _LLVM_PROFDATA for host layouts it knows).
  2. Fuzzer stats: AFL++ fuzzer_stats summed over every instance (corpus_count:
     max, since instances sync one corpus); else the harness's libFuzzer slot
     log, fork-mode aware (the -fork= marker, /proc/<pid>/cmdline, the
     /tmp/libFuzzerTemp.FuzzWithFork<pid>.dir worker logs).
  3. With a coverage_binary: run it over the named seed_* inputs plus a random
     sample (SNAPSHOT_COVERAGE_MAX_SAMPLES, default 500) of the corpus and every
     AFL++ queue, merge the per-process profraws, and read line totals with
     `llvm-cov export --summary-only` (coverage_dso[] and workspace / nix-built
     shared libs the binary links are passed as -object).
  4. new_crashes_since_previous: this harness's crashes/new files newer than
     its previous snapshot; top_unreached_functions: up to 15 zero-count
     functions.

The snapshot text is the script's template byte for byte. The exit status is 0
even when instrumentation is broken (the orchestrator reads
instrumentation.ok); a WARN goes to stderr.
"""
from __future__ import annotations

import contextlib
import fnmatch
import glob
import io
import json
import os
import random
import re
import subprocess
import sys
import time
from dataclasses import dataclass, field
from pathlib import Path

from cc_fuzzer_core import tools
from cc_fuzzer_core.paths import Campaign, CampaignError, HarnessLayout, _field_text, campaign as _campaign

SCHEMA = "coverage-snapshot/v2"
DEFAULT_MAX_SAMPLES = 500
RUN_TIMEOUT_S = 5
_LIB_DIR_RE = re.compile(r"/_build(_cov|_fuzz|_symcc)?/|/nix/store/")
_FORK_LOG_RE = re.compile(r"fuzzing in separate process|INFO: fork_mode|Job [0-9]+ exited")
_JOB_EXITED_RE = re.compile(r"Job [0-9]+ exited")
_STATUS_RE = re.compile(r"^#[0-9]+")


@dataclass
class SnapshotResult:
    path: str                  # as printed (relative to the project root by default)
    doc: dict
    instrumentation_ok: bool
    tracking_enabled: bool
    messages: list = field(default_factory=list)   # stderr lines before the path is printed
    warning: str | None = None                     # stderr line after it (broken instrumentation)


# ---------------------------------------------------------------------------
# helpers (formerly _lib/snapshot_helpers.py)
# ---------------------------------------------------------------------------

def libfuzzer_slot_field(manifest: Path, harness: str, name: str) -> str:
    """<name> of the first libFuzzer slot bound to harness ("" if none)."""
    try:
        with open(manifest) as f:
            for s in json.load(f).get("slots", []):
                if s.get("engine") == "libfuzzer" and s.get("harness") == harness:
                    return str(s.get(name, ""))
    except Exception:
        pass
    return ""


def cov_summary(text: str) -> tuple:
    """llvm-cov --summary-only JSON -> (covered, total, "pct" as %.2f)."""
    try:
        lines = json.loads(text)["data"][0]["totals"]["lines"]
        covered, total = lines.get("covered", 0), lines.get("count", 0)
        pct = (covered / total * 100) if total else 0
        return covered, total, f"{pct:.2f}"
    except Exception:
        return 0, 0, 0


def unreached_functions(text: str, limit: int = 15) -> list:
    try:
        funcs = json.loads(text)["data"][0].get("functions", [])
        return [f["name"] for f in funcs if f.get("count", 0) == 0][:limit]
    except Exception:
        return []


def aggregate_afl_stats(files) -> tuple:
    """(execs, paths, crashes, hangs, execs_per_sec text) summed over
    fuzzer_stats files; corpus_count is the max."""
    execs = paths = crashes = hangs = rate = 0.0
    for fp in files:
        try:
            text = Path(fp).read_text(errors="replace")
        except OSError:
            continue
        for line in text.split("\n"):
            parts = [p for p in re.split(r"[: ]+", line)]
            val = _awk_num(parts[1]) if len(parts) > 1 else 0.0
            if line.startswith("execs_done"):
                execs += val
            elif line.startswith("corpus_count"):
                paths = max(paths, val)
            elif line.startswith("saved_crashes"):
                crashes += val
            elif line.startswith("saved_hangs"):
                hangs += val
            elif line.startswith("execs_per_sec"):
                rate += val
    rate_text = f"{int(rate)}" if rate == int(rate) else f"{rate:.2f}"
    return int(execs), int(paths), int(crashes), int(hangs), rate_text


def _awk_num(s: str) -> float:
    m = re.match(r"^[ \t]*[+-]?(\d+\.?\d*|\.\d+)([eE][+-]?\d+)?", s)
    return float(m.group(0)) if m else 0.0


def _int_or_zero(s) -> int:
    return int(s) if isinstance(s, str) and s.isdigit() and s.isascii() else 0


def parse_status_line(line: str) -> tuple:
    """A libFuzzer "#N ... cov: C ... exec/s: R" line -> (execs, paths, rate)."""
    first = line.split()[0] if line.split() else ""
    execs = first.replace("#", "").replace(":", "")
    m = re.search(r"cov: ([0-9]+)", line)
    paths = m.group(1) if m else ""
    m = re.search(r"exec/s: ([0-9]+)", line)
    rate = m.group(1) if m else ""
    return _int_or_zero(execs), _int_or_zero(paths), _int_or_zero(rate)


def _last_status(path) -> str:
    last = ""
    try:
        with open(path, errors="replace") as f:
            for line in f:
                if _STATUS_RE.match(line):
                    last = line.rstrip("\n")
    except OSError:
        pass
    return last


def _run(argv, *, env=None, timeout=None, cwd=None) -> subprocess.CompletedProcess | None:
    try:
        return subprocess.run(argv, env=env, cwd=cwd, capture_output=True, timeout=timeout,
                              stdin=subprocess.DEVNULL)
    except (OSError, subprocess.SubprocessError):
        return None


def _executable(p: str) -> bool:
    return bool(p) and os.path.isfile(p) and os.access(p, os.X_OK)


def _newest_snapshot(snapshots: Path, harness: str) -> Path | None:
    """`ls -t coverage-<h>-*.json | head -1`: newest mtime, ties by name."""
    cands = []
    for p in snapshots.glob(f"coverage-{glob.escape(harness)}-*.json"):
        try:
            cands.append((-p.stat().st_mtime_ns, p.name, p))
        except OSError:
            pass
    return min(cands)[2] if cands else None


def _files_in(d: Path):
    try:
        return sorted(e.path for e in os.scandir(d) if e.is_file(follow_symlinks=False))
    except OSError:
        return []


# ---------------------------------------------------------------------------
# snapshot
# ---------------------------------------------------------------------------

def snapshot(c: Campaign, harness: str = "", *, env=None, now: int | None = None,
             refresh_current: bool = True) -> SnapshotResult:
    """Write one harness's coverage snapshot (see module docstring)."""
    env = os.environ if env is None else env
    root = c.project_root
    lay = c.layout()
    harness = harness or lay.default_harness()
    ts = int(time.time()) if now is None else now
    msgs: list[str] = []

    def io_(p) -> Path:
        return Path(p) if os.path.isabs(p) else root / p

    state_dir = env.get("FUZZ_STATE_DIR") or "fuzz/state"
    snapshots = f"{state_dir}/snapshots"
    cov_dir = io_(env.get("FUZZ_COV_DIR") or str(lay.coverage_dir(harness)))
    corpus_dir = io_(env.get("FUZZ_CORPUS_DIR") or str(lay.corpus_dir(harness)))
    for d in (io_(state_dir), io_(snapshots), cov_dir):
        d.mkdir(parents=True, exist_ok=True)
    out_file = f"{snapshots}/{HarnessLayout.coverage_snapshot_name(harness, ts)}"

    # 1. tools
    llvm_cov = tools.which("llvm-cov", c, env=env) or ""
    llvm_profdata = tools.which("llvm-profdata", c, env=env) or ""
    llvm_ok = bool(llvm_cov and llvm_profdata)

    # 2. the harness record
    rec = lay.harness_record(harness) or {}

    def field_text(name):
        t = _field_text(rec.get(name))
        return "" if t in (None, "None") else t

    coverage_binary = field_text("coverage_binary")
    tracking = field_text("coverage_tracking") != "False"
    build_present = bool(coverage_binary) and _executable(str(io_(coverage_binary)))
    dso_list = []
    dso_text = field_text("coverage_dso")
    if dso_text:
        try:
            v = json.loads(dso_text)
            dso_list = [str(x) for x in v] if isinstance(v, list) else []
        except Exception:
            pass

    # 3. engine + fuzzer stats
    engine, execs, paths, crashes, hangs, rate = "unknown", 0, 0, 0, 0, "0"
    parsed, fork_mode = False, False
    out_dir = io_(env.get("FUZZ_OUT_DIR") or str(lay.harness_root(harness) / "aflpp-out"))
    manifest = io_(state_dir) / "fuzzers.json"
    lf_log = libfuzzer_slot_field(manifest, harness, "log_file")
    stats = [str(i / "fuzzer_stats") for i in HarnessLayout.afl_instances(out_dir)
             if (i / "fuzzer_stats").is_file()]
    crashes_root = env.get("FUZZ_CRASHES_DIR") or "fuzz/crashes"
    if stats:
        engine = "aflpp"
        execs, paths, crashes, hangs, rate = aggregate_afl_stats(stats)
        if len(stats) > 1:
            msgs.append(f"snapshot: aggregated {len(stats)} AFL++ instances (execs={execs}, corpus={paths} max)")
        parsed = True
    elif lf_log and io_(lf_log).is_file():
        engine = "libfuzzer"
        log_text = io_(lf_log).read_text(errors="replace")
        if "-fork=" in log_text or _FORK_LOG_RE.search(log_text):
            fork_mode = True
        pid = ""
        pid_file = libfuzzer_slot_field(manifest, harness, "pid_file") or f"{state_dir}/fuzzer.pid"
        if io_(pid_file).is_file():
            try:
                pid = io_(pid_file).read_text().rstrip("\n")
            except OSError:
                pid = ""
            if pid:
                try:
                    if "-fork=" in Path(f"/proc/{pid}/cmdline").read_bytes().replace(b"\0", b" ").decode(errors="replace"):
                        fork_mode = True
                except OSError:
                    pass
                if os.path.isdir(f"/tmp/libFuzzerTemp.FuzzWithFork{pid}.dir"):
                    fork_mode = True
        last = _last_status(io_(lf_log))
        if last:
            p_execs, p_paths, p_rate = parse_status_line(last)
            if p_execs > 0:
                execs, paths, rate, parsed = p_execs, p_paths, str(p_rate), True
        if fork_mode and pid:
            fork_dir = Path(f"/tmp/libFuzzerTemp.FuzzWithFork{pid}.dir")
            if fork_dir.is_dir():
                worker_logs = sorted(glob.glob(str(fork_dir / "*.log")))
                status = []
                for wl in worker_logs:
                    try:
                        status += [ln.rstrip("\n") for ln in open(wl, errors="replace") if _STATUS_RE.match(ln)]
                    except OSError:
                        pass
                if status:
                    def key(ln):  # sort -t'#' -k2 -n
                        m = re.match(r"\s*([0-9]+)", ln.split("#", 2)[1] if "#" in ln else "")
                        return int(m.group(1)) if m else 0
                    f_execs, f_paths, f_rate = parse_status_line(sorted(status, key=key)[-1])
                    fork_count = max(1, len(worker_logs))
                    if f_execs > execs:
                        execs, paths = f_execs, f_paths
                    if f_rate > 0:
                        rate = str(f_rate * fork_count)
                    parsed = True
        if not parsed and _JOB_EXITED_RE.search(log_text):
            parsed, execs, paths, rate = True, 0, 0, "0"
        crashes = 0
        for sub in ("new", "known"):
            for dp, _dirs, fns in os.walk(io_(f"{crashes_root}/{sub}")):
                crashes += sum(1 for fn in fns if fn.endswith(".bin") and os.path.isfile(os.path.join(dp, fn))
                               and not os.path.islink(os.path.join(dp, fn)))

    # 4. coverage measurement
    cov_lines, cov_total, cov_pct, cov_run_ok = 0, 0, 0, False
    input_dirs = [corpus_dir] if corpus_dir.is_dir() else []
    if out_dir.is_dir():
        input_dirs += [i / "queue" for i in HarnessLayout.afl_instances(out_dir) if (i / "queue").is_dir()]
    if tracking and build_present and llvm_ok:
        cov_bin = str(io_(coverage_binary))
        profraw, profdata = cov_dir / "default.profraw", cov_dir / "default.profdata"
        for p in [profraw, profdata, *map(Path, glob.glob(str(cov_dir / "snap_*.profraw")))]:
            try:
                p.unlink()
            except OSError:
                pass
        if input_dirs:
            run_env = dict(env)
            run_env["LLVM_PROFILE_FILE"] = str(cov_dir / "snap_%p.profraw")
            max_samples = _int_or_zero(env.get("SNAPSHOT_COVERAGE_MAX_SAMPLES") or str(DEFAULT_MAX_SAMPLES))
            sampled = 0
            # Named predicate seeds first (they live only in corpus/), then a
            # random sample of everything else.
            for pat in ("seed_*.bin", "seed_*.txt"):
                for f in sorted(glob.glob(str(corpus_dir / pat))):
                    if os.path.isfile(f):
                        _run([cov_bin, f], env=run_env, timeout=RUN_TIMEOUT_S, cwd=root)
                        sampled += 1
            if sampled < max_samples:
                pool = [f for d in input_dirs for f in _files_in(d) if not os.path.basename(f).startswith("seed_")]
                random.shuffle(pool)
                for f in pool[:max_samples - sampled]:
                    _run([cov_bin, f], env=run_env, timeout=RUN_TIMEOUT_S, cwd=root)
            snaps = sorted(glob.glob(str(cov_dir / "snap_*.profraw")))
            if snaps:
                _run([llvm_profdata, "merge", "-sparse", *snaps, "-o", str(profraw)])
                for s in snaps:
                    try:
                        os.unlink(s)
                    except OSError:
                        pass
            if profraw.is_file():
                r = _run([llvm_profdata, "merge", "-sparse", str(profraw), "-o", str(profdata)])
                if r is not None and r.returncode == 0:
                    objects = list(dso_list)
                    ldd = tools.which("ldd", c, env=env)
                    if ldd:
                        lr = _run([ldd, cov_bin])
                        for line in (lr.stdout.decode(errors="replace") if lr else "").split("\n"):
                            parts = line.split()  # awk '/=>/ {print $3}'
                            if "=>" in line and len(parts) >= 3 and _LIB_DIR_RE.search(parts[2]):
                                objects.append(parts[2])
                    objects = sorted({p for p in objects if os.path.isfile(p)})
                    obj_args = [a for p in objects for a in ("-object", p)]
                    sr = _run([llvm_cov, "export", cov_bin, *obj_args, f"-instr-profile={profdata}",
                               "--summary-only"])
                    summary = sr.stdout.decode(errors="replace") if sr else ""
                    if summary.strip():
                        cov_lines, cov_total, cov_pct = cov_summary(summary)
                        cov_run_ok = True

    # 5. crashes since this harness's previous snapshot
    prev = _newest_snapshot(io_(snapshots), harness)
    prev_ts = 0
    if prev is not None:
        stem = re.sub(rf"^coverage-({re.escape(harness)}-)?", "", prev.name, count=1)
        stem = re.sub(r".json$", "", stem, count=1)
        prev_ts = int(stem) if stem.isdigit() and stem.isascii() else 0
    new_crashes = []
    new_dir = io_(f"{crashes_root}/new")
    for dp, dirs, fns in os.walk(new_dir):
        dirs.sort()
        for fn in sorted(fns):
            fp = os.path.join(dp, fn)
            if not fnmatch.fnmatchcase(fn, f"{harness}__*.bin") or os.path.islink(fp) or not os.path.isfile(fp):
                continue
            if os.stat(fp).st_mtime > prev_ts:
                rel = f"{crashes_root}/new" + fp[len(str(new_dir)):]
                new_crashes.append(rel)
    # sorted, and only then capped: readdir order would otherwise decide WHICH
    # 50 crashes a snapshot reports, not just the order they appear in
    new_crashes = sorted(new_crashes)[:50]

    # 6. top unreached functions
    unreached = []
    profdata = cov_dir / "default.profdata"
    if cov_run_ok and profdata.is_file():
        r = _run([llvm_cov, "export", str(io_(coverage_binary)), f"-instr-profile={profdata}"])
        unreached = unreached_functions(r.stdout.decode(errors="replace")) if r else []

    # 7. strict instrumentation check
    errs = []
    if tracking:
        if not llvm_ok:
            errs.append("llvm-cov/llvm-profdata not found in PATH or /usr/lib/llvm-*/bin/")
        if not build_present:
            errs.append("coverage_binary missing or not executable per harness-built.json")
        if cov_lines == 0 and cov_total == 0 and build_present:
            errs.append("coverage run produced zero lines despite instrumented build - check LLVM_PROFILE_FILE handling")
    if not parsed and engine != "unknown":
        if not (fork_mode and cov_lines > 0):  # fork mode with valid coverage: zero exec stats are expected
            errs.append(f"engine {engine} detected but log parsing failed - exec stats will be zero")
    ok = not errs

    def b(v):
        return "true" if v else "false"

    text = (
        "{\n"
        f'  "schema": "{SCHEMA}",\n'
        f'  "harness": "{harness}",\n'
        f'  "timestamp": {ts},\n'
        f'  "engine": "{engine}",\n'
        '  "fuzzer_stats": {\n'
        f'    "execs": {execs},\n'
        f'    "paths": {paths},\n'
        f'    "crashes": {crashes},\n'
        f'    "hangs": {hangs},\n'
        f'    "execs_per_sec": {rate}\n'
        "  },\n"
        '  "coverage": {\n'
        f'    "lines_covered": {cov_lines},\n'
        f'    "lines_total": {cov_total},\n'
        f'    "line_pct": {cov_pct}\n'
        "  },\n"
        '  "instrumentation": {\n'
        f'    "tracking_enabled": {b(tracking)},\n'
        f'    "coverage_build_present": {b(build_present)},\n'
        f'    "llvm_cov_available": {b(llvm_ok)},\n'
        f'    "coverage_run_ok": {b(cov_run_ok)},\n'
        f'    "parsed_engine_log": {b(parsed)},\n'
        f'    "fork_mode": {b(fork_mode)},\n'
        f'    "ok": {b(ok)},\n'
        f'    "errors": {json.dumps(errs)}\n'
        "  },\n"
        f'  "previous_snapshot_ts": {prev_ts},\n'
        f'  "new_crashes_since_previous": {json.dumps(new_crashes)},\n'
        f'  "top_unreached_functions": {json.dumps(unreached)}\n'
        "}\n"
    )
    io_(out_file).write_text(text)
    try:
        doc = json.loads(text)
    except ValueError:
        doc = {}

    if refresh_current:
        from cc_fuzzer_core.state import update_current
        with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
            try:
                update_current(c)
            except Exception:
                pass
    warning = None
    if not ok and tracking:
        warning = (f"WARN: instrumentation is broken - see fuzz/state/snapshots/coverage-{ts}.json "
                   "instrumentation.errors")
    return SnapshotResult(out_file, doc, ok, tracking, msgs, warning)


# ---------------------------------------------------------------------------
# CLI: cc-fuzzer coverage snapshot
# ---------------------------------------------------------------------------

def _cmd_snapshot(a):
    harness, args = "", list(a.args)
    while args:
        arg = args.pop(0)
        if arg == "--harness":
            harness = args.pop(0) if args else ""
        elif arg in ("-h", "--help"):
            sys.stdout.write(__doc__.split("\n\n")[1] + "\n\nUsage: cc-fuzzer coverage snapshot "
                             "[--harness <name>]   (default: every declared harness)\n")
            return 0
        else:
            sys.stderr.write(f"ERROR: unknown arg '{arg}'\n")
            return 2
    try:
        c = _campaign()
    except CampaignError as e:
        sys.stderr.write(f"{e}\n")
        return e.code
    for h in ([harness] if harness else c.layout().declared_harnesses()):
        r = snapshot(c, h)
        for m in r.messages:
            sys.stderr.write(m + "\n")
        sys.stdout.write(r.path + "\n")
        sys.stdout.flush()
        if r.warning:
            sys.stderr.write(r.warning + "\n")
    return 0


def register_cli(subparsers):
    from cc_fuzzer_core.cli import add_raw_verb, add_subsystem

    _p, verbs = add_subsystem(subparsers, "coverage", "coverage snapshots")
    add_raw_verb(verbs, "coverage", "snapshot", _cmd_snapshot,
                 "write coverage-<harness>-<ts>.json (port of snapshot-coverage.sh); [--harness H]")
