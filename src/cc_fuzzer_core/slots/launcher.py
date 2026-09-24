"""Launch one fuzzer slot (port of scripts/launch-fuzzer-slot.sh + _lib/launch_slot.py).

launch(campaign, SlotRequest) -> LaunchResult. A slot is one fuzzer process
bound to one declared harness, with its own pid / engine / log files in the
state dir and an entry in fuzzers.json (fuzzers/v2). The process is started in
the background (SIGHUP ignored, stdin from /dev/null, stdout+stderr to the slot
log) and outlives the caller.

  libFuzzer  cwd fuzz/harnesses/<h>/.libfuzzer-cwd/ (so ./crash-* attribute to
             the harness); -fork=N from --libfuzzer-forks or fuzz_forks.
  AFL++      cwd = project root; -o fuzz/harnesses/<h>/aflpp-out; -M/-S role,
             -p schedule, -c cmplog binary, -x per-harness merged dict.

Refusals (same messages and exit codes as the script): undeclared harness (2),
bad slot name (2), binary not executable (2), safety-defeating ASAN_OPTIONS /
UBSAN_OPTIONS (2), slot already running (3), undetectable engine (1), bad
engine / role / schedule / timeout (2), afl-fuzz missing (1).

Paths are printed and recorded the way the script did (the state dir as
${FUZZ_STATE_DIR:-<abs fuzz>/state}, harness record paths as written), but every
file is opened against the project root: a relative FUZZ_STATE_DIR used to make
the libFuzzer launch (which cd's into its cwd first) fail to open its log.

Tools (nm, afl-fuzz) resolve through cc_fuzzer_core.tools.which.
"""
from __future__ import annotations

import json
import os
import re
import signal
import subprocess
import time
from dataclasses import dataclass, field
from pathlib import Path

from cc_fuzzer_core import enums, tools
from cc_fuzzer_core.config import resolve_fuzz_forks
from cc_fuzzer_core.paths import Campaign, _field_text, state_dir_text

MANIFEST_SCHEMA = "fuzzers/v2"
POWER_SCHEDULES = ("explore", "exploit", "fast", "coe", "quad", "lin", "seek", "rare")
_SLOT_RE = re.compile(r"^[a-z0-9-]+$")
_UNSAFE_SAN_OPTS = ("abort_on_error=0", "detect_leaks=0", "halt_on_error=0")
_INT_RE = re.compile(r"^\s*[+-]?[0-9]+\s*$")


@dataclass
class SlotRequest:
    """launch-fuzzer-slot.sh's arguments ("" = not given)."""
    slot: str = "main"
    engine: str = "auto"
    harness: str = ""
    binary: str = ""
    corpus: str = ""
    role: str = ""
    power_schedule: str = ""
    libfuzzer_forks: str = ""
    timeout_ms: str = ""
    restart_of: str = ""


@dataclass
class LaunchResult:
    code: int
    out: str = ""
    err: str = ""
    pid: int | None = None
    entry: dict | None = None   # the fuzzers.json slot entry written


@dataclass
class SlotBinaries:
    """Which binaries a slot runs. The one place a slot's binaries are chosen
    (UPDATE_ROADMAP.md §12 will route this through variants.select)."""
    harness_binary: str
    cmplog_binary: str = ""
    cmplog_enabled: bool = False


class _Refuse(Exception):
    def __init__(self, code: int, message: str):
        super().__init__(message)
        self.code = code


def _text(v) -> str:
    """A harness record field as harness-path.sh printed it ("" for null)."""
    t = _field_text(v)
    return "" if t is None else t


def resolve_binaries(c: Campaign, harness: str, requested: str = "") -> SlotBinaries:
    """The slot's harness binary (--binary, else the harness record's
    harness_binary) and, for AFL++, its cmplog binary."""
    rec = c.layout().harness_record(harness) or {}
    cmplog_bin = _text(rec.get("cmplog_binary"))
    return SlotBinaries(
        harness_binary=requested or _text(rec.get("harness_binary")),
        cmplog_binary="" if cmplog_bin == "None" else cmplog_bin,
        cmplog_enabled=_text(rec.get("cmplog_enabled")) in ("True", "true"),
    )


def _dict_files(value) -> list[str]:
    """dict_files may be a JSON array or a bare string (single dict)."""
    val = _text(value)
    if not val or val == "None":
        return []
    try:
        arr = json.loads(val) if val.startswith("[") else [val]
        return [f for f in arr if f]
    except Exception:
        return []


def _pid_alive(pid) -> bool:
    try:
        pid = int(str(pid).strip())
        if pid <= 0:
            return False
        os.kill(pid, 0)
        return True
    except (ValueError, OSError):
        return False


def _detect_engine(binary_abs: str) -> str | None:
    nm = tools.which("nm")
    if nm:
        try:
            out = subprocess.run([nm, binary_abs], capture_output=True, timeout=60).stdout
            if b"LLVMFuzzerTestOneInput" in out:
                return "libfuzzer"
        except (OSError, subprocess.SubprocessError):
            pass
    if tools.which("afl-fuzz"):
        return "aflpp"
    return None


def _ignore_sighup():  # nohup
    signal.signal(signal.SIGHUP, signal.SIG_IGN)


def _spawn(argv, cwd: Path, log: Path) -> int:
    with open(log, "wb") as out:
        proc = subprocess.Popen(argv, cwd=cwd, stdin=subprocess.DEVNULL, stdout=out,
                                stderr=subprocess.STDOUT, preexec_fn=_ignore_sighup, close_fds=True)
    return proc.pid


def update_manifest(manifest: Path, entry: dict, *, restart_of: str = "") -> dict:
    """Upsert entry (keyed by slot) into fuzzers.json atomically. restart_count
    carries over from the previous entry, +1 when restart_of is set (which also
    stamps last_restart_at = started_at)."""
    if entry["engine"] not in enums.ENGINES:
        raise ValueError("launch_slot: invalid engine '%s' (expected one of: %s)"
                         % (entry["engine"], ", ".join(sorted(enums.ENGINES))))
    try:
        with open(manifest) as f:
            doc = json.load(f)
        if doc.get("schema") != MANIFEST_SCHEMA:
            doc = {"schema": MANIFEST_SCHEMA, "slots": []}
    except Exception:
        doc = {"schema": MANIFEST_SCHEMA, "slots": []}
    slots = doc["slots"]
    idx = next((i for i, s in enumerate(slots) if s.get("slot") == entry["slot"]), None)
    restart_count, last_restart_at = 0, None
    if idx is not None:
        prev = slots[idx]
        restart_count = int(prev.get("restart_count", 0))
        if restart_of:
            restart_count += 1
            last_restart_at = entry["started_at"]
        else:
            last_restart_at = prev.get("last_restart_at")
    harness = entry.pop("harness", "")
    entry.update(restart_count=restart_count, last_restart_at=last_restart_at)
    entry["harness"] = harness
    if idx is None:
        slots.append(entry)
    else:
        slots[idx] = entry
    tmp = Path(str(manifest) + ".tmp")
    with open(tmp, "w") as f:
        json.dump(doc, f, indent=2)
    os.replace(tmp, manifest)
    return entry


def launch(c: Campaign, req: SlotRequest, *, env=None) -> LaunchResult:
    """Launch one slot (see module docstring). Never raises for a refusal:
    LaunchResult.code / .err carry it."""
    env = os.environ if env is None else env
    err: list[str] = []
    try:
        return _launch(c, req, env, err)
    except _Refuse as e:
        err.append(str(e))
        return LaunchResult(e.code, "", "".join(f"{ln}\n" for ln in err))


def _launch(c: Campaign, req: SlotRequest, env, err: list) -> LaunchResult:
    root = c.project_root
    lay = c.layout()

    def io(p) -> Path:  # a displayed path, opened against the project root
        return Path(p) if os.path.isabs(p) else root / p

    def abs_(p: str) -> str:  # launch-fuzzer-slot.sh's _abs
        if os.path.isabs(p):
            return p
        return os.path.realpath(root / p) if (root / p).exists() else f"{root}/{p}"

    state_dir = state_dir_text(c, env)
    slot, engine, harness = req.slot, req.engine, req.harness

    # Harness binding: --harness, else the first declared harness.
    if not harness:
        harness = lay.default_harness()
    if not harness:
        raise _Refuse(2, "ERROR: no --harness <name> given and no declared harness resolvable")
    if not lay.is_known_harness(harness):
        raise _Refuse(2, f"ERROR: harness '{harness}' is not declared in fuzz-config.json:harnesses[]")

    bins = resolve_binaries(c, harness, req.binary)
    binary = bins.harness_binary
    # The per-harness corpus is authoritative; the retired singular fuzz/corpus
    # is overridden with a warning, any other explicit --corpus honoured.
    per_harness = str(lay.corpus_dir(harness))
    corpus = req.corpus
    if not corpus:
        corpus = per_harness
    elif corpus == "fuzz/corpus" or corpus.endswith("/fuzz/corpus"):
        err.append(f"WARN: --corpus pointed at the retired singular '{corpus}'; using per-harness {per_harness}")
        corpus = per_harness

    if not _SLOT_RE.match(slot):
        raise _Refuse(2, f"ERROR: invalid --slot '{slot}' (must match ^[a-z0-9-]+$)")
    if len(slot) > 32:
        raise _Refuse(2, "ERROR: --slot too long (max 32 chars)")
    if not binary:
        raise _Refuse(2, "ERROR: --binary is required")
    if not (io(binary).is_file() and os.access(io(binary), os.X_OK)):
        raise _Refuse(2, f"ERROR: binary not executable: {binary}")

    out_root = env.get("FUZZ_OUT_DIR") or f"{root}/out"
    for d in (state_dir, out_root, corpus):
        io(d).mkdir(parents=True, exist_ok=True)

    for var in ("ASAN_OPTIONS", "UBSAN_OPTIONS"):
        val = env.get(var, "")
        if any(o in val for o in _UNSAFE_SAN_OPTS):
            raise _Refuse(2, f"ERROR: {var} contains a safety-defeating option: {val}\n"
                             f"       refusing to launch. Unset or fix {var} and retry.")

    pid_file = f"{state_dir}/fuzzer-{slot}.pid"
    engine_file = f"{state_dir}/fuzzer-{slot}.engine"
    log_file = f"{state_dir}/fuzzer-{slot}.log"

    try:
        existing = "".join(io(pid_file).read_text().split())
    except OSError:
        existing = ""
    if existing and _pid_alive(existing):
        raise _Refuse(3, f"ERROR: slot '{slot}' already running (PID {existing})\n"
                         f"       stop-fuzzer.sh --slot {slot} first if you want to restart it.")

    if engine == "auto":
        engine = _detect_engine(str(io(binary)))
        if engine is None:
            raise _Refuse(1, f"ERROR: cannot auto-detect engine for {binary} (no LLVMFuzzerTestOneInput "
                             "symbol and afl-fuzz not in PATH)")
    if engine not in enums.ENGINES:
        raise _Refuse(2, f"ERROR: invalid --engine '{engine}' (expected libfuzzer or aflpp)")

    rec = lay.harness_record(harness) or {}
    fuzzing_mode = _text(rec.get("fuzzing_mode")) or "in_process"

    # Per-input timeout: explicit, else 5000 ms for AFL++ process_based targets
    # (AFL's 1000 ms calibration kills slow-start seeds), else 1000 ms.
    timeout_ms = req.timeout_ms
    if not timeout_ms:
        timeout_ms = "5000" if engine == "aflpp" and fuzzing_mode == "process_based" else "1000"
    if not timeout_ms.isdigit() or not timeout_ms.isascii():
        raise _Refuse(2, f"ERROR: --timeout-ms must be a positive integer (got '{timeout_ms}')")
    if int(timeout_ms) < 100:
        raise _Refuse(2, "ERROR: --timeout-ms below 100ms floor")

    dict_files = _dict_files(rec.get("dict_files"))

    slot_cwd = lay.harness_root(harness) / ".libfuzzer-cwd"
    afl_out = str(lay.harness_root(harness) / "aflpp-out")
    slot_cwd.mkdir(parents=True, exist_ok=True)
    io(afl_out).mkdir(parents=True, exist_ok=True)

    if engine == "libfuzzer":
        forks = req.libfuzzer_forks
        if not forks:
            r = resolve_fuzz_forks(c, env)
            if r.warning:
                err.append(r.warning)
            forks = r.value
        dict_flags = [f"-dict={abs_(df)}" for df in dict_files if io(df).is_file()]
        fork_on = bool(_INT_RE.match(forks)) and int(forks) > 0
        mode = f"mode={fuzzing_mode}, harness={harness}"
        if fork_on:
            fork_flags = [f"-fork={forks}"]
            err.append(f"slot={slot}: launching libFuzzer with -fork={forks} ({mode})")
        else:
            fork_flags = []
            err.append(f"slot={slot}: launching libFuzzer single-process (fuzz_forks=0, {mode})")
        rss_mb, extra = 2048, []
        if fuzzing_mode == "process_based":
            extra, rss_mb = ["-close_fd_mask=3"], 4096
        lf_timeout = max(1, (int(timeout_ms) + 999) // 1000)  # libFuzzer -timeout is seconds
        argv = [abs_(binary), abs_(corpus), *dict_flags, *fork_flags, *extra,
                "-print_final_stats=1", f"-timeout={lf_timeout}", f"-rss_limit_mb={rss_mb}", "-print_pcs=0"]
        pid = _spawn(argv, slot_cwd, io(log_file))
    else:
        afl = tools.which("afl-fuzz")
        if not afl:
            raise _Refuse(1, "ERROR: --engine aflpp but afl-fuzz not in PATH")
        dict_flag = []
        if dict_files:
            # Per-harness merged dict so harnesses don't stomp on each other.
            merged = f"{state_dir}/merged-dict-{harness}.dict"
            with open(io(merged), "wb") as f:
                for df in dict_files:
                    if io(df).is_file():
                        f.write(f"# === {df} ===\n".encode())
                        f.write(io(df).read_bytes())
                        f.write(b"\n")
            dict_flag = ["-x", merged]
        cmplog_flag = []
        cb = bins.cmplog_binary
        if bins.cmplog_enabled and cb and io(cb).is_file() and os.access(io(cb), os.X_OK):
            cmplog_flag = ["-c", cb]
            err.append(f"slot={slot}: cmplog enabled ({cb})")
        role_flag = {"master": ["-M", slot], "secondary": ["-S", slot], "": []}.get(req.role)
        if role_flag is None:
            raise _Refuse(2, f"ERROR: invalid --role '{req.role}' (expected master or secondary)")
        power_flag = []
        if req.power_schedule:
            if req.power_schedule not in POWER_SCHEDULES:
                raise _Refuse(2, f"ERROR: invalid --power-schedule '{req.power_schedule}'")
            power_flag = ["-p", req.power_schedule]
        target_args = ["@@"] if fuzzing_mode == "process_based" else []
        err.append(f"slot={slot}: launching AFL++ (role={req.role or 'standalone'}, "
                   f"schedule={req.power_schedule or 'default'}, mode={fuzzing_mode}, "
                   f"timeout={timeout_ms}ms, harness={harness})")
        # -t <ms>+ : skip (don't abort on) seeds that time out during the dry run.
        argv = [afl, "-t", f"{timeout_ms}+", *dict_flag, *cmplog_flag, *role_flag, *power_flag,
                "-i", corpus, "-o", afl_out, "--", binary, *target_args]
        pid = _spawn(argv, root, io(log_file))

    io(pid_file).write_text(f"{pid}\n")
    io(engine_file).write_text(f"{engine}\n")
    try:
        pgid = os.getpgid(pid)
    except OSError:
        pgid = pid
    started_at = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
    entry = update_manifest(io(f"{state_dir}/fuzzers.json"), {
        "slot": slot,
        "engine": engine,
        "binary": binary,
        "pid": str(pid),
        "pgid": str(pgid),
        "started_at": started_at,
        "log_file": log_file,
        "pid_file": pid_file,
        "engine_file": engine_file,
        "role": req.role or None,
        "afl_power_schedule": req.power_schedule or None,
        "harness": harness,
    }, restart_of=req.restart_of)
    out = f"slot={slot} engine={engine} pid={pid} pgid={pgid} log={log_file}\n"
    return LaunchResult(0, out, "".join(f"{ln}\n" for ln in err), pid, entry)
