"""Queue fuzzer-found crash files for triage (port of scripts/detect-crashes.sh).

detect(campaign) -> DetectResult. The first stage of the crash flow in
STATE_SCHEMA.md: while at least one fuzzer slot is alive, every crash-like file
in an engine location modified in the last 5 minutes is hard-linked (copied
across filesystems) into fuzz/crashes/new/<harness>__<sha256[:16]>.bin. The
harness comes from the path (fuzz/harnesses/<harness>/...), "unknown" when it
can't be derived. Files already queued, or byte-identical to a known finding's
repro / duplicate, are skipped.

Scanned: only the output locations the slot launcher (slots/launcher.py) gives
the engines, for every fuzz/harnesses/<h>/:
  <h>/.libfuzzer-cwd/{crash,leak,oom,timeout}-*   libFuzzer (its cwd; artifacts
                                                  land directly in it)
  <h>/aflpp-out/<instance>/crashes/id:*           AFL++ (-o <h>/aflpp-out; the
                                                  instance is the -M/-S name or
                                                  "default")
(This used to be a depth-6 `find` over the whole project, which never reached
the AFL++ crashes (depth 7) and matched crash-*-named source files anywhere.)

The core only returns data; telling the host about queued crashes (the plugin's
PostToolUse hook JSON) is the caller's job.
"""
from __future__ import annotations

import fnmatch
import hashlib
import json
import os
import re
import shutil
import time
from dataclasses import dataclass, field
from pathlib import Path

from cc_fuzzer_core.paths import Campaign, HarnessLayout

RECENT_SECONDS = 5 * 60
LIBFUZZER_DIR = ".libfuzzer-cwd"
AFL_OUT_DIR = "aflpp-out"
LIBFUZZER_PATTERNS = ("crash-*", "leak-*", "oom-*", "timeout-*")
AFL_CRASH_PATTERN = "id:*"
_HARNESS_IN_PATH_RE = re.compile(r"^(.*/)?fuzz/harnesses/([a-z0-9][a-z0-9_-]{0,31})/")


@dataclass
class DetectResult:
    new_dir: Path
    alive: bool                              # False => nothing was scanned
    queued: list = field(default_factory=list)   # [(source, staged)] as project-relative strings

    @property
    def count(self) -> int:
        return len(self.queued)

    def to_dict(self) -> dict:
        return {"alive": self.alive, "new_dir": str(self.new_dir), "queued": self.count,
                "files": [{"source": s, "staged": d} for s, d in self.queued]}


def _pid_alive(pid) -> bool:
    try:
        pid = int(str(pid).strip())
        if pid <= 0:
            return False
        os.kill(pid, 0)
        return True
    except (ValueError, OSError):  # EPERM counts as dead, like `kill -0`
        return False


def any_slot_alive(state_dir: Path) -> bool:
    """Any live slot in fuzzers.json; the legacy fuzzer.pid when there is no
    manifest."""
    manifest = state_dir / "fuzzers.json"
    if manifest.is_file():
        try:
            doc = json.loads(manifest.read_text())
            return any(_pid_alive(s.get("pid", "")) for s in doc.get("slots", []) if s.get("pid"))
        except Exception:
            return False
    legacy = state_dir / "fuzzer.pid"
    if legacy.is_file():
        try:
            return _pid_alive(legacy.read_text())
        except OSError:
            return False
    return False


def harness_from_path(rel: str) -> str | None:
    m = _HARNESS_IN_PATH_RE.match(rel[2:] if rel.startswith("./") else rel)
    return m.group(2) if m else None


def _sha256(path: Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def _subdirs(d: Path) -> list[os.DirEntry]:
    try:
        return sorted((e for e in os.scandir(d) if e.is_dir(follow_symlinks=False)), key=lambda e: e.name)
    except OSError:
        return []


def _recent_files(d: Path, patterns, now: float) -> list[str]:
    """Names of regular files (symlinks not followed) directly in d matching
    one of `patterns` and modified within RECENT_SECONDS of `now` (or later)."""
    out = []
    try:
        entries = sorted(os.scandir(d), key=lambda e: e.name)
    except OSError:
        return out
    for e in entries:
        try:
            if (e.is_file(follow_symlinks=False) and any(fnmatch.fnmatchcase(e.name, p) for p in patterns)
                    and e.stat(follow_symlinks=False).st_mtime > now - RECENT_SECONDS):
                out.append(e.name)
        except OSError:
            continue
    return out


def candidates(c: Campaign, *, now: float) -> list[str]:
    """Recent crash files in the engines' output locations (module
    docstring), as project-relative paths, harness by harness."""
    out: list[str] = []
    for h in _subdirs(c.harnesses_dir):
        root = Path(h.path)
        rel = os.path.relpath(root, c.project_root)
        for name in _recent_files(root / LIBFUZZER_DIR, LIBFUZZER_PATTERNS, now):
            out.append(f"{rel}/{LIBFUZZER_DIR}/{name}")
        for inst in _subdirs(root / AFL_OUT_DIR):
            crashes = Path(inst.path) / "crashes"
            for name in _recent_files(crashes, (AFL_CRASH_PATTERN,), now):
                out.append(f"{rel}/{AFL_OUT_DIR}/{inst.name}/crashes/{name}")
    return out


def _known_digests(known: Path, short: str) -> set[str]:
    found = set()
    if not known.is_dir():
        return found
    for dirpath, _dirs, files in os.walk(known):
        for fn in files:
            if fn == "repro.bin" or fnmatch.fnmatchcase(fn, f"*{short}*.bin"):
                try:
                    found.add(_sha256(Path(dirpath) / fn))
                except OSError:
                    pass
    return found


def detect(c: Campaign, *, now: float | None = None) -> DetectResult:
    """Queue recent crash files for triage (see module docstring)."""
    now = time.time() if now is None else now
    crashes = c.crashes_dir
    new_dir, known = crashes / "new", crashes / "known"
    result = DetectResult(new_dir=new_dir, alive=any_slot_alive(c.state_dir))
    if not result.alive:
        return result
    new_dir.mkdir(parents=True, exist_ok=True)
    for rel in candidates(c, now=now):
        src = c.project_root / rel
        try:
            digest = _sha256(src)
        except OSError:
            continue
        short = digest[:16]
        harness = harness_from_path(rel) or "unknown"
        target = new_dir / HarnessLayout.crash_filename(harness, short)
        if target.is_file():
            continue  # already queued
        if digest in _known_digests(known, short):
            continue
        try:
            os.link(src, target)
        except OSError:
            try:
                shutil.copy(src, target)
            except OSError:
                continue
        result.queued.append((rel, os.path.relpath(target, c.project_root)))
    return result
