"""Queue fuzzer-found crash files for triage (port of scripts/detect-crashes.sh).

detect(campaign) -> DetectResult. The first stage of the crash flow in
STATE_SCHEMA.md: while at least one fuzzer slot is alive, every crash-like file
in an engine location modified in the last 5 minutes is hard-linked (copied
across filesystems) into fuzz/crashes/new/<harness>__<sha256[:16]>.bin. The
harness comes from the path (fuzz/harnesses/<harness>/...), "unknown" when it
can't be derived. Files already queued, or byte-identical to a known finding's
repro / duplicate, are skipped.

Scanned (find . -maxdepth 6 under the project root, as before):
  */crashes/id:*   AFL++          crash-* leak-* oom-* timeout-*   libFuzzer

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

MAX_DEPTH = 6
RECENT_SECONDS = 5 * 60
_NAME_PATTERNS = ("crash-*", "leak-*", "oom-*", "timeout-*")
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


def _is_candidate(rel: str, name: str) -> bool:
    return fnmatch.fnmatchcase(rel, "*/crashes/id:*") or any(
        fnmatch.fnmatchcase(name, p) for p in _NAME_PATTERNS)


def candidates(root: Path, *, now: float, exclude=()) -> list[str]:
    """Crash-like files under root (depth <= MAX_DEPTH, symlinks not followed)
    modified within RECENT_SECONDS of `now` (or later), as "./rel" paths in
    directory order, excluding anything under an `exclude` dir."""
    excl = [os.path.abspath(e) for e in exclude]
    out: list[str] = []

    def walk(d: str, rel: str, depth: int):
        try:
            entries = list(os.scandir(d))
        except OSError:
            return
        for e in entries:
            r = f"{rel}/{e.name}"
            if any(e.path == x or e.path.startswith(x + os.sep) for x in excl):
                continue
            try:
                if e.is_file(follow_symlinks=False):
                    if _is_candidate(r, e.name) and e.stat(follow_symlinks=False).st_mtime > now - RECENT_SECONDS:
                        out.append(r)
                elif e.is_dir(follow_symlinks=False) and depth < MAX_DEPTH:
                    walk(e.path, r, depth + 1)
            except OSError:
                continue

    walk(str(root), ".", 1)
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
    new_dir, known, flaky = crashes / "new", crashes / "known", crashes / "flaky"
    result = DetectResult(new_dir=new_dir, alive=any_slot_alive(c.state_dir))
    if not result.alive:
        return result
    new_dir.mkdir(parents=True, exist_ok=True)
    for rel in candidates(c.project_root, now=now, exclude=(new_dir, known, flaky)):
        src = c.project_root / rel[2:]
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
        result.queued.append((rel[2:], os.path.relpath(target, c.project_root)))
    return result
