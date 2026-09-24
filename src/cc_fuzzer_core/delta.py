"""Git-diff "recently changed" targets (port of scripts/find-delta-targets.sh).

find_targets(campaign, range_=None) -> DeltaResult. Writes
<state>/snapshots/delta-<ts>.json (schema delta-targets/v1): the commits in the
range and one target per `git diff --unified=0` hunk (file, the hunk header's
function context when git supplies one, changed line span, added / modified /
deleted). coverage-analyst weights gaps by it when present; nothing enables it
implicitly.

Range auto-pick: main..HEAD when main exists and HEAD isn't main, else
master..HEAD likewise, else HEAD~30..HEAD. `<base>..<tip>` and
`<base>...<tip>` are accepted; both ends must resolve.

git resolves through cc_fuzzer_core.tools.which.
"""
from __future__ import annotations

import json
import os
import re
import subprocess
import sys
import time
from dataclasses import dataclass, field
from pathlib import Path

from cc_fuzzer_core import tools
from cc_fuzzer_core.paths import Campaign, CampaignError, campaign as _campaign

SCHEMA = "delta-targets/v1"
_DIFF_FILE_RE = re.compile(r"^diff --git a/(.+) b/(.+)$")
_HUNK_RE = re.compile(r"^@@ -\d+(?:,\d+)? \+(\d+)(?:,(\d+))? @@(.*)$")


class DeltaError(RuntimeError):
    def __init__(self, message: str, code: int = 2):
        super().__init__(message)
        self.code = code


@dataclass
class DeltaResult:
    path: str                 # the snapshot as printed (relative to the project root by default)
    range: str
    commits: list = field(default_factory=list)
    targets: list = field(default_factory=list)

    @property
    def files_changed(self) -> int:
        return len({t["file"] for t in self.targets})


def parse_diff(text: str) -> list[dict]:
    """Hunks of a `git diff --unified=0` as delta targets."""
    targets, current_file, kind = [], None, "modified"
    for line in text.split("\n"):
        m = _DIFF_FILE_RE.match(line)
        if m:
            current_file, kind = m.group(2), "modified"
            continue
        if line.startswith("new file"):
            kind = "added"
            continue
        if line.startswith("deleted file"):
            kind = "deleted"
            continue
        m = _HUNK_RE.match(line)
        if m and current_file:
            start = int(m.group(1))
            count = int(m.group(2)) if m.group(2) is not None else 1
            # count == 0 is a pure deletion at line N: report it at N.
            end = start + max(count - 1, 0) if count > 0 else start
            targets.append({"file": current_file, "function_context": m.group(3).strip() or None,
                            "lines_changed": [start, end], "kind": kind})
    return targets


def _git(root: Path, *args) -> subprocess.CompletedProcess:
    git = tools.which("git") or "git"
    return subprocess.run([git, "-C", str(root), *args], capture_output=True)


def _resolves(root: Path, ref: str) -> bool:
    return _git(root, "rev-parse", "--quiet", "--verify", ref).returncode == 0


def auto_range(root: Path) -> str:
    branch = _git(root, "rev-parse", "--abbrev-ref", "HEAD").stdout.decode(errors="replace").strip()
    for base in ("main", "master"):
        if _git(root, "rev-parse", "--verify", "--quiet", base).returncode == 0 and branch != base:
            return f"{base}..HEAD"
    return "HEAD~30..HEAD"


def find_targets(c: Campaign, range_: str | None = None, *, state_dir: str | None = None,
                 now: int | None = None) -> DeltaResult:
    """Compute and write the delta snapshot. Raises DeltaError (exit code 2)
    with find-delta-targets.sh's messages. state_dir (as displayed; relative
    to the project root) defaults to $FUZZ_STATE_DIR or fuzz/state."""
    root = c.project_root
    if _git(root, "rev-parse", "--git-dir").returncode != 0:
        raise DeltaError(f"ERROR: {root} is not a git repository - delta mode requires git history")
    rng = range_ or auto_range(root)
    base = rng.split("..", 1)[0]
    tip = rng.rsplit("..", 1)[-1] or "HEAD"
    if not _resolves(root, base):
        raise DeltaError(f"ERROR: base of range '{base}' does not resolve - unknown ref or commit")
    if not _resolves(root, tip):
        raise DeltaError(f"ERROR: tip of range '{tip}' does not resolve - unknown ref or commit")

    ts = int(time.time()) if now is None else now
    state_dir = state_dir or os.environ.get("FUZZ_STATE_DIR") or "fuzz/state"
    snaps = f"{state_dir}/snapshots"
    snaps_io = Path(snaps if os.path.isabs(snaps) else root / snaps)
    snaps_io.mkdir(parents=True, exist_ok=True)
    out = f"{snaps}/delta-{ts}.json"
    out_io, tmp_io = snaps_io / f"delta-{ts}.json", snaps_io / f"delta-{ts}.json.tmp"

    log = _git(root, "log", "--format=%H", rng)
    commits = [ln.strip() for ln in log.stdout.decode(errors="replace").split("\n") if ln.strip()] \
        if log.returncode == 0 else []
    diff = _git(root, "diff", "--unified=0", rng)
    targets = parse_diff(diff.stdout.decode(errors="replace")) if diff.returncode == 0 else []
    res = DeltaResult(out, rng, commits, targets)

    # The script's template, byte for byte: "range" is pasted unescaped, and
    # the result must parse before it is promoted.
    tmp_io.write_text("{\n"
                      f'  "schema": "{SCHEMA}",\n'
                      f'  "timestamp": {ts},\n'
                      f'  "range": "{rng}",\n'
                      f'  "commits": {json.dumps(commits)},\n'
                      f'  "files_changed": {res.files_changed},\n'
                      f'  "targets": {json.dumps(targets)}\n'
                      "}\n")
    try:
        json.loads(tmp_io.read_text())
    except ValueError:
        tmp_io.unlink()
        raise DeltaError(f"ERROR: produced invalid JSON; refusing to promote {out}")
    os.replace(tmp_io, out_io)
    return res


# ---------------------------------------------------------------------------
# CLI: cc-fuzzer delta find
# ---------------------------------------------------------------------------

def _cmd_find(a):
    rng, args = "", list(a.args)
    while args:
        arg = args.pop(0)
        if arg == "--range":
            rng = args.pop(0) if args else ""
        elif arg.startswith("--range="):
            rng = arg[len("--range="):]
        elif arg in ("-h", "--help"):
            print("Usage: find-delta-targets.sh [--range <git-range>]")
            print("Default: main..HEAD if main exists, else master..HEAD, else HEAD~30..HEAD")
            return 0
        else:
            sys.stderr.write(f"ERROR: unknown argument: {arg}\n")
            return 2
    try:
        c = _campaign()
    except CampaignError as e:
        sys.stderr.write(f"{e}\n")
        return e.code
    try:
        r = find_targets(c, rng or None)
    except DeltaError as e:
        sys.stderr.write(f"{e}\n")
        return e.code
    print(r.path)
    sys.stdout.flush()
    sys.stderr.write(f"delta: {len(r.targets)} hunks across {r.files_changed} files in {r.range}\n")
    return 0


def register_cli(subparsers):
    from cc_fuzzer_core.cli import add_raw_verb, add_subsystem

    _p, verbs = add_subsystem(subparsers, "delta", "git-diff delta targets")
    add_raw_verb(verbs, "delta", "find", _cmd_find,
                 "write snapshots/delta-<ts>.json (port of find-delta-targets.sh); [--range R]")
