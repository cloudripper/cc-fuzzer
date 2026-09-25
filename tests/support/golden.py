"""Golden-snapshot harness for differential (bash-vs-Python) tests.

A test copies a fixture campaign into a throwaway sandbox, runs ONE command
against it, and captures everything observable about the run:

    exit code, stdout, stderr, every file created or modified under the
    project dir (text files line-by-line, binaries by sha256), every file
    deleted, every directory created.

`GoldenTestCase.assertGolden(name, result)` compares that capture with the
committed tests/golden/<name>.json; `CC_FUZZER_UPDATE_GOLDEN=1` rewrites the
golden instead. The goldens are recorded from the CURRENT bash entry points;
when a subsystem is ported, its test runs the Python command in a fresh
sandbox on the same fixture and asserts the same golden (or compares the two
captures directly with `assertSameBehaviour`):

    class TestValidate(GoldenTestCase):
        def test_warm(self):
            bash_run = self.sandbox("campaign-warm").run(bash("scripts/validate-state.sh"))
            self.assertGolden("validate-state/warm", bash_run)
            py_run = self.sandbox("campaign-warm").run(core("schema", "validate"))
            self.assertSameBehaviour(bash_run, py_run)

Determinism:
  - Clock: every run sees a frozen wall clock (FROZEN_NOW). Bash gets it via
    the tests/support/bin/date shim, Python via tests/support/pyclock/
    sitecustomize.py (both keyed on CC_FUZZER_TEST_NOW). Fixture files get
    mtime FROZEN_NOW - 60.
  - Paths: the sandbox project dir, the sandbox root and the repo root are
    rewritten to <PROJECT>, <TMP> and <ROOT>; mktemp names are collapsed.
  - PIDs / anything else: Sandbox.add_sub(literal, placeholder) or
    Sandbox.add_regex(pattern, replacement).
  - Environment: CLAUDE_*, FUZZ_*, CC_FUZZER_*, PROJECT_ROOT and PYTHONPATH
    are scrubbed from the inherited env; HOME/TMPDIR point into the sandbox;
    TZ=UTC, LC_ALL=C.UTF-8. tests/support/bin (date, strings shims) is first
    on PATH.
"""
from __future__ import annotations

import difflib
import hashlib
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import unittest
from dataclasses import dataclass, field
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]
TESTS = REPO / "tests"
FIXTURES = TESTS / "fixtures"
GOLDEN_DIR = TESTS / "golden"
SUPPORT_BIN = TESTS / "support" / "bin"
PYCLOCK = TESTS / "support" / "pyclock"

# 2026-09-21T14:13:20Z. Fixture timestamps are authored relative to this.
FROZEN_NOW = 1790000000
FIXTURE_MTIME = FROZEN_NOW - 60

UPDATE = os.environ.get("CC_FUZZER_UPDATE_GOLDEN") == "1"
# A golden belongs to ONE entry point: the bash command it is named after, in
# tests/test_golden_bash.py. Every other test that replays a recorded case
# through a different command (the bash-vs-core parity tests do exactly that)
# must COMPARE, never rewrite -- otherwise an UPDATE_GOLDEN run silently
# restamps the file with the other command's argv, which is how argv from the
# core leaked into 40 goldens. So recording is opt-in, not opt-out.
RECORDING_ALLOWED = False


class allow_recording:
    """`with allow_recording():` -- inside, CC_FUZZER_UPDATE_GOLDEN=1 rewrites.
    test_golden_bash enables it for its own module; nothing else should."""
    def __enter__(self):
        global RECORDING_ALLOWED
        self._prev = RECORDING_ALLOWED
        RECORDING_ALLOWED = True

    def __exit__(self, *exc):
        global RECORDING_ALLOWED
        RECORDING_ALLOWED = self._prev
        return False

_SCRUB_PREFIXES = ("CLAUDE", "FUZZ_", "CC_FUZZER_", "CCFUZZ", "PYTHON")
_SCRUB_EXACT = {"PROJECT_ROOT", "STATE_DIR", "OUT", "SANITIZER"}
_REAL_DATE = shutil.which("date") or "/usr/bin/date"


# ---------------------------------------------------------------------------
# Command builders
# ---------------------------------------------------------------------------

def bash(script: str, *args: str) -> list[str]:
    """argv running a repo bash script (path relative to the repo root)."""
    return ["bash", str(REPO / script), *args]


def python_script(script: str, *args: str) -> list[str]:
    """argv running a repo python script (path relative to the repo root)."""
    return [sys.executable, str(REPO / script), *args]


def core(*args: str) -> list[str]:
    """argv running the core package CLI (`cc-fuzzer <subsystem> <verb> ...`)."""
    return [sys.executable, "-m", "cc_fuzzer_core", *args]


# ---------------------------------------------------------------------------
# Capture
# ---------------------------------------------------------------------------

@dataclass
class RunResult:
    argv: list
    exit_code: int
    stdout: str
    stderr: str
    files: dict = field(default_factory=dict)      # relpath -> {"lines": [...]} | {"sha256", "size"}
    deleted: list = field(default_factory=list)
    created_dirs: list = field(default_factory=list)

    def to_golden(self) -> dict:
        return {
            "exit_code": self.exit_code,
            "stdout": self.stdout.splitlines(),
            "stderr": self.stderr.splitlines(),
            "files": self.files,
            "deleted": self.deleted,
            "created_dirs": self.created_dirs,
        }

    def file_text(self, rel: str) -> str:
        entry = self.files[rel]
        return "\n".join(entry["lines"]) + ("\n" if entry.get("trailing_newline", True) else "")

    def file_json(self, rel: str):
        return json.loads(self.file_text(rel))


def _file_entry(path: Path, normalize) -> dict:
    data = path.read_bytes()
    try:
        text = data.decode("utf-8")
        if "\x00" in text:
            raise UnicodeDecodeError("utf-8", data, 0, 1, "nul")
    except UnicodeDecodeError:
        return {"sha256": hashlib.sha256(data).hexdigest(), "size": len(data)}
    entry = {"lines": normalize(text).split("\n")}
    if entry["lines"] and entry["lines"][-1] == "":
        entry["lines"].pop()
    else:
        entry["trailing_newline"] = False
    return entry


def _tree_state(root: Path) -> tuple[dict, set]:
    """({relpath: digest}, {reldirs}) for everything under root."""
    files, dirs = {}, set()
    if not root.exists():
        return files, dirs
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d != "__pycache__"]
        dp = Path(dirpath)
        for d in dirnames:
            dirs.add((dp / d).relative_to(root).as_posix())
        for fn in filenames:
            p = dp / fn
            rel = p.relative_to(root).as_posix()
            if p.is_symlink():
                files[rel] = "link:" + os.readlink(p)
            elif p.is_file():
                files[rel] = hashlib.sha256(p.read_bytes()).hexdigest()
    return files, dirs


# ---------------------------------------------------------------------------
# Sandbox
# ---------------------------------------------------------------------------

class Sandbox:
    """A temp dir holding a private copy of one fixture campaign.

    Layout:  <tmp>/project  (the fixture's contents; cwd for runs)
             <tmp>/home     (HOME)
             <tmp>/tmp      (TMPDIR)
    """

    def __init__(self, fixture: str | None = None, *, now: int = FROZEN_NOW):
        self.now = now
        self.tmp = Path(tempfile.mkdtemp(prefix="ccf-golden-")).resolve()
        self.project = self.tmp / "project"
        self.home = self.tmp / "home"
        self.tmpdir = self.tmp / "tmp"
        for d in (self.home, self.tmpdir):
            d.mkdir()
        if fixture:
            src = FIXTURES / fixture
            if not src.is_dir():
                raise FileNotFoundError(f"no such fixture: {src}")
            shutil.copytree(src, self.project, symlinks=True)
            # .gitkeep only exists so git keeps a fixture's empty dirs.
            for keep in self.project.rglob(".gitkeep"):
                keep.unlink()
        else:
            self.project.mkdir()
        self._set_mtimes(self.project, now - 60)
        self._subs: list[tuple[str, str]] = []
        self._regexes: list[tuple[re.Pattern, str]] = [
            (re.compile(r"(<TMP>/tmp/tmp\.)[A-Za-z0-9]+"), r"\1XXXXXXXXXX"),
        ]

    # -- setup helpers -----------------------------------------------------

    @staticmethod
    def _set_mtimes(root: Path, mtime: int):
        for dirpath, dirnames, filenames in os.walk(root):
            for name in filenames + dirnames:
                p = Path(dirpath) / name
                if not p.is_symlink():
                    os.utime(p, (mtime, mtime))
        if root.exists():
            os.utime(root, (mtime, mtime))

    def path(self, rel: str) -> Path:
        return self.project / rel

    def write(self, rel: str, content, mode: int | None = None) -> Path:
        p = self.path(rel)
        p.parent.mkdir(parents=True, exist_ok=True)
        if isinstance(content, bytes):
            p.write_bytes(content)
        else:
            p.write_text(content)
        if mode is not None:
            p.chmod(mode)
        os.utime(p, (self.now - 60, self.now - 60))
        return p

    def edit_json(self, rel: str, fn):
        """Load a fixture JSON file, pass it to fn (mutate in place or return
        a replacement), and write it back with the plugin's usual indent=2."""
        p = self.path(rel)
        doc = json.loads(p.read_text())
        new = fn(doc)
        doc = doc if new is None else new
        self.write(rel, json.dumps(doc, indent=2) + "\n")

    def add_sub(self, literal: str, placeholder: str):
        """Replace `literal` with `placeholder` in all captured output."""
        if literal:
            self._subs.append((str(literal), placeholder))

    def add_regex(self, pattern: str, replacement: str):
        self._regexes.append((re.compile(pattern), replacement))

    def git(self, *args: str, cwd: Path | None = None) -> str:
        """Run git with a pinned identity/clock (commit hashes are stable)."""
        env = self.env({
            "GIT_AUTHOR_NAME": "Fixture", "GIT_AUTHOR_EMAIL": "fixture@example.invalid",
            "GIT_COMMITTER_NAME": "Fixture", "GIT_COMMITTER_EMAIL": "fixture@example.invalid",
            "GIT_CONFIG_NOSYSTEM": "1", "GIT_CONFIG_GLOBAL": os.devnull,
        })
        env.setdefault("GIT_AUTHOR_DATE", f"@{self.now - 86400} +0000")
        env.setdefault("GIT_COMMITTER_DATE", env["GIT_AUTHOR_DATE"])
        out = subprocess.run(["git", *args], cwd=cwd or self.project, env=env,
                             capture_output=True, text=True, check=True)
        return out.stdout

    # -- running -------------------------------------------------------------

    def env(self, extra: dict | None = None) -> dict:
        env = {k: v for k, v in os.environ.items()
               if not k.startswith(_SCRUB_PREFIXES) and k not in _SCRUB_EXACT}
        env.update({
            "PATH": f"{SUPPORT_BIN}{os.pathsep}{os.environ.get('PATH', '/usr/bin:/bin')}",
            "HOME": str(self.home),
            "TMPDIR": str(self.tmpdir),
            "TZ": "UTC",
            "LC_ALL": "C.UTF-8",
            "LANG": "C.UTF-8",
            "PYTHONPATH": f"{PYCLOCK}{os.pathsep}{REPO / 'src'}",
            "PYTHONDONTWRITEBYTECODE": "1",
            "PYTHONHASHSEED": "0",
            "PYTHONIOENCODING": "utf-8",
            "CC_FUZZER_TEST_NOW": str(self.now),
            "CC_FUZZER_REAL_DATE": _REAL_DATE,
            "CC_FUZZER_ROOT": str(REPO),
            # Hermeticity: a golden must not record a fact about the machine
            # that ran it. Pin the CPU budget (fuzz_forks caps at nproc-1) and
            # pin the coverage toolchain ABSENT, so a host that happens to
            # ship llvm-cov does not change the recorded output. Cases that
            # want llvm point CC_FUZZER_TOOL_LLVM_* at tests/support/stub-llvm.
            "CC_FUZZER_CPUS": "2",
            "CC_FUZZER_TOOL_LLVM_COV": "",
            "CC_FUZZER_TOOL_LLVM_PROFDATA": "",
            # Never let a script under test chmod the checkout read-only.
            "CC_FUZZER_DISABLE_READONLY_LOCK": "1",
        })
        if extra:
            for k, v in extra.items():
                if v is None:
                    env.pop(k, None)
                else:
                    env[k] = str(v)
        return env

    def normalize(self, text: str) -> str:
        subs = list(self._subs) + [
            # the interpreter's absolute path is a fact about the machine
            # (/usr/bin vs /usr/local/bin vs a venv), never about the behaviour
            # under test
            (sys.executable, "<PYTHON>"),
            (str(self.project), "<PROJECT>"),
            (str(self.tmp), "<TMP>"),
            (str(REPO), "<ROOT>"),
        ]
        for literal, placeholder in sorted(subs, key=lambda s: -len(s[0])):
            text = text.replace(literal, placeholder)
        for pat, rep in self._regexes:
            text = pat.sub(rep, text)
        return text

    def run(self, argv, *, cwd: str | Path | None = None, stdin: str | bytes | None = None,
            env: dict | None = None, timeout: int = 120) -> RunResult:
        before_files, before_dirs = _tree_state(self.project)
        workdir = self.project if cwd is None else (self.project / cwd if not os.path.isabs(str(cwd)) else Path(cwd))
        if isinstance(stdin, str):
            stdin = stdin.encode()
        proc = subprocess.run(
            [str(a) for a in argv], cwd=workdir, env=self.env(env),
            input=stdin if stdin is not None else b"",
            capture_output=True, timeout=timeout,
        )
        after_files, after_dirs = _tree_state(self.project)
        files = {}
        for rel, digest in sorted(after_files.items()):
            if before_files.get(rel) != digest:
                p = self.project / rel
                if digest.startswith("link:"):
                    files[rel] = {"symlink": self.normalize(digest[5:])}
                else:
                    files[rel] = _file_entry(p, self.normalize)
        return RunResult(
            argv=[self.normalize(str(a)) for a in argv],
            exit_code=proc.returncode,
            stdout=self.normalize(proc.stdout.decode("utf-8", "replace")),
            stderr=self.normalize(proc.stderr.decode("utf-8", "replace")),
            files=files,
            deleted=sorted(set(before_files) - set(after_files)),
            created_dirs=sorted(after_dirs - before_dirs),
        )

    def cleanup(self):
        # Scripts under test may leave read-only files behind; make the tree
        # writable so rmtree can't fail.
        for dirpath, dirnames, filenames in os.walk(self.tmp):
            for name in dirnames + filenames:
                p = Path(dirpath) / name
                if not p.is_symlink():
                    try:
                        p.chmod(p.stat().st_mode | 0o700)
                    except OSError:
                        pass
        shutil.rmtree(self.tmp, ignore_errors=True)


# ---------------------------------------------------------------------------
# TestCase
# ---------------------------------------------------------------------------

def _dump(doc) -> str:
    return json.dumps(doc, indent=2, sort_keys=True, ensure_ascii=False) + "\n"


class GoldenTestCase(unittest.TestCase):
    maxDiff = None

    def sandbox(self, fixture: str | None = None, **kw) -> Sandbox:
        sb = Sandbox(fixture, **kw)
        self.addCleanup(sb.cleanup)
        return sb

    def assertGolden(self, name: str, result: RunResult, *, ignore: tuple = ()):
        """Compare result with tests/golden/<name>.json (or rewrite it when
        CC_FUZZER_UPDATE_GOLDEN=1). `ignore` drops capture fields (e.g.
        ("stderr",)) from the comparison."""
        path = GOLDEN_DIR / f"{name}.json"
        actual = result.to_golden()
        actual["argv"] = result.argv
        if UPDATE and RECORDING_ALLOWED:
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(_dump(actual))
            return
        if not path.exists():
            self.fail(f"missing golden {path.relative_to(REPO)}; "
                      "record it with CC_FUZZER_UPDATE_GOLDEN=1")
        expected = json.loads(path.read_text())
        for k in ("argv", *ignore):
            expected.pop(k, None)
            actual.pop(k, None)
        if expected != actual:
            diff = "".join(difflib.unified_diff(
                _dump(expected).splitlines(True), _dump(actual).splitlines(True),
                fromfile=f"golden/{name}.json", tofile="actual"))
            self.fail(f"golden mismatch for {name} "
                      f"(CC_FUZZER_UPDATE_GOLDEN=1 re-records):\n{diff}")

    def assertSameBehaviour(self, a: RunResult, b: RunResult,
                            fields=("exit_code", "stdout", "files", "deleted", "created_dirs")):
        """Differential check between two captures (e.g. bash vs Python) of the
        same command on the same fixture."""
        da, db = a.to_golden(), b.to_golden()
        for f in fields:
            if da[f] != db[f]:
                diff = "".join(difflib.unified_diff(
                    _dump(da[f]).splitlines(True), _dump(db[f]).splitlines(True),
                    fromfile=" ".join(a.argv), tofile=" ".join(b.argv)))
                self.fail(f"behaviour differs in {f!r}:\n{diff}")


def require_tools(*tools: str):
    """unittest.skipUnless helper for entry points needing external tools."""
    missing = [t for t in tools if shutil.which(t) is None]
    return unittest.skipUnless(not missing, f"requires {', '.join(missing)} on PATH")
