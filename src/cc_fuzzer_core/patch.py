"""Validating a patch before anyone submits it.

A CRS is scored on patches as well as findings, and a patch is wrong in three
different ways that look alike from the outside:

  1. it does not actually stop the PoV;
  2. it stops the PoV by breaking the program (the tests catch this);
  3. it stops the PoV by disabling the code path rather than fixing the bug
     (nothing catches this automatically -- but a patch that deletes the
     feature is visible in how much it touches, so scope is reported).

This module does not write patches. It refuses to let an unchecked one be
called validated, the same way §11 refuses to let an unverified crash become a
finding. The sequence is fixed, and every step is a gate:

    before   the PoV must crash WITHOUT the patch. If it does not, the
             finding is stale or the harness moved, and everything after this
             would be measuring nothing.
    apply    the patch applies cleanly.
    build    the patched tree builds. A build failure is not a fix.
    after    the PoV must NOT crash with the patch applied.
    tests    the project's own tests must still pass.

`before` exists because it is the step everyone skips. A patch "fixes" a PoV
that never reproduced in the first place, and the result looks exactly like
success.

Building, testing and applying are the host's -- a CRS already knows how to do
all three for its target, and the core must not guess. They are supplied as
commands in fuzz-config.json, in the same shape as §4's verifier:

    "patch": {
      "apply":  "command:git apply {patch}",
      "build":  "command:./build.sh",
      "test":   "command:ctest --output-on-failure",
      "revert": "command:git checkout -- .",
      "timeout_s": 900
    }

Running the PoV is the core's by default (§12 replay on the local binary). A
host whose authoritative runner lives elsewhere -- OSS-CRS's `libCRS run-pov`,
which runs against a sidecar build -- supplies it the same way:

    "patch": {
      "build":     "command:/opt/crs/build.sh {patch}",
      "pov":       "command:/opt/crs/pov.sh {pov} {harness}",
      "pov_after": "command:/opt/crs/pov.sh {pov} {harness} --rebuild-id {build}",
      "test":      "command:/opt/crs/test.sh {patch} {build}"
    }

`{build}` is the last non-empty stdout line of the build step (a rebuild id,
an image tag, an output dir), empty before the build has run. `pov_after`
defaults to `pov`. A pov command answers with one pov-run/v1 JSON object:

    {"schema": "pov-run/v1", "crashed": true, "output": "<sanitizer report>"}

`output` is optional; when present the stack hash is computed from it, exactly
as local replay does. Anything else -- no JSON, a timeout, a missing command --
is inconclusive, never a pass.

A patch is judged against every PoV it is meant to fix (a cluster of variants
of one bug): all must crash before, and none may crash after. A PoV that crashes
SOMEWHERE ELSE after the patch is not fixed either: the patch moved the crash.

CLI: `cc-fuzzer patch validate --patch p.diff --pov crash.bin [--pov ...] --harness NAME`.
"""
from __future__ import annotations

import json
import os
import shlex
import subprocess
import sys
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Mapping

VERDICT_SCHEMA = "patch-verdict/v1"
POV_RUN_SCHEMA = "pov-run/v1"

# outcomes
FIXES, DOES_NOT_FIX, BREAKS_TESTS, BUILD_FAILED, APPLY_FAILED, STALE, INCONCLUSIVE = (
    "fixes", "does_not_fix", "breaks_tests", "build_failed", "apply_failed",
    "stale_finding", "inconclusive")
STATUSES = (FIXES, DOES_NOT_FIX, BREAKS_TESTS, BUILD_FAILED, APPLY_FAILED,
            STALE, INCONCLUSIVE)

STEPS = ("before", "apply", "build", "after", "tests")
DEFAULT_TIMEOUT_S = 900
# A patch far larger than the bug is worth flagging: it may be fixing by
# deletion. Advisory only -- some real fixes are large.
SCOPE_SOFT_MAX_FILES = 5
SCOPE_SOFT_MAX_LINES = 200


class PatchError(RuntimeError):
    pass


@dataclass(frozen=True)
class Step:
    name: str
    ok: bool
    detail: str = ""
    seconds: float = 0.0
    value: str = ""     # last non-empty stdout line (build: the {build} placeholder)

    def as_dict(self) -> dict:
        return {"step": self.name, "ok": self.ok, "detail": self.detail,
                "seconds": round(self.seconds, 3), "value": self.value}


@dataclass(frozen=True)
class Scope:
    files: int = 0
    added: int = 0
    removed: int = 0
    paths: tuple = field(default=())

    @property
    def lines(self) -> int:
        return self.added + self.removed

    def concerns(self) -> list:
        out = []
        if self.files > SCOPE_SOFT_MAX_FILES:
            out.append(f"touches {self.files} files (> {SCOPE_SOFT_MAX_FILES})")
        if self.lines > SCOPE_SOFT_MAX_LINES:
            out.append(f"{self.lines} changed lines (> {SCOPE_SOFT_MAX_LINES})")
        if self.added == 0 and self.removed > 0:
            out.append("removes code without adding any -- check it fixes the bug "
                       "rather than deleting the path that reaches it")
        return out

    def as_dict(self) -> dict:
        return {"files": self.files, "added": self.added, "removed": self.removed,
                "lines": self.lines, "paths": list(self.paths),
                "concerns": self.concerns()}


@dataclass(frozen=True)
class PatchVerdict:
    status: str
    reason: str = ""
    steps: tuple = field(default=())
    scope: Scope = field(default_factory=Scope)
    pov: str = ""               # the first PoV, for single-PoV callers
    stack_hash: str = ""        # the first PoV's bug
    seconds: float = 0.0
    povs: tuple = field(default=())      # PovResult per PoV
    build: str = ""             # the build step's {build} value

    @property
    def validated(self) -> bool:
        return self.status == FIXES

    def as_dict(self) -> dict:
        return {"schema": VERDICT_SCHEMA, "status": self.status,
                "validated": self.validated, "reason": self.reason,
                "steps": [s.as_dict() for s in self.steps],
                "scope": self.scope.as_dict(), "pov": self.pov,
                "stack_hash": self.stack_hash, "seconds": round(self.seconds, 3),
                "povs": [p.as_dict() for p in self.povs], "build": self.build}


@dataclass
class PovResult:
    pov: str
    stack_hash: str = ""
    before: str = ""            # crash | no-crash | error
    after: str = ""             # "" (not run) | no-crash | same | moved | error
    after_hash: str = ""
    detail: str = ""

    def as_dict(self) -> dict:
        return {"pov": self.pov, "stack_hash": self.stack_hash,
                "before": self.before, "after": self.after,
                "after_hash": self.after_hash, "detail": self.detail}


@dataclass(frozen=True)
class PovRun:
    """One run of one PoV: did it crash, and as which bug."""
    crashed: bool
    stack_hash: str = ""
    detail: str = ""


# ---------------------------------------------------------------------------
# scope, straight from the diff
# ---------------------------------------------------------------------------

def scope_of(diff_text: str) -> Scope:
    files, added, removed = [], 0, 0
    for line in (diff_text or "").splitlines():
        if line.startswith("+++ ") or line.startswith("--- "):
            p = line[4:].strip()
            if p not in ("/dev/null",) and p not in files:
                if p.startswith(("a/", "b/")):
                    p = p[2:]
                if p not in files:
                    files.append(p)
        elif line.startswith("+") and not line.startswith("+++"):
            added += 1
        elif line.startswith("-") and not line.startswith("---"):
            removed += 1
    return Scope(len(files), added, removed, tuple(files))


# ---------------------------------------------------------------------------
# the host's commands
# ---------------------------------------------------------------------------

PLACEHOLDERS = ("patch", "pov", "harness", "build")


class _Fill(dict):
    def __missing__(self, key):
        raise PatchError(f"unknown placeholder {{{key}}} in a patch command "
                         f"(known: {', '.join('{' + k + '}' for k in PLACEHOLDERS)})")


def _command(spec: str, **fmt) -> list:
    spec = (spec or "").strip()
    if spec.startswith("command:"):
        spec = spec[len("command:"):]
    if not spec:
        return []
    return shlex.split(spec.format_map(_Fill({k: "" for k in PLACEHOLDERS}, **fmt)))


def run_step(name: str, argv: list, *, cwd, timeout: int, env=None) -> Step:
    if not argv:
        return Step(name, True, "not configured; skipped")
    t0 = time.monotonic()
    try:
        p = subprocess.run(argv, cwd=str(cwd), capture_output=True, text=True,
                           timeout=timeout, env=env)
    except subprocess.TimeoutExpired:
        return Step(name, False, f"timed out after {timeout}s", time.monotonic() - t0)
    except OSError as e:
        return Step(name, False, f"cannot run {argv[0]}: {e}", time.monotonic() - t0)
    tail = " | ".join((p.stderr or p.stdout or "").strip().splitlines()[-3:])
    lines = [ln.strip() for ln in (p.stdout or "").splitlines() if ln.strip()]
    return Step(name, p.returncode == 0, tail if p.returncode else "",
                time.monotonic() - t0, lines[-1] if lines else "")


def config_block(config: Mapping | None) -> dict:
    block = (config or {}).get("patch")
    return dict(block) if isinstance(block, Mapping) else {}


# ---------------------------------------------------------------------------
# validation
# ---------------------------------------------------------------------------

def pov_runner(record: Mapping, cfg: Mapping, *, harness: str, timeout: int,
               cwd, build: str = "", phase: str = "before", patch: str = ""):
    """pov -> PovRun, for one phase. The host's command when configured,
    otherwise §12 replay on the local binary."""
    key = "pov_after" if phase == "after" and cfg.get("pov_after") else "pov"
    spec = cfg.get(key, "")
    if not spec:
        from cc_fuzzer_core.crash import replay as _replay

        def local(pov: str) -> PovRun:
            r = _replay.replay(record, pov, harness=harness, attempts=1)
            return PovRun(r.verdict != _replay.NO_CRASH, r.stack_hash, r.reason)
        return local

    def host(pov: str) -> PovRun:
        argv = _command(spec, pov=pov, harness=harness, build=build, patch=patch)
        return run_pov_command(argv, cwd=cwd, timeout=timeout)
    return host


def run_pov_command(argv: list, *, cwd, timeout: int) -> PovRun:
    """Run a host pov command and read its pov-run/v1 answer. Raises PatchError
    on anything that is not an answer: an unreadable result is not a pass."""
    try:
        p = subprocess.run(argv, cwd=str(cwd), capture_output=True, text=True,
                           timeout=timeout)
    except subprocess.TimeoutExpired:
        raise PatchError(f"pov command timed out after {timeout}s") from None
    except OSError as e:
        raise PatchError(f"cannot run pov command {argv[0] if argv else ''}: {e}") from None
    out = (p.stdout or "").strip()
    try:
        doc = json.loads(out.splitlines()[-1]) if out else None
    except ValueError:
        doc = None
    if not isinstance(doc, Mapping) or not isinstance(doc.get("crashed"), bool):
        tail = " | ".join((p.stderr or out).strip().splitlines()[-3:])
        raise PatchError(f"pov command (exit {p.returncode}) gave no {POV_RUN_SCHEMA} "
                         f"answer" + (f": {tail}" if tail else ""))
    if doc.get("schema") not in (None, POV_RUN_SCHEMA):
        raise PatchError(f"pov command answered {doc.get('schema')!r}, not {POV_RUN_SCHEMA}")
    h = ""
    text = doc.get("output") or ""
    if doc["crashed"] and text:
        from cc_fuzzer_core.crash import classify as _classify
        from cc_fuzzer_core.crash import replay as _replay
        cl = _classify.classify(text)
        h = _replay.stack_hash(text, category=cl.category)
    return PovRun(doc["crashed"], h, str(doc.get("reason") or ""))


def validate(record: Mapping, patch_path: str, pov, *, project_root,
             config: Mapping | None = None, harness: str = "",
             stack_hash: str = "", replay_fn=None) -> PatchVerdict:
    """Run the five gates against one PoV or several (a cluster of variants of
    one bug). Returns a PatchVerdict; never raises on a failing patch -- a patch
    that does not work is a result, not an error.

    `stack_hash` pins the bug when there is one PoV; with several, each PoV's
    own `before` run defines its bug. `replay_fn(pov, phase, build) -> PovRun`
    replaces the runner entirely (tests, or a host calling in-process).
    """
    cfg = config_block(config)
    timeout = int(cfg.get("timeout_s") or DEFAULT_TIMEOUT_S)
    root = Path(project_root)
    t0 = time.monotonic()
    steps: list = []

    povs = [pov] if isinstance(pov, (str, os.PathLike)) else list(pov or [])
    povs = [str(p) for p in povs]
    if not povs:
        raise PatchError("no PoV given: a patch cannot be shown to fix nothing")
    patch_file = Path(patch_path)
    if not patch_file.is_file():
        raise PatchError(f"no such patch: {patch_path}")
    for p in povs:
        if not Path(p).is_file():
            raise PatchError(f"no such PoV: {p}")
    scope = scope_of(patch_file.read_text(errors="replace"))
    results = [PovResult(p) for p in povs]
    build = ""

    def runner(phase):
        if replay_fn is not None:
            return lambda p: replay_fn(p, phase, build)
        return pov_runner(record, cfg, harness=harness, timeout=timeout, cwd=root,
                          build=build, phase=phase, patch=str(patch_file))

    def done(status, reason):
        return PatchVerdict(status, reason, tuple(steps), scope, povs[0],
                            results[0].stack_hash, time.monotonic() - t0,
                            tuple(results), build)

    def names(rs):
        return ", ".join(Path(r.pov).name for r in rs)

    # 1. before -- the step everyone skips
    t = time.monotonic()
    run = runner("before")
    for r in results:
        try:
            got = run(r.pov)
        except Exception as e:  # noqa: BLE001
            r.before, r.detail = "error", f"{type(e).__name__}: {e}"
            continue
        r.before = "crash" if got.crashed else "no-crash"
        r.stack_hash = (stack_hash if len(results) == 1 and stack_hash else "") \
            or got.stack_hash
    errored = [r for r in results if r.before == "error"]
    stale = [r for r in results if r.before == "no-crash"]
    detail = "; ".join(
        [f"{Path(r.pov).name}: {r.detail}" for r in errored]
        + [f"{Path(r.pov).name} does not crash the unpatched build" for r in stale])
    steps.append(Step("before", not errored and not stale, detail, time.monotonic() - t))
    if errored:
        return done(INCONCLUSIVE, f"could not run the PoV before patching: {detail}")
    if stale:
        return done(STALE,
                    f"{names(stale)} does not reproduce without the patch, so this "
                    "patch cannot be shown to fix it -- re-check the finding")

    # 2-3. apply, build
    for name, key in (("apply", "apply"), ("build", "build")):
        argv = _command(cfg.get(key, ""), patch=str(patch_file), pov=povs[0],
                        harness=harness, build=build)
        st = run_step(name, argv, cwd=root, timeout=timeout)
        steps.append(st)
        if not st.ok:
            _revert(cfg, root, timeout, steps, patch_file, build)
            return done(APPLY_FAILED if name == "apply" else BUILD_FAILED,
                        f"{name} failed: {st.detail}")
        if name == "build":
            build = st.value

    # 4. after -- no PoV may crash, here or anywhere else
    t = time.monotonic()
    run = runner("after")
    for r in results:
        try:
            got = run(r.pov)
        except Exception as e:  # noqa: BLE001
            r.after, r.detail = "error", f"{type(e).__name__}: {e}"
            continue
        r.after_hash = got.stack_hash if got.crashed else ""
        if not got.crashed:
            r.after = "no-crash"
        elif got.stack_hash and r.stack_hash and got.stack_hash != r.stack_hash:
            r.after = "moved"
        else:
            r.after = "same"
    errored = [r for r in results if r.after == "error"]
    same = [r for r in results if r.after == "same"]
    moved = [r for r in results if r.after == "moved"]
    detail = "; ".join(
        [f"{Path(r.pov).name}: {r.detail}" for r in errored]
        + [f"{Path(r.pov).name} still reproduces the same crash" for r in same]
        + [f"{Path(r.pov).name} now crashes elsewhere ({r.after_hash})" for r in moved])
    steps.append(Step("after", not (errored or same or moved), detail,
                      time.monotonic() - t))
    if errored:
        _revert(cfg, root, timeout, steps, patch_file, build)
        return done(INCONCLUSIVE, f"could not run the PoV after patching: {detail}")
    if same or moved:
        _revert(cfg, root, timeout, steps, patch_file, build)
        why = ("the PoV still reproduces with the patch applied" if same and len(povs) == 1
               and not moved else
               "the patch moved the crash rather than fixing it" if moved and len(povs) == 1
               else f"{len(same) + len(moved)} of {len(povs)} PoVs still crash: {detail}")
        return done(DOES_NOT_FIX, why)

    # 5. tests
    st = run_step("tests", _command(cfg.get("test", ""), patch=str(patch_file),
                                    pov=povs[0], harness=harness, build=build),
                  cwd=root, timeout=timeout)
    steps.append(st)
    _revert(cfg, root, timeout, steps, patch_file, build)
    if not st.ok:
        return done(BREAKS_TESTS, f"the patch stops the PoV but breaks the tests: {st.detail}")

    note = "; ".join(scope.concerns())
    what = "PoV no longer reproduces" if len(povs) == 1 else \
        f"none of the {len(povs)} PoVs reproduces"
    return done(FIXES, f"{what} and the tests still pass"
                + (f" (scope: {note})" if note else ""))


def _revert(cfg: Mapping, root: Path, timeout: int, steps: list,
            patch_file: Path | None = None, build: str = "") -> None:
    argv = _command(cfg.get("revert", ""), patch=str(patch_file or ""), build=build)
    # (pov/harness are not meaningful to a revert and fill as empty)
    if argv:
        steps.append(run_step("revert", argv, cwd=root, timeout=timeout))


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def _cmd_validate(a):
    from cc_fuzzer_core import config as _config
    from cc_fuzzer_core.paths import campaign
    from cc_fuzzer_core.variants import harness_record
    try:
        c = campaign()
        cfg = json.load(open(a.config)) if a.config else _config.load(c)
        v = validate(harness_record(harness=a.harness), a.patch, a.pov,
                     project_root=c.project_root, config=cfg, harness=a.harness,
                     stack_hash=a.stack_hash)
    except PatchError as e:
        print(f"error: {e}", file=sys.stderr)
        return 2
    if a.json:
        print(json.dumps(v.as_dict(), indent=2))
    else:
        print(f"{v.status}: {v.reason}")
        for s in v.steps:
            print(f"  {'ok  ' if s.ok else 'FAIL'} {s.name}"
                  + (f" -- {s.detail}" if s.detail else ""))
        if len(v.povs) > 1:
            for p in v.povs:
                print(f"  {p.pov}: before={p.before} after={p.after or '-'}")
    return 0 if v.validated else 1


def _cmd_scope(a):
    s = scope_of(Path(a.patch).read_text(errors="replace"))
    print(json.dumps(s.as_dict(), indent=2))
    return 0


def register_cli(subparsers):
    from cc_fuzzer_core.cli import add_subsystem
    _p, verbs = add_subsystem(subparsers, "patch",
                              "Validate a patch before it is submitted.")

    v = verbs.add_parser("validate", help="run the five gates (exit 1 = not validated)")
    v.add_argument("--patch", required=True)
    v.add_argument("--pov", required=True, action="append",
                   help="a reproducer the patch must stop (repeat for a cluster)")
    v.add_argument("--harness", default="")
    v.add_argument("--stack-hash", default="")
    v.add_argument("--config")
    v.add_argument("--json", action="store_true")
    v.set_defaults(func=_cmd_validate)

    v = verbs.add_parser("scope", help="what the diff touches, and what is worth a look")
    v.add_argument("patch")
    v.set_defaults(func=_cmd_scope)
