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

CLI: `cc-fuzzer patch validate --patch p.diff --pov crash.bin --harness NAME`.
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

    def as_dict(self) -> dict:
        return {"step": self.name, "ok": self.ok, "detail": self.detail,
                "seconds": round(self.seconds, 3)}


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
    pov: str = ""
    stack_hash: str = ""
    seconds: float = 0.0

    @property
    def validated(self) -> bool:
        return self.status == FIXES

    def as_dict(self) -> dict:
        return {"schema": VERDICT_SCHEMA, "status": self.status,
                "validated": self.validated, "reason": self.reason,
                "steps": [s.as_dict() for s in self.steps],
                "scope": self.scope.as_dict(), "pov": self.pov,
                "stack_hash": self.stack_hash, "seconds": round(self.seconds, 3)}


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

def _command(spec: str, **fmt) -> list:
    spec = (spec or "").strip()
    if spec.startswith("command:"):
        spec = spec[len("command:"):]
    if not spec:
        return []
    return shlex.split(spec.format(**fmt))


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
    return Step(name, p.returncode == 0, tail if p.returncode else "",
                time.monotonic() - t0)


def config_block(config: Mapping | None) -> dict:
    block = (config or {}).get("patch")
    return dict(block) if isinstance(block, Mapping) else {}


# ---------------------------------------------------------------------------
# validation
# ---------------------------------------------------------------------------

def validate(record: Mapping, patch_path: str, pov: str, *, project_root,
             config: Mapping | None = None, harness: str = "",
             stack_hash: str = "", replay_fn=None) -> PatchVerdict:
    """Run the five gates. Returns a PatchVerdict; never raises on a failing
    patch -- a patch that does not work is a result, not an error."""
    cfg = config_block(config)
    timeout = int(cfg.get("timeout_s") or DEFAULT_TIMEOUT_S)
    root = Path(project_root)
    t0 = time.monotonic()
    steps: list = []

    patch_file = Path(patch_path)
    if not patch_file.is_file():
        raise PatchError(f"no such patch: {patch_path}")
    if not Path(pov).is_file():
        raise PatchError(f"no such PoV: {pov}")
    scope = scope_of(patch_file.read_text(errors="replace"))

    from cc_fuzzer_core.crash import replay as _replay
    rep = replay_fn or (lambda: _replay.replay(record, pov, harness=harness, attempts=1))

    def done(status, reason):
        return PatchVerdict(status, reason, tuple(steps), scope, pov, stack_hash,
                            time.monotonic() - t0)

    # 1. before -- the step everyone skips
    t = time.monotonic()
    try:
        base = rep()
    except Exception as e:  # noqa: BLE001
        steps.append(Step("before", False, f"{type(e).__name__}: {e}", time.monotonic() - t))
        return done(INCONCLUSIVE, f"could not replay the PoV before patching: {e}")
    crashed = base.verdict != _replay.NO_CRASH
    steps.append(Step("before", crashed,
                      "" if crashed else "the PoV does not crash the unpatched build",
                      time.monotonic() - t))
    if not crashed:
        return done(STALE,
                    "the PoV does not reproduce without the patch, so this patch "
                    "cannot be shown to fix anything -- re-check the finding")
    want = stack_hash or base.stack_hash

    # 2-3. apply, build
    for name, key in (("apply", "apply"), ("build", "build")):
        argv = _command(cfg.get(key, ""), patch=str(patch_file), pov=pov,
                        harness=harness)
        s = run_step(name, argv, cwd=root, timeout=timeout)
        steps.append(s)
        if not s.ok:
            _revert(cfg, root, timeout, steps)
            return done(APPLY_FAILED if name == "apply" else BUILD_FAILED,
                        f"{name} failed: {s.detail}")

    # 4. after -- the PoV must stop reproducing
    t = time.monotonic()
    try:
        after = rep()
    except Exception as e:  # noqa: BLE001
        steps.append(Step("after", False, f"{type(e).__name__}: {e}", time.monotonic() - t))
        _revert(cfg, root, timeout, steps)
        return done(INCONCLUSIVE, f"could not replay the PoV after patching: {e}")

    still = after.verdict != _replay.NO_CRASH and after.stack_hash == want
    steps.append(Step("after", not still,
                      "the PoV still reproduces the same crash" if still else "",
                      time.monotonic() - t))
    if still:
        _revert(cfg, root, timeout, steps)
        return done(DOES_NOT_FIX, "the PoV still reproduces with the patch applied")

    # 5. tests
    s = run_step("tests", _command(cfg.get("test", ""), patch=str(patch_file),
                                   pov=pov, harness=harness),
                 cwd=root, timeout=timeout)
    steps.append(s)
    _revert(cfg, root, timeout, steps)
    if not s.ok:
        return done(BREAKS_TESTS, f"the patch stops the PoV but breaks the tests: {s.detail}")

    note = "; ".join(scope.concerns())
    return done(FIXES, "PoV no longer reproduces and the tests still pass"
                + (f" (scope: {note})" if note else ""))


def _revert(cfg: Mapping, root: Path, timeout: int, steps: list) -> None:
    argv = _command(cfg.get("revert", ""))
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
    v.add_argument("--pov", required=True, help="the reproducer the patch must stop")
    v.add_argument("--harness", default="")
    v.add_argument("--stack-hash", default="")
    v.add_argument("--config")
    v.add_argument("--json", action="store_true")
    v.set_defaults(func=_cmd_validate)

    v = verbs.add_parser("scope", help="what the diff touches, and what is worth a look")
    v.add_argument("patch")
    v.set_defaults(func=_cmd_scope)
