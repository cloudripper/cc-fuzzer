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
as local replay does.

Each step has a policy, because "not configured", "ran and passed" and "ran
but had nothing to do" are three different facts (libCRS apply-patch-test
succeeds, by contract, when a project ships no test script):

    "patch": {"steps": {"build": "required", "test": "preferred"}}

    policy      the step did not run (not configured, or reported ran:false)
    required    the gate fails: inconclusive, never a pass
    preferred   the gate passes and the step is listed in unverified_steps
    optional    the gate passes, silently (the default: today's behaviour)

A command step may say which of those happened with a step-result/v1 line as
the last line of stdout; a plain exit code keeps working:

    {"schema": "step-result/v1", "ok": true, "ran": false, "reason": "no test script"} Anything else -- no JSON, a timeout, a missing command --
is inconclusive, never a pass.

A patch is judged against every PoV it is meant to fix (a cluster of variants
of one bug): all must crash before, and none may crash after. A PoV that crashes
SOMEWHERE ELSE after the patch is not fixed either: the patch moved the crash.

Extra gates run after `tests`, in order, against the patched build (a
failure is `extra_gate_failed`):

    "patch": {"extra_gates": [
      {"name": "robust", "command": "command:/opt/robust-fuzz.sh {build} {pov} 420",
       "policy": "preferred"},
      {"name": "neighbours", "neighbours": true}]}

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

# Exported across containers; a change to as_dict()'s shape is a new version
# (tests/golden/exports holds the v1 shape).
VERDICT_SCHEMA = "patch-export/v1"
POV_RUN_SCHEMA = "pov-run/v1"
STEP_RESULT_SCHEMA = "step-result/v1"

REQUIRED, PREFERRED, OPTIONAL = "required", "preferred", "optional"
POLICIES = (REQUIRED, PREFERRED, OPTIONAL)
# Today's behaviour: an unconfigured step is skipped and the gate passes.
DEFAULT_POLICY = {"apply": OPTIONAL, "build": OPTIONAL, "tests": OPTIONAL,
                  "after": REQUIRED}

# outcomes
GATE_FAILED = "extra_gate_failed"
FIXES, DOES_NOT_FIX, BREAKS_TESTS, BUILD_FAILED, APPLY_FAILED, STALE, INCONCLUSIVE = (
    "fixes", "does_not_fix", "breaks_tests", "build_failed", "apply_failed",
    "stale_finding", "inconclusive")
STATUSES = (FIXES, DOES_NOT_FIX, BREAKS_TESTS, GATE_FAILED, BUILD_FAILED, APPLY_FAILED,
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
    ran: bool = True    # False: not configured, or the runner said it had nothing to do
    policy: str = ""

    def as_dict(self) -> dict:
        return {"step": self.name, "ok": self.ok, "ran": self.ran,
                "policy": self.policy, "detail": self.detail,
                "seconds": round(self.seconds, 3), "value": self.value}


@dataclass(frozen=True)
class Scope:
    files: int = 0
    added: int = 0
    removed: int = 0
    paths: tuple = field(default=())
    functions: tuple = field(default=())   # hunk-header function contexts

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
                "functions": list(self.functions), "concerns": self.concerns()}


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
    unverified_steps: tuple = field(default=())   # preferred steps that did not run
    determinism: dict = field(default_factory=dict)  # determinism/v1: the knobs used

    @property
    def validated(self) -> bool:
        return self.status == FIXES

    def as_dict(self) -> dict:
        return {"schema": VERDICT_SCHEMA, "status": self.status, "verdict": self.status,
                "validated": self.validated, "reason": self.reason,
                "steps": [s.as_dict() for s in self.steps],
                "scope": self.scope.as_dict(), "pov": self.pov,
                "stack_hash": self.stack_hash, "seconds": round(self.seconds, 3),
                "povs": [p.as_dict() for p in self.povs], "build": self.build,
                "unverified_steps": list(self.unverified_steps),
                "determinism": dict(self.determinism)}


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
    from cc_fuzzer_core.delta import _function_of
    files, added, removed, funcs = [], 0, 0, []
    for line in (diff_text or "").splitlines():
        if line.startswith("@@"):
            fn = _function_of(line.split("@@")[-1] if line.count("@@") >= 2 else "")
            if fn and fn not in funcs:
                funcs.append(fn)
            continue
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
    return Scope(len(files), added, removed, tuple(files), tuple(funcs))


# ---------------------------------------------------------------------------
# the host's commands
# ---------------------------------------------------------------------------

PLACEHOLDERS = ("patch", "pov", "harness", "build", "stack_hash")


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


def policies(cfg: Mapping) -> dict:
    """The step policy map: defaults, then patch.steps ("test" == "tests")."""
    out = dict(DEFAULT_POLICY)
    block = cfg.get("steps") or {}
    if not isinstance(block, Mapping):
        raise PatchError("patch.steps must be an object")
    for k, v in block.items():
        k = "tests" if k == "test" else k
        if v not in POLICIES:
            raise PatchError(f"patch.steps.{k}={v!r} is not one of {', '.join(POLICIES)}")
        out[k] = v
    return out


def _step_result(stdout: str):
    """A step-result/v1 on the last stdout line, or None."""
    lines = [ln.strip() for ln in (stdout or "").splitlines() if ln.strip()]
    if not lines or not lines[-1].startswith("{"):
        return None
    try:
        doc = json.loads(lines[-1])
    except ValueError:
        return None
    if not isinstance(doc, Mapping) or doc.get("schema") != STEP_RESULT_SCHEMA:
        return None
    return doc


def run_step(name: str, argv: list, *, cwd, timeout: int, env=None,
             policy: str = OPTIONAL) -> Step:
    """Run one command step and say which of pass / fail / did-not-run it was.

    A step that did not run passes unless its policy is `required`.
    """
    if not argv:
        return Step(name, policy != REQUIRED, "not configured; skipped",
                    ran=False, policy=policy)
    t0 = time.monotonic()
    try:
        p = subprocess.run(argv, cwd=str(cwd), capture_output=True, text=True,
                           timeout=timeout, env=env)
    except subprocess.TimeoutExpired:
        return Step(name, False, f"timed out after {timeout}s", time.monotonic() - t0,
                    policy=policy)
    except OSError as e:
        return Step(name, False, f"cannot run {argv[0]}: {e}", time.monotonic() - t0,
                    policy=policy)
    secs = time.monotonic() - t0
    tail = " | ".join((p.stderr or p.stdout or "").strip().splitlines()[-3:])
    doc = _step_result(p.stdout)
    if doc is None:
        lines = [ln.strip() for ln in (p.stdout or "").splitlines() if ln.strip()]
        return Step(name, p.returncode == 0, tail if p.returncode else "", secs,
                    lines[-1] if lines else "", policy=policy)
    reported_ok = doc.get("ok") is True
    ran = doc.get("ran", True) is not False
    reason = str(doc.get("reason") or "")
    value = str(doc.get("value") or "")
    if reported_ok and p.returncode != 0:
        # A runner that says ok and exits non-zero has not told us anything.
        return Step(name, False, f"step-result says ok but exit was {p.returncode}"
                    + (f": {tail}" if tail else ""), secs, value, ran, policy)
    if not ran:
        return Step(name, reported_ok and policy != REQUIRED,
                    reason or "the runner reported it did not run", secs, value,
                    False, policy)
    return Step(name, reported_ok, "" if reported_ok else (reason or tail), secs,
                value, True, policy)


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
             stack_hash: str = "", replay_fn=None,
             sensitivity: Mapping | None = None) -> PatchVerdict:
    """Run the gates against one PoV or several (a cluster of variants of
    one bug). Returns a PatchVerdict; never raises on a failing patch -- a patch
    that does not work is a result, not an error.

    `stack_hash` pins the bug when there is one PoV; with several, each PoV's
    own `before` run defines its bug. `replay_fn(pov, phase, build) -> PovRun`
    replaces the runner entirely (tests, or a host calling in-process).
    """
    cfg = config_block(config)
    pol = policies(cfg)
    from cc_fuzzer_core import determinism as _det
    knobs = _det.resolve(config)
    timeout = int(cfg.get("timeout_s") or DEFAULT_TIMEOUT_S)
    root = Path(project_root)
    t0 = time.monotonic()
    steps: list = []
    if not (cfg.get("pov") and cfg.get("pov_after")) and replay_fn is None:
        from cc_fuzzer_core import variants as _v
        record = _v.with_verify_source(record, config)

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
        unverified = tuple(st.name for st in steps
                           if not st.ran and st.ok and st.policy == PREFERRED)
        return PatchVerdict(status, reason, tuple(steps), scope, povs[0],
                            results[0].stack_hash, time.monotonic() - t0,
                            tuple(results), build, unverified, _det.echo(knobs))

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
        st = run_step(name, argv, cwd=root, timeout=timeout, policy=pol[name])
        steps.append(st)
        if not st.ok:
            _revert(cfg, root, timeout, steps, patch_file, build)
            if not st.ran:
                return done(INCONCLUSIVE, f"required step {name} did not run: {st.detail}")
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
                  cwd=root, timeout=timeout, policy=pol["tests"])
    steps.append(st)
    if not st.ok:
        _revert(cfg, root, timeout, steps, patch_file, build)
        if not st.ran:
            return done(INCONCLUSIVE, f"required step tests did not run: {st.detail}")
        return done(BREAKS_TESTS, f"the patch stops the PoV but breaks the tests: {st.detail}")

    # 6. extra gates, in order, against the patched build
    gate_env = {**os.environ,
                "CC_FUZZER_BUILD": build, "CC_FUZZER_POV": povs[0],
                "CC_FUZZER_POVS": os.pathsep.join(povs),
                "CC_FUZZER_STACK_HASH": results[0].stack_hash,
                "CC_FUZZER_TOUCHED_FUNCTIONS": ",".join(scope.functions),
                "CC_FUZZER_HARNESS": harness, "CC_FUZZER_PATCH": str(patch_file),
                "CC_FUZZER_FUZZER_SEED": str(knobs["fuzzer_seed"])}
    for g in extra_gates(cfg):
        if g["neighbours"]:
            st = _neighbours_gate(g, runner("after"), povs[0], results[0].stack_hash,
                                  sensitivity)
        else:
            argv = _command(g["command"], patch=str(patch_file), pov=povs[0],
                            harness=harness, build=build,
                            stack_hash=results[0].stack_hash)
            st = run_step(f"gate:{g['name']}", argv, cwd=root,
                          timeout=g["timeout_s"] or timeout, env=gate_env,
                          policy=g["policy"])
        steps.append(st)
        if not st.ok:
            _revert(cfg, root, timeout, steps, patch_file, build)
            if not st.ran:
                return done(INCONCLUSIVE, f"required gate {g['name']} did not run: {st.detail}")
            return done(GATE_FAILED, f"gate {g['name']} failed: {st.detail}")
    _revert(cfg, root, timeout, steps, patch_file, build)

    note = "; ".join(scope.concerns())
    unrun = [st.name for st in steps if not st.ran and st.policy == PREFERRED]
    if unrun:
        note = "; ".join(filter(None, [note, f"not run: {', '.join(unrun)}"]))
    what = "PoV no longer reproduces" if len(povs) == 1 else \
        f"none of the {len(povs)} PoVs reproduces"
    return done(FIXES, f"{what} and the tests still pass"
                + (f" (scope: {note})" if note else ""))


def extra_gates(cfg: Mapping) -> list:
    """patch.extra_gates, validated: [{name, command | neighbours, policy, timeout_s}].

    Each runs after `tests`, in order, against the patched build. A command
    gate gets the usual placeholders plus {stack_hash}, and the environment
    CC_FUZZER_{BUILD,POV,POVS,STACK_HASH,TOUCHED_FUNCTIONS,HARNESS,PATCH}.
    `{"neighbours": true}` is built in (see _neighbours_gate). A configured
    gate is `required` unless it says otherwise.
    """
    raw = cfg.get("extra_gates") or []
    if not isinstance(raw, (list, tuple)):
        raise PatchError("patch.extra_gates must be a list")
    out, names = [], set()
    for i, g in enumerate(raw):
        if not isinstance(g, Mapping):
            raise PatchError(f"patch.extra_gates[{i}] must be an object")
        name = str(g.get("name") or "")
        if not name or name in names:
            raise PatchError(f"patch.extra_gates[{i}] needs a unique name")
        names.add(name)
        nb = g.get("neighbours") is True
        cmd = g.get("command") or ""
        if nb == bool(cmd):
            raise PatchError(f"patch.extra_gates[{i}] ({name}) needs exactly one of "
                             f"command or neighbours: true")
        policy = g.get("policy") or REQUIRED
        if policy not in POLICIES:
            raise PatchError(f"patch.extra_gates[{i}].policy={policy!r} is not one of "
                             f"{', '.join(POLICIES)}")
        out.append({"name": name, "command": cmd, "neighbours": nb, "policy": policy,
                    "timeout_s": int(g.get("timeout_s") or 0)})
    return out


def _neighbours_gate(g: Mapping, run_after, pov: str, want: str, sensitivity) -> Step:
    """Replay single-byte variants of the PoV against the patched build.

    The variants are the sensitivity map's own mutations at every byte that
    mattered (load-bearing `#`, constrained `~`) and at every neighbour
    offset. A patch narrower than the bug -- one that rejects the exact value
    in the PoV but not the range around it -- fails here: some variant still
    reproduces THE SAME bug. Crashes elsewhere are reported, not failed.
    """
    import tempfile
    from cc_fuzzer_core import minimize as _minimize
    name, policy, t0 = f"gate:{g['name']}", g["policy"], time.monotonic()
    mask = (sensitivity or {}).get("mask") or ""
    if not mask:
        return Step(name, policy != REQUIRED, "no sensitivity map for this PoV",
                    ran=False, policy=policy)
    offsets = {i for i, m in enumerate(mask) if m in "#~"}
    for n in (sensitivity or {}).get("neighbours") or []:
        offsets.update(n.get("offsets") or [])
    data = Path(pov).read_bytes()
    offsets = sorted(o for o in offsets if 0 <= o < len(data))
    same, other = [], []
    with tempfile.TemporaryDirectory() as td:
        v = Path(td) / "variant.bin"
        for o in offsets:
            for m in _minimize.MUTATIONS:
                buf = bytearray(data)
                buf[o] ^= m
                v.write_bytes(bytes(buf))
                try:
                    got = run_after(str(v))
                except Exception as e:  # noqa: BLE001
                    return Step(name, False, f"could not run a variant: {e}",
                                time.monotonic() - t0, policy=policy)
                if got.crashed and (not got.stack_hash or not want or got.stack_hash == want):
                    same.append(f"{o}^0x{m:02x}")
                elif got.crashed:
                    other.append(f"{o}^0x{m:02x}:{got.stack_hash}")
    n = 2 * len(offsets)
    if same:
        return Step(name, False, f"{len(same)} of {n} single-byte variants still reproduce "
                    f"the bug: {', '.join(same[:8])}", time.monotonic() - t0, policy=policy)
    note = f"{n} variants, none reproduce the bug"
    if other:
        note += f"; {len(other)} crash elsewhere: {', '.join(other[:8])}"
    return Step(name, True, note, time.monotonic() - t0, policy=policy)


def robust_fuzz(binary: str, pov: str, seconds: int, *, corpus: str = "",
                stack_hash: str = "", touched=(), timeout_pad_s: int = 60,
                seed: int = 0) -> dict:
    """The reference extra gate: fuzz the PATCHED libFuzzer build for
    `seconds`, seeded with the PoV (and a corpus), and fail on any crash that
    is the original bug (same stack hash) or whose top frame sits in a
    function the patch touched. Returns a step-result/v1.

    A crash elsewhere in untouched code is reported and passes: it is a
    different, pre-existing bug, and not this patch's to fix.
    """
    import shutil
    import tempfile
    from cc_fuzzer_core.crash import classify as _classify
    from cc_fuzzer_core.crash import replay as _replay

    def res(ok, reason, ran=True, **extra):
        return {"schema": STEP_RESULT_SCHEMA, "ok": ok, "ran": ran, "reason": reason, **extra}

    if not Path(binary).is_file() or not os.access(binary, os.X_OK):
        return res(False, f"no executable fuzzer at {binary}")
    touched = {t for t in touched if t}
    with tempfile.TemporaryDirectory() as td:
        seeds, art = Path(td) / "seeds", Path(td) / "artifacts"
        seeds.mkdir()
        art.mkdir()
        shutil.copy(pov, seeds / "pov")
        if corpus and Path(corpus).is_dir():
            for f in Path(corpus).iterdir():
                if f.is_file():
                    shutil.copy(f, seeds / f"c-{f.name}")
        try:
            # -seed=0 is libFuzzer's "pick one"; a fixed seed makes reruns comparable.
            subprocess.run([binary, f"-max_total_time={int(seconds)}", f"-seed={int(seed)}",
                            f"-artifact_prefix={art}/", "-print_final_stats=0", str(seeds)],
                           capture_output=True, timeout=int(seconds) + timeout_pad_s)
        except subprocess.TimeoutExpired:
            pass                      # it ran; whatever it wrote still counts
        except OSError as e:
            return res(False, f"cannot run {binary}: {e}")
        crashes = sorted(p for p in art.iterdir() if p.name.startswith("crash-"))
        other = []
        for c in crashes:
            rc, out = _replay.run_once(binary, str(c))
            cl = _classify.classify(out, rc)
            if not cl.is_crash:
                continue
            h = _replay.stack_hash(out, category=cl.category)
            fn = (cl.top_frame or "").split(" @ ")[0]
            if stack_hash and h == stack_hash:
                return res(False, f"the original bug ({h}) still reproduces from {c.name}")
            if fn and fn in touched:
                return res(False, f"a crash in {fn}, a function the patch touched ({h})")
            other.append(h)
    note = f"{int(seconds)}s: {len(crashes)} crash artifact(s)"
    if other:
        note += f", {len(set(other))} distinct bug(s) outside the patch"
    return res(True, note, crashes=len(crashes), seed=int(seed))


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


def _cmd_robust_fuzz(a):
    touched = a.touched if a.touched is not None else \
        os.environ.get("CC_FUZZER_TOUCHED_FUNCTIONS", "")
    r = robust_fuzz(a.binary, a.pov, a.seconds, corpus=a.corpus,
                    stack_hash=a.stack_hash or os.environ.get("CC_FUZZER_STACK_HASH", ""),
                    touched=[t for t in touched.split(",") if t],
                    seed=a.seed if a.seed is not None
                    else int(os.environ.get("CC_FUZZER_FUZZER_SEED", "0") or 0))
    print(json.dumps(r))
    return 0 if r["ok"] else 1


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

    v = verbs.add_parser("robust-fuzz", help="reference extra gate: fuzz the patched build; "
                                             "prints step-result/v1 (exit 1 = gate fails)")
    v.add_argument("binary", help="the patched libFuzzer binary")
    v.add_argument("pov")
    v.add_argument("seconds", type=int)
    v.add_argument("--corpus", default="")
    v.add_argument("--stack-hash", default="", help="default $CC_FUZZER_STACK_HASH")
    v.add_argument("--seed", type=int, default=None,
                   help="libFuzzer -seed; default $CC_FUZZER_FUZZER_SEED, else 0")
    v.add_argument("--touched", default=None,
                   help="comma-separated functions; default $CC_FUZZER_TOUCHED_FUNCTIONS")
    v.set_defaults(func=_cmd_robust_fuzz)

    v = verbs.add_parser("scope", help="what the diff touches, and what is worth a look")
    v.add_argument("patch")
    v.set_defaults(func=_cmd_scope)
