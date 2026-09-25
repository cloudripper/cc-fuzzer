"""Builders: one build-spec/v1, several toolchains (§6).

`cc_fuzzer_core.variants` says WHAT each binary must be. A builder says how
THIS toolchain produces it. The split is what lets a second toolchain be added
without re-deciding what a verify binary is:

    nix       the plugin's derivation. The core renders the per-variant
              compiler, cflags and env; nix-build.sh puts them in the
              derivation and runs it, because only the plugin has nix.
    script    a project's own build.sh, handed the spec through the
              environment (CC_FUZZER_VARIANT, _SANITIZERS, _CFLAGS, _OUTPUT...).
    clang     compile the harness directly with clang++. The reference
              implementation, and the one a test can actually run.
    oss-fuzz  an OSS-Fuzz image: the spec becomes $SANITIZER / $FUZZING_ENGINE
              and the binaries are read back from $OUT.

Two layers, deliberately separate:

  plan(spec, backend)   PURE. Returns a `build-plan/v1`: for each variant, the
                        exact command/environment that toolchain would use. No
                        subprocess, no filesystem. This is what tests pin and
                        what nix-build.sh consumes.
  build(...)            Runs a plan where the core can (clang, script) and
                        returns a `build-result/v1`. A backend the core cannot
                        drive itself reports `status: "delegated"` with the
                        plan, for its host to execute.

A `build-result/v1` is `{variant: {status, binary, reason}}` with status one of
ok, failed, skipped, unsupported or delegated. write-harness-built ingests it.
"""
from __future__ import annotations

import json
import sys
from typing import Mapping

from cc_fuzzer_core import variants as _variants

PLAN_SCHEMA = "build-plan/v1"
RESULT_SCHEMA = "build-result/v1"

OK, FAILED, SKIPPED, UNSUPPORTED, DELEGATED = (
    "ok", "failed", "skipped", "unsupported", "delegated")
STATUSES = (OK, FAILED, SKIPPED, UNSUPPORTED, DELEGATED)

NIX, SCRIPT, CLANG, OSS_FUZZ = "nix", "script", "clang", "oss-fuzz"
BACKENDS = (NIX, SCRIPT, CLANG, OSS_FUZZ)


class BuildError(RuntimeError):
    pass


def check_backend(name: str) -> str:
    if name not in BACKENDS:
        raise BuildError(f"unknown build backend '{name}' (known: {', '.join(BACKENDS)})")
    return name


def _adapter(backend: str):
    from importlib import import_module
    mod = {NIX: "nix", SCRIPT: "script", CLANG: "clang", OSS_FUZZ: "ossfuzz"}[check_backend(backend)]
    return import_module(f"cc_fuzzer_core.builders.{mod}")


# ---------------------------------------------------------------------------
# the pure layer
# ---------------------------------------------------------------------------

def plan(spec: Mapping, backend: str, **kw) -> dict:
    """A build-plan/v1 for `spec` on `backend`. Pure: nothing is run."""
    a = _adapter(backend)
    steps = [a.step(v, **kw) for v in spec.get("variants", [])]
    return {
        "schema": PLAN_SCHEMA,
        "backend": backend,
        "harness": spec.get("harness", ""),
        "steps": steps,
        "skipped": list(spec.get("skipped", [])),
    }


def plan_for(config: Mapping | None, harness: str, backend: str, **kw) -> dict:
    return plan(_variants.spec(config or {}, harness), backend, **kw)


# ---------------------------------------------------------------------------
# results
# ---------------------------------------------------------------------------

def result(harness: str, backend: str, entries: Mapping) -> dict:
    """A build-result/v1. `entries` is {variant: {status, binary?, reason?}}."""
    out = {}
    for name, e in entries.items():
        status = e.get("status")
        if status not in STATUSES:
            raise BuildError(f"{name}: status {status!r} is not one of {', '.join(STATUSES)}")
        row = {"status": status}
        if e.get("binary"):
            row["binary"] = e["binary"]
        if e.get("reason"):
            row["reason"] = e["reason"]
        if e.get("command"):
            row["command"] = e["command"]
        out[name] = row
    return {"schema": RESULT_SCHEMA, "harness": harness, "backend": backend, "variants": out}


def failed_required(spec: Mapping, res: Mapping) -> list:
    """Required variants this result did not produce -- the difference between
    a degraded build and a failed one."""
    req = {v["name"] for v in spec.get("variants", []) if v.get("required")}
    got = res.get("variants", {})
    return sorted(n for n in req if got.get(n, {}).get("status") != OK)


# ---------------------------------------------------------------------------
# recording: build-result/v1 -> the harness record
# ---------------------------------------------------------------------------

# variant -> (the flag carrying its path, the flag turning it off, the flag
# carrying the reason). None where the record has no such field.
RECORD_FLAGS = {
    "fuzzer":   ("--harness-binary", None, None),
    "coverage": ("--coverage-binary", "--no-coverage", "--coverage-disabled-reason"),
    "verify":   ("--verify-binary", "--no-verify", None),
    "cmplog":   ("--cmplog-binary", "--no-cmplog", "--cmplog-disabled-reason"),
    "symcc":    ("--symcc-binary", None, None),
}

# Why a variant has no binary, in the words the harness record wants. A
# skipped variant was turned off by the campaign; an unsupported one was asked
# for and could not be built here. Recording both as "disabled" without the
# reason is how a campaign ends up unable to say why it has no verify binary.
_NO_BINARY_REASON = {
    SKIPPED: "not requested for this harness",
    UNSUPPORTED: "not supported by this build backend",
    FAILED: "build failed",
    DELEGATED: "build was delegated and never reported back",
}


def record_args(res: Mapping, *, spec: Mapping | None = None) -> list:
    """The write-harness-built arguments that record this build-result/v1.

    Raises BuildError when a REQUIRED variant is missing, because a harness
    record without its fuzzing binary is not a degraded build to write down,
    it is a failed one.
    """
    if res.get("schema") != RESULT_SCHEMA:
        raise BuildError(f"expected {RESULT_SCHEMA}, got {res.get('schema')!r}")
    rows = res.get("variants") or {}
    if spec is not None:
        missing = failed_required(spec, res)
        if missing:
            raise BuildError("required variant(s) not built: " + ", ".join(missing))
    # A variant the declaration marks required must be PRESENT and ok. An
    # absent row is not "nothing to record": it is a build that never produced
    # the binary, and recording around it makes the campaign look ready.
    for v in _variants.DEFAULTS:
        if v.required and rows.get(v.name, {}).get("status") != OK:
            row = rows.get(v.name) or {}
            raise BuildError(
                f"{v.name}: {row.get('status', 'not built')}"
                f" ({row.get('reason', 'no entry in the build result')})")
    out = ["--build-backend", res.get("backend", "")]
    for name, (path_flag, off_flag, reason_flag) in RECORD_FLAGS.items():
        row = rows.get(name)
        if row is None:
            if off_flag:
                out += [off_flag]
                if reason_flag:
                    out += [reason_flag, _NO_BINARY_REASON[SKIPPED]]
            continue
        if row.get("status") == OK and row.get("binary"):
            out += [path_flag, row["binary"]]
            continue
        if off_flag:
            out += [off_flag]
            if reason_flag:
                reason = row.get("reason") or _NO_BINARY_REASON.get(
                    row.get("status"), "not built")
                out += [reason_flag, reason]
    return out


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def _config(a):
    from cc_fuzzer_core import config as _c
    if getattr(a, "config", None):
        with open(a.config) as f:
            return json.load(f)
    try:
        return _c.load()
    except Exception:
        return {}


def _cmd_plan(a):
    kw = {}
    if getattr(a, "source", None):
        kw["sources"] = list(a.source)
    if getattr(a, "out_dir", None):
        kw["out_dir"] = a.out_dir
    print(json.dumps(plan_for(_config(a), a.harness, a.backend, **kw), indent=2))
    return 0


def _cmd_record_args(a):
    with open(a.result) as f:
        res = json.load(f)
    spec = None
    if a.harness or a.config:
        spec = _variants.spec(_config(a), a.harness or res.get("harness", ""))
    args = record_args(res, spec=spec)
    if a.null:
        sys.stdout.write("\0".join(args))
    else:
        print("\n".join(args))
    return 0


def _cmd_backends(a):
    for b in BACKENDS:
        print(b)
    return 0


def _run(fn):
    def wrapper(a):
        try:
            return fn(a)
        except (BuildError, _variants.VariantError) as e:
            print(f"error: {e}", file=sys.stderr)
            return 2
    return wrapper


def register_cli(subparsers):
    from cc_fuzzer_core.cli import add_subsystem
    _p, verbs = add_subsystem(subparsers, "build",
                              "Turn a build-spec/v1 into one toolchain's commands.")

    v = verbs.add_parser("backends", help="the build backends the core knows")
    v.set_defaults(func=_run(_cmd_backends))

    v = verbs.add_parser("record-args",
                         help="write-harness-built arguments for a build-result/v1")
    v.add_argument("--result", required=True, help="a build-result/v1 JSON file")
    v.add_argument("--harness", default="", help="check the result against this harness's spec")
    v.add_argument("--config", help="read this fuzz-config.json instead of the campaign's")
    v.add_argument("-0", "--null", action="store_true", help="NUL-separate (for xargs -0)")
    v.set_defaults(func=_run(_cmd_record_args))

    v = verbs.add_parser("plan", help="the build-plan/v1 for a harness (runs nothing)")
    v.add_argument("--harness", default="")
    v.add_argument("--backend", default=CLANG, choices=BACKENDS)
    v.add_argument("--source", action="append", help="a source file (repeatable)")
    v.add_argument("--out-dir", help="where the binaries go")
    v.add_argument("--config", help="read this fuzz-config.json instead of the campaign's")
    v.set_defaults(func=_run(_cmd_plan))
