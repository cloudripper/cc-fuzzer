"""Build variants declared as NEEDS, not as compiler flags (§6).

A harness is built several ways from one source: the fuzzing binary, a
coverage binary, a clean verify binary, and optionally cmplog and SymCC ones.
Until now each of those was a list of clang flags written into a prompt and
into nix-build.sh, so "what this binary is for" only existed as the flags that
happened to produce it -- and a builder that is not clang (OSS-Fuzz's, say)
had nothing to translate.

A Variant states the need instead:

    purpose          what the binary is FOR: fuzz, coverage, verify, cmplog, symcc
    sanitizers       which sanitizers must be active
    instrumentation  libfuzzer | afl | source-coverage | cmplog | symcc | none
    link_mode        who supplies main(): fuzzer-main, standalone-main, afl
    debug_info       line tables required
    frame_pointer    frames must be walkable (a readable stack, not a fast one)
    optimization     the -O level this purpose needs
    required         a build that cannot produce it has FAILED, not degraded

A builder maps those needs to whatever its toolchain wants: the nix builder to
today's clang flags (unchanged output), the script builder to environment
variables for a project's own build.sh, the OSS-Fuzz builder to $SANITIZER and
$FUZZING_ENGINE. That is the whole point of the split: adding a builder must
not mean re-deciding what a "verify binary" is.

The defaults are lifted from nix-build.sh (fuzzer, coverage and verify on;
cmplog and symcc opt-in) so the existing behaviour is unchanged. A campaign
overrides them per harness in fuzz-config.json:

    "harnesses": [{"name": "parser", "variants": {"cmplog": {"enabled": true}}}]

`spec(campaign, harness)` resolves defaults + overrides into a `build-spec/v1`
document, which is what a builder is handed and what `cc-fuzzer variants spec`
prints.

CLI: `cc-fuzzer variants list|show|spec`.
"""
from __future__ import annotations

import json
import os
import sys
from dataclasses import dataclass, replace
from typing import Mapping

SPEC_SCHEMA = "build-spec/v1"

# purposes
FUZZ, COVERAGE, VERIFY, CMPLOG, SYMCC = "fuzz", "coverage", "verify", "cmplog", "symcc"
PURPOSES = (FUZZ, COVERAGE, VERIFY, CMPLOG, SYMCC)

# instrumentation
LIBFUZZER, AFL, SOURCE_COVERAGE, INSTR_CMPLOG, INSTR_SYMCC, NONE = (
    "libfuzzer", "afl", "source-coverage", "cmplog", "symcc", "none")
INSTRUMENTATION = (LIBFUZZER, AFL, SOURCE_COVERAGE, INSTR_CMPLOG, INSTR_SYMCC, NONE)

# who supplies main()
FUZZER_MAIN, STANDALONE_MAIN, AFL_MAIN = "fuzzer-main", "standalone-main", "afl"
LINK_MODES = (FUZZER_MAIN, STANDALONE_MAIN, AFL_MAIN)

OPT_LEVELS = ("0", "1", "2", "3", "s", "g")

# The state field each variant's binary path is recorded in, and the suffix the
# bundle symlink carries (nix-build.sh out_suffix; "" for the fuzzing binary).
BINARY_FIELD = {
    "fuzzer": "harness_binary",
    "coverage": "coverage_binary",
    "verify": "verify_binary",
    "cmplog": "cmplog_binary",
    "symcc": "symcc_binary",
}
BINARY_SUFFIX = {"fuzzer": "", "coverage": "_cov", "verify": "_verify",
                 "cmplog": "_cmplog", "symcc": "_symcc"}


class VariantError(ValueError):
    pass


@dataclass(frozen=True)
class Variant:
    name: str
    purpose: str
    sanitizers: tuple = ()
    instrumentation: str = NONE
    link_mode: str = STANDALONE_MAIN
    debug_info: bool = True
    frame_pointer: bool = True
    optimization: str = "1"
    required: bool = False
    enabled: bool = True

    def binary_field(self) -> str:
        return BINARY_FIELD[self.name]

    def binary_suffix(self) -> str:
        return BINARY_SUFFIX[self.name]

    def as_dict(self) -> dict:
        return {
            "name": self.name,
            "purpose": self.purpose,
            "sanitizers": list(self.sanitizers),
            "instrumentation": self.instrumentation,
            "link_mode": self.link_mode,
            "debug_info": self.debug_info,
            "frame_pointer": self.frame_pointer,
            "optimization": self.optimization,
            "required": self.required,
            "enabled": self.enabled,
            "binary_field": self.binary_field(),
            "binary_suffix": self.binary_suffix(),
        }


# ---------------------------------------------------------------------------
# defaults (nix-build.sh's variant block, stated as needs)
# ---------------------------------------------------------------------------

DEFAULTS = (
    Variant("fuzzer", FUZZ,
            sanitizers=("address", "undefined", "fuzzer"),
            instrumentation=LIBFUZZER, link_mode=FUZZER_MAIN,
            required=True, enabled=True),
    # -O0 and no frame-pointer flag: line-accurate counts matter here, speed
    # and stack readability do not.
    Variant("coverage", COVERAGE,
            instrumentation=SOURCE_COVERAGE, link_mode=STANDALONE_MAIN,
            frame_pointer=False, optimization="0", enabled=True),
    # No `fuzzer` sanitizer and no coverage instrumentation: a crash has to
    # reproduce on a binary that carries neither, or the evidence is about the
    # instrumentation rather than the bug (§12 selects this one for replay).
    Variant("verify", VERIFY,
            sanitizers=("address", "undefined"),
            instrumentation=NONE, link_mode=STANDALONE_MAIN,
            enabled=True),
    Variant("cmplog", CMPLOG,
            instrumentation=INSTR_CMPLOG, link_mode=AFL_MAIN,
            enabled=False),
    Variant("symcc", SYMCC,
            instrumentation=INSTR_SYMCC, link_mode=STANDALONE_MAIN,
            frame_pointer=False, enabled=False),
)
BY_NAME = {v.name: v for v in DEFAULTS}
NAMES = tuple(v.name for v in DEFAULTS)


def default(name: str) -> Variant:
    if name not in BY_NAME:
        raise VariantError(f"unknown variant '{name}' (known: {', '.join(NAMES)})")
    return BY_NAME[name]


# ---------------------------------------------------------------------------
# overrides
# ---------------------------------------------------------------------------

_BOOL_FIELDS = ("debug_info", "frame_pointer", "required", "enabled")
_STR_FIELDS = {"purpose": PURPOSES, "instrumentation": INSTRUMENTATION,
               "link_mode": LINK_MODES, "optimization": OPT_LEVELS}


def apply_override(base: Variant, over: Mapping) -> Variant:
    """One variant's override block from fuzz-config.json."""
    if not isinstance(over, Mapping):
        raise VariantError(f"variants.{base.name} must be an object")
    out = base
    for k, v in over.items():
        if k in _BOOL_FIELDS:
            if not isinstance(v, bool):
                raise VariantError(f"variants.{base.name}.{k} must be true or false")
            out = replace(out, **{k: v})
        elif k in _STR_FIELDS:
            if v not in _STR_FIELDS[k]:
                raise VariantError(
                    f"variants.{base.name}.{k}={v!r} is not one of {', '.join(_STR_FIELDS[k])}")
            out = replace(out, **{k: v})
        elif k == "sanitizers":
            if not isinstance(v, (list, tuple)) or not all(isinstance(s, str) for s in v):
                raise VariantError(f"variants.{base.name}.sanitizers must be a list of strings")
            out = replace(out, sanitizers=tuple(v))
        else:
            raise VariantError(
                f"variants.{base.name}.{k} is not a known field "
                f"(known: sanitizers, {', '.join((*_STR_FIELDS, *_BOOL_FIELDS))})")
    return out


def resolve(overrides: Mapping | None = None) -> list:
    """Every variant with its overrides applied, in declaration order."""
    overrides = overrides or {}
    if not isinstance(overrides, Mapping):
        raise VariantError("variants must be an object")
    for name in overrides:
        default(name)                      # raises on an unknown variant
    return [apply_override(v, overrides.get(v.name, {})) for v in DEFAULTS]


def enabled(overrides: Mapping | None = None) -> list:
    return [v for v in resolve(overrides) if v.enabled]


# ---------------------------------------------------------------------------
# the document a builder is handed
# ---------------------------------------------------------------------------

def harness_overrides(config: Mapping, harness: str) -> dict:
    """The `variants` block for one harness in fuzz-config.json (a campaign-wide
    `variants` block applies to every harness; the per-harness one wins)."""
    doc = config or {}
    base = dict(doc.get("variants") or {})
    for h in doc.get("harnesses") or []:
        if isinstance(h, Mapping) and h.get("name") == harness:
            for k, v in (h.get("variants") or {}).items():
                base[k] = {**base.get(k, {}), **v} if isinstance(v, Mapping) else v
            break
    return base


def spec(config: Mapping | None = None, harness: str = "") -> dict:
    """A `build-spec/v1`: what this harness needs built, as needs."""
    over = harness_overrides(config or {}, harness)
    return {
        "schema": SPEC_SCHEMA,
        "harness": harness,
        "variants": [v.as_dict() for v in resolve(over) if v.enabled],
        "skipped": [v.name for v in resolve(over) if not v.enabled],
    }


def required_names(config: Mapping | None = None, harness: str = "") -> list:
    return [v["name"] for v in spec(config, harness)["variants"] if v["required"]]


# ---------------------------------------------------------------------------
# selection: which binary an action is allowed to run on (§12)
# ---------------------------------------------------------------------------

# The actions that reach for a binary.
A_FUZZ, A_CMPLOG, A_CONCOLIC, A_COVERAGE = "fuzz", "cmplog", "concolic", "coverage"
A_REPLAY, A_VERIFY, A_POC = "replay", "verify", "poc"
ACTIONS = (A_FUZZ, A_CMPLOG, A_CONCOLIC, A_COVERAGE, A_REPLAY, A_VERIFY, A_POC)

# action -> the variants it may use, best first.
_ALLOWED = {
    A_FUZZ:     ("fuzzer",),
    A_COVERAGE: ("coverage",),
    A_CMPLOG:   ("cmplog",),
    A_CONCOLIC: ("symcc",),
    # Evidence actions. NEVER cmplog, symcc or coverage: a crash reproduced on
    # an instrumented binary is evidence about the instrumentation.
    A_VERIFY:   ("verify",),
    A_POC:      ("verify",),
    A_REPLAY:   ("verify", "fuzzer"),
}
# Actions only the slot launcher may ask for: an instrumented binary is for
# feeding the fuzzer, never for running by hand.
LAUNCHER_ONLY = (A_CMPLOG, A_CONCOLIC)
LAUNCHER_CALLER = "launcher"

# Evidence quality of a selection. `weak` is still usable -- it is what the
# triager falls back to when no verify binary was built -- but it is recorded
# so a finding cannot silently rest on it.
STRONG, WEAK = "strong", "weak"


class SelectionError(VariantError):
    pass


@dataclass(frozen=True)
class Selection:
    binary: str
    variant: str
    reason: str
    evidence_grade: str = STRONG

    def as_dict(self) -> dict:
        return {"binary": self.binary, "variant": self.variant,
                "reason": self.reason, "evidence_grade": self.evidence_grade}


def check_action(action: str) -> str:
    if action not in ACTIONS:
        raise SelectionError(f"unknown action '{action}' (known: {', '.join(ACTIONS)})")
    return action


def allowed_variants(action: str) -> tuple:
    return _ALLOWED[check_action(action)]


def forbidden_for_evidence() -> tuple:
    """Variants whose binaries can never carry evidence."""
    return ("cmplog", "symcc", "coverage")


def select(record: Mapping, action: str, *, caller: str = "", harness: str = "") -> Selection:
    """Which binary `action` runs on, from a harness-built record.

    Raises SelectionError rather than falling back to whatever is built: under
    time pressure a triager reaches for the binary that already exists, and
    that is exactly how an instrumented binary ends up behind a finding.
    """
    check_action(action)
    if action in LAUNCHER_ONLY and caller != LAUNCHER_CALLER:
        raise SelectionError(
            f"{action} binaries are reachable only through the slot launcher "
            f"(caller={caller or 'unset'!s}); they are for feeding the fuzzer, not for "
            f"running by hand")
    rec = record or {}
    for i, name in enumerate(allowed_variants(action)):
        field = BINARY_FIELD[name]
        path = rec.get(field)
        path = "" if path in (None, "None") else str(path)
        if not path:
            continue
        if i == 0:
            return Selection(path, name, f"{action} runs on {field}")
        return Selection(
            path, name,
            f"{action} fell back to {field}: no {BINARY_FIELD[allowed_variants(action)[0]]} "
            f"was built for {harness or 'this harness'}",
            WEAK)
    wanted = ", ".join(BINARY_FIELD[n] for n in allowed_variants(action))
    raise SelectionError(
        f"no binary for action '{action}' on {harness or 'this harness'}: "
        f"none of {wanted} is recorded")


def check_binary(record: Mapping, action: str, binary: str, *, caller: str = "",
                 harness: str = "") -> Selection:
    """Refuse `binary` unless it is the one select() would have chosen."""
    sel = select(record, action, caller=caller, harness=harness)
    if os.path.realpath(binary) != os.path.realpath(sel.binary):
        raise SelectionError(
            f"'{action}' may not run on {binary}: use {sel.binary} ({sel.variant})")
    return sel


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


def _cmd_list(a):
    for v in DEFAULTS:
        state = "on " if v.enabled else "off"
        print(f"{v.name:<9} {state}  purpose={v.purpose:<8} instr={v.instrumentation:<15} "
              f"link={v.link_mode:<16} {'required' if v.required else ''}")
    return 0


def _cmd_show(a):
    v = default(a.variant)
    print(json.dumps(v.as_dict(), indent=2))
    return 0


def harness_record(campaign=None, harness: str = "") -> dict:
    """The harness-built record select() reads. Falls back to the
    harness-built.json mirror when no harness is named."""
    from cc_fuzzer_core.paths import HarnessLayout, campaign as _campaign
    c = campaign or _campaign(strict=False)
    if harness:
        layout = HarnessLayout(c.fuzz_root, c.state_dir)
        for rec in (layout.records() if hasattr(layout, "records") else []):
            if rec.get("name") == harness:
                return rec
        try:
            doc = json.loads((c.state_dir / "harnesses.json").read_text())
            for rec in doc.get("harnesses", []):
                if rec.get("name") == harness:
                    return rec
        except Exception:
            pass
        raise SelectionError(f"no harness named '{harness}' in harnesses.json")
    try:
        return json.loads((c.state_dir / "harness-built.json").read_text())
    except Exception:
        raise SelectionError("no harness-built.json; name a harness with --harness")


def _cmd_select(a):
    rec = harness_record(harness=a.harness)
    sel = select(rec, a.action, caller=a.caller, harness=a.harness)
    if a.json:
        print(json.dumps(sel.as_dict(), indent=2))
    else:
        print(sel.binary)
    return 0


def _cmd_spec(a):
    print(json.dumps(spec(_config(a), a.harness), indent=2))
    return 0


def _run(fn):
    def wrapper(a):
        try:
            return fn(a)
        except VariantError as e:
            print(f"error: {e}", file=sys.stderr)
            return 2
    return wrapper


def register_cli(subparsers):
    from cc_fuzzer_core.cli import add_subsystem
    _p, verbs = add_subsystem(subparsers, "variants",
                              "Build variants declared as needs (build-spec/v1).")

    v = verbs.add_parser("list", help="the declared variants and their defaults")
    v.set_defaults(func=_run(_cmd_list))

    v = verbs.add_parser("show", help="one variant's declaration as JSON")
    v.add_argument("variant", choices=NAMES)
    v.set_defaults(func=_run(_cmd_show))

    v = verbs.add_parser("select",
                         help="which binary an action may run on (§12)")
    v.add_argument("--harness", default="")
    v.add_argument("--action", required=True, choices=ACTIONS)
    v.add_argument("--caller", default="", help="e.g. launcher, for cmplog/concolic")
    v.add_argument("--json", action="store_true")
    v.set_defaults(func=_run(_cmd_select))

    v = verbs.add_parser("spec", help="the build-spec/v1 for a harness")
    v.add_argument("--harness", default="", help="harness name (for its overrides)")
    v.add_argument("--config", help="read this fuzz-config.json instead of the campaign's")
    v.set_defaults(func=_run(_cmd_spec))
