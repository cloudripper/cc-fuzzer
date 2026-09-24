"""Root and campaign path resolution (UPDATE_ROADMAP.md §1).

Three questions, one answer each:

plugin_root()  Where do the shared data files live (STATE_SCHEMA.md, rules/,
               dictionaries/, templates/, references/)? Resolution order:
                 1. $CC_FUZZER_ROOT
                 2. the installed package data: files("cc_fuzzer_core")/"data"
                 3. the source checkout this module was imported from (the
                    dev / plugin layout, where data sits at the repo root)
               Host adapters map their own variables onto CC_FUZZER_ROOT
               before calling in (the plugin does it in scripts/_lib/root.sh);
               the core never reads host variables itself.

campaign()     Which project / fuzz tree / state dir is this? A port of
               scripts/_lib/path-anchor.sh that returns
               Campaign(project_root, fuzz_root, state_dir) and never changes
               the process cwd. state_dir honours $FUZZ_STATE_DIR (relative
               values resolve against project_root).

HarnessLayout  Per-harness paths and lookups inside one campaign. A port of
               scripts/_lib/harness-path.sh; `cc-fuzzer paths <verb>` is its
               CLI and harness-path.sh's CLI mode is a shim onto it.
"""
from __future__ import annotations

import json
import os
import re
import shlex
import sys
from dataclasses import dataclass
from importlib import resources
from pathlib import Path
from typing import Mapping

ENV_ROOT = "CC_FUZZER_ROOT"

HARNESS_NAME_RE = re.compile(r"^[a-z0-9][a-z0-9_-]{0,31}$")
_CRASH_NAME_RE = re.compile(r"^([a-z0-9][a-z0-9_-]{0,31})__([0-9a-f]+)$")


class RootNotFound(RuntimeError):
    pass


class CampaignError(RuntimeError):
    """Campaign resolution failed. `str(e)` is the (multi-line) message
    path-anchor.sh prints; `code` is its exit status."""

    def __init__(self, message: str, code: int = 2):
        super().__init__(message)
        self.code = code


# ---------------------------------------------------------------------------
# Plugin / data root
# ---------------------------------------------------------------------------

def _looks_like_root(p: Path) -> bool:
    return (p / "STATE_SCHEMA.md").is_file()


def plugin_root(env: Mapping[str, str] | None = None) -> Path:
    """The directory holding the shared data files (see module docstring)."""
    env = os.environ if env is None else env
    explicit = env.get(ENV_ROOT)
    if explicit:
        return Path(explicit)
    try:
        packaged = Path(str(resources.files("cc_fuzzer_core") / "data"))
    except (ModuleNotFoundError, TypeError):  # pragma: no cover - zipimport etc.
        packaged = None
    if packaged is not None and _looks_like_root(packaged):
        return packaged
    checkout = Path(__file__).resolve().parents[2]
    if _looks_like_root(checkout):
        return checkout
    raise RootNotFound(
        f"cannot locate cc-fuzzer data: set {ENV_ROOT}, or install the package with its data")


def package_data_dir() -> Path:
    """cc_fuzzer_core/data inside the package itself. It always carries the
    core-owned data (models.json); an installed wheel adds the shared data
    force-included from the repo root (STATE_SCHEMA.md, rules/, ...)."""
    return Path(__file__).resolve().parent / "data"


def data(*parts: str, env: Mapping[str, str] | None = None) -> Path:
    """Path of a data file/dir, e.g. data("rules"), data("STATE_SCHEMA.md"),
    data("models.json"). Looked up under plugin_root() first; core-owned files
    that only the package ships (models.json) fall back to package_data_dir(),
    so they resolve in a checkout, under CC_FUZZER_ROOT and when installed."""
    own = package_data_dir().joinpath(*parts)
    try:
        p = plugin_root(env).joinpath(*parts)
    except RootNotFound:
        if own.exists():
            return own
        raise
    return own if not p.exists() and own.exists() else p


# ---------------------------------------------------------------------------
# Campaign
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class Campaign:
    project_root: Path
    fuzz_root: Path
    state_dir: Path

    @property
    def snapshots_dir(self) -> Path:
        return self.state_dir / "snapshots"

    @property
    def harnesses_dir(self) -> Path:
        return self.fuzz_root / "harnesses"

    @property
    def crashes_dir(self) -> Path:
        return self.fuzz_root / "crashes"

    def layout(self) -> "HarnessLayout":
        return HarnessLayout(self.fuzz_root, self.state_dir)


def _logical_cwd() -> str:
    """$PWD when it names the cwd (keeps symlinked paths as the shell shows
    them, like bash's $PWD), else os.getcwd()."""
    cwd = os.getcwd()
    pwd = os.environ.get("PWD")
    try:
        if pwd and os.path.isabs(pwd) and os.path.samefile(pwd, cwd):
            return pwd
    except OSError:
        pass
    return cwd


def find_project_root(start: str | os.PathLike | None = None) -> Path | None:
    """Walk up from start (default: cwd) to the first directory that contains
    fuzz/ and is not itself named fuzz. None when there is none."""
    d = Path(os.path.abspath(start if start is not None else _logical_cwd()))
    while str(d) != d.anchor:
        if (d / "fuzz").is_dir() and d.name != "fuzz":
            return d
        d = d.parent
    return None


def resolve_state_dir(project_root: Path, fuzz_root: Path,
                      env: Mapping[str, str] | None = None) -> Path:
    """$FUZZ_STATE_DIR (relative => against project_root), else fuzz/state."""
    env = os.environ if env is None else env
    override = env.get("FUZZ_STATE_DIR")
    if override:
        p = Path(override)
        return p if p.is_absolute() else project_root / p
    return fuzz_root / "state"


def state_dir_text(c: "Campaign", env: Mapping[str, str] | None = None) -> str:
    """The state dir as the path-anchored scripts print it:
    ${FUZZ_STATE_DIR:-$FUZZ_ROOT/state} -- a relative override stays relative
    (to the project root), the default is absolute. For messages and recorded
    paths only; do I/O through Campaign.state_dir."""
    env = os.environ if env is None else env
    raw = env.get("FUZZ_STATE_DIR")
    if raw and resolve_state_dir(c.project_root, c.fuzz_root, env) == c.state_dir:
        return raw
    return str(c.state_dir)


def campaign(start: str | os.PathLike | None = None, *,
             project_root: str | os.PathLike | None = None,
             env: Mapping[str, str] | None = None,
             strict: bool = True) -> Campaign:
    """Resolve the campaign the way path-anchor.sh does, without cd'ing.

    project_root (argument, else $PROJECT_ROOT) wins over the upward walk from
    `start`. With strict=True a recursive fuzz/fuzz/ is refused (state
    corruption); strict=False lets diagnostics (doctor) inspect such a tree.
    Raises CampaignError with path-anchor.sh's messages and exit code.
    """
    env = os.environ if env is None else env
    explicit = project_root if project_root is not None else (env.get("PROJECT_ROOT") or None)
    if explicit is not None:
        root = Path(os.path.abspath(explicit))
        if not (root / "fuzz").is_dir():
            raise CampaignError(f"ERROR: PROJECT_ROOT={explicit} does not contain fuzz/")
    else:
        root = find_project_root(start)
        if root is None:
            raise CampaignError(
                "ERROR: not inside a cc-fuzzer project (no fuzz/ directory found in any parent)\n"
                "       run from the project root, or set PROJECT_ROOT=/path/to/project")
    fuzz_root = root / "fuzz"
    if strict and (fuzz_root / "fuzz").is_dir():
        raise CampaignError(
            f"ERROR: recursive fuzz/fuzz/ detected at {root}/fuzz/fuzz/\n"
            "       this is state corruption - run /cc-fuzzer:doctor to diagnose and fix\n"
            "       (most likely: a script ran with cwd inside fuzz/, creating nested copies)")
    return Campaign(root, fuzz_root, resolve_state_dir(root, fuzz_root, env))


# ---------------------------------------------------------------------------
# Harness layout (port of harness-path.sh)
# ---------------------------------------------------------------------------

def _load_json(path: Path):
    try:
        with open(path) as f:
            return json.load(f)
    except Exception:
        return None


class HarnessLayout:
    """Per-harness paths for one campaign (schema v12, multi-harness only).

    fuzz_root / state_dir may be relative (resolved against the caller's cwd),
    which is how harness-path.sh's CLI behaves: FUZZ_ROOT defaults to "fuzz".
    The declared-harness list is read once from fuzz-config.json and cached;
    call invalidate() after changing it.
    """

    def __init__(self, fuzz_root: str | os.PathLike = "fuzz",
                 state_dir: str | os.PathLike | None = None):
        self.fuzz_root = Path(fuzz_root)
        self.state_dir = Path(state_dir) if state_dir is not None else self.fuzz_root / "state"
        self._declared: list[str] | None = None

    @classmethod
    def from_env(cls, env: Mapping[str, str] | None = None) -> "HarnessLayout":
        """Mirror harness-path.sh's own resolution: ${FUZZ_ROOT:-fuzz} and
        ${FUZZ_STATE_DIR:-$FUZZ_ROOT/state}, both as given (no anchoring)."""
        env = os.environ if env is None else env
        fuzz_root = env.get("FUZZ_ROOT") or "fuzz"
        state = env.get("FUZZ_STATE_DIR") or f"{fuzz_root}/state"
        return cls(fuzz_root, state)

    # -- declared harnesses ---------------------------------------------------

    def invalidate(self) -> None:
        self._declared = None

    def declared_harnesses(self) -> list[str]:
        if self._declared is None:
            names: list[str] = []
            doc = _load_json(self.state_dir / "fuzz-config.json")
            hs = doc.get("harnesses") if isinstance(doc, dict) else None
            if isinstance(hs, list):
                names = [h["name"] for h in hs if isinstance(h, dict) and h.get("name")]
            self._declared = names
        return list(self._declared)

    def is_multi(self) -> bool:  # multi is the only mode since v0.30
        return True

    def is_known_harness(self, name: str) -> bool:
        return name in self.declared_harnesses()

    def default_harness(self) -> str:
        d = self.declared_harnesses()
        return d[0] if d else ""

    # -- per-harness directories ---------------------------------------------

    def harness_root(self, name: str) -> Path:
        return self.fuzz_root / "harnesses" / name

    def harness_dir(self, name: str) -> Path:
        return self.harness_root(name) / "harness"

    def corpus_dir(self, name: str) -> Path:
        return self.harness_root(name) / "corpus"

    def quarantine_dir(self, name: str) -> Path:
        return self.harness_root(name) / "corpus-quarantine"

    def coverage_dir(self, name: str) -> Path:
        return self.harness_root(name) / "coverage"

    # -- basenames --------------------------------------------------------------

    @staticmethod
    def coverage_snapshot_name(name: str, ts) -> str:
        return f"coverage-{name}-{ts}.json"

    @staticmethod
    def gaps_snapshot_name(name: str, ts) -> str:
        return f"gaps-{name}-{ts}.json"

    @staticmethod
    def concolic_snapshot_name(name: str, ts) -> str:
        return f"concolic-{name}-{ts}.json"

    @staticmethod
    def cmplog_dict_name(name: str, ts) -> str:
        return f"cmplog-dict-{name}-{ts}.dict"

    @staticmethod
    def crash_filename(name: str, digest: str) -> str:
        return f"{name}__{digest}.bin"

    @staticmethod
    def parse_crash_filename(path: str | os.PathLike) -> tuple[str, str] | None:
        """<harness>__<hash>[.bin] -> (harness, hash); None if nonconforming."""
        base = os.path.basename(os.fspath(path))
        if base.endswith(".bin"):
            base = base[:-4]
        m = _CRASH_NAME_RE.match(base)
        return (m.group(1), m.group(2)) if m else None

    # -- record lookups ---------------------------------------------------------

    def harness_record(self, name: str) -> dict | None:
        doc = _load_json(self.state_dir / "harnesses.json")
        if not isinstance(doc, dict):
            return None
        for h in doc.get("harnesses", []):
            if isinstance(h, dict) and h.get("name") == name:
                return h
        return None

    def harness_field(self, name: str, field: str):
        rec = self.harness_record(name)
        return None if rec is None else rec.get(field)

    def harness_binary(self, name: str):
        return self.harness_field(name, "harness_binary")

    def slot_to_harness(self, slot: str) -> str | None:
        doc = _load_json(self.state_dir / "fuzzers.json")
        if not isinstance(doc, dict):
            return None
        for s in doc.get("slots", []):
            if isinstance(s, dict) and s.get("slot") == slot:
                return s.get("harness", "")
        return None

    @staticmethod
    def afl_instances(out_dir: str | os.PathLike) -> list[Path]:
        """AFL++ instance dirs under out_dir (those with fuzzer_stats or
        queue/), default/ first when present, then the rest by name."""
        if not os.fspath(out_dir):
            return []
        out = Path(out_dir)
        if not out.is_dir():
            return []

        def is_instance(d: Path) -> bool:
            return (d / "fuzzer_stats").is_file() or (d / "queue").is_dir()

        found = []
        if (out / "default").is_dir() and is_instance(out / "default"):
            found.append(out / "default")
        for d in sorted(p for p in out.iterdir() if not p.name.startswith(".")):
            if d.name != "default" and d.is_dir() and is_instance(d):
                found.append(d)
        return found


def _field_text(v) -> str | None:
    """Render a record field the way harness-path.sh prints it."""
    if v is None:
        return None
    if isinstance(v, (list, dict)):
        return json.dumps(v)
    return str(v)


# ---------------------------------------------------------------------------
# CLI: cc-fuzzer paths <verb>
# ---------------------------------------------------------------------------

def _print(*lines):
    for ln in lines:
        if ln is not None:
            sys.stdout.write(f"{ln}\n")


def _cmd_root(_a):
    try:
        _print(plugin_root())
    except RootNotFound as e:
        sys.stderr.write(f"{e}\n")
        return 1
    return 0


def _cmd_data(a):
    try:
        _print(data(*a.parts))
    except RootNotFound as e:
        sys.stderr.write(f"{e}\n")
        return 1
    return 0


def _cmd_campaign(a):
    try:
        c = campaign(a.start, strict=not a.lenient)
    except CampaignError as e:
        if a.missing_ok and "not inside a cc-fuzzer project" in str(e):
            return 1
        sys.stderr.write(f"{e}\n")
        return e.code
    fields = {"PROJECT_ROOT": c.project_root, "FUZZ_ROOT": c.fuzz_root, "STATE_DIR": c.state_dir}
    if a.format == "json":
        _print(json.dumps({k.lower(): str(v) for k, v in fields.items()}))
    elif a.format == "sh":
        _print(*(f"{k}={shlex.quote(str(v))}" for k, v in fields.items()))
    else:
        _print(*(f"{k}={v}" for k, v in fields.items()))
    return 0


def _layout_cmd(fn):
    def run(a):
        return fn(HarnessLayout.from_env(), a)
    return run


def _hp_is_multi(lay, _a):
    _print("multi")


def _hp_declared(lay, _a):
    names = lay.declared_harnesses()
    _print(*(names or [""]))


def _hp_is_known(lay, a):
    if lay.is_known_harness(a.name):
        _print("yes")
        return 0
    _print("no")
    return 1


def _hp_default(lay, _a):
    _print(lay.default_harness())


def _hp_dir(method):
    def run(lay, a):
        _print(getattr(lay, method)(a.name))
    return run


def _hp_basename(method):
    def run(lay, a):
        _print(getattr(HarnessLayout, method)(a.name, a.value))
    return run


def _hp_parse_crash(lay, a):
    r = HarnessLayout.parse_crash_filename(a.path)
    if r is None:
        return 1
    _print(f"{r[0]}\t{r[1]}")
    return 0


def _hp_field(lay, a):
    _print(_field_text(lay.harness_field(a.name, a.field)))


def _hp_binary(lay, a):
    _print(_field_text(lay.harness_binary(a.name)))


def _hp_slot(lay, a):
    _print(lay.slot_to_harness(a.slot))


def _hp_afl(lay, a):
    _print(*HarnessLayout.afl_instances(a.out_dir))


def register_cli(subparsers):
    from cc_fuzzer_core.cli import add_subsystem

    _p, verbs = add_subsystem(subparsers, "paths", "root, campaign and per-harness path resolution")

    v = verbs.add_parser("root", help="print the data root (CC_FUZZER_ROOT / package data / checkout)")
    v.set_defaults(func=_cmd_root)
    v = verbs.add_parser("data", help="print the path of a shared data file/dir")
    v.add_argument("parts", nargs="*")
    v.set_defaults(func=_cmd_data)
    v = verbs.add_parser("campaign", help="resolve PROJECT_ROOT / FUZZ_ROOT / STATE_DIR (port of path-anchor.sh)")
    v.add_argument("--start", help="walk up from here (default: cwd)")
    v.add_argument("--lenient", action="store_true", help="do not refuse a recursive fuzz/fuzz/")
    v.add_argument("--missing-ok", action="store_true",
                   help="no project found => exit 1 silently (hooks, session-start probes)")
    v.add_argument("--format", choices=("lines", "sh", "json"), default="lines",
                   help="sh = shell-quoted assignments for eval")
    v.set_defaults(func=_cmd_campaign)

    # harness-path.sh verbs (same names, arguments, output and exit codes).
    hp = "harness-path.sh verb; FUZZ_ROOT/FUZZ_STATE_DIR from env"
    v = verbs.add_parser("is_multi", help=hp)
    v.set_defaults(func=_layout_cmd(_hp_is_multi))
    v = verbs.add_parser("declared_harnesses", help=hp)
    v.set_defaults(func=_layout_cmd(_hp_declared))
    v = verbs.add_parser("is_known_harness", help=hp)
    v.add_argument("name", nargs="?", default="")
    v.set_defaults(func=_layout_cmd(_hp_is_known))
    v = verbs.add_parser("default_harness", help=hp)
    v.set_defaults(func=_layout_cmd(_hp_default))
    for m in ("harness_root", "harness_dir", "corpus_dir", "quarantine_dir", "coverage_dir"):
        v = verbs.add_parser(m, help=hp)
        v.add_argument("name", nargs="?", default="")
        v.set_defaults(func=_layout_cmd(_hp_dir(m)))
    for m in ("coverage_snapshot_name", "gaps_snapshot_name", "concolic_snapshot_name",
              "cmplog_dict_name", "crash_filename"):
        v = verbs.add_parser(m, help=hp)
        v.add_argument("name", nargs="?", default="")
        v.add_argument("value", nargs="?", default="")
        v.set_defaults(func=_layout_cmd(_hp_basename(m)))
    v = verbs.add_parser("parse_crash_filename", help=hp)
    v.add_argument("path", nargs="?", default="")
    v.set_defaults(func=_layout_cmd(_hp_parse_crash))
    v = verbs.add_parser("harness_field", help=hp)
    v.add_argument("name", nargs="?", default="")
    v.add_argument("field", nargs="?", default="")
    v.set_defaults(func=_layout_cmd(_hp_field))
    v = verbs.add_parser("harness_binary", help=hp)
    v.add_argument("name", nargs="?", default="")
    v.set_defaults(func=_layout_cmd(_hp_binary))
    v = verbs.add_parser("slot_to_harness", help=hp)
    v.add_argument("slot", nargs="?", default="")
    v.set_defaults(func=_layout_cmd(_hp_slot))
    v = verbs.add_parser("afl_instances", help=hp)
    v.add_argument("out_dir", nargs="?", default="")
    v.set_defaults(func=_layout_cmd(_hp_afl))
