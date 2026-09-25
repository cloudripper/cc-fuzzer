"""fuzz-config.json read/write, including nested blocks (UPDATE_ROADMAP.md §2 row 1).

Replaces the `python3 -c` snippets in scripts/_lib/fuzz-config.sh, which is now
a shim onto `cc-fuzzer config <verb>`. Every other reader of fuzz-config.json
in the core goes through load()/lookup() so there is one parser and one
"missing / unreadable file => {}" rule.

API
  config_path(campaign)                  state_dir/fuzz-config.json
  load(campaign_or_path) -> dict          {} when missing, unreadable or not an object
  lookup(doc, key, default)               dotted keys walk nested blocks ("yolo.max_ticks")
  set_value(campaign, key, raw) -> SetResult   the `set` verb (digits => int)
  update_block(campaign, block, merge)    merge a dict into one top-level block
  resolve_fuzz_forks(campaign, env) -> ForkResolution
                                          FUZZ_FORKS > FUZZ_FORKS_OVERRIDE > file > 2,
                                          capped at nproc-1 (floor 1); 0 = no fork mode

Writers keep the plugin's on-disk formats: `set` rewrites the file with
sort_keys (as fuzz-config.sh always did); update_block() keeps key order and
adds a trailing newline (the yolo-state.sh writer). Both write atomically.
"""
from __future__ import annotations

import json
import os
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Mapping

from cc_fuzzer_core.paths import Campaign, CampaignError, campaign as _campaign, resolve_state_dir

FILENAME = "fuzz-config.json"
DEFAULT_SCHEMA = "fuzz-config/v3"
DEFAULT_FUZZ_FORKS = 2

_MISSING = object()


# ---------------------------------------------------------------------------
# read
# ---------------------------------------------------------------------------

def config_path(c: Campaign | str | os.PathLike) -> Path:
    """The fuzz-config.json of a campaign (or of a state dir / explicit file)."""
    if isinstance(c, Campaign):
        return c.state_dir / FILENAME
    p = Path(c)
    return p if p.name == FILENAME or p.suffix == ".json" else p / FILENAME


def _read(path: Path):
    """Parsed JSON, _MISSING when the file does not exist, None when unreadable."""
    if not path.is_file():
        return _MISSING
    try:
        with open(path) as f:
            return json.load(f)
    except Exception:
        return None


def load(c: Campaign | str | os.PathLike) -> dict:
    doc = _read(config_path(c))
    return doc if isinstance(doc, dict) else {}


def lookup(doc, key: str, default=None):
    """doc[key], or a dotted walk into nested blocks. A literal top-level key
    containing '.' wins over the nested reading."""
    if isinstance(doc, dict) and key in doc:
        return doc[key]
    cur = doc
    for part in key.split("."):
        if isinstance(cur, dict) and part in cur:
            cur = cur[part]
        else:
            return default
    return cur


def block(c: Campaign | str | os.PathLike, name: str) -> dict:
    """A top-level block (e.g. "yolo", "tick") as a dict; {} when absent/not a dict."""
    b = load(c).get(name)
    return b if isinstance(b, dict) else {}


def value_text(v) -> str:
    """How `config get` prints a value: containers as JSON, scalars the way
    fuzz-config.sh's python printed them (str(): True/False/None)."""
    if isinstance(v, (dict, list)):
        return json.dumps(v)
    return str(v)


def get_text(c: Campaign | str | os.PathLike, key: str) -> str | None:
    """fuzz-config.sh `_config_get`: "" for a missing file or key, None (print
    nothing at all) when the file exists but cannot be parsed."""
    doc = _read(config_path(c))
    if doc is _MISSING:
        return ""
    if not isinstance(doc, dict):
        return None
    return value_text(lookup(doc, key, ""))


# ---------------------------------------------------------------------------
# write
# ---------------------------------------------------------------------------

def _write_atomic(path: Path, doc, *, sort_keys: bool, trailing_newline: bool):
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_name(path.name + ".tmp")
    with open(tmp, "w") as f:
        json.dump(doc, f, indent=2, sort_keys=sort_keys)
        if trailing_newline:
            f.write("\n")
    os.replace(tmp, path)


def coerce(raw: str):
    """The `set` value rule: an all-digits string is stored as an int."""
    if raw.isdigit():
        try:
            return int(raw)
        except ValueError:
            pass
    return raw


@dataclass(frozen=True)
class SetResult:
    path: Path
    key: str
    value: object


def set_value(c: Campaign | str | os.PathLike, key: str, raw: str) -> SetResult:
    """Set key (dotted => nested block, created as needed) to coerce(raw).
    An unreadable file is replaced; the schema is never downgraded (a fresh
    file gets fuzz-config/v3)."""
    path = config_path(c)
    doc = load(path)
    doc.setdefault("schema", DEFAULT_SCHEMA)
    value = coerce(raw)
    if "." in key and key not in doc:
        parts = key.split(".")
        cur = doc
        for part in parts[:-1]:
            nxt = cur.get(part)
            if nxt is None:
                nxt = cur[part] = {}
            elif not isinstance(nxt, dict):
                raise ValueError(f"cannot set {key}: {part} is not a block")
            cur = nxt
        cur[parts[-1]] = value
    else:
        doc[key] = value
    _write_atomic(path, doc, sort_keys=True, trailing_newline=False)
    return SetResult(path, key, value)


def update_block(c: Campaign | str | os.PathLike, name: str, merge: dict) -> dict:
    """Merge `merge` into the top-level block `name` (created if absent) and
    write the file back. Returns the merged block. The file must exist."""
    path = config_path(c)
    with open(path) as f:
        doc = json.load(f)
    b = doc.get(name) or {}
    b.update(merge)
    doc[name] = b
    _write_atomic(path, doc, sort_keys=False, trailing_newline=True)
    return b


def write(c: Campaign | str | os.PathLike, doc: dict) -> Path:
    """Rewrite the whole file (key order kept, trailing newline)."""
    path = config_path(c)
    _write_atomic(path, doc, sort_keys=False, trailing_newline=True)
    return path


# ---------------------------------------------------------------------------
# fuzz_forks
# ---------------------------------------------------------------------------

ENV_CPUS = "CC_FUZZER_CPUS"


def cpus(env=None) -> int:
    """CPUs the campaign may use. $CC_FUZZER_CPUS states it outright -- a
    container that is given a CPU budget smaller than the machine says so
    here, and it keeps `fuzz_forks` from varying with whatever host a run
    lands on. Otherwise: the CPUs this process may actually run on."""
    env = os.environ if env is None else env
    raw = (env.get(ENV_CPUS) or "").strip()
    if raw:
        try:
            return max(1, int(raw))
        except ValueError:
            pass
    try:
        return len(os.sched_getaffinity(0))
    except (AttributeError, OSError):
        return os.cpu_count() or 2


def fork_cap(env=None) -> int:
    """cpus() - 1 with a floor of 1."""
    return max(1, cpus(env) - 1)


@dataclass(frozen=True)
class ForkResolution:
    value: str            # what to pass to -fork= (a digit string; "0" = no fork mode)
    cap: int
    requested: str        # the raw value before validation / capping
    source: str           # env | override | file | default
    warning: str | None   # set when the request exceeded the cap


def resolve_fuzz_forks(c: Campaign | str | os.PathLike,
                       env: Mapping[str, str] | None = None) -> ForkResolution:
    env = os.environ if env is None else env
    cap = fork_cap()
    default = str(DEFAULT_FUZZ_FORKS)
    if env.get("FUZZ_FORKS"):
        want, source = env["FUZZ_FORKS"], "env"
    elif env.get("FUZZ_FORKS_OVERRIDE"):
        want, source = env["FUZZ_FORKS_OVERRIDE"], "override"
    else:
        want, source = get_text(c, "fuzz_forks") or "", "file"
        if not want:
            want, source = default, "default"
    requested = want
    # Digits only; anything else falls back to the default. 0 is a valid
    # sentinel meaning "disable fork mode".
    if not want or not all("0" <= ch <= "9" for ch in want):
        want = default
    warning = None
    if int(want) > cap:
        warning = f"WARN: requested fuzz_forks={want} exceeds cap (nproc-1={cap}); using {cap}"
        want = str(cap)
    return ForkResolution(want, cap, requested, source, warning)


# ---------------------------------------------------------------------------
# CLI: cc-fuzzer config <verb>   (fuzz-config.sh is a shim onto this)
# ---------------------------------------------------------------------------

HELP = """\
fuzz-config.sh - per-project cc-fuzzer configuration

Commands:
  get <key>          Print resolved value (env > override > file > default)
  set <key> <value>  Write to fuzz/state/fuzz-config.json
  show               Show resolution trace for fuzz_forks

Recognized keys:
  fuzz_forks         libFuzzer -fork=N. Default 2, cap nproc-1.

Resolution order: FUZZ_FORKS env > FUZZ_FORKS_OVERRIDE > config file > default
"""


def _cli_path() -> Path:
    """The campaign's config file; outside any project, the legacy
    ${FUZZ_STATE_DIR:-fuzz/state} relative to the cwd (fuzz-config.sh never
    anchored itself)."""
    try:
        return config_path(_campaign(strict=False))
    except CampaignError:
        cwd = Path.cwd()
        return config_path(resolve_state_dir(cwd, cwd / "fuzz"))


def _display(p: Path) -> str:
    """Paths under the cwd print relative (as fuzz-config.sh printed them)."""
    try:
        return os.path.relpath(p) if Path(os.path.abspath(p)).is_relative_to(Path.cwd()) else str(p)
    except ValueError:
        return str(p)


def _forks(path, a=None):
    r = resolve_fuzz_forks(path)
    if r.warning:
        sys.stderr.write(r.warning + "\n")
    return r


def _cmd_get(a):
    path = _cli_path()
    if a.key == "fuzz_forks":
        print(_forks(path).value)
        return 0
    text = get_text(path, a.key)
    if text is not None:
        print(text)
    return 0


def _cmd_set(a):
    path = _cli_path()
    try:
        r = set_value(path, a.key, a.value)
    except ValueError as e:
        sys.stderr.write(f"ERROR: {e}\n")
        return 2
    print(f"set {a.key} = {a.value} in {_display(r.path)}")
    return 0


def _cmd_show(_a):
    path = _cli_path()
    r = _forks(path)
    file_value = get_text(path, "fuzz_forks")
    print(f"Resolved fuzz_forks: {r.value}")
    print(f"  cap (nproc-1):     {r.cap}")
    print(f"  env FUZZ_FORKS:    {os.environ.get('FUZZ_FORKS') or '(unset)'}")
    print(f"  config file value: {file_value or ''}")
    print(f"  config file:       {_display(path)}")
    return 0


def _cmd_help(_a):
    sys.stdout.write(HELP)
    return 0


def _cmd_path(_a):
    print(_cli_path())
    return 0


def register_cli(subparsers):
    from cc_fuzzer_core.cli import add_subsystem

    p, verbs = add_subsystem(subparsers, "config", "fuzz-config.json get/set (dotted keys reach nested blocks)")
    p.set_defaults(func=_cmd_help)  # bare `config` == fuzz-config.sh with no args
    v = verbs.add_parser("get", help="print a resolved value (fuzz_forks: env > override > file > default)")
    v.add_argument("key")
    v.set_defaults(func=_cmd_get)
    v = verbs.add_parser("set", help="write a value (all-digit values are stored as ints)")
    v.add_argument("key")
    v.add_argument("value")
    v.set_defaults(func=_cmd_set)
    v = verbs.add_parser("show", help="show the fuzz_forks resolution trace")
    v.set_defaults(func=_cmd_show)
    v = verbs.add_parser("path", help="print the fuzz-config.json path in use")
    v.set_defaults(func=_cmd_path)
    v = verbs.add_parser("help", help="usage")
    v.set_defaults(func=_cmd_help)
