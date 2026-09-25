"""External tool lookup (llvm-cov, llvm-profdata, afl-fuzz, nm, ...).

which(name) is the ONE way the core finds a tool binary. Resolution order:

  1. $CC_FUZZER_TOOL_<NAME>    NAME = the tool name upper-cased with every
                               non-alphanumeric as "_" (llvm-cov -> LLVM_COV).
                               Set it EMPTY to pin the tool as UNAVAILABLE:
                               resolution stops there and never reaches PATH,
                               so a host can state "this image has no symcc"
                               (and a test can stop depending on what happens
                               to be installed on the machine running it).
  2. <state_dir>/nix-env.json  tools[<name>]: the pin the plugin's nix profile
                               captures (scripts/capture-nix-env.sh)
  3. PATH

A candidate counts only if it is an executable file. There are deliberately no
host-layout scans here (versioned LLVM install dirs, the nix store, ...): a
host adapter that knows such places exports CC_FUZZER_TOOL_<NAME> before
calling in (the plugin's scripts/_lib/nix-tools.sh does).

CLI: `cc-fuzzer tool which <name>` prints the path (exit 1, silent, when not found).
"""
from __future__ import annotations

import json
import os
import re
import shutil
import sys
from pathlib import Path
from typing import Mapping

from cc_fuzzer_core.paths import Campaign, CampaignError, campaign as _campaign

ENV_PREFIX = "CC_FUZZER_TOOL_"
NIX_ENV_FILE = "nix-env.json"


def env_var(name: str) -> str:
    """The override variable for a tool: llvm-cov -> CC_FUZZER_TOOL_LLVM_COV."""
    return ENV_PREFIX + re.sub(r"[^A-Za-z0-9]", "_", name).upper()


def _executable(p) -> bool:
    return bool(p) and os.path.isfile(p) and os.access(p, os.X_OK)


def _state_dir(c: Campaign | None) -> Path | None:
    if c is not None:
        return c.state_dir
    try:
        return _campaign(strict=False).state_dir
    except CampaignError:
        return None


def pinned(name: str, c: Campaign | None = None) -> str | None:
    """tools[<name>] from the campaign's nix-env.json, if executable."""
    sd = _state_dir(c)
    if sd is None:
        return None
    try:
        with open(sd / NIX_ENV_FILE) as f:
            p = (json.load(f).get("tools") or {}).get(name) or ""
    except Exception:
        return None
    return p if isinstance(p, str) and _executable(p) else None


def which(name: str, c: Campaign | None = None, *, env: Mapping[str, str] | None = None) -> str | None:
    """Absolute path of tool `name`, or None (see module docstring). `c` is
    the campaign whose nix-env.json pin applies (default: the one around the
    cwd, if any)."""
    if not name:
        return None
    env = os.environ if env is None else env
    override = env.get(env_var(name))
    if override is not None and not override.strip():
        return None                       # pinned unavailable
    if override and _executable(override):
        return os.path.abspath(override)
    p = pinned(name, c)
    if p:
        return p
    return shutil.which(name, path=env.get("PATH", os.defpath))


# ---------------------------------------------------------------------------
# CLI: cc-fuzzer tool <verb>
# ---------------------------------------------------------------------------

def _cmd_which(a):
    p = which(a.name)
    if not p:
        return 1
    print(p)
    return 0


def register_cli(subparsers):
    from cc_fuzzer_core.cli import add_subsystem

    _p, verbs = add_subsystem(subparsers, "tool", "external tool lookup ($CC_FUZZER_TOOL_<NAME>, nix-env.json pin, PATH)")
    v = verbs.add_parser("which", help="print the resolved path of a tool (exit 1 when not found)")
    v.add_argument("name")
    v.set_defaults(func=_cmd_which)
