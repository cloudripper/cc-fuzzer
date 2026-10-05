#!/usr/bin/env python3
"""Check claude-code.contract.json against the real Claude Code binary.

The docs describe the latest release only; the images pin one version. This
fetches that version's npm platform package and checks that every name the
contract lists (CLI flags, env vars, hook fields, stream-json fields, tool
names) is in its binary. A name being present says nothing about what it
means: entries under `semantics` record the version they were last verified
on, and a contract whose `version` moved past that is flagged for review.

    scripts/claude-code-contract.py check [--version V] [--strict]
    scripts/claude-code-contract.py diff OLD NEW
    scripts/claude-code-contract.py tools [V]      # the tools a headless session gets
    scripts/claude-code-contract.py fetch V        # print the cached binary path
    scripts/claude-code-contract.py installed      # the local `claude` against `version`

check  exit 0 ok, 1 a required name is missing (or, with --strict, a
       semantics entry is unverified for this version), 2 usage/fetch error
diff   our names whose presence differs, then every env var the two
       binaries do not share (the upgrade review)
installed  exit 0 when the local `claude --version` is at least the
       contract's version, 3 when it is older (doctor warns), 4 when there is
       no `claude` to ask
tools  runs the binary headless against a closed port (no model is called)
       and prints the tool list of its init event, against the contract's
       recorded `headless_tools` for that version. The list depends on the
       platform (Grep/Glob are absent on Linux) and on the model being one
       Claude Code does not recognize, as ours are.
"""
from __future__ import annotations

import argparse
import io
import json
import os
import re
import subprocess
import sys
import tempfile
import threading
import tarfile
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
CONTRACT = ROOT / "claude-code.contract.json"
CACHE = Path(os.environ.get("XDG_CACHE_HOME", Path.home() / ".cache")) / "claude-code-contract"
REGISTRY = "https://registry.npmjs.org"
_ENV_RE = re.compile(rb"\b((?:CLAUDE|ANTHROPIC)_[A-Z0-9_]{3,})\b")


def load(path: Path = CONTRACT) -> dict:
    return json.loads(path.read_text())


def fetch(version: str, package: str) -> Path:
    """The `claude` binary of `package`@`version`, downloaded once."""
    out = CACHE / version / "claude"
    if out.is_file():
        return out
    with urllib.request.urlopen(f"{REGISTRY}/{package}/{version}", timeout=60) as r:
        tarball = json.load(r)["dist"]["tarball"]
    with urllib.request.urlopen(tarball, timeout=600) as r:
        data = r.read()
    with tarfile.open(fileobj=io.BytesIO(data), mode="r:gz") as t:
        member = next((m for m in t.getmembers()
                       if m.isfile() and Path(m.name).name == "claude"), None)
        if member is None:
            raise RuntimeError(f"{package}@{version}: no claude binary in the tarball")
        out.parent.mkdir(parents=True, exist_ok=True)
        tmp = out.with_suffix(".part")
        tmp.write_bytes(t.extractfile(member).read())
        tmp.replace(out)
    return out


def headless_tools(binary: Path, timeout: float = 120) -> list[str]:
    """The init event's tool list. ANTHROPIC_BASE_URL points at a closed
    port and the process is killed once init arrives, so no model is called."""
    binary.chmod(0o755)
    with tempfile.TemporaryDirectory() as home:
        env = {"PATH": "/usr/bin:/bin", "HOME": home, "ANTHROPIC_AUTH_TOKEN": "x",
               "ANTHROPIC_BASE_URL": "http://127.0.0.1:9", "ANTHROPIC_MODEL": "unrecognized-model",
               "CLAUDE_CODE_MAX_RETRIES": "0"}
        p = subprocess.Popen([str(binary), "-p", "--verbose", "--output-format", "stream-json",
                              "--max-turns", "1", "hi"], cwd=home, env=env, text=True,
                             stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                             stderr=subprocess.DEVNULL)
        timer = threading.Timer(timeout, p.kill)
        timer.start()
        try:
            for line in p.stdout:
                try:
                    e = json.loads(line)
                except ValueError:
                    continue
                if e.get("type") == "system" and e.get("subtype") == "init":
                    return sorted(e.get("tools") or [])
        finally:
            timer.cancel()
            p.kill()
            p.wait()
    raise RuntimeError(f"{binary}: no init event within {timeout:.0f}s")


def _vtuple(v: str) -> tuple:
    return tuple(int(x) for x in re.findall(r"\d+", v)[:3])


def installed(contract: dict) -> int:
    try:
        out = subprocess.run(["claude", "--version"], capture_output=True, text=True,
                             timeout=20).stdout
    except (OSError, subprocess.TimeoutExpired):
        print("no `claude` on PATH to check")
        return 4
    m = re.search(r"\d+\.\d+\.\d+", out)
    if not m:
        print(f"cannot read a version from `claude --version`: {out.strip()[:80]}")
        return 4
    have, tested = m.group(0), contract["version"]
    if _vtuple(have) < _vtuple(tested):
        print(f"Claude Code {have} is older than {tested}, the version this was tested on")
        return 3
    print(f"Claude Code {have} (tested on {tested})")
    return 0


def names(contract: dict) -> list[tuple[str, str]]:
    return [(kind, n) for kind, ns in contract["requires"].items() for n in ns]


def check(contract: dict, binary: bytes, version: str, strict: bool = False) -> int:
    missing = [(k, n) for k, n in names(contract) if n.encode() not in binary]
    stale = [(n, s.get("verified", "?")) for n, s in contract.get("semantics", {}).items()
             if s.get("verified") != version]
    for k, n in missing:
        print(f"MISSING  {k:6s} {n}")
    for n, v in stale:
        print(f"REVIEW   {n}: meaning last verified on {v}, contract pins {version}")
    print(f"claude-code {version}: {len(names(contract)) - len(missing)}/{len(names(contract))} "
          f"names present, {len(stale)} semantics to review")
    return 1 if missing or (strict and stale) else 0


def diff(contract: dict, old: bytes, new: bytes, vo: str, vn: str) -> None:
    for k, n in names(contract):
        a, b = n.encode() in old, n.encode() in new
        if a != b:
            print(f"{'GONE' if a else 'NEW '}  {k:6s} {n}  ({vo}: {a}, {vn}: {b})")
    eo, en = set(_ENV_RE.findall(old)), set(_ENV_RE.findall(new))
    print(f"\nenv vars only in {vn} ({len(en - eo)}):")
    for n in sorted(en - eo):
        print(f"  + {n.decode()}")
    print(f"env vars only in {vo} ({len(eo - en)}):")
    for n in sorted(eo - en):
        print(f"  - {n.decode()}")


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    sub = ap.add_subparsers(dest="cmd", required=True)
    c = sub.add_parser("check")
    c.add_argument("--version", help="default: the contract's")
    c.add_argument("--strict", action="store_true")
    d = sub.add_parser("diff")
    d.add_argument("old")
    d.add_argument("new")
    t = sub.add_parser("tools")
    t.add_argument("version", nargs="?")
    sub.add_parser("installed")
    f = sub.add_parser("fetch")
    f.add_argument("version")
    a = ap.parse_args(argv)
    contract = load()
    pkg = contract["package"]
    try:
        if a.cmd == "fetch":
            print(fetch(a.version, pkg))
            return 0
        if a.cmd == "installed":
            return installed(contract)
        if a.cmd == "tools":
            v = a.version or contract["version"]
            got = headless_tools(fetch(v, pkg))
            want = contract.get("headless_tools", {}).get(v)
            print(" ".join(got))
            if want is not None and sorted(want) != got:
                print(f"differs from the contract's record for {v}: "
                      f"+{sorted(set(got) - set(want))} -{sorted(set(want) - set(got))}")
                return 1
            return 0
        if a.cmd == "check":
            v = a.version or contract["version"]
            return check(contract, fetch(v, pkg).read_bytes(), v, a.strict)
        diff(contract, fetch(a.old, pkg).read_bytes(), fetch(a.new, pkg).read_bytes(), a.old, a.new)
        return 0
    except (OSError, RuntimeError, KeyError, ValueError) as e:
        print(f"error: {e}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
