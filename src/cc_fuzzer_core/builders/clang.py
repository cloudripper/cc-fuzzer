"""The clang builder: compile the harness directly (§6).

The reference implementation of the spec, and the only one a test can run
end to end without nix, AFL or an OSS-Fuzz image. A host with a clang on PATH
gets working fuzz/coverage/verify binaries from this alone.

Tools resolve through cc_fuzzer_core.tools.which, so a compiler the core
cannot find is reported `unsupported` with the tool named -- never a build
that silently produces nothing.
"""
from __future__ import annotations

import os
import subprocess
from pathlib import Path
from typing import Mapping

from cc_fuzzer_core import tools
from cc_fuzzer_core.builders import FAILED, OK, UNSUPPORTED, result
from cc_fuzzer_core.builders import toolchain


def step(variant: Mapping, **kw) -> dict:
    sources = list(kw.get("sources") or [])
    main_src = kw.get("main_source")
    if toolchain.needs_main(variant) and main_src:
        sources = sources + [main_src]
    out_dir = kw.get("out_dir", ".")
    harness = kw.get("harness", "")
    out = str(Path(out_dir) / toolchain.output_name(harness, variant))
    cc = toolchain.compiler(variant)
    return {
        "variant": variant["name"],
        "purpose": variant["purpose"],
        "command": [cc, *toolchain.cflags(variant), *sources,
                    *(kw.get("ldflags") or []), "-o", out],
        "env": toolchain.env(variant),
        "output": out,
        "binary_field": variant["binary_field"],
        "binary_suffix": variant["binary_suffix"],
        "needs_main": toolchain.needs_main(variant),
        "required": bool(variant.get("required")),
    }


def run_step(s: Mapping, *, env=None, timeout=600) -> dict:
    """Execute one step. Returns a build-result entry."""
    cmd = list(s["command"])
    found = tools.which(cmd[0])
    if not found:
        return {"status": UNSUPPORTED, "reason": f"{cmd[0]} not found",
                "command": " ".join(cmd)}
    cmd[0] = found
    run_env = dict(os.environ if env is None else env)
    run_env.update(s.get("env") or {})
    Path(s["output"]).parent.mkdir(parents=True, exist_ok=True)
    try:
        p = subprocess.run(cmd, capture_output=True, text=True, env=run_env, timeout=timeout)
    except subprocess.TimeoutExpired:
        return {"status": FAILED, "reason": f"timed out after {timeout}s",
                "command": " ".join(cmd)}
    if p.returncode != 0 or not os.path.exists(s["output"]):
        tail = (p.stderr or p.stdout or "").strip().splitlines()[-5:]
        return {"status": FAILED, "reason": " | ".join(tail) or f"exit {p.returncode}",
                "command": " ".join(cmd)}
    return {"status": OK, "binary": s["output"], "command": " ".join(cmd)}


def build(plan: Mapping, *, env=None, timeout=600) -> dict:
    entries = {s["variant"]: run_step(s, env=env, timeout=timeout) for s in plan.get("steps", [])}
    return result(plan.get("harness", ""), plan.get("backend", "clang"), entries)
