"""The script builder: a project's own build.sh, told what to produce (§6).

The legacy backend ran `build.sh` with no way to say which variant it wanted,
so a project that could build a coverage binary had no way to be asked for
one. The spec goes in through the environment; anything the script does not
read, it ignores, which is why the legacy build keeps working unchanged.
"""
from __future__ import annotations

from typing import Mapping

from cc_fuzzer_core.builders import toolchain

PREFIX = "CC_FUZZER_"


def variant_env(variant: Mapping, harness: str = "") -> dict:
    """What build.sh is told about the variant it is being asked for."""
    env = {
        PREFIX + "VARIANT": variant["name"],
        PREFIX + "PURPOSE": variant["purpose"],
        PREFIX + "SANITIZERS": ",".join(variant.get("sanitizers") or ()),
        PREFIX + "INSTRUMENTATION": variant["instrumentation"],
        PREFIX + "LINK_MODE": variant["link_mode"],
        PREFIX + "CFLAGS": " ".join(toolchain.cflags(variant)),
        PREFIX + "COMPILER": toolchain.compiler(variant),
        PREFIX + "OUTPUT": toolchain.output_name(harness, variant),
        PREFIX + "REQUIRED": "1" if variant.get("required") else "0",
    }
    env.update(toolchain.env(variant))
    return env


def step(variant: Mapping, **kw) -> dict:
    harness = kw.get("harness", "")
    return {
        "variant": variant["name"],
        "purpose": variant["purpose"],
        "command": [kw.get("script", "build.sh")],
        "env": variant_env(variant, harness),
        "output": toolchain.output_name(harness, variant),
        "binary_field": variant["binary_field"],
        "binary_suffix": variant["binary_suffix"],
    }
