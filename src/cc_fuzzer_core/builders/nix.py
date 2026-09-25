"""The nix builder's share of the work (§6).

Only the plugin has nix, so the core does not run the build: it renders what
each variant needs into the three values nix-build.sh puts in the derivation
(compiler, cflags, extraEnv) and reports `delegated`. nix-build.sh reads this
instead of carrying its own copy of the flag table, so the two cannot drift.
"""
from __future__ import annotations

from typing import Mapping

from cc_fuzzer_core.builders import DELEGATED
from cc_fuzzer_core.builders import toolchain


def step(variant: Mapping, **kw) -> dict:
    return {
        "variant": variant["name"],
        "purpose": variant["purpose"],
        "compiler": toolchain.compiler(variant),
        "cflags": toolchain.cflags(variant),
        "env": toolchain.env(variant),
        "install_as": toolchain.output_name(kw.get("harness", ""), variant),
        "binary_field": variant["binary_field"],
        "binary_suffix": variant["binary_suffix"],
        "needs_main": toolchain.needs_main(variant),
        "status": DELEGATED,
        "reason": "nix builds run through the host's nix-build.sh",
    }
