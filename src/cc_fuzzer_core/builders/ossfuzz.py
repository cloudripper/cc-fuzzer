"""The OSS-Fuzz builder (§6).

An OSS-Fuzz image decides the toolchain itself: a build asks for a sanitizer
and an engine through $SANITIZER / $FUZZING_ENGINE and collects binaries from
$OUT. So the spec does not become cflags here, it becomes those variables.

Mapping (roadmap §6):
    fuzz      SANITIZER=address     FUZZING_ENGINE=libfuzzer
    verify    SANITIZER=undefined   FUZZING_ENGINE=none
    coverage  SANITIZER=coverage    FUZZING_ENGINE=libfuzzer
    cmplog    FUZZING_ENGINE=afl    AFL_LLVM_CMPLOG=1
    symcc     unsupported -- reported as such, never silently skipped

`unsupported` is deliberately distinct from `skipped`: skipped means the
campaign turned the variant off, unsupported means it asked and this image
cannot. §12 needs to tell those apart before it selects a binary.
"""
from __future__ import annotations

import os
from typing import Mapping

from cc_fuzzer_core import variants as _v
from cc_fuzzer_core.builders import UNSUPPORTED
from cc_fuzzer_core.builders import toolchain

OUT_ENV = "OUT"

SANITIZER = {_v.FUZZ: "address", _v.VERIFY: "undefined", _v.COVERAGE: "coverage",
             _v.CMPLOG: "address"}
ENGINE = {_v.FUZZ: "libfuzzer", _v.VERIFY: "none", _v.COVERAGE: "libfuzzer",
          _v.CMPLOG: "afl"}


def out_dir(env=None) -> str:
    env = os.environ if env is None else env
    return env.get(OUT_ENV, "/out")


def step(variant: Mapping, **kw) -> dict:
    purpose = variant["purpose"]
    name = toolchain.output_name(kw.get("harness", ""), variant)
    out = f"{kw.get('out_dir') or out_dir(kw.get('env'))}/{name}"
    if purpose == _v.SYMCC:
        return {"variant": variant["name"], "purpose": purpose,
                "status": UNSUPPORTED,
                "reason": "OSS-Fuzz images do not carry SymCC",
                "binary_field": variant["binary_field"],
                "binary_suffix": variant["binary_suffix"]}
    env = {"SANITIZER": SANITIZER[purpose], "FUZZING_ENGINE": ENGINE[purpose]}
    if purpose == _v.CMPLOG:
        env["AFL_LLVM_CMPLOG"] = "1"
    return {
        "variant": variant["name"],
        "purpose": purpose,
        "command": ["compile"],
        "env": env,
        "output": out,
        "binary_field": variant["binary_field"],
        "binary_suffix": variant["binary_suffix"],
        "needs_main": toolchain.needs_main(variant),
    }
