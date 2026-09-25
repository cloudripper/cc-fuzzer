"""Needs -> clang flags, in ONE place (§6).

Every clang-family builder (nix, script, clang) asks this module what a
variant's flags are, so the answer exists once instead of once per builder and
again in a prompt. The output reproduces nix-build.sh's variant block exactly;
tests/test_builders.py pins that, flag for flag.

Flag order is fixed and matters only because it makes the nix parity readable:

    -g                          debug_info
    -O<level>                   optimization
    -fno-omit-frame-pointer     frame_pointer
    <instrumentation flags>     source-coverage; cmplog and symcc use the
                                compiler or the environment, not a cflag
    -fsanitize=<list>           sanitizers, comma-joined, last
"""
from __future__ import annotations

from typing import Mapping

from cc_fuzzer_core import variants as _v

# instrumentation -> the compiler that provides it
COMPILER = {
    _v.LIBFUZZER: "clang++",
    _v.SOURCE_COVERAGE: "clang++",
    _v.NONE: "clang++",
    _v.INSTR_CMPLOG: "afl-clang-fast++",
    _v.INSTR_SYMCC: "sym++",
}
# instrumentation -> extra cflags
INSTR_CFLAGS = {
    _v.SOURCE_COVERAGE: ("-fprofile-instr-generate", "-fcoverage-mapping"),
}
# instrumentation -> environment the compiler needs
INSTR_ENV = {
    _v.INSTR_CMPLOG: {"AFL_LLVM_CMPLOG": "1"},
}
# the tool name to resolve through cc_fuzzer_core.tools.which
TOOL = {"clang++": "clang++", "afl-clang-fast++": "afl-clang-fast++", "sym++": "sym++"}

# Sanitizers that LOG AND CONTINUE by default. A fuzzer needs the opposite: a
# violation has to abort, or there is no crash to find and dedupe -- the run
# just prints and carries on. Asking for one of these therefore also means
# asking for -fno-sanitize-recover on it.
RECOVERING = ("integer", "implicit-conversion")


def compiler(variant: Mapping) -> str:
    return COMPILER.get(variant.get("instrumentation"), "clang++")


def cflags(variant: Mapping) -> list:
    out = []
    if variant.get("debug_info", True):
        out.append("-g")
    out.append("-O" + str(variant.get("optimization", "1")))
    if variant.get("frame_pointer", True):
        out.append("-fno-omit-frame-pointer")
    out.extend(INSTR_CFLAGS.get(variant.get("instrumentation"), ()))
    san = list(variant.get("sanitizers") or ())
    if san:
        out.append("-fsanitize=" + ",".join(san))
        recovering = [s for s in san if s in RECOVERING]
        if recovering:
            out.append("-fno-sanitize-recover=" + ",".join(recovering))
    return out


def env(variant: Mapping) -> dict:
    return dict(INSTR_ENV.get(variant.get("instrumentation"), {}))


def needs_main(variant: Mapping) -> bool:
    """True when the binary needs a main() of its own (the cov_main.c shim).
    libFuzzer supplies one via -fsanitize=fuzzer; AFL supplies its own driver."""
    return variant.get("link_mode") == _v.STANDALONE_MAIN


def output_name(harness: str, variant: Mapping) -> str:
    """`parser_fuzzer`, `parser_fuzzer_cov`, ... -- the names the state schema
    and nix-build.sh's symlinks already use."""
    return f"{harness}_fuzzer{variant.get('binary_suffix', '')}"
