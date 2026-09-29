"""Determinism knobs: the numbers that decide a result, in config and echoed.

Replay attempts, probe budgets and seeds used to be module constants, so two
runs that disagreed could not say whether they had even used the same
settings. They are configuration now, and every result carries the values it
was produced with:

    {"determinism": {"replay_attempts": 3, "replay_timeout_s": 30,
                     "minimize_max_probes": 400, "minimize_max_rounds": 40,
                     "sensitivity_max_probes": 1024, "fuzzer_seed": 1337}}

An explicit argument wins over config, config over the defaults below.

Reproducible runs also need pinned model IDs in data/models.json (a dated
model ID, not an alias that moves): the same knobs with a different model
behind an alias are not the same run.
"""
from __future__ import annotations

from typing import Mapping

SCHEMA = "determinism/v1"

KNOBS = ("replay_attempts", "replay_timeout_s", "minimize_max_probes",
         "minimize_max_rounds", "sensitivity_max_probes", "fuzzer_seed")


class DeterminismError(ValueError):
    pass


def defaults() -> dict:
    from cc_fuzzer_core import minimize
    from cc_fuzzer_core.crash import replay
    return {"replay_attempts": replay.ATTEMPTS, "replay_timeout_s": replay.TIMEOUT_S,
            "minimize_max_probes": minimize.MAX_PROBES,
            "minimize_max_rounds": minimize.MAX_ROUNDS,
            "sensitivity_max_probes": minimize.SENSITIVITY_MAX_PROBES,
            "fuzzer_seed": 0}


def resolve(config: Mapping | None = None, **explicit) -> dict:
    """The knob values to use: explicit (not None) > config > defaults."""
    block = (config or {}).get("determinism") or {}
    if not isinstance(block, Mapping):
        raise DeterminismError("determinism must be an object")
    unknown = sorted(set(block) - set(KNOBS))
    if unknown:
        raise DeterminismError(f"unknown determinism knob(s): {', '.join(unknown)} "
                               f"(known: {', '.join(KNOBS)})")
    out = defaults()
    for k in KNOBS:
        v = explicit.get(k)
        if v is None:
            v = block.get(k, out[k])
        if isinstance(v, bool) or not isinstance(v, int) or v < 0:
            raise DeterminismError(f"determinism.{k} must be a non-negative integer, got {v!r}")
        out[k] = v
    for k in ("replay_attempts", "replay_timeout_s"):
        if out[k] < 1:
            raise DeterminismError(f"determinism.{k} must be at least 1")
    return out


def echo(values: Mapping) -> dict:
    """What a result carries: the values used, schema-tagged."""
    return {"schema": SCHEMA, **{k: values[k] for k in KNOBS}}
