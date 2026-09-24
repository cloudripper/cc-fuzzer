"""Model aliasing in one place (UPDATE_ROADMAP.md §8).

The mapping lives in data/models.json (package data, found via paths.data()):

  tiers         tier -> model id        deep -> opus, standard -> sonnet, fast -> haiku
  default_tier  the tier of an agent the mapping does not know
  agents        agent -> tier (or a literal model id); preserves each agent's
                current frontmatter `model:`
  pricing       model id -> {input_per_mtok, output_per_mtok} in USD. Advisory
                (a spend signal for the YOLO cost cap), not billing.

Overrides, lowest to highest precedence, each a partial document of the same
shape (tier-level and agent-level entries are both allowed):
  1. the packaged data/models.json
  2. fuzz-config.json `models` block (per campaign)
  3. the JSON file named by $CC_FUZZER_MODELS (per host / container)

    from cc_fuzzer_core import models
    models.resolve("crash-triager")                  -> "opus"
    m = models.load(campaign); m.tier_of("mutator")  -> "fast"
    m.cost(tokens_in, tokens_out, agent="poc-builder")

Consumers: the YOLO evaluator (deep-tier spend, the cost cap), the lever
board's cost tiers, and (§3) the rendered agent frontmatter.
"""
from __future__ import annotations

import json
import os
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Mapping

ENV_MODELS = "CC_FUZZER_MODELS"
DATA_FILE = "models.json"
DEEP, STANDARD, FAST = "deep", "standard", "fast"
# Cost tier of a deterministic lever that dispatches no model at all.
TIER_NONE = "none"


class ModelsError(RuntimeError):
    pass


@dataclass(frozen=True)
class ModelMap:
    tiers: dict
    agents: dict
    pricing: dict            # model id -> (usd per input token, usd per output token)
    default_tier: str = STANDARD
    sources: tuple = field(default=(), compare=False)

    # -- resolution ----------------------------------------------------------
    def resolve(self, agent: str) -> str:
        """The model id an agent runs on (unknown agents: the default tier)."""
        v = self.agents.get(agent)
        if v is None:
            v = self.default_tier
        return self.tiers.get(v, v)

    def tier_of(self, agent: str) -> str | None:
        """The tier an agent is mapped to; None for an unknown agent or one
        pinned to a model id that no tier uses."""
        v = self.agents.get(agent)
        if v is None:
            return None
        if v in self.tiers:
            return v
        return next((t for t, m in self.tiers.items() if m == v), None)

    def agents_in_tier(self, tier: str) -> frozenset:
        return frozenset(a for a in self.agents if self.tier_of(a) == tier)

    # -- pricing -------------------------------------------------------------
    def rate(self, model: str) -> tuple[float, float]:
        """(usd/input token, usd/output token); an unpriced model is charged
        at the default tier's model rate."""
        if model in self.pricing:
            return self.pricing[model]
        return self.pricing.get(self.tiers.get(self.default_tier), (0.0, 0.0))

    def cost(self, tokens_in: int, tokens_out: int, *, agent: str = "", model: str | None = None) -> float:
        """USD for one call: an explicit (priced) model wins, else the agent's."""
        m = model if model and model in self.pricing else self.resolve(agent or "")
        ri, ro = self.rate(m)
        return tokens_in * ri + tokens_out * ro

    def event_cost(self, e: dict) -> float:
        """Cost of an events.jsonl record carrying tokens_in/tokens_out."""
        return self.cost(int(e.get("tokens_in") or 0), int(e.get("tokens_out") or 0),
                         agent=e.get("agent_called") or e.get("agent") or "", model=e.get("model"))

    def as_dict(self) -> dict:
        return {
            "tiers": dict(self.tiers),
            "default_tier": self.default_tier,
            "agents": {a: {"tier": self.tier_of(a), "model": self.resolve(a)} for a in sorted(self.agents)},
            "pricing": {m: {"input_per_mtok": round(i * 1e6, 6), "output_per_mtok": round(o * 1e6, 6)}
                        for m, (i, o) in sorted(self.pricing.items())},
            "sources": list(self.sources),
        }


# ---------------------------------------------------------------------------
# loading + overrides
# ---------------------------------------------------------------------------

def _packaged() -> dict:
    from cc_fuzzer_core.paths import data
    with open(data(DATA_FILE)) as f:
        return json.load(f)


def _layer(base: dict, over, source: str) -> None:
    if over is None:
        return
    if not isinstance(over, dict):
        raise ModelsError(f"{source}: models override must be a JSON object")
    for key in ("tiers", "agents", "pricing"):
        v = over.get(key)
        if v is None:
            continue
        if not isinstance(v, dict):
            raise ModelsError(f"{source}: `{key}` must be an object")
        base.setdefault(key, {}).update(v)
    if over.get("default_tier") is not None:
        base["default_tier"] = over["default_tier"]


def _pricing(raw: dict, source: str) -> dict:
    out = {}
    for model, p in raw.items():
        try:
            out[model] = (float(p["input_per_mtok"]) / 1e6, float(p["output_per_mtok"]) / 1e6)
        except (TypeError, KeyError, ValueError):
            raise ModelsError(f"{source}: pricing[{model!r}] needs numeric input_per_mtok/output_per_mtok")
    return out


def _config_block(config) -> dict | None:
    """The `models` block from a fuzz-config dict, a Campaign or a state dir."""
    if config is None:
        return None
    if isinstance(config, dict):
        return config.get("models")
    from cc_fuzzer_core import config as _config
    return _config.load(config).get("models")


def load(config=None, env: Mapping[str, str] | None = None) -> ModelMap:
    """The effective mapping. `config` is a fuzz-config.json dict, a Campaign
    or a state dir (its `models` block is layered in); env supplies
    $CC_FUZZER_MODELS. Raises ModelsError on a malformed override."""
    env = os.environ if env is None else env
    doc = _packaged()
    sources = ["package:data/models.json"]
    block = _config_block(config)
    if block is not None:
        _layer(doc, block, "fuzz-config.json models")
        sources.append("fuzz-config.json:models")
    path = env.get(ENV_MODELS)
    if path:
        try:
            with open(path) as f:
                over = json.load(f)
        except (OSError, ValueError) as e:
            raise ModelsError(f"${ENV_MODELS}={path}: {e}")
        _layer(doc, over, path)
        sources.append(path)
    tiers = dict(doc.get("tiers") or {})
    default_tier = doc.get("default_tier") or STANDARD
    if default_tier not in tiers:
        raise ModelsError(f"default_tier {default_tier!r} is not one of the tiers {sorted(tiers)}")
    return ModelMap(tiers=tiers, agents=dict(doc.get("agents") or {}),
                    pricing=_pricing(doc.get("pricing") or {}, "pricing"),
                    default_tier=default_tier, sources=tuple(sources))


def resolve(agent: str, config=None, env: Mapping[str, str] | None = None) -> str:
    """models.resolve(agent) -> model id (see load() for config/env)."""
    return load(config, env).resolve(agent)


# ---------------------------------------------------------------------------
# CLI: cc-fuzzer models <verb>
# ---------------------------------------------------------------------------

def _cli_map() -> ModelMap:
    from cc_fuzzer_core.paths import CampaignError, campaign
    try:
        c = campaign(strict=False)
    except CampaignError:
        c = None
    return load(c)


def _run(fn):
    def run(a):
        try:
            return fn(_cli_map(), a)
        except ModelsError as e:
            sys.stderr.write(f"models: {e}\n")
            return 2
    return run


def _cmd_resolve(m, a):
    print(m.resolve(a.agent))
    return 0


def _cmd_tier(m, a):
    t = m.tier_of(a.agent)
    if t is None:
        return 1
    print(t)
    return 0


def _cmd_show(m, a):
    if a.json:
        print(json.dumps(m.as_dict(), indent=2))
        return 0
    print("tiers: " + ", ".join(f"{t}={mid}" for t, mid in m.tiers.items()) + f" (default {m.default_tier})")
    for agent in sorted(m.agents):
        print(f"  {agent:<20} {m.tier_of(agent) or '-':<9} {m.resolve(agent)}")
    print("sources: " + " < ".join(m.sources))
    return 0


def _cmd_price(m, a):
    i, o = m.rate(a.model)
    print(f"{a.model}: input ${i * 1e6:g}/MTok, output ${o * 1e6:g}/MTok")
    return 0


def register_cli(subparsers):
    from cc_fuzzer_core.cli import add_subsystem

    _p, verbs = add_subsystem(subparsers, "models", "agent -> tier -> model aliasing (data/models.json + overrides)")
    v = verbs.add_parser("resolve", help="print the model id an agent runs on")
    v.add_argument("agent")
    v.set_defaults(func=_run(_cmd_resolve))
    v = verbs.add_parser("tier", help="print an agent's tier (exit 1 if unmapped)")
    v.add_argument("agent")
    v.set_defaults(func=_run(_cmd_tier))
    v = verbs.add_parser("show", help="print the effective mapping")
    v.add_argument("--json", action="store_true")
    v.set_defaults(func=_run(_cmd_show))
    v = verbs.add_parser("price", help="print a model's advisory rate")
    v.add_argument("model")
    v.set_defaults(func=_run(_cmd_price))
