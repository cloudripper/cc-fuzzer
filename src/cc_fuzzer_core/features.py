"""Feature flags for the unscored subsystems (UPDATE_ROADMAP.md §9).

Four flags, all on by default. Turning one off GATES its subsystem (the code
stays; the entry points skip, the levers go quiet, the prompt blocks are
stripped) so a downstream host can run the engine without it:

  impact_tiering        exploit-tier / CVSS / weaponization work: the
                        impact_review lever, the poc_upgrade (_weak_poc)
                        signal, and the promote gate's boundary statements
  disclosure_reporting  disclosure reports: the reporting entry points
                        (cross-ref-findings.sh, blame-finding.sh) skip and
                        campaign-header stops asking for authorization.json
  logic_oracles         oracle-driven (logic-bug) fuzzing: ORACLE_TYPE is
                        restricted to `crash`, oracle-smoke-test.sh is a no-op
  advisory_lookup       CVE / advisory intel: cve-context-build.sh skips, the
                        cve_refresh lever is ineligible, and every reader of
                        cve-context-*.json ignores it

Precedence, lowest to highest (the last one that names a flag wins):
  1. the default (true)
  2. fuzz-config.json `cve.enabled` -- a legacy alias for advisory_lookup only
  3. fuzz-config.json `features {<name>: bool}`
  4. $CC_FUZZER_FEATURES, e.g. "-advisory_lookup,-disclosure_reporting".
     Comma/space separated; `-name` turns a flag off, `+name` or a bare
     `name` turns it on; later entries win.
Unknown names and non-bool values are ignored by load() and reported in
Features.problems (`feature list` prints them; `schema validate` reports a
bad config block).

    from cc_fuzzer_core import features
    f = features.load(campaign)          # or a state dir / fuzz-config dict
    f.enabled("advisory_lookup")         -> True
    f.disabled()                         -> ["logic_oracles"]
    features.strip_blocks(text, f)       # drop <!-- feature:X -->...<!-- /feature -->

CLI: `cc-fuzzer feature enabled <name>` (exit 0 on, 1 off, 2 unknown) and
`cc-fuzzer feature list [--json]`.
"""
from __future__ import annotations

import json
import os
import re
import sys
from dataclasses import dataclass, field
from typing import Iterable, Mapping

ENV_FEATURES = "CC_FUZZER_FEATURES"

IMPACT_TIERING = "impact_tiering"
DISCLOSURE_REPORTING = "disclosure_reporting"
LOGIC_ORACLES = "logic_oracles"
ADVISORY_LOOKUP = "advisory_lookup"
# Display / iteration order.
FEATURES = (IMPACT_TIERING, DISCLOSURE_REPORTING, LOGIC_ORACLES, ADVISORY_LOOKUP)

SRC_DEFAULT = "default"
SRC_CVE_ALIAS = "fuzz-config.json:cve.enabled"
SRC_CONFIG = "fuzz-config.json:features"
SRC_ENV = "$" + ENV_FEATURES


class FeatureError(ValueError):
    pass


def check_name(name: str) -> str:
    if name not in FEATURES:
        raise FeatureError(f"unknown feature '{name}' (known: {', '.join(FEATURES)})")
    return name


@dataclass(frozen=True)
class Features:
    flags: dict                                  # name -> bool (every FEATURES name)
    sources: dict = field(default_factory=dict, compare=False)   # name -> where the value came from
    problems: tuple = field(default=(), compare=False)           # ignored config/env entries

    def enabled(self, name: str) -> bool:
        return self.flags[check_name(name)]

    def disabled(self) -> list:
        return [n for n in FEATURES if not self.flags[n]]

    def as_dict(self) -> dict:
        return {
            "features": {n: {"enabled": self.flags[n], "source": self.sources.get(n, SRC_DEFAULT)}
                         for n in FEATURES},
            "disabled": self.disabled(),
            "problems": list(self.problems),
        }


ALL_ON = Features({n: True for n in FEATURES}, {n: SRC_DEFAULT for n in FEATURES})


# ---------------------------------------------------------------------------
# loading
# ---------------------------------------------------------------------------

def _config_doc(config) -> dict:
    """A fuzz-config dict from a dict, a Campaign, a state dir or a file path."""
    if config is None:
        return {}
    if isinstance(config, dict):
        return config
    from cc_fuzzer_core import config as _config
    return _config.load(config)


def block_problems(block) -> list:
    """What is wrong with a fuzz-config.json `features` block ([] when fine)."""
    if block is None:
        return []
    if not isinstance(block, dict):
        return ["fuzz-config.json: features must be an object"]
    out = []
    for k, v in block.items():
        if k not in FEATURES:
            out.append(f"fuzz-config.json: features.{k} is not a known feature (known: {', '.join(FEATURES)})")
        elif not isinstance(v, bool):
            out.append(f"fuzz-config.json: features.{k} must be true or false (got {json.dumps(v)})")
    return out


def parse_env(text: str) -> tuple[dict, list]:
    """($CC_FUZZER_FEATURES as name -> bool, [problems]). Later entries win."""
    out, problems = {}, []
    for tok in re.split(r"[,\s]+", text or ""):
        if not tok:
            continue
        on = not tok.startswith("-")
        name = tok[1:] if tok[0] in "+-" else tok
        if name not in FEATURES:
            problems.append(f"{SRC_ENV}: unknown feature '{name}' ignored")
            continue
        out[name] = on
    return out, problems


def load(config=None, env: Mapping[str, str] | None = None) -> Features:
    """The effective flags. `config` is a fuzz-config.json dict, a Campaign, a
    state dir or None (defaults + env only)."""
    env = os.environ if env is None else env
    doc = _config_doc(config)
    flags = {n: True for n in FEATURES}
    sources = {n: SRC_DEFAULT for n in FEATURES}
    problems = []

    cve = doc.get("cve")
    if isinstance(cve, dict) and cve.get("enabled") is not None:
        # truthiness, as the old `cve.enabled` toolbox gate read it
        flags[ADVISORY_LOOKUP] = bool(cve["enabled"])
        sources[ADVISORY_LOOKUP] = SRC_CVE_ALIAS

    block = doc.get("features")
    problems += block_problems(block)
    if isinstance(block, dict):
        for k, v in block.items():
            if k in FEATURES and isinstance(v, bool):
                flags[k] = v
                sources[k] = SRC_CONFIG

    over, env_problems = parse_env(env.get(ENV_FEATURES, ""))
    problems += env_problems
    for k, v in over.items():
        flags[k] = v
        sources[k] = SRC_ENV
    return Features(flags, sources, tuple(problems))


def enabled(name: str, config=None, env: Mapping[str, str] | None = None) -> bool:
    """features.enabled(name) against a campaign / state dir / config dict."""
    return load(config, env).enabled(name)


# ---------------------------------------------------------------------------
# prompt blocks: <!-- feature:X --> ... <!-- /feature -->
# ---------------------------------------------------------------------------

_MARKER_RE = re.compile(r"<!--\s*(?:feature:([A-Za-z0-9_]+)|(/feature))\s*-->")


def _is_on(features, name: str) -> bool:
    check_name(name)
    if isinstance(features, Features):
        return features.enabled(name)
    if isinstance(features, Mapping):
        return bool(features.get(name, True))
    # an iterable of the ENABLED names
    return name in set(features)


def strip_blocks(text: str, features: "Features | Mapping[str, bool] | Iterable[str]") -> str:
    """Remove every `<!-- feature:X -->...<!-- /feature -->` block whose
    feature is disabled (a block inside a removed block goes with it; a
    disabled block inside an enabled one is removed on its own). Blocks of
    enabled features are kept verbatim, markers included. A block whose
    markers sit on lines of their own is removed with those whole lines.

    `features` is a Features, a name -> bool mapping (absent names count as
    enabled) or an iterable of the enabled names. Raises FeatureError on an
    unknown feature name and on unbalanced markers."""
    out = []
    pos = 0            # next char of `text` not yet copied or dropped
    stack = []         # (name, marker start offset, dropped?)
    drop_at = None     # marker start of the outermost open disabled block
    for m in _MARKER_RE.finditer(text):
        if m.group(1):
            on = _is_on(features, m.group(1))
            if not on and drop_at is None:
                drop_at = m.start()
            stack.append((m.group(1), m.start(), not on))
            continue
        if not stack:
            raise FeatureError(f"unbalanced <!-- /feature --> at offset {m.start()}")
        _name, opened, dropped = stack.pop()
        if dropped and opened == drop_at:
            start, end = _line_start(text, opened), _line_end(text, m.end())
            if start is None or end is None:   # not whole lines: drop the span only
                start, end = opened, m.end()
            out.append(text[pos:start])
            pos, drop_at = end, None
    if stack:
        raise FeatureError(f"unclosed <!-- feature:{stack[-1][0]} --> block")
    out.append(text[pos:])
    return "".join(out)


def _line_start(text: str, i: int):
    """Start of i's line when only blanks precede i on it, else None."""
    j = text.rfind("\n", 0, i) + 1
    return j if text[j:i].strip() == "" else None


def _line_end(text: str, i: int):
    """Just past the newline of i's line (or the end of text) when only
    blanks follow i on it, else None."""
    j = text.find("\n", i)
    rest = text[i:] if j == -1 else text[i:j]
    if rest.strip():
        return None
    return len(text) if j == -1 else j + 1


# ---------------------------------------------------------------------------
# CLI: cc-fuzzer feature <verb>
# ---------------------------------------------------------------------------

def _cli_config(a):
    """--state-dir wins; else the campaign around the cwd; else no config."""
    if getattr(a, "state_dir", None):
        return a.state_dir
    from cc_fuzzer_core.paths import CampaignError, campaign
    try:
        return campaign(strict=False)
    except CampaignError:
        return None


def _cmd_enabled(a):
    if a.name not in FEATURES:
        sys.stderr.write(f"feature: unknown feature '{a.name}' (known: {', '.join(FEATURES)})\n")
        return 2
    return 0 if load(_cli_config(a)).enabled(a.name) else 1


def _cmd_list(a):
    f = load(_cli_config(a))
    if a.json:
        print(json.dumps(f.as_dict(), indent=2))
    else:
        for n in FEATURES:
            print(f"{n:<22} {'on' if f.flags[n] else 'off':<4} ({f.sources[n]})")
    for p in f.problems:
        sys.stderr.write(f"WARN: {p}\n")
    return 0


def register_cli(subparsers):
    from cc_fuzzer_core.cli import add_subsystem

    _p, verbs = add_subsystem(subparsers, "feature", "feature flags (fuzz-config.json features + $CC_FUZZER_FEATURES)")
    v = verbs.add_parser("enabled", help="exit 0 when the feature is on, 1 when off, 2 when unknown")
    v.add_argument("name")
    v.add_argument("--state-dir", help="read this state dir's fuzz-config.json (default: the campaign's)")
    v.set_defaults(func=_cmd_enabled)
    v = verbs.add_parser("list", help="print every flag with its value and source")
    v.add_argument("--json", action="store_true")
    v.add_argument("--state-dir", help="read this state dir's fuzz-config.json (default: the campaign's)")
    v.set_defaults(func=_cmd_list)
