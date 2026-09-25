"""Prompt sources and the renderer that produces a host's agent files (§3).

The prompts are host-neutral SOURCES under `prompts/<agent>.md`. Everything
that assumes a particular machine -- nix, the reproducible shell, host
toolchain discovery, `apt install`, "on PATH" -- lives in an environment
PROFILE instead (`prompts/profiles/<profile>.md`), and a source splices one in
at a marker:

    <!-- profile:environment -->

The renderer puts the three pieces together:

    render(agent, profile, features) ->
        1. splice every <!-- profile:<slot> --> marker from the profile file
        2. strip <!-- feature:X -->...<!-- /feature --> blocks of OFF features
        3. rewrite the frontmatter `model:` from cc_fuzzer_core.models (§8)

Consumers:
  - a host that keeps RENDERED copies in its own tree (the Claude Code plugin
    does) renders every feature on, commits the result, and runs
    `cc-fuzzer prompts check` to fail when those copies drift.
  - a host that renders at runtime just calls render(), e.g.
    render("crash-triager", profile="oss-fuzz", features=f, frontmatter=False).

WHERE the rendered copies go is the host's business, not the core's: it comes
from `prompts/render.json` ({"output_dir": ..., "profile": ...}) or the
`--dir` / `--profile` flags. The core never assumes a host's layout.

A host adapter with no host-neutral form is listed in that file's
`plugin_only`: it stays hand-written and the drift check ignores it.

CLI: `cc-fuzzer prompts list|render|write|check`.
"""
from __future__ import annotations

import difflib
import json
import re
import sys
from dataclasses import dataclass
from pathlib import Path

from cc_fuzzer_core import features as _features
from cc_fuzzer_core import models as _models
from cc_fuzzer_core import paths as _paths

# Environment profiles. `nix` and `host` are the plugin's; `oss-fuzz` is the
# container's (its toolchain comes from the OSS-Fuzz base image).
PROFILES = ("nix", "host", "oss-fuzz")
# Fallback when prompts/render.json names no profile.
DEFAULT_PROFILE = "nix"

SOURCE_DIRNAME = "prompts"
PROFILE_DIRNAME = "profiles"
# Host render settings, a data file beside the sources (never baked into the
# core): {"output_dir": <relative to the root>, "profile": <name>,
# "plugin_only": [<agent>, ...]}.
RENDER_FILE = "render.json"
# The profile slot holding inline `name = value` variables.
VARS_SLOT = "vars"

# <!-- profile:environment --> in a source; <!-- slot:environment --> in a profile.
_PROFILE_MARKER_RE = re.compile(r"^[ \t]*<!--\s*profile:([A-Za-z0-9_-]+)\s*-->[ \t]*$", re.M)
_SLOT_MARKER_RE = re.compile(r"^[ \t]*<!--\s*slot:([A-Za-z0-9_-]+)\s*-->[ \t]*$", re.M)
# {{cc}} / {{scripts}} in a source, defined by the profile's slot:vars.
_VAR_RE = re.compile(r"\{\{([A-Za-z0-9_]+)\}\}")
_FRONTMATTER_RE = re.compile(r"\A---\n(.*?\n)---\n", re.S)
_MODEL_LINE_RE = re.compile(r"^model:[ \t]*.*$", re.M)
_NAME_LINE_RE = re.compile(r"^name:[ \t]*.*$", re.M)


class PromptError(RuntimeError):
    pass


# ---------------------------------------------------------------------------
# locating sources
# ---------------------------------------------------------------------------

def render_settings(root=None) -> dict:
    """The host's render settings from `prompts/render.json` ({} when absent).
    Keys: output_dir (relative to the root), profile, plugin_only."""
    path = source_dir(root) / RENDER_FILE
    if not path.is_file():
        return {}
    try:
        doc = json.loads(path.read_text())
    except ValueError as e:
        raise PromptError(f"{path}: {e}") from None
    if not isinstance(doc, dict):
        raise PromptError(f"{path}: expected an object")
    return doc


def plugin_only(root=None) -> tuple:
    """Agents the host keeps hand-written (no source, never rendered)."""
    return tuple(render_settings(root).get("plugin_only", ()))


def default_profile(root=None) -> str:
    return check_profile(render_settings(root).get("profile", DEFAULT_PROFILE))


def output_dir(root=None, out_dir=None) -> Path:
    """Where rendered copies go. `--dir` wins; otherwise render.json's
    output_dir, resolved against the root. Without either there is no default:
    the core does not know the host's layout."""
    if out_dir is not None:
        return Path(out_dir)
    rel = render_settings(root).get("output_dir")
    if not rel:
        raise PromptError(
            f"no output directory: pass --dir, or set output_dir in "
            f"{source_dir(root) / RENDER_FILE}")
    base = Path(root) if root is not None else _paths.plugin_root()
    return base / rel


def source_dir(root=None) -> Path:
    """Where `prompts/<agent>.md` lives. `root` is the repo/data root (the
    prompts dir is `<root>/prompts`, alongside `<root>/agents`); without one it
    is resolved like any other data dir, so it works installed too."""
    if root is not None:
        return Path(root) / SOURCE_DIRNAME
    return _paths.data(SOURCE_DIRNAME)


def profile_dir(root=None) -> Path:
    return source_dir(root) / PROFILE_DIRNAME


def agents(root=None) -> list:
    """Every agent with a host-neutral source, sorted."""
    d = source_dir(root)
    if not d.is_dir():
        raise PromptError(f"no prompt sources at {d}")
    return sorted(p.stem for p in d.glob("*.md"))


def source_path(agent: str, root=None) -> Path:
    p = source_dir(root) / f"{agent}.md"
    if not p.is_file():
        known = ", ".join(agents(root))
        extra = f" ({agent} is host-only)" if agent in plugin_only(root) else ""
        raise PromptError(f"no prompt source for '{agent}'{extra}; known: {known}")
    return p


def check_profile(profile: str) -> str:
    if profile not in PROFILES:
        raise PromptError(f"unknown profile '{profile}' (known: {', '.join(PROFILES)})")
    return profile


# ---------------------------------------------------------------------------
# profile slots
# ---------------------------------------------------------------------------

def load_profile(profile: str, root=None) -> dict:
    """A profile file as slot -> text. Text before the first `<!-- slot:X -->`
    is a comment header and is dropped. A missing file yields {} -- that is an
    error only if a source actually asks for a slot."""
    check_profile(profile)
    path = profile_dir(root) / f"{profile}.md"
    if not path.is_file():
        return {}
    text = path.read_text()
    marks = list(_SLOT_MARKER_RE.finditer(text))
    out = {}
    for i, m in enumerate(marks):
        end = marks[i + 1].start() if i + 1 < len(marks) else len(text)
        name = m.group(1)
        if name in out:
            raise PromptError(f"{path}: duplicate slot '{name}'")
        out[name] = text[m.end():end].strip("\n")
    return out


def profile_vars(profile: str, root=None) -> dict:
    """A profile's inline variables, from its `<!-- slot:vars -->` section:
    one `name = value` per line, blanks and `#` comments ignored. Sources use
    them as `{{name}}` (see substitute_vars)."""
    body = load_profile(profile, root).get(VARS_SLOT, "")
    out = {}
    for lineno, raw in enumerate(body.splitlines(), 1):
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        if "=" not in line:
            raise PromptError(
                f"{profile_dir(root) / (profile + '.md')}: slot:{VARS_SLOT} line {lineno}: "
                f"expected `name = value`, got {raw!r}")
        name, _, value = line.partition("=")
        out[name.strip()] = value.strip()
    return out


def substitute_vars(text: str, variables: dict, *, where: str = "<prompt>",
                    profile: str = "") -> str:
    """Replace every `{{name}}` with the profile's value for it. An undefined
    name is an error, so a source can never render to a half-written command."""
    def sub(m):
        name = m.group(1)
        if name not in variables:
            known = ", ".join(sorted(variables)) or "none"
            raise PromptError(
                f"{where}: profile '{profile}' defines no variable '{name}' (has: {known})")
        return variables[name]

    return _VAR_RE.sub(sub, text)


def splice_profile(text: str, profile: str, root=None, *, where: str = "<prompt>") -> str:
    """Replace every `<!-- profile:<slot> -->` line with that slot's text."""
    if not _PROFILE_MARKER_RE.search(text):
        check_profile(profile)
        return text
    slots = load_profile(profile, root)

    def sub(m):
        name = m.group(1)
        if name not in slots:
            raise PromptError(
                f"{where}: profile '{profile}' has no slot '{name}' "
                f"({profile_dir(root) / (profile + '.md')})")
        return slots[name]

    return _PROFILE_MARKER_RE.sub(sub, text)


# ---------------------------------------------------------------------------
# frontmatter
# ---------------------------------------------------------------------------

def _set_model(text: str, agent: str, config=None, env=None) -> str:
    """Rewrite the frontmatter `model:` from models.resolve() (§8). A prompt
    with no frontmatter, or an agent the model map does not name, is left
    alone."""
    fm = _FRONTMATTER_RE.match(text)
    if not fm:
        return text
    try:
        model = _models.resolve(agent, config, env)
    except Exception:  # an agent outside the map keeps whatever it declares
        return text
    block = fm.group(1)
    line = f"model: {model}"
    if _MODEL_LINE_RE.search(block):
        new = _MODEL_LINE_RE.sub(line, block, count=1)
    elif _NAME_LINE_RE.search(block):
        new = _NAME_LINE_RE.sub(lambda m: m.group(0) + "\n" + line, block, count=1)
    else:
        new = block + line + "\n"
    return text[:fm.start(1)] + new + text[fm.end(1):]


def _drop_frontmatter(text: str) -> str:
    fm = _FRONTMATTER_RE.match(text)
    return text[fm.end():].lstrip("\n") if fm else text


# ---------------------------------------------------------------------------
# rendering
# ---------------------------------------------------------------------------

def render(agent: str, profile: str = "", features=None, *,
           root=None, config=None, env=None, frontmatter: bool = True) -> str:
    """The final prompt text for `agent` on `profile`.

    features: a features.Features, a {name: bool} mapping, an iterable of the
    ENABLED names, or None for all on.
    frontmatter: False drops the Claude Code frontmatter block entirely (what
    a non-Claude host wants).
    """
    profile = check_profile(profile or default_profile(root))
    path = source_path(agent, root)
    text = path.read_text()
    text = splice_profile(text, profile, root, where=str(path))
    text = substitute_vars(text, profile_vars(profile, root), where=str(path), profile=profile)
    text = _features.strip_blocks(text, _features.ALL_ON if features is None else features)
    if frontmatter:
        text = _set_model(text, agent, config, env)
    else:
        text = _drop_frontmatter(text)
    return text


def render_all(profile: str = "", features=None, *, root=None,
               config=None, env=None, frontmatter: bool = True) -> dict:
    return {a: render(a, profile, features, root=root, config=config, env=env,
                      frontmatter=frontmatter)
            for a in agents(root)}


# ---------------------------------------------------------------------------
# drift between the sources and a host's committed copies
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class Drift:
    agent: str
    path: Path
    reason: str     # "missing" | "changed"
    diff: str = ""

    def __str__(self) -> str:
        return f"{self.agent}: {self.reason} ({self.path})"


def check(root=None, out_dir=None, profile: str = "") -> list:
    """Every rendered prompt whose committed copy no longer matches.
    [] means the host's tree is in sync with the sources."""
    d = output_dir(root, out_dir)
    profile = profile or default_profile(root)
    drifts = []
    for agent in agents(root):
        want = render(agent, profile, root=root)
        path = d / f"{agent}.md"
        if not path.is_file():
            drifts.append(Drift(agent, path, "missing"))
            continue
        have = path.read_text()
        if have != want:
            diff = "".join(difflib.unified_diff(
                have.splitlines(True), want.splitlines(True),
                fromfile=f"{path} (committed)", tofile=f"{agent} (rendered)"))
            drifts.append(Drift(agent, path, "changed", diff))
    return drifts


def write(root=None, out_dir=None, profile: str = "") -> list:
    """Render every source into the output dir. Returns the paths changed."""
    d = output_dir(root, out_dir)
    profile = profile or default_profile(root)
    d.mkdir(parents=True, exist_ok=True)
    changed = []
    for agent in agents(root):
        text = render(agent, profile, root=root)
        path = d / f"{agent}.md"
        if not path.is_file() or path.read_text() != text:
            path.write_text(text)
            changed.append(path)
    return changed


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def _features_arg(spec):
    """--features wins; without it $CC_FUZZER_FEATURES applies, as everywhere
    else (§9). Note the `=`: `--features=-advisory_lookup`, since a bare
    `-name` looks like an option to argparse."""
    if spec is None:
        return _features.load()
    if not spec:
        return _features.ALL_ON
    flags, problems = _features.parse_env(spec)
    for p in problems:
        print(p, file=sys.stderr)
    base = {n: True for n in _features.FEATURES}
    base.update(flags)
    return base


def _cmd_list(a):
    if getattr(a, "json", False):
        import json
        print(json.dumps({"agents": agents(a.root), "plugin_only": list(plugin_only(a.root)),
                          "profiles": list(PROFILES)}, indent=2))
    else:
        for name in agents(a.root):
            print(name)
    return 0


def _cmd_render(a):
    text = render(a.agent, a.profile, _features_arg(a.features), root=a.root,
                  frontmatter=not a.no_frontmatter)
    if a.output:
        Path(a.output).write_text(text)
    else:
        sys.stdout.write(text)
    return 0


def _cmd_write(a):
    changed = write(a.root, a.dir, a.profile)
    for p in changed:
        print(f"wrote {p}")
    if not changed:
        print("rendered prompts already up to date")
    return 0


def _cmd_check(a):
    profile = a.profile or default_profile(a.root)
    drifts = check(a.root, a.dir, profile)
    if not drifts:
        print(f"prompts ok ({len(agents(a.root))} agents, profile {profile})")
        return 0
    for d in drifts:
        print(f"drift: {d}", file=sys.stderr)
        if d.diff and not a.quiet:
            sys.stderr.write(d.diff)
    print(f"{len(drifts)} rendered file(s) differ from prompts/; "
          f"run `cc-fuzzer prompts write`", file=sys.stderr)
    return 1


def _run(fn):
    def wrapper(a):
        try:
            return fn(a)
        except PromptError as e:
            print(f"error: {e}", file=sys.stderr)
            return 2
    return wrapper


def register_cli(subparsers):
    from cc_fuzzer_core.cli import add_subsystem
    _p, verbs = add_subsystem(subparsers, "prompts",
                              "Host-neutral prompt sources and the agent renderer.")

    def verb(name, help_text):
        v = verbs.add_parser(name, help=help_text)
        v.add_argument("--root", help="root holding prompts/ (default: resolved)")
        return v

    v = verb("list", "agents that have a host-neutral source")
    v.add_argument("--json", action="store_true")
    v.set_defaults(func=_run(_cmd_list))

    v = verb("render", "render one agent to stdout")
    v.add_argument("agent")
    v.add_argument("--profile", default="", choices=PROFILES,
                   help="default: prompts/render.json")
    v.add_argument("--features", default=None,
                   help="e.g. --features=-advisory_lookup,-logic_oracles "
                        "(default: $CC_FUZZER_FEATURES)")
    v.add_argument("--no-frontmatter", action="store_true",
                   help="drop the Claude Code frontmatter block")
    v.add_argument("-o", "--output")
    v.set_defaults(func=_run(_cmd_render))

    v = verb("write", "render every source into the output dir")
    v.add_argument("--dir", help="output dir (default: render.json output_dir)")
    v.add_argument("--profile", default="", choices=PROFILES,
                   help="default: prompts/render.json")
    v.set_defaults(func=_run(_cmd_write))

    v = verb("check", "fail if the rendered copies drifted from prompts/")
    v.add_argument("--dir", help="output dir (default: render.json output_dir)")
    v.add_argument("--profile", default="", choices=PROFILES,
                   help="default: prompts/render.json")
    v.add_argument("-q", "--quiet", action="store_true", help="names only, no diff")
    v.set_defaults(func=_run(_cmd_check))
