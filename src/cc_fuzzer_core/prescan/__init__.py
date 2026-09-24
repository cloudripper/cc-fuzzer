"""Tier-1 code-review prescan (UPDATE_ROADMAP.md §2 row 7).

    code_review_prescan.prescan(target_root, out, ...) -> PrescanResult
                                                (was _lib/code_review_prescan.py)
    sast_scan.run_sast / run_semgrep_config / attribute   (was _lib/sast_scan.py)
    merge.merge(prescan, partials, out, md) -> MergeResult (was _lib/code_review_merge.py)
    plan_review(campaign, ReviewOptions) -> ReviewPlan     (code-review-run.sh's
                                                defaults: CLI > fuzz-config.json
                                                code_review > harness-built.json)
    review(campaign, ReviewOptions) -> ReviewResult        (plan + prescan + window plan)

The bundled semgrep packs are every rule-bearing subdirectory of
paths.data("rules"); semgrep / codeql / git resolve through tools.which.

CLI:
  cc-fuzzer prescan run [flags]        code-review-run.sh (the shim): prints
                                       BATCH_PLAN ... and READY: <prescan>
  cc-fuzzer prescan merge [flags] P..  code-review-run.sh merge-code-review
  cc-fuzzer prescan scan [flags]       the prescan alone (code_review_prescan.py)
  cc-fuzzer prescan sast [flags]       a standalone SAST run (sast_scan.py, debug)
"""
from __future__ import annotations

import glob
import json
import math
import os
import sys
import time
from dataclasses import dataclass
from pathlib import Path

from cc_fuzzer_core.paths import Campaign, CampaignError, campaign as _campaign, state_dir_text

DEFAULT_MAX_FUNCTIONS = "50"
DEFAULT_BATCH_SIZE = "30"
DEFAULT_SAST = "auto"

_RUN_HELP = r"""code-review-run.sh

Three-tier code-review pipeline orchestrator. Runs Tier-1 (deterministic
prescan) directly here, then exposes the prescan artifact so the calling
context (the campaign command, /fuzz-review, or the orchestrator
agent) can dispatch the `code-reviewer` subagent for Tier-2 (Sonnet) and
optionally Tier-3 (Opus).

This script does NOT call subagents itself — that's the dispatcher's job.
The script's contract is:

  1. Resolve the target source root (from --target-root or
     harness-built.json:target_source).
  2. Read fuzz-config.json:code_review for defaults.
  3. Cross-link the latest cve-context-*.json so the prescan can use the
     hotspot data.
  4. Run the prescan, write fuzz/state/snapshots/code-review-prescan-<ts>.json.
  5. Echo a "READY: <prescan-path>" line on stdout for the caller.

The caller (campaign command or /fuzz-review) then:
  - Reads the prescan
  - Dispatches `code-reviewer` agent (Sonnet) on the top-N functions
  - Optionally dispatches the Opus deep-pass on the agent's high-confidence findings
  - Writes fuzz/state/snapshots/code-review-<ts>.json + fuzz/state/code-review.md

Usage:
  scripts/code-review-run.sh \\
      [--target-root <path>] \\
      [--max-functions <N>|all] \\
      [--sweep]              (review EVERY function: max-functions=all, mode=sweep)
      [--batch-size <S>]     (reviewer window size; default 30)
      [--excluded-paths <comma-list>] \\
      [--sast off|auto|on]   (Tier-1 external SAST; default auto)
      [--no-sast]            (alias for --sast off)
      [--sast-rules <dirs>]  (extra semgrep rule dirs; bundled pack always included)
      [--codeql-db <path>]   (analyze a PREBUILT CodeQL database; skipped if absent)
      [--refresh]   (ignore stale-source-hash check)
      [--no-cve-context]   (skip cross-linking the latest cve-context)

  scripts/code-review-run.sh merge-code-review \\
      --prescan <prescan.json> --out <code-review-<ts>.json> --md <code-review.md> \\
      [--target <name>] -- <window-partial.json> [<window-partial.json> ...]

The prescan run prints a machine-readable plan line the caller parses:
  BATCH_PLAN windows=<n> batch_size=<S> candidates=<c> mode=<capped|sweep>

Exit codes:
  0  prescan ran (or was skipped because already-fresh) / merge succeeded
  2  bad arguments or no target source available

"""


@dataclass
class ReviewOptions:
    """code-review-run.sh's flags. Empty strings mean "not given" (the config
    / default applies), exactly like the script's ${CLI_X:-...} chain."""
    target_root: str = ""
    max_functions: str = ""
    sweep: bool = False           # sugar for max_functions="all"; wins over it
    batch_size: str = ""
    excluded_paths: str = ""
    sast: str = ""                # off|auto|on
    sast_rules: str = ""
    codeql_db: str = ""
    refresh: bool = False         # accepted, unused (as before)
    no_cve_context: bool = False


@dataclass
class ReviewPlan:
    """The resolved prescan inputs. Paths are as the script printed / passed
    them; relative ones are relative to the project root."""
    target_root: str
    max_functions: str
    excluded_paths: str
    sast: str
    sast_rules: str
    codeql_db: str
    cve_context: str              # "" = none
    batch_size: str
    out: str                      # <state>/snapshots/code-review-prescan-<ts>.json

    def prescan_argv(self) -> list[str]:
        """The `prescan scan` argv code-review-run.sh passed its prescan."""
        argv = ["--target-root", self.target_root, "--out", self.out,
                "--max-functions", self.max_functions, "--sast", self.sast]
        for flag, v in (("--excluded-paths", self.excluded_paths), ("--cve-context", self.cve_context),
                        ("--sast-rules", self.sast_rules), ("--codeql-db", self.codeql_db)):
            if v:
                argv += [flag, v]
        return argv


@dataclass
class ReviewResult:
    plan: ReviewPlan
    candidates: str               # scope.candidates_selected, as printed
    mode: str
    windows: int | str

    def batch_plan_line(self) -> str:
        return (f"BATCH_PLAN windows={self.windows} batch_size={self.plan.batch_size} "
                f"candidates={self.candidates} mode={self.mode}")


class ReviewError(RuntimeError):
    def __init__(self, message: str, code: int = 2):
        super().__init__(message)
        self.code = code


def _io(c: Campaign, p: str) -> str:
    return p if os.path.isabs(p) else str(c.project_root / p)


def _config_defaults(state_dir: Path) -> tuple[str, str, str, str, str]:
    """(scan_path, max_functions, excludes, sast_mode, codeql_db) from
    fuzz-config.json:code_review, each as the script read it (str(), stripped,
    "" when absent; all "" when the file is unreadable or oddly shaped)."""
    cfg = state_dir / "fuzz-config.json"
    blank = ("", "", "", "", "")
    if not cfg.is_file():
        return blank
    try:
        d = json.loads(cfg.read_text())
        cr = (d.get("code_review") or {})
        paths = cr.get("scan_paths") or ""
        if isinstance(paths, list):
            paths = paths[0] if paths else ""
        excl = cr.get("excluded_paths") or []
        if isinstance(excl, list):
            excl = ",".join(excl)
        sast = (cr.get("sast") or {})
        # sast may be a bool (enabled) or an object; normalize to a mode string.
        if isinstance(sast, bool):
            sast_mode = "auto" if sast else "off"
            codeql_db = ""
        else:
            sast_mode = sast.get("mode", "") or ("off" if sast.get("enabled") is False else "")
            codeql_db = sast.get("codeql_db", "") or ""
        vals = (paths or "", cr.get("max_functions_to_review", "") or "", excl or "",
                sast_mode or "", codeql_db or "")
    except Exception:
        return blank
    # One `read -r` per value: surrounding whitespace is dropped.
    return tuple(str(v).split("\n", 1)[0].strip(" \t") for v in vals)


def _auto_target_root(c: Campaign) -> str:
    """The directory of harness-built.json:target_source (or the dir itself)."""
    try:
        d = json.loads((c.state_dir / "harness-built.json").read_text())
        ts = d.get("target_source", "")
        if ts:
            ts = _io(c, os.path.normpath(ts))
            if os.path.isfile(ts):
                return os.path.dirname(os.path.abspath(ts)) or "."
            if os.path.isdir(ts):
                return os.path.abspath(ts)
    except Exception:
        pass
    return ""


def _latest(pattern: str) -> str:
    """`ls -t <pattern> | head -1`: newest mtime, ties by name ("" if none)."""
    cands = []
    for p in glob.glob(pattern):
        try:
            cands.append((-os.stat(p).st_mtime_ns, p))
        except OSError:
            pass
    return min(cands)[1] if cands else ""


def plan_review(c: Campaign, opts: ReviewOptions, *, now: int | None = None) -> ReviewPlan:
    """Resolve the prescan inputs (CLI > config > auto-detect / default).
    ReviewError when no target source root can be found."""
    cli_max = "all" if opts.sweep else opts.max_functions
    cfg_root, cfg_max, cfg_excl, cfg_sast, cfg_db = _config_defaults(c.state_dir)
    target = opts.target_root or cfg_root or _auto_target_root(c)
    if not target or not os.path.isdir(_io(c, target)):
        raise ReviewError(
            "ERROR: cannot resolve target source root.\n"
            "       Tried: --target-root, fuzz-config.json:code_review.scan_paths,\n"
            "       and auto-detect from harness-built.json:target_source.\n"
            "       Pass --target-root <dir> or set code_review.scan_paths in fuzz-config.json.")
    snaps = f"{state_dir_text(c)}/snapshots"
    cve = "" if opts.no_cve_context else _latest(
        f"{glob.escape(_io(c, snaps))}/cve-context-*.json")
    if cve:
        cve = f"{snaps}/{os.path.basename(cve)}"
    ts = int(time.time()) if now is None else now
    return ReviewPlan(
        target_root=target,
        max_functions=cli_max or cfg_max or DEFAULT_MAX_FUNCTIONS,
        excluded_paths=opts.excluded_paths or cfg_excl,
        # The prescan auto-includes the bundled rule packs; --sast-rules only ADDS.
        sast=opts.sast or cfg_sast or DEFAULT_SAST,
        sast_rules=opts.sast_rules,
        codeql_db=opts.codeql_db or cfg_db,
        cve_context=cve,
        batch_size=opts.batch_size or DEFAULT_BATCH_SIZE,
        out=f"{snaps}/code-review-prescan-{ts}.json",
    )


def window_count(candidates, batch_size) -> int | str:
    """ceil(candidates / batch_size); 0 with no candidates; "1" when the batch
    size isn't a usable int (the script's fallback)."""
    try:
        cand = int(candidates or 0)
        b = int(batch_size or 30)
        return 0 if cand == 0 else math.ceil(cand / b)
    except (ValueError, ZeroDivisionError):
        return "1"


def _result(c: Campaign, plan: ReviewPlan) -> ReviewResult:
    try:
        d = json.loads(Path(_io(c, plan.out)).read_text())
        scope = d.get("scope") or {}
        cand = scope.get("candidates_selected", len(d.get("top_candidates") or []))
        mode = scope.get("mode", "capped")
    except Exception:
        cand, mode = "", ""
    # As the script echoed them (Python's print form); empty => its defaults.
    cand, mode = str(cand) or "0", str(mode) or "capped"
    return ReviewResult(plan, cand, mode, window_count(cand, plan.batch_size))


def review(c: Campaign, opts: ReviewOptions, *, now: int | None = None) -> ReviewResult:
    """code-review-run.sh as a function: plan, run the prescan, plan windows."""
    from cc_fuzzer_core.prescan.code_review_prescan import prescan

    plan = plan_review(c, opts, now=now)
    c.snapshots_dir.mkdir(parents=True, exist_ok=True)
    prescan(plan.target_root, plan.out, max_functions=plan.max_functions,
            excluded_paths=plan.excluded_paths, cve_context=plan.cve_context, sast=plan.sast,
            sast_rules=plan.sast_rules, codeql_db=plan.codeql_db, base=c.project_root)
    return _result(c, plan)


# ---------------------------------------------------------------------------
# CLI: cc-fuzzer prescan <verb>
# ---------------------------------------------------------------------------

_RUN_FLAGS = {"--target-root": "target_root", "--max-functions": "max_functions",
              "--batch-size": "batch_size", "--excluded-paths": "excluded_paths",
              "--sast": "sast", "--sast-rules": "sast_rules", "--codeql-db": "codeql_db"}


def _campaign_dirs():
    """path-anchor + the script's `mkdir -p $STATE_DIR $SNAPSHOTS_DIR`."""
    c = _campaign()
    c.snapshots_dir.mkdir(parents=True, exist_ok=True)
    return c


def _cmd_run(a):
    from cc_fuzzer_core.prescan import code_review_prescan

    try:
        c = _campaign_dirs()
    except CampaignError as e:
        sys.stderr.write(f"{e}\n")
        return e.code
    opts, args = ReviewOptions(), list(a.args)
    while args:
        arg = args.pop(0)
        if arg in _RUN_FLAGS:
            # A flag given last with no value reads as "" (the script looped
            # forever on its failing `shift 2`).
            setattr(opts, _RUN_FLAGS[arg], args.pop(0) if args else "")
        elif arg == "--sweep":
            opts.sweep = True
        elif arg == "--no-sast":
            opts.sast = "off"
        elif arg == "--refresh":
            opts.refresh = True
        elif arg == "--no-cve-context":
            opts.no_cve_context = True
        elif arg in ("--help", "-h"):
            sys.stdout.write(_RUN_HELP)
            return 0
        else:
            sys.stderr.write(f"ERROR: unknown arg '{arg}'\n")
            return 2
    try:
        plan = plan_review(c, opts)
    except ReviewError as e:
        sys.stderr.write(f"{e}\n")
        return e.code
    sys.stderr.write(f"[code-review] running prescan: target={plan.target_root} "
                     f"max={plan.max_functions} sast={plan.sast}\n")
    if plan.cve_context:
        sys.stderr.write(f"[code-review] cve-context: {plan.cve_context}\n")
    sys.stderr.flush()
    # The prescan's own CLI (argparse included), so a bad --sast / --max-functions
    # fails with its usual message; its stdout (the artifact path) is dropped.
    if code_review_prescan.main(plan.prescan_argv(), base=c.project_root, quiet=True) != 0:
        sys.stderr.write("ERROR: prescan failed\n")
        return 2
    r = _result(c, plan)
    sys.stderr.write(f"[code-review] prescan complete: {r.candidates} candidate function(s), mode={r.mode}\n")
    sys.stderr.flush()
    # Machine-readable plan the skill parses to drive the windowed reviewer dispatch.
    print(r.batch_plan_line())
    print(f"READY: {plan.out}")
    return 0


def _cmd_merge(a):
    from cc_fuzzer_core.prescan import merge

    try:
        _campaign_dirs()
    except CampaignError as e:
        sys.stderr.write(f"{e}\n")
        return e.code
    return _argparse_main(merge.main, a.args)


def _argparse_main(fn, argv):
    try:
        return fn(list(argv))
    except SystemExit as e:  # argparse usage errors / --help
        return e.code if isinstance(e.code, int) else (0 if e.code is None else 2)


def _cmd_scan(a):
    from cc_fuzzer_core.prescan import code_review_prescan
    return _argparse_main(code_review_prescan.main, a.args)


def _cmd_sast(a):
    from cc_fuzzer_core.prescan import sast_scan
    return _argparse_main(sast_scan.main, a.args)


def register_cli(subparsers):
    from cc_fuzzer_core.cli import add_raw_verb, add_subsystem

    _p, verbs = add_subsystem(subparsers, "prescan", "Tier-1 code-review prescan (grep + SAST ranking)")
    add_raw_verb(verbs, "prescan", "run", _cmd_run,
                 "resolve defaults, run the prescan, print BATCH_PLAN / READY (port of code-review-run.sh)")
    add_raw_verb(verbs, "prescan", "merge", _cmd_merge,
                 "merge reviewer window partials (code-review-run.sh merge-code-review)")
    add_raw_verb(verbs, "prescan", "scan", _cmd_scan,
                 "run the prescan alone (port of _lib/code_review_prescan.py)")
    add_raw_verb(verbs, "prescan", "sast", _cmd_sast,
                 "standalone SAST scan, for debugging (port of _lib/sast_scan.py)")
