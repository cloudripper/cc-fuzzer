#!/usr/bin/env python3
"""code_review_prescan.py — deterministic Tier-1 of the code-review pipeline.

The prescan walks the target source tree and produces a ranked list of
functions worth deeper LLM review. It does NO LLM calls. Output is a JSON
artifact the `code-reviewer` agent (Sonnet) reads in Tier-2.

What it does:
  - File inventory (respects excludes).
  - Coarse text-pattern grep for known-dangerous APIs / pattern signatures.
  - Function inventory via regex (file:line + name + LOC).
  - CVE-pattern cross-reference: hot functions/files from cve-context get a
    suspicion-score bump.
  - Git-history weighting: recently-modified files get a bump (when in a git
    repo). Skipped silently when git isn't available.
  - Suspicion score per function (composite of all the above).
  - Top-N selection.

Output: a JSON file (path passed via --out) containing the scope summary,
the full function inventory, and the top-N candidates with explanation.

CLI:
    code_review_prescan.py \\
        --target-root /path/to/source \\
        --out fuzz/state/code-review-prescan-<ts>.json \\
        [--max-functions 50] \\
        [--excluded-paths "tests/,docs/,examples/,third_party/,vendor/"] \\
        [--cve-context fuzz/state/snapshots/cve-context-<ts>.json]
"""
from __future__ import annotations
import argparse
import json
import os
import re
import subprocess
import sys
import time
from dataclasses import dataclass, asdict, field
from pathlib import Path
from typing import Dict, List, Optional, Set, Tuple


# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

# File extensions we consider. C/C++ for now (the plugin's stated scope).
SOURCE_EXTENSIONS = {".c", ".cc", ".cpp", ".cxx", ".cc", ".C", ".h", ".hh",
                     ".hpp", ".hxx", ".H"}

DEFAULT_EXCLUDED = [
    "tests/", "test/", "testsuite/", "regression/",
    "docs/", "doc/", "documentation/",
    "examples/", "example/", "sample/", "samples/",
    "third_party/", "thirdparty/", "vendor/",
    "build/", "build-aux/", "cmake/", "m4/",
    "fuzz/",  # the campaign's own fuzz/ directory; not the target
    ".git/", "node_modules/", "venv/", ".venv/", "__pycache__/",
]


# Each rule: (compiled regex, category, weight). Categories are descriptive;
# weights go into the suspicion score.
#
# Conservative on purpose. False positives are cheap (the Sonnet pass filters
# them); false negatives mean Sonnet never sees the function.
PATTERN_RULES: List[Tuple[re.Pattern, str, int]] = [
    # Classic dangerous string APIs
    (re.compile(r"\bstrcpy\s*\("),       "strcpy_call",            5),
    (re.compile(r"\bstrcat\s*\("),       "strcat_call",            5),
    (re.compile(r"\bsprintf\s*\("),      "sprintf_call",           5),
    (re.compile(r"\bvsprintf\s*\("),     "vsprintf_call",          5),
    (re.compile(r"\bgets\s*\("),         "gets_call",              8),
    # memcpy/memmove are not inherently dangerous; flag them as a signal,
    # the Sonnet pass decides if the length is attacker-controlled.
    (re.compile(r"\bmemcpy\s*\("),       "memcpy_call",            2),
    (re.compile(r"\bmemmove\s*\("),      "memmove_call",           2),
    (re.compile(r"\bstrncpy\s*\("),      "strncpy_call",           1),
    (re.compile(r"\bstrncat\s*\("),      "strncat_call",           1),
    (re.compile(r"\bsnprintf\s*\("),     "snprintf_call",          1),

    # Stack-allocated with attacker-controlled size
    (re.compile(r"\balloca\s*\("),       "alloca_call",            6),
    (re.compile(r"\b_alloca\s*\("),      "alloca_call",            6),

    # Shell injection / process surface
    (re.compile(r"\bsystem\s*\("),       "system_call",            7),
    (re.compile(r"\bpopen\s*\("),        "popen_call",             7),
    (re.compile(r"\bexecv?p?l?e?\s*\("), "exec_call",              5),

    # Non-literal format-string risk: printf(buf) instead of printf("%s", buf)
    # This regex is intentionally narrow (printf called with a single
    # identifier argument); a Sonnet pass will sharpen.
    (re.compile(r"\bf?printf\s*\(\s*[A-Za-z_]\w*\s*\)"),
                                          "format_string_nonliteral", 6),
    (re.compile(r"\bsyslog\s*\(\s*[A-Z_]+\s*,\s*[A-Za-z_]\w*\s*\)"),
                                          "syslog_format_risk",       4),

    # Allocation with size from arithmetic (overflow risk if attacker-controlled)
    (re.compile(r"\bmalloc\s*\([^,)]*[\*+]"),  "malloc_arith_size",  3),
    (re.compile(r"\bcalloc\s*\([^,)]*,\s*[^)]*[\*+]"),
                                                 "calloc_arith_size", 3),
    (re.compile(r"\brealloc\s*\([^,)]*,\s*[^)]*[\*+]"),
                                                 "realloc_arith_size", 3),

    # Integer parsing without error check (atoi family silently returns 0)
    (re.compile(r"\batoi\s*\("),         "atoi_call",              2),
    (re.compile(r"\batol\s*\("),         "atol_call",              2),

    # Indexed write with non-constant index (rough)
    (re.compile(r"\b\w+\s*\[\s*[a-z_]\w*\s*\]\s*="),
                                          "indexed_write",         1),

    # Loop bound from input (heuristic: 'for (i = 0; i < len; ...)' where
    # 'len' appears in the function signature — we score it from the
    # function's input args by looking at later signal aggregation).
    (re.compile(r"for\s*\(\s*\w+\s*=\s*0\s*;\s*\w+\s*<\s*\w+\s*;"),
                                          "input_bounded_loop",    1),

    # Recursive function call to its own name (we won't know the function
    # name here; assigned during per-function scoring below).

    # Untrusted-data → pointer arithmetic
    (re.compile(r"(?:\b\w+\s*\+\s*\w+|\b\w+\s*-\s*\w+)\s*[\];]"),
                                          "ptr_arith",             0),  # informational
]


# Function-definition regex. C/C++ is hard to parse with regex, but we don't
# need to be precise — we want a coarse "name + line where the body starts."
# Recognised shapes:
#   static int foo(args) {
#   void bar(args)
#   {
#   struct s *baz(args)
#   typedef ret (*fn)(args) — IGNORED (function-pointer typedefs)
#
# The pattern:
#   start-of-line optional qualifiers, return type, NAME(args), optional brace
#   on same line or following line.
#
# False positives: function-pointer typedefs, K&R-style prototypes, macros.
# Sonnet pass will tolerate these (they just won't have meaningful content).
FUNC_DEF_RE = re.compile(
    r"^\s*"
    r"(?:(?:static|inline|extern|const|__attribute__\s*\([^)]+\))\s+)*"
    r"(?:[\w:][\w:\s\*<>,]*?\s+)"          # return type (non-greedy)
    r"(?P<name>[A-Za-z_]\w*)\s*"           # function name
    r"\([^;)]*\)\s*"                       # arg list (no semicolons → not a proto-only decl)
    r"(?:\{|$)",                           # opening brace OR end-of-line (brace next line)
    re.M,
)


# ---------------------------------------------------------------------------
# Data classes
# ---------------------------------------------------------------------------

@dataclass
class FunctionEntry:
    file: str
    name: str
    line_start: int
    line_end: int
    loc: int
    suspicion_score: int = 0
    score_breakdown: Dict[str, int] = field(default_factory=dict)
    pattern_hits: Dict[str, int] = field(default_factory=dict)
    cve_hotspot_match: bool = False
    cve_pattern_hints: List[str] = field(default_factory=list)
    file_recently_changed: bool = False

    def to_dict(self) -> dict:
        return asdict(self)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _is_excluded(rel_path: str, excludes: List[str]) -> bool:
    p = rel_path + "/"  # so "tests/" matches "tests/foo.c"
    return any(seg in ("/" + p) for seg in (e if e.startswith("/") else "/" + e for e in excludes))


def _enumerate_sources(root: Path, excludes: List[str]) -> List[Path]:
    out: List[Path] = []
    for dirpath, dirnames, filenames in os.walk(root):
        # Filter dirs in-place so we don't descend into excluded trees.
        rel_dir = os.path.relpath(dirpath, root)
        if rel_dir == ".":
            rel_dir = ""
        # Excluded?
        if rel_dir and _is_excluded(rel_dir + "/", excludes):
            dirnames[:] = []
            continue
        # Also prune child dirs that match excludes (saves a stat() per file).
        dirnames[:] = [d for d in dirnames
                       if not _is_excluded(((rel_dir + "/" if rel_dir else "") + d + "/"), excludes)]
        for f in filenames:
            ext = ""
            if "." in f:
                ext = "." + f.rsplit(".", 1)[-1]
            if ext in SOURCE_EXTENSIONS:
                out.append(Path(dirpath) / f)
    return out


def _inventory_functions(path: Path, text: str) -> List[FunctionEntry]:
    """Extract a coarse list of functions defined in `text` (the contents of
    `path`). Returns FunctionEntry stubs with line_start / line_end / loc
    populated; pattern hits and scoring happen later."""
    lines = text.splitlines()
    out: List[FunctionEntry] = []
    seen_names_at_line: Set[Tuple[int, str]] = set()
    for m in FUNC_DEF_RE.finditer(text):
        name = m.group("name")
        # Skip obvious non-function names
        if name in {"if", "for", "while", "switch", "return", "sizeof",
                    "typeof", "do", "case"}:
            continue
        # Compute line number from offset
        line_start = text.count("\n", 0, m.start()) + 1
        # If this offset doesn't actually begin a function body, skip.
        if (line_start, name) in seen_names_at_line:
            continue
        seen_names_at_line.add((line_start, name))
        # Find the matching closing brace via depth counter.
        # Scan from m.end() forward in the original text.
        depth = 0
        i = m.end() - 1
        # If '{' is on the NEXT line, skip ahead to find it.
        if "{" not in text[m.start():m.end()]:
            j = text.find("{", m.end())
            if j == -1:
                continue
            i = j
        # Walk braces
        line_end = line_start
        end_offset = i
        depth = 0
        while end_offset < len(text):
            ch = text[end_offset]
            if ch == "{":
                depth += 1
            elif ch == "}":
                depth -= 1
                if depth == 0:
                    line_end = text.count("\n", 0, end_offset) + 1
                    break
            end_offset += 1
        if depth != 0:
            # Mis-parse (likely a #if-guarded brace); skip.
            continue
        loc = line_end - line_start + 1
        # Reject implausibly large functions (more likely a parse error).
        if loc > 5000:
            continue
        out.append(FunctionEntry(
            file=str(path), name=name,
            line_start=line_start, line_end=line_end, loc=loc,
        ))
    return out


def _score_function(entry: FunctionEntry, file_text_lines: List[str],
                    cve_hotspot_files: Set[str], cve_hotspot_functions: Set[str],
                    cve_pattern_tags: Set[str],
                    recently_changed: bool) -> None:
    """Compute the suspicion score in-place."""
    # Pull just the body lines (1-indexed inclusive).
    body_text = "\n".join(file_text_lines[entry.line_start - 1: entry.line_end])

    # Pattern hits
    for pat, category, weight in PATTERN_RULES:
        hits = len(pat.findall(body_text))
        if hits:
            entry.pattern_hits[category] = entry.pattern_hits.get(category, 0) + hits
            entry.suspicion_score += hits * weight
            entry.score_breakdown[category] = (
                entry.score_breakdown.get(category, 0) + hits * weight
            )

    # Recursive call to its own name (cheap proxy for unbounded recursion)
    own_calls = len(re.findall(r"\b" + re.escape(entry.name) + r"\s*\(", body_text))
    # Subtract 1 for the definition itself; the regex matched IT too if the
    # definition lives on line_start. To be safe, only count if >= 2.
    if own_calls >= 2:
        entry.pattern_hits["recursive_self_call"] = own_calls - 1
        entry.suspicion_score += 3
        entry.score_breakdown["recursive_self_call"] = 3

    # LOC weighting (long functions are more complex → +1 per 100 LOC)
    if entry.loc >= 100:
        bump = entry.loc // 100
        entry.suspicion_score += bump
        entry.score_breakdown["large_function"] = bump

    # CVE hotspot cross-reference
    if entry.file in cve_hotspot_files or entry.file.endswith("/" + next(iter(cve_hotspot_files), "")):
        for hot_file in cve_hotspot_files:
            if entry.file.endswith(hot_file) or entry.file == hot_file:
                entry.cve_hotspot_match = True
                entry.suspicion_score += 5
                entry.score_breakdown["cve_hotspot_file"] = 5
                break
    if entry.name in cve_hotspot_functions:
        entry.cve_hotspot_match = True
        entry.suspicion_score += 10
        entry.score_breakdown["cve_hotspot_function"] = 10
        entry.cve_pattern_hints = sorted(cve_pattern_tags)

    # Recent change weight
    if recently_changed:
        entry.file_recently_changed = True
        entry.suspicion_score += 3
        entry.score_breakdown["recently_changed"] = 3


def _recently_changed_files(target_root: Path, days: int = 30) -> Set[str]:
    """Return absolute paths of source files modified in `target_root` within
    the last `days` according to git log. Empty set if not a git repo."""
    try:
        # `git -C <root> log --since=<days> --name-only --pretty=format:`
        out = subprocess.check_output(
            ["git", "-C", str(target_root), "log",
             f"--since={days}.days.ago", "--name-only", "--pretty=format:"],
            stderr=subprocess.DEVNULL, timeout=10,
        ).decode("utf-8", errors="replace")
    except Exception:
        return set()
    files = {ln.strip() for ln in out.splitlines() if ln.strip()}
    # Convert to absolute paths so we can compare against function-entry file
    return {str(target_root / f) for f in files}


def _load_cve_hotspots(cve_context_path: Optional[Path]) -> Tuple[Set[str], Set[str], Set[str]]:
    """Return (hotspot_files, hotspot_functions, pattern_tags). Empty sets when
    the CVE context is missing."""
    if not cve_context_path or not cve_context_path.exists():
        return set(), set(), set()
    try:
        with cve_context_path.open() as f:
            doc = json.load(f)
    except Exception:
        return set(), set(), set()
    hotspots = doc.get("hotspots") or {}
    files = {(h.get("path") or "") for h in (hotspots.get("by_file") or []) if h.get("path")}
    funcs = {(h.get("name") or "") for h in (hotspots.get("by_function") or []) if h.get("name")}
    pat = set((doc.get("pattern_frequency") or {}).keys())
    return files, funcs, pat


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("--target-root", required=True,
                    help="Root directory of the target source.")
    ap.add_argument("--out", required=True,
                    help="Output JSON path.")
    ap.add_argument("--max-functions", type=int, default=50,
                    help="Top-N functions to surface in the candidates list (default 50).")
    ap.add_argument("--excluded-paths", default="",
                    help="Comma-separated path fragments to exclude (defaults union with built-ins).")
    ap.add_argument("--cve-context", default="",
                    help="Optional path to cve-context-<ts>.json for hotspot cross-ref.")
    args = ap.parse_args()

    target_root = Path(args.target_root).resolve()
    if not target_root.is_dir():
        print(f"ERROR: target-root not a directory: {target_root}", file=sys.stderr)
        return 2

    user_excludes = [e.strip() for e in args.excluded_paths.split(",") if e.strip()]
    excludes = sorted(set(DEFAULT_EXCLUDED + user_excludes))

    cve_files, cve_funcs, cve_pat_tags = _load_cve_hotspots(
        Path(args.cve_context) if args.cve_context else None
    )

    recent = _recently_changed_files(target_root, days=30)

    sources = _enumerate_sources(target_root, excludes)
    all_functions: List[FunctionEntry] = []
    loc_total = 0
    for src in sources:
        try:
            text = src.read_text(encoding="utf-8", errors="replace")
        except Exception:
            continue
        lines = text.splitlines()
        loc_total += len(lines)
        funcs = _inventory_functions(src, text)
        is_recent = str(src) in recent
        for entry in funcs:
            _score_function(entry, lines,
                            cve_hotspot_files=cve_files,
                            cve_hotspot_functions=cve_funcs,
                            cve_pattern_tags=cve_pat_tags,
                            recently_changed=is_recent)
            # Normalise file path to be relative to target_root for portability
            try:
                entry.file = str(Path(entry.file).resolve().relative_to(target_root))
            except Exception:
                pass
            all_functions.append(entry)

    # Sort by suspicion score descending; ties broken by LOC descending.
    all_functions.sort(key=lambda f: (-f.suspicion_score, -f.loc))
    top = all_functions[: args.max_functions]

    out = {
        "schema": "code-review-prescan/v1",
        "ts": int(time.time()),
        "target_root": str(target_root),
        "scope": {
            "files_scanned": len(sources),
            "functions_inventoried": len(all_functions),
            "loc_total": loc_total,
            "excluded_paths": excludes,
            "cve_context_consumed": str(args.cve_context) if args.cve_context else None,
            "recently_changed_files": len(recent),
        },
        "top_candidates": [f.to_dict() for f in top],
        # Full inventory is kept for transparency/audit but with NO score
        # breakdowns or pattern hits on the non-top entries (keeps the file
        # small — only top-N gets the rich annotation).
        "full_inventory_summary": [
            {"file": f.file, "name": f.name, "line_start": f.line_start,
             "loc": f.loc, "suspicion_score": f.suspicion_score}
            for f in all_functions
        ],
    }

    out_path = Path(args.out)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    tmp = out_path.with_suffix(out_path.suffix + ".tmp")
    with tmp.open("w") as f:
        json.dump(out, f, indent=2)
        f.write("\n")
    tmp.replace(out_path)

    print(out_path)
    return 0


if __name__ == "__main__":
    sys.exit(main())
