#!/usr/bin/env python3
"""cve-patterns.py — rule-based pattern tagger for parsed CVE artifacts.

Takes a parsed patch diff (from cve-sources.py) and/or the CVE description
text and emits structured tags:

  - patch_idiom: what the fix LOOKS LIKE (bounds_check_added, null_check_added,
                 size_overflow_guard, ...)
  - bug_class:   what the bug IS (oob_write, oob_read, uaf, int_overflow, ...)
  - cwe:         best-guess CWE id (CWE-787, CWE-125, ...)

Deterministic rules only — regex over diff lines and description text. No
LLM. The output is conservative on purpose: a missed tag is fine, a wrong
tag would mislead downstream agents.

CLI:
    python3 cve-patterns.py < diff.patch
    python3 cve-patterns.py --description "OOB write in xmlParseDoc..." < diff.patch
"""
from __future__ import annotations
import argparse
import json
import re
import sys
from dataclasses import dataclass, asdict, field
from typing import List, Optional, Set, Tuple


# ---------------------------------------------------------------------------
# Tag taxonomy
# ---------------------------------------------------------------------------

@dataclass
class PatternHit:
    pattern: str                   # idiom name, e.g. "bounds_check_added"
    bug_class: Optional[str] = None    # e.g. "oob_write"
    cwe: Optional[str] = None      # e.g. "CWE-787"
    evidence: str = ""             # truncated matched line
    source: str = "diff"           # "diff" | "description"

    def to_dict(self) -> dict:
        return {k: v for k, v in asdict(self).items() if v is not None and v != ""}


@dataclass
class TagSet:
    bug_classes: Set[str] = field(default_factory=set)
    cwes: Set[str] = field(default_factory=set)
    patch_idioms: Set[str] = field(default_factory=set)
    hits: List[PatternHit] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "bug_classes": sorted(self.bug_classes),
            "cwes": sorted(self.cwes),
            "patch_idioms": sorted(self.patch_idioms),
            "hits": [h.to_dict() for h in self.hits],
        }


# ---------------------------------------------------------------------------
# Rule tables
# ---------------------------------------------------------------------------

# Each diff rule: regex over a `+` line, idiom name, bug_class, cwe.
# Patterns are intentionally conservative — better to miss a tag than to
# mislabel one. If the rule fires on too many false positives, the downstream
# agents lose trust in the tag.
_DIFF_RULES: List[Tuple[re.Pattern, str, Optional[str], Optional[str]]] = [
    # bounds_check_added: `+if (x >= n)` / `+if (x < bound)` style
    (re.compile(r"^\+\s*if\s*\(\s*[A-Za-z_][\w\->.]*\s*[<>]=?\s*[\w\->.()]+\s*\)\s*\{?\s*(?:return|goto|break)?\s*"),
     "bounds_check_added", "oob_write", "CWE-787"),

    # null_check_added: `+if (!p)` / `+if (p == NULL)`
    (re.compile(r"^\+\s*if\s*\(\s*(?:!\s*[A-Za-z_]\w*|[A-Za-z_]\w*\s*==\s*NULL)\s*\)"),
     "null_check_added", "null_deref", "CWE-476"),

    # size_overflow_guard: SIZE_MAX, __builtin_*_overflow, INT_MAX, UINT_MAX
    (re.compile(r"^\+.*(?:SIZE_MAX|__builtin_[a-z]+_overflow|UINT_MAX|INT_MAX|SSIZE_MAX|U?INT(?:8|16|32|64)_MAX)"),
     "size_overflow_guard", "int_overflow", "CWE-190"),

    # memcpy_to_memmove: -memcpy +memmove (overlapping copy fix)
    (re.compile(r"^\-.*\bmemcpy\s*\("),
     "memcpy_to_memmove_candidate", None, None),
    (re.compile(r"^\+.*\bmemmove\s*\("),
     "memcpy_to_memmove_candidate", None, None),

    # format_string_fix: -printf(var)  +printf("%s", var)
    (re.compile(r"^\+.*(?:printf|fprintf|snprintf|sprintf)\s*\(\s*[^\"]*\"%s\""),
     "format_string_fix", "format_string", "CWE-134"),

    # ref_count_fix: changes around _ref/_unref/get/put
    (re.compile(r"^[-+].*(?:_ref\s*\(|_unref\s*\(|g_object_(?:ref|unref)\s*\(|put_(?:page|user)\s*\()"),
     "ref_count_fix", "uaf", "CWE-416"),

    # double_free_fix: explicitly nullifying a pointer after free
    (re.compile(r"^\+\s*(?:[A-Za-z_]\w*->)?\w+\s*=\s*NULL\s*;"),
     "post_free_null_assignment", "double_free", "CWE-415"),

    # use_after_free flag: adding a check before deref of recently-freed
    (re.compile(r"^\+\s*(?:if|while)\s*\(.*\)\s*(?:break|goto|return).*\b(?:freed|use_after_free|stale)"),
     "use_after_free_guard", "uaf", "CWE-416"),

    # integer signedness fix: changes int → size_t or unsigned int on a size variable
    (re.compile(r"^\-\s*(?:int|long)\s+[A-Za-z_]\w*(?:size|len|count|n)\b"),
     "signedness_fix_candidate", "int_overflow", "CWE-190"),
    (re.compile(r"^\+\s*(?:size_t|unsigned\s+int|uint(?:8|16|32|64)_t)\s+[A-Za-z_]\w*(?:size|len|count|n)\b"),
     "signedness_fix_candidate", "int_overflow", "CWE-190"),

    # type_check_added: discriminator before downcast
    (re.compile(r"^\+\s*if\s*\(\s*[A-Za-z_]\w*->(?:type|kind|tag)\s*[!=]=\s*[A-Z_]\w*\s*\)"),
     "type_check_added", "type_confusion", "CWE-843"),

    # lock_added: thread-safety guard
    (re.compile(r"^\+.*(?:mutex_lock|spin_lock|pthread_mutex_lock|g_mutex_lock|down_(?:read|write))\s*\("),
     "lock_added", "race", "CWE-362"),
]


# Description rules: tag bug class from human-readable CVE description.
# These run BEFORE diff rules so the diff-side rules can sharpen with bug-
# class context. We use case-insensitive matches with explicit phrasings.
_DESC_RULES: List[Tuple[re.Pattern, str, str]] = [
    (re.compile(r"out[- ]of[- ]bounds?\s+write|OOB\s+write|heap[- ]buffer[- ]overflow", re.I),
     "oob_write", "CWE-787"),
    (re.compile(r"out[- ]of[- ]bounds?\s+read|OOB\s+read", re.I),
     "oob_read", "CWE-125"),
    (re.compile(r"stack[- ]based\s+buffer\s+overflow|stack\s+overflow", re.I),
     "stack_overflow", "CWE-121"),
    (re.compile(r"use[- ]after[- ]free|\bUAF\b", re.I),
     "uaf", "CWE-416"),
    (re.compile(r"double[- ]free", re.I),
     "double_free", "CWE-415"),
    (re.compile(r"null\s+pointer\s+dereference|NULL\s+deref(?:erence)?", re.I),
     "null_deref", "CWE-476"),
    (re.compile(r"integer\s+overflow|integer\s+underflow", re.I),
     "int_overflow", "CWE-190"),
    (re.compile(r"format[- ]string\s+(?:vulnerability|bug|issue)", re.I),
     "format_string", "CWE-134"),
    (re.compile(r"type\s+confusion", re.I),
     "type_confusion", "CWE-843"),
    (re.compile(r"race\s+condition|TOCTOU|time[- ]of[- ]check", re.I),
     "race", "CWE-362"),
    (re.compile(r"uninitialized\s+(?:memory\s+)?(?:read|use)", re.I),
     "uninit_read", "CWE-908"),
    (re.compile(r"division\s+by\s+zero|divide[- ]by[- ]zero", re.I),
     "divide_by_zero", "CWE-369"),
    (re.compile(r"infinite\s+(?:loop|recursion)", re.I),
     "infinite_loop", "CWE-835"),
]


# ---------------------------------------------------------------------------
# Tag inference
# ---------------------------------------------------------------------------

def tag_description(description: str) -> TagSet:
    """Extract bug-class tags from a CVE description string."""
    ts = TagSet()
    if not description:
        return ts
    for pat, bug_class, cwe in _DESC_RULES:
        m = pat.search(description)
        if m:
            ts.bug_classes.add(bug_class)
            ts.cwes.add(cwe)
            ts.hits.append(PatternHit(
                pattern=bug_class, bug_class=bug_class, cwe=cwe,
                evidence=description[max(0, m.start() - 20):m.end() + 40][:160],
                source="description",
            ))
    return ts


def tag_diff(diff_text: str) -> TagSet:
    """Extract patch-idiom + bug-class tags from a unified diff string."""
    ts = TagSet()
    if not diff_text:
        return ts
    seen_idioms: Set[str] = set()
    for line in diff_text.splitlines():
        # Skip diff headers; only inspect actual hunk lines.
        if line.startswith(("diff --git", "index ", "---", "+++ ", "@@", "Subject:", "From ")):
            continue
        for pat, idiom, bug_class, cwe in _DIFF_RULES:
            if pat.search(line):
                ts.patch_idioms.add(idiom)
                if bug_class:
                    ts.bug_classes.add(bug_class)
                if cwe:
                    ts.cwes.add(cwe)
                # Record first hit per idiom only (avoid evidence floods)
                if idiom not in seen_idioms:
                    seen_idioms.add(idiom)
                    ts.hits.append(PatternHit(
                        pattern=idiom, bug_class=bug_class, cwe=cwe,
                        evidence=line[:160], source="diff",
                    ))
    return ts


def tag_combined(diff_text: str, description: str) -> TagSet:
    """Combined: description tags first (broad), diff tags refine (specific)."""
    desc = tag_description(description)
    diff = tag_diff(diff_text)
    out = TagSet()
    out.bug_classes  = desc.bug_classes  | diff.bug_classes
    out.cwes         = desc.cwes         | diff.cwes
    out.patch_idioms = diff.patch_idioms  # idioms only come from diffs
    out.hits         = desc.hits + diff.hits
    return out


# ---------------------------------------------------------------------------
# Pattern-driven guidance tables
#
# Rule-based suggestions per bug-class. cve-context-builder uses these to
# emit a human/LLM-readable guidance document. The intent is to inform seed
# generation and gap analysis — NOT to detect "these CVEs are present in the
# target." We document the PATTERN that historically caused vulns here so the
# fuzzer can probe similar pattern space for NEW bugs.
# ---------------------------------------------------------------------------

SEED_STRATEGIES = {
    "oob_write": [
        "Length fields near INT_MAX, UINT_MAX, SIZE_MAX, and 2^31-1.",
        "Negative length fields cast to unsigned (e.g. -1, INT_MIN as size_t).",
        "Length fields equal to buffer size + 1 (classic off-by-one).",
        "Truncated inputs where the declared length exceeds the actual bytes.",
        "Nested structures where a child claims a larger size than its parent.",
    ],
    "oob_read": [
        "Length fields slightly larger than the actual buffer length.",
        "Index fields near 0 (off-by-one before the start of an array).",
        "Strings without null terminators where the API expects C strings.",
        "Format strings with more conversion specifiers than provided args.",
        "Truncated TLV records where the length field promises bytes that aren't there.",
    ],
    "stack_overflow": [
        "Deeply nested structures (recursive grammars: nested XML elements, nested S-expressions).",
        "Inputs that trigger pathological recursion in the parser.",
        "Inputs whose stack-allocated buffers are sized from untrusted length fields.",
    ],
    "uaf": [
        "Operations that reuse a freed handle in a subsequent call sequence.",
        "Reference-count manipulation: extra unref, missing ref pairs.",
        "Container modification during iteration (invalidates iterators or callbacks).",
        "Error paths that free an object the success path also frees.",
    ],
    "double_free": [
        "Operations that call _free / _destroy twice on the same object.",
        "Error branches that converge with the success path after each has run cleanup.",
        "Reset / clear operations followed by destroy.",
    ],
    "null_deref": [
        "Empty / zero-length inputs.",
        "Inputs that satisfy length checks but lack required fields.",
        "Inputs that trigger allocation failures (request sizes near memory limits).",
        "Optional fields that downstream code unconditionally dereferences.",
    ],
    "int_overflow": [
        "Length × element-size combinations that overflow size_t.",
        "Sum of multiple length fields that exceeds INT_MAX.",
        "Negative deltas in offset arithmetic.",
        "Multiplication of attacker-controlled count by a stride constant.",
        "Implicit signed → unsigned conversions on user-provided lengths.",
    ],
    "format_string": [
        "Inputs containing %s, %x, %n in fields that are later used as format strings.",
        "Inputs with many %s converters to crash on the missing-args path.",
    ],
    "type_confusion": [
        "Type-tag fields set to unexpected discriminators.",
        "Polymorphic objects with mismatched type/payload combinations.",
        "Records that switch type mid-parse.",
    ],
    "race": [
        "Concurrent operations on shared state (usually not directly fuzz-reachable; flag for harness review).",
    ],
    "uninit_read": [
        "Partially-initialised structures (set some fields, leave others zero).",
        "Branches that bypass the standard init path.",
        "calloc → malloc swaps that miss zero-init expectations.",
    ],
    "divide_by_zero": [
        "Inputs that make a denominator zero (count = 0, size = 0, total = 0).",
    ],
    "infinite_loop": [
        "Self-referential structures (cycles in linked lists, parent-child loops).",
        "Inputs that make a loop's terminating condition unreachable.",
        "Pathological grammars with productions that never reduce input length.",
    ],
}

COVERAGE_TARGET_HINTS = {
    "oob_write":      "Length-arithmetic sites (memcpy, memmove, strcpy, indexed writes); loop bounds derived from input bytes.",
    "oob_read":       "Strings / buffers without explicit bound checks; format-parsing loops; nul-terminator assumptions.",
    "stack_overflow": "Recursive parsers; stack-allocated buffers sized from input.",
    "uaf":            "Reference-count paths (_ref / _unref / put_*); object lifetime boundaries; container resize.",
    "double_free":    "Cleanup paths in error branches; goto-based unwind; reset followed by destroy.",
    "null_deref":     "Pointer-returning APIs at error-path edges; allocator return checks; optional-field deref sites.",
    "int_overflow":   "Size calculations involving input-derived lengths; arithmetic on counters; type narrowing.",
    "format_string":  "printf-family calls where the format string is non-literal.",
    "type_confusion": "Downcast sites; tag-based dispatch; union-like discriminator reads.",
    "race":           "Locking primitives; shared resource access; refcount + free ordering.",
    "uninit_read":    "Struct init paths; calloc vs malloc decisions; partial-write branches.",
    "divide_by_zero": "Arithmetic on user-derived denominators (counts, sizes, totals).",
    "infinite_loop":  "Loop termination conditions derived from input; recursion depth checks.",
}


def render_guidance(per_cve: list, aggregate: dict, target: str) -> str:
    """Render the CVE-pattern guidance markdown.

    Intended for both human readers and downstream LLM agents (seed-generator,
    campaign-planner, coverage-analyst, mutator). The document is explicitly
    PATTERN guidance, NOT a presence-check.
    """
    fetch = aggregate.get("fetch_stats") or {}
    total = int(fetch.get("total", 0) or 0)
    parsed = int(fetch.get("parsed", 0) or 0)
    with_poc = int(fetch.get("with_poc", 0) or 0)
    days_since = aggregate.get("time_since_last_high_cve_days")
    pat_freq = aggregate.get("pattern_frequency") or {}
    idioms = aggregate.get("patch_idioms") or []
    hotspots = aggregate.get("hotspots") or {}

    by_class: dict = {}
    for cve in per_cve:
        for cls in (cve.get("tags") or []):
            by_class.setdefault(cls, []).append(cve)

    out: list = []
    header_recency = (f"Last HIGH/CRITICAL CVE: {days_since} days ago." if days_since is not None else "")
    out.append(f"# CVE pattern guidance for `{target}`")
    out.append("")
    out.append(f"Generated from **{total}** CVEs found in NVD ({parsed} with parsed patches; {with_poc} with PoCs). " + header_recency)
    out.append("")
    out.append("**This document is PATTERN guidance, not a presence check.** It describes the kinds of bugs the target has historically had and the seed-shape ideas a fuzzer should explore to find **NEW** bugs in the same pattern space. None of the listed CVEs are claimed to be present in the current codebase — they're studied to extract the failure modes worth probing.")
    out.append("")
    out.append("Audience: `seed-generator`, `campaign-planner`, `coverage-analyst`, `mutator`, and the user.")
    out.append("")

    # Top patterns
    out.append("## Top patterns by frequency")
    out.append("")
    if not pat_freq:
        out.append("_No patterns extracted from this CVE set. Either the patches were unparseable or the descriptions did not match any rule. The seed-generator should fall back to format-only reasoning._")
        out.append("")
    else:
        ranked = sorted(pat_freq.items(), key=lambda kv: -kv[1])[:8]
        for cls, freq in ranked:
            out.append(f"### `{cls}` — {freq} historical occurrence(s)")
            out.append("")
            # Aggregate locations from per-CVE patches
            loc_counter: dict = {}
            example_cves: list = []
            for cve in by_class.get(cls, []):
                if len(example_cves) < 5:
                    desc = (cve.get("description_summary") or "")[:180]
                    cwe = cve.get("cwe_id") or ""
                    example_cves.append((cve.get("id"), cwe, desc))
                for p in (cve.get("patches") or []):
                    files = p.get("files_changed") or [None]
                    funcs = p.get("functions_changed") or [None]
                    for fp in files:
                        for fn in funcs:
                            if fn is None and fp is None:
                                continue
                            key = f"{fp}::{fn}" if (fp and fn) else (fp or fn or "?")
                            loc_counter[key] = loc_counter.get(key, 0) + 1
            if loc_counter:
                top_locs = sorted(loc_counter.items(), key=lambda kv: -kv[1])[:5]
                out.append("**Historically appeared at**: " + ", ".join(f"`{loc}` ({c}×)" for loc, c in top_locs) + ".")
                out.append("")
            class_cve_ids = {c.get("id") for c in by_class.get(cls, [])}
            class_idioms = [i for i in idioms if class_cve_ids & set(i.get("example_cves") or [])]
            if class_idioms:
                out.append("**Patch idioms in fixes for this pattern**:")
                for idiom in class_idioms[:5]:
                    out.append(f"- `{idiom.get('pattern')}` ({idiom.get('count', 0)} fix(es))")
                out.append("")
            if example_cves:
                out.append("**Representative CVEs**:")
                for cid, cwe, desc in example_cves:
                    cwe_str = f" [{cwe}]" if cwe else ""
                    out.append(f"- `{cid}`{cwe_str} — {desc}")
                out.append("")
            strategies = SEED_STRATEGIES.get(cls)
            if strategies:
                out.append("**Seed strategies for probing this pattern in NEW code**:")
                for s in strategies:
                    out.append(f"- {s}")
                out.append("")
            cov_hint = COVERAGE_TARGET_HINTS.get(cls)
            if cov_hint:
                out.append(f"**Coverage targets**: {cov_hint}")
                out.append("")

    # Hotspots
    out.append("## Hotspot locations")
    out.append("")
    by_file = hotspots.get("by_file") or []
    if not by_file:
        out.append("_No hotspots — CVEs were not concentrated in any one file._")
        out.append("")
    else:
        for spot in by_file[:8]:
            path = spot.get("path", "?")
            count = spot.get("cve_count", 0)
            top_fns = spot.get("top_funcs") or []
            out.append(f"### `{path}` — {count} CVE(s)")
            out.append("")
            if top_fns:
                out.append("**Top affected functions**: " + ", ".join(f"`{fn}`" for fn in top_fns[:5]) + ".")
                out.append("")
            file_classes: dict = {}
            for cve in per_cve:
                for p in (cve.get("patches") or []):
                    if path in (p.get("files_changed") or []):
                        for cls in (cve.get("tags") or []):
                            file_classes[cls] = file_classes.get(cls, 0) + 1
            if file_classes:
                rank = sorted(file_classes.items(), key=lambda kv: -kv[1])[:5]
                out.append("**Pattern mix here**: " + ", ".join(f"`{cls}` ({c})" for cls, c in rank) + ".")
                out.append("")
            out.append("**Why this matters**: a function name recurring across multiple CVEs is a region where the parsing / decoding / state-machine logic is dense and historically error-prone. The campaign's `## Coverage Targets` should call these out and the seed-generator should bias toward inputs that exercise these entry paths.")
            out.append("")

    # PoCs cross-reference
    pocs = [c for c in per_cve if (c.get("poc") or {}).get("available")]
    if pocs:
        out.append("## Reference PoCs cached for this campaign")
        out.append("")
        out.append("Retrieved from trusted sources (Tier A: same-repo regression tests; Tier B: recognised security-org advisories). Tier A blobs have been auto-promoted to `fuzz/corpus/cve_<id>.<ext>`; Tier B material is retained as reference only.")
        out.append("")
        for c in pocs[:20]:
            cid = c.get("id")
            tier = (c.get("poc") or {}).get("tier")
            kind = (c.get("poc") or {}).get("kind")
            promoted = (c.get("poc") or {}).get("promoted_to_corpus")
            note = " (auto-promoted to corpus)" if promoted else " (retained as reference)"
            out.append(f"- `{cid}` — Tier {tier} {kind}{note}")
        out.append("")

    out.append("## How agents should use this document")
    out.append("")
    out.append("- **`seed-generator`** reads each top-pattern section's *Seed strategies* and synthesises target-specific inputs that exercise those patterns through the harness's documented input format. The strategies are GENERIC; the seed-generator's job is to translate them into bytes the target's parser will actually consume.")
    out.append("- **`campaign-planner`** uses *Hotspot locations* and *Top patterns* to populate `plan.md`'s `## Coverage Targets` and `## Mutator Notes`. It does NOT copy this document verbatim; it references the relevant excerpts.")
    out.append("- **`coverage-analyst`** tags gaps in hotspot regions as `cve_hotspot` (a priority signal). The `hint` field on each gap should cite this document's pattern data.")
    out.append("- **`mutator`** (when invoked) reads the patch-idiom rollups to understand what kinds of fixes the maintainer has historically shipped — that's the mirror image of the violations the fuzzer should produce.")
    out.append("")
    out.append("**None of these consumers should treat this document as a list of bugs to verify exist.** The patterns guide where to LOOK for new bugs; the historical CVEs guide WHAT to look for.")
    out.append("")
    return "\n".join(out)


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("--description", default="", help="CVE description text")
    ap.add_argument("--diff-only", action="store_true",
                    help="Tag the diff (stdin) only, skip description")
    ap.add_argument("--desc-only", action="store_true",
                    help="Tag the description only, no diff read")
    args = ap.parse_args()

    if args.desc_only:
        ts = tag_description(args.description)
    elif args.diff_only:
        ts = tag_diff(sys.stdin.read())
    else:
        ts = tag_combined(sys.stdin.read(), args.description)

    print(json.dumps(ts.to_dict(), indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main())
