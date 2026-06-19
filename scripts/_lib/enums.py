#!/usr/bin/env python3
"""enums.py — single source of truth (SSOT) for every cc-fuzzer state enum.

Before this module the enum vocabularies were copy-pasted across Python
heredocs, _lib modules, and bash `case` statements, and they had drifted: a
`status == "promoted"` reader vs a `status == "finding"` writer, a bash `add`
that validated only the logic-category subset, an impact gate that mixed
oracle_kind values with pattern tokens. This module is the one place every enum
is defined; consumers import the frozensets/maps (Python) or shell out to the
CLI (bash) so they can never drift again.

Two interfaces, one definition:

  Python:  from enums import CATEGORIES, EXPLOITABILITY, ...
           (consumers use the project's _LIB_DIR / sys.path.insert pattern,
            same as cve-context-builder.py imports its siblings.)

  CLI:     python3 enums.py print <name> [--sep <s>]   # members, newline-sep
           python3 enums.py check <name> <value>       # exit 0 if member else 1

`<name>` is case-insensitive and accepts either the canonical UPPER_SNAKE name
or a lowercased alias (e.g. `categories`, `CATEGORIES`). The CLI is
dependency-free and does no I/O beyond argv/stdout, so it is cheap to call —
but callers on a hot path should fetch members ONCE into a variable, not invoke
per loop iteration.
"""
from __future__ import annotations
import os
import sys

# ---------------------------------------------------------------------------
# Finding categories (findings.jsonl `category`)
# ---------------------------------------------------------------------------
# Crash classes: memory-safety + the sanitizer-shaped DoS classes. `ubsan-<kind>`
# is validated by prefix, not membership, so it is NOT listed here.
CATEGORIES_CRASH = frozenset({
    "heap-buffer-overflow", "heap-use-after-free", "stack-buffer-overflow",
    "global-buffer-overflow", "stack-overflow", "null-deref",
    "assertion-failure", "oom", "timeout", "flaky", "harness-artifact",
})
# Logic classes: oracle-driven findings (oracle_type != crash, carry divergence).
CATEGORIES_LOGIC = frozenset({
    "invariant-violation", "roundtrip-mismatch", "differential-divergence",
    "parser-differential", "auth-bypass", "access-control",
    "incorrect-validation", "canonicalization", "state-confusion",
    "integer-truncation", "logic-error",
})
CATEGORIES = CATEGORIES_CRASH | CATEGORIES_LOGIC

# ---------------------------------------------------------------------------
# Exploitability (findings.jsonl `exploitability`)
# ---------------------------------------------------------------------------
EXPLOITABILITY = frozenset({"likely", "medium", "unlikely", "harness-artifact"})

# ---------------------------------------------------------------------------
# Lifecycle / provenance
# ---------------------------------------------------------------------------
# findings.jsonl `status` for crash-sourced findings (the ledger lifecycle).
FINDING_STATUS = frozenset({"candidate", "finding", "stale"})
# code-review/v1 finding `status` (the cr lifecycle, see code-reviewer.md).
CR_STATUS = frozenset({"candidate", "triaging", "confirmed", "poc", "dismissed"})
# findings.jsonl `source`.
FINDING_SOURCE = frozenset({"crash", "code_review"})
# code-review/v1 `confidence`. needs_deep_pass is NOT a confidence value — it is
# a separate boolean flag (see HARNESS .md fix); every finding has a real
# confidence so it stays importable.
CONFIDENCE = frozenset({"high", "medium", "low"})

# ---------------------------------------------------------------------------
# Oracle vocabulary
# ---------------------------------------------------------------------------
ORACLE_TYPE = frozenset({"crash", "invariant", "roundtrip", "differential", "metamorphic"})
ORACLE_KIND = frozenset({
    "memory", "authorization", "integrity", "info_disclosure",
    "state_confusion", "logic_other",
})

# oracle_kind values that, on an OPEN candidate, justify spending an
# impact_review (Opus deep pass) lever. Judgment call: include the kinds whose
# impact crosses a privilege/trust boundary and is therefore worth Opus
# reachability analysis to prove portable impact — authorization, integrity,
# info_disclosure, state_confusion. EXCLUDED:
#   - memory: already sanitizer-provable; the crash itself is the impact and the
#     normal triage/poc path covers it, so it doesn't need the impact lever.
#   - logic_other: catch-all with no clear boundary mapping (roundtrip /
#     differential / canonicalization with "no clear boundary"); not inherently
#     high-impact, so it shouldn't burn the Opus lever by default.
HIGH_IMPACT_ORACLE_KINDS = frozenset({
    "authorization", "integrity", "info_disclosure", "state_confusion",
})
# When the impact gate also wants to look at `category` (the findings.jsonl
# vocabulary, hyphenated) rather than oracle_kind, match against THESE — the
# real category values whose impact crosses a boundary. Kept separate from
# HIGH_IMPACT_ORACLE_KINDS because the two vocabularies differ (underscore vs
# hyphen; oracle_kind is coarser than category).
HIGH_IMPACT_CATEGORIES = frozenset({
    "auth-bypass", "access-control", "incorrect-validation",
    "canonicalization", "state-confusion",
})

# ---------------------------------------------------------------------------
# code-review/v1 `pattern` vocabulary and its mapping to findings categories.
# Moved here out of findings_ops.py _cr_to_category. The cr pattern vocabulary
# (cve-patterns.md bug classes + the logic classes) overlaps the category enum
# but is not identical; anything unrecognized maps to logic-error so import-cr
# never produces an invalid category.
# ---------------------------------------------------------------------------
_CR_CRASH_MAP = {
    "oob_write": "heap-buffer-overflow",
    "oob_read": "heap-buffer-overflow",
    "stack_overflow": "stack-overflow",
    "uaf": "heap-use-after-free",
    "double_free": "heap-use-after-free",
    "null_deref": "null-deref",
    "int_overflow": "integer-truncation",
    "divide_by_zero": "assertion-failure",
    "infinite_loop": "timeout",
}
_CR_LOGIC_MAP = {
    "auth_bypass": "auth-bypass",
    "access_control": "access-control",
    "incorrect_validation": "incorrect-validation",
    "missing_validation": "incorrect-validation",
    "canonicalization": "canonicalization",
    "state_confusion": "state-confusion",
    "toctou_logic": "state-confusion",
    "integer_truncation": "integer-truncation",
    "signedness_logic": "integer-truncation",
    "parser_differential": "parser-differential",
    "roundtrip_mismatch": "roundtrip-mismatch",
    "error_path": "logic-error",
}
CR_TO_CATEGORY = {**_CR_CRASH_MAP, **_CR_LOGIC_MAP}
CR_PATTERN_CLASSES = frozenset(CR_TO_CATEGORY.keys())


def cr_to_category(pattern):
    """Map a code-review/v1 `pattern` to a findings.jsonl `category`.

    Unrecognized patterns fall back to `logic-error` so the import never
    produces an invalid category (findings.sh re-validates against CATEGORIES).
    """
    return CR_TO_CATEGORY.get(pattern, "logic-error")

# ---------------------------------------------------------------------------
# current.json recommendation.branch — the per-tick action selector.
# Reconciled across the two current.json builders and validate-state.sh.
# ---------------------------------------------------------------------------
REC_BRANCHES = frozenset({
    "sleep", "restart_fuzzer", "fix_instrumentation", "triage",
    "analyze_gaps", "reanalyze_gaps", "generate_seeds", "concolic",
    "mutator", "stop",
})

# ---------------------------------------------------------------------------
# gaps-report/v1 gap `reason` (why a path is uncovered).
# ---------------------------------------------------------------------------
GAP_REASONS = frozenset({
    "checksum_barrier", "deep_path_condition", "magic_value",
    "unreached_function", "format_invariant", "resource_guard",
})

# Specialist agent a gap recommends (gaps-report `recommended_agent`).
HARNESS_ACTIONS = frozenset({
    "harness-writer", "seed-generator", "concolic-executor", "mutator",
    "coverage-analyst",
})

# ---------------------------------------------------------------------------
# Fuzzing engines.
# ---------------------------------------------------------------------------
ENGINES = frozenset({"libfuzzer", "aflpp"})

# ---------------------------------------------------------------------------
# YOLO self-loop directive verbs (yolo-route.sh / yolo_evaluate.py).
# ---------------------------------------------------------------------------
YOLO_VERBS = frozenset({
    "dispatch", "run", "schedule", "orchestrator", "halt", "done", "inactive",
})

# ---------------------------------------------------------------------------
# code-reviewer-deep revisit lenses (revisit_passes tokens). The 8 lenses the
# impact_review lever cycles through so a revisit adopts an under-used angle.
# ---------------------------------------------------------------------------
CR_LENS_TOKENS = frozenset({
    "broad:invariant", "broad:stateful", "broad:trust_boundary",
    "broad:protocol", "broad:differential",
    "narrow:frontier", "narrow:near_confirmed", "narrow:fuzzer_stall",
})

# ---------------------------------------------------------------------------
# Snapshot filename prefixes (fuzz/state/snapshots/<prefix>-<ts>.json).
# ---------------------------------------------------------------------------
SNAPSHOT_PREFIXES = frozenset({
    "coverage-snapshot", "gaps-report", "concolic-result",
    "code-review-prescan", "code-review", "tick-coverage", "tick-briefing",
    "ceiling-probe", "planner-consult", "cve-context", "plan",
})


# ---------------------------------------------------------------------------
# Registry + CLI
# ---------------------------------------------------------------------------
_REGISTRY = {
    "categories": CATEGORIES,
    "categories_crash": CATEGORIES_CRASH,
    "categories_logic": CATEGORIES_LOGIC,
    "exploitability": EXPLOITABILITY,
    "finding_status": FINDING_STATUS,
    "cr_status": CR_STATUS,
    "finding_source": FINDING_SOURCE,
    "confidence": CONFIDENCE,
    "oracle_type": ORACLE_TYPE,
    "oracle_kind": ORACLE_KIND,
    "high_impact_oracle_kinds": HIGH_IMPACT_ORACLE_KINDS,
    "high_impact_categories": HIGH_IMPACT_CATEGORIES,
    "cr_pattern_classes": CR_PATTERN_CLASSES,
    "rec_branches": REC_BRANCHES,
    "gap_reasons": GAP_REASONS,
    "harness_actions": HARNESS_ACTIONS,
    "engines": ENGINES,
    "yolo_verbs": YOLO_VERBS,
    "cr_lens_tokens": CR_LENS_TOKENS,
    "snapshot_prefixes": SNAPSHOT_PREFIXES,
}


def _resolve(name):
    key = name.strip().lower()
    if key not in _REGISTRY:
        sys.stderr.write(
            "enums.py: unknown enum '%s'. Known: %s\n"
            % (name, ", ".join(sorted(_REGISTRY)))
        )
        return None
    return _REGISTRY[key]


# ---------------------------------------------------------------------------
# doc-drift: guard against STATE_SCHEMA.md's human-readable enum lists drifting
# out of sync with this module (the machine SSOT). Only the enums whose doc
# mirror is a single unambiguous inline pipe-list on a line that names exactly
# one `enums.py <NAME>` are checked — the prose-heavy lists (category, pattern,
# cr_status) intentionally interleave explanation and are skipped here. Edit
# `_DOC_MIRRORS` when a new clean single-line mirror is added.
# ---------------------------------------------------------------------------
# enum-key -> the UPPER_SNAKE name as it appears in the doc's "enums.py `NAME`" marker.
_DOC_MIRRORS = {
    "rec_branches": "REC_BRANCHES",
    "finding_status": "FINDING_STATUS",
    "oracle_type": "ORACLE_TYPE",
    "oracle_kind": "ORACLE_KIND",
}


def _doc_drift(path):
    """Compare STATE_SCHEMA.md's documented enum lists against the SSOT.

    Returns 0 if all checked enums agree (or their marker line isn't found —
    reported as a warning), 1 on any membership disagreement.
    """
    import re
    try:
        text = open(path, encoding="utf-8").read()
    except Exception as e:
        sys.stderr.write("enums.py doc-drift: cannot read %s: %s\n" % (path, e))
        return 2

    rc = 0
    for key, upper in _DOC_MIRRORS.items():
        members = _REGISTRY[key]
        # Find the single line that mentions `enums.py` `<NAME>`; pull the first
        # backticked `a | b | c` pipe-list on that line.
        marker = re.compile(r"`enums\.py`\s*`%s`" % re.escape(upper))
        found = None
        for line in text.splitlines():
            if marker.search(line):
                found = line
                break
        if found is None:
            sys.stderr.write("enums.py doc-drift: WARN no documented mirror for %s\n" % upper)
            continue
        m = re.search(r"`([a-z0-9_]+(?:\s*\|\s*[a-z0-9_]+)+)`", found)
        if not m:
            sys.stderr.write("enums.py doc-drift: WARN %s mirror line has no pipe-list\n" % upper)
            continue
        doc_set = {t.strip() for t in m.group(1).split("|") if t.strip()}
        if doc_set != set(members):
            rc = 1
            missing_in_doc = set(members) - doc_set
            extra_in_doc = doc_set - set(members)
            sys.stderr.write("enums.py doc-drift: %s DRIFT\n" % upper)
            if missing_in_doc:
                sys.stderr.write("    in enums.py but not in STATE_SCHEMA.md: %s\n" % sorted(missing_in_doc))
            if extra_in_doc:
                sys.stderr.write("    in STATE_SCHEMA.md but not in enums.py: %s\n" % sorted(extra_in_doc))
    if rc == 0:
        sys.stdout.write("enums.py doc-drift: OK (%d enums checked)\n" % len(_DOC_MIRRORS))
    return rc


def _main(argv):
    if len(argv) >= 1 and argv[0] == "doc-drift":
        path = argv[1] if len(argv) > 1 else os.path.join(
            os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))),
            "STATE_SCHEMA.md",
        )
        return _doc_drift(path)
    if len(argv) < 2:
        sys.stderr.write(
            "usage: enums.py print <name> [--sep <s>] | check <name> <value> | doc-drift [STATE_SCHEMA.md]\n"
        )
        return 2
    cmd = argv[0]
    name = argv[1]
    members = _resolve(name)
    if members is None:
        return 2
    if cmd == "print":
        sep = "\n"
        if "--sep" in argv:
            i = argv.index("--sep")
            if i + 1 < len(argv):
                sep = argv[i + 1]
        sys.stdout.write(sep.join(sorted(members)))
        if sep == "\n":
            sys.stdout.write("\n")
        return 0
    if cmd == "check":
        if len(argv) < 3:
            sys.stderr.write("usage: enums.py check <name> <value>\n")
            return 2
        return 0 if argv[2] in members else 1
    sys.stderr.write("enums.py: unknown command '%s'\n" % cmd)
    return 2


if __name__ == "__main__":
    sys.exit(_main(sys.argv[1:]))
