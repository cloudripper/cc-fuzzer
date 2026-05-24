#!/usr/bin/env python3
"""cve-sources.py — tiered parser registry for CVE reference URLs.

Maps each reference URL the NVD record carries to a parser that extracts a
normalised record. The orchestrator (cve-context-build.sh) walks every CVE's
references through this registry to populate the per-CVE parsed.json.

Tier 1 (deterministic): per-domain parsers. v0.18 ships GitHub + GitLab.
Tier 2 (generic fallback): URL + content snippet only.
Tier 3 (LLM-assisted): deferred to v0.19+.

Each parser receives (url, fetched_text_or_bytes) and returns a
ParsedReference. The orchestrator decides whether to call the parser at all
based on the URL host; this module's `dispatch()` runs that decision.

CLI:
    python3 cve-sources.py classify <url>          # what parser would run?
    python3 cve-sources.py fetch    <url>          # fetch + parse + emit JSON
    python3 cve-sources.py extract  <url> < file   # parse with provided text
"""
from __future__ import annotations
import json
import os
import re
import sys
import time
import urllib.error
import urllib.request
from dataclasses import dataclass, asdict, field
from typing import Callable, List, Optional, Tuple
from urllib.parse import urlparse


# ---------------------------------------------------------------------------
# Normalised record
# ---------------------------------------------------------------------------

@dataclass
class ParsedReference:
    url: str
    kind: str = "raw"                  # patch | advisory | raw | poc
    source: str = "raw"                # github | gitlab | raw
    title: str = ""
    summary: str = ""                  # one-paragraph human-readable
    commit_sha: Optional[str] = None
    repo: Optional[str] = None         # owner/repo
    files_changed: List[str] = field(default_factory=list)
    functions_changed: List[str] = field(default_factory=list)
    diff_excerpt: str = ""             # first ~800 chars of unified diff
    fix_pattern_hint: Optional[str] = None  # filled by cve-patterns.py later
    fetch_status: str = "ok"           # ok | error | skipped
    fetch_error: str = ""

    def to_dict(self) -> dict:
        d = asdict(self)
        # Drop empty/None to keep the JSON tight.
        return {k: v for k, v in d.items()
                if v not in (None, "", [], 0) or k in ("kind", "source", "url", "fetch_status")}


# ---------------------------------------------------------------------------
# Fetch helpers
# ---------------------------------------------------------------------------

USER_AGENT = "cc-fuzzer/0.18 cve-sources/1"
DEFAULT_TIMEOUT = 15  # seconds per request
MAX_FETCH_BYTES = 5 * 1024 * 1024  # hard cap on any single fetch (5 MB)


def _fetch(url: str, accept: str = "text/plain", token: Optional[str] = None) -> Tuple[str, str]:
    """Fetch a URL with a size cap and a sane UA. Returns (body, content_type).

    Raises urllib.error.HTTPError / URLError on transport failures.
    """
    req = urllib.request.Request(url, headers={
        "User-Agent": USER_AGENT,
        "Accept": accept,
    })
    if token:
        req.add_header("Authorization", f"Bearer {token}")
    with urllib.request.urlopen(req, timeout=DEFAULT_TIMEOUT) as resp:
        ct = resp.headers.get("Content-Type", "")
        # Read up to MAX_FETCH_BYTES + 1 so we can detect oversize.
        body = resp.read(MAX_FETCH_BYTES + 1)
        if len(body) > MAX_FETCH_BYTES:
            raise ValueError(f"fetch exceeds size cap ({MAX_FETCH_BYTES} bytes)")
    try:
        return body.decode("utf-8", errors="replace"), ct
    except Exception:
        return body.decode("latin-1", errors="replace"), ct


# ---------------------------------------------------------------------------
# Tier 1 parsers
# ---------------------------------------------------------------------------

# GitHub commit URLs:
#   https://github.com/<owner>/<repo>/commit/<sha>            (web view)
#   https://github.com/<owner>/<repo>/commit/<sha>.patch      (raw patch)
#   https://github.com/<owner>/<repo>/commit/<sha>.diff       (raw diff)
_RE_GITHUB_COMMIT = re.compile(
    r"^https?://github\.com/([^/]+)/([^/]+)/commit/([0-9a-f]{7,40})(?:\.(patch|diff))?(?:[?#].*)?$",
    re.IGNORECASE,
)

# GitLab commit URLs:
#   https://gitlab.com/<owner>/<repo>/-/commit/<sha>
#   https://gitlab.com/<owner>/<repo>/-/commit/<sha>.patch
_RE_GITLAB_COMMIT = re.compile(
    r"^https?://gitlab\.com/([^/]+)/([^/]+(?:/[^/]+)*)/-/commit/([0-9a-f]{7,40})(?:\.(patch|diff))?(?:[?#].*)?$",
    re.IGNORECASE,
)

# GitHub PR URLs:
#   https://github.com/<owner>/<repo>/pull/<n>
# We DON'T fetch these directly — they're not patches. We record them as raw.
# A future v0.19 enhancement could resolve PR → merge commit and recurse.


def _parse_unified_diff(text: str) -> Tuple[List[str], List[str]]:
    """Extract (files_changed, functions_changed) from a unified diff blob.

    files_changed comes from `diff --git a/path b/path` headers; only the
    'b/' (new) path is recorded.
    functions_changed comes from `@@ -... +... @@ <context>` markers where
    the trailing context resembles a C/C++ function signature.
    """
    files: List[str] = []
    funcs: List[str] = []
    for line in text.splitlines():
        if line.startswith("diff --git"):
            # Form: "diff --git a/foo/bar.c b/foo/bar.c"
            parts = line.split(" b/", 1)
            if len(parts) == 2:
                files.append(parts[1].strip())
        elif line.startswith("@@"):
            # Form: "@@ -10,7 +10,8 @@ static int foo(struct s *p)"
            # The trailing token after the second @@ is the function context.
            try:
                tail = line.split("@@", 2)[2].strip()
            except IndexError:
                continue
            if tail and len(tail) < 200:
                # Heuristic for "looks like a function name": contains a
                # `(` and at least one identifier-shape token before it.
                m = re.search(r"([A-Za-z_][A-Za-z0-9_:.]*)\s*\(", tail)
                if m:
                    name = m.group(1)
                    if name not in funcs:
                        funcs.append(name)
    # De-dupe files preserving order
    seen = set()
    dedup_files = []
    for f in files:
        if f not in seen:
            seen.add(f)
            dedup_files.append(f)
    return dedup_files, funcs


def parse_github_commit(url: str, text: str = "") -> ParsedReference:
    """Parse a GitHub commit URL.

    Idempotent: if `text` is non-empty it's used as the diff body; otherwise
    we append `.patch` to the canonical URL and fetch.
    """
    m = _RE_GITHUB_COMMIT.match(url)
    if not m:
        return ParsedReference(url=url, kind="raw", source="raw",
                               fetch_status="error",
                               fetch_error="github commit regex did not match")
    owner, repo, sha = m.group(1), m.group(2), m.group(3)
    suffix = m.group(4)  # 'patch' | 'diff' | None
    canonical = f"https://github.com/{owner}/{repo}/commit/{sha}.patch" if suffix != "patch" else url

    diff_text = text
    fetch_error = ""
    if not diff_text:
        try:
            token = os.environ.get(os.environ.get("CVE_GITHUB_TOKEN_ENV", "GITHUB_TOKEN"), "")
            diff_text, _ct = _fetch(canonical, accept="text/plain", token=token or None)
        except Exception as e:
            fetch_error = f"{type(e).__name__}: {e}"
            return ParsedReference(url=url, kind="raw", source="github",
                                   repo=f"{owner}/{repo}", commit_sha=sha,
                                   fetch_status="error", fetch_error=fetch_error)

    files, funcs = _parse_unified_diff(diff_text)
    excerpt = diff_text[:800]
    # Title: best-effort from the first `Subject:` header in the patch
    title = ""
    for line in diff_text.splitlines()[:20]:
        if line.startswith("Subject:"):
            title = line[len("Subject:"):].strip()
            break
    return ParsedReference(
        url=url, kind="patch", source="github",
        title=title, summary="", commit_sha=sha,
        repo=f"{owner}/{repo}",
        files_changed=files, functions_changed=funcs,
        diff_excerpt=excerpt, fetch_status="ok",
    )


def parse_gitlab_commit(url: str, text: str = "") -> ParsedReference:
    m = _RE_GITLAB_COMMIT.match(url)
    if not m:
        return ParsedReference(url=url, kind="raw", source="raw",
                               fetch_status="error",
                               fetch_error="gitlab commit regex did not match")
    owner, repo, sha = m.group(1), m.group(2), m.group(3)
    suffix = m.group(4)
    canonical = (f"https://gitlab.com/{owner}/{repo}/-/commit/{sha}.patch"
                 if suffix != "patch" else url)

    diff_text = text
    if not diff_text:
        try:
            diff_text, _ct = _fetch(canonical, accept="text/plain")
        except Exception as e:
            return ParsedReference(url=url, kind="raw", source="gitlab",
                                   repo=f"{owner}/{repo}", commit_sha=sha,
                                   fetch_status="error",
                                   fetch_error=f"{type(e).__name__}: {e}")

    files, funcs = _parse_unified_diff(diff_text)
    return ParsedReference(
        url=url, kind="patch", source="gitlab",
        title="", summary="", commit_sha=sha,
        repo=f"{owner}/{repo}",
        files_changed=files, functions_changed=funcs,
        diff_excerpt=diff_text[:800], fetch_status="ok",
    )


def parse_generic(url: str, text: str = "") -> ParsedReference:
    """Tier-2 fallback: record the URL and a short content snippet."""
    summary = (text or "")[:400].strip()
    return ParsedReference(url=url, kind="raw", source="raw",
                           summary=summary, fetch_status="ok" if text else "skipped")


# ---------------------------------------------------------------------------
# Dispatch
# ---------------------------------------------------------------------------

Parser = Callable[[str, str], ParsedReference]

REGISTRY: List[Tuple[re.Pattern, Parser, str]] = [
    (_RE_GITHUB_COMMIT, parse_github_commit, "github_commit"),
    (_RE_GITLAB_COMMIT, parse_gitlab_commit, "gitlab_commit"),
]


def classify(url: str) -> str:
    """Return the name of the parser that would handle this URL, or 'generic'."""
    for pat, _func, name in REGISTRY:
        if pat.match(url):
            return name
    return "generic"


def dispatch(url: str, text: str = "") -> ParsedReference:
    for pat, func, _name in REGISTRY:
        if pat.match(url):
            return func(url, text)
    return parse_generic(url, text)


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def main() -> int:
    if len(sys.argv) < 3:
        print("usage:\n"
              "  cve-sources.py classify <url>\n"
              "  cve-sources.py fetch    <url>\n"
              "  cve-sources.py extract  <url>   # read content from stdin\n",
              file=sys.stderr)
        return 2
    cmd, url = sys.argv[1], sys.argv[2]
    if cmd == "classify":
        print(classify(url))
        return 0
    if cmd == "fetch":
        rec = dispatch(url, text="")
        print(json.dumps(rec.to_dict(), indent=2))
        return 0
    if cmd == "extract":
        text = sys.stdin.read()
        rec = dispatch(url, text=text)
        print(json.dumps(rec.to_dict(), indent=2))
        return 0
    print(f"unknown command: {cmd}", file=sys.stderr)
    return 2


if __name__ == "__main__":
    sys.exit(main())
