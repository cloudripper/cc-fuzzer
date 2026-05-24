#!/usr/bin/env python3
"""cve-poc-trust.py — gate PoC URLs into trust tiers BEFORE any fetch.

PoC URLs in CVE references are a real attack surface. Hostile content can
exfiltrate credentials, compromise the analyst environment, or poison the
corpus. This evaluator classifies every URL into one of three tiers before
the orchestrator even thinks about downloading the content.

Tier A — auto-promote eligible (after check-seed-safety.sh):
    URL is in the SAME repo as the parsed patch, under a recognised
    test/regression/corpus/fuzz directory, with a data-blob extension.

Tier B — retain as reference, do not promote:
    URL host is in the recognised security-org allow-list. Content is a
    structured patch/advisory or a data blob.

Tier C — DO NOT download:
    Everything else. Gists, pastebins, exploit-db, random "PoC" repos,
    third-party security blogs. The fetch never happens.

Code files (any tier) are NEVER executed or imported. They are retained as
text reference material only.

CLI:
    python3 cve-poc-trust.py <url> [<patch-repo>]
    where <patch-repo> is the owner/repo string of the parsed patch (so we
    can decide whether the PoC URL is same-repo).

Output: JSON record with { tier, rationale, is_code, is_blob, host, path }.
Exit 0 always (classification is informational; the caller decides).
"""
from __future__ import annotations
import json
import sys
from dataclasses import dataclass, asdict
from typing import Optional
from urllib.parse import urlparse


# ---------------------------------------------------------------------------
# Allow-lists. Conservative on purpose.
# ---------------------------------------------------------------------------

# Same-repo hosts where Tier A is reachable IF the path qualifies.
SAME_REPO_HOSTS = {"github.com", "gitlab.com", "raw.githubusercontent.com"}

# Recognised security-org hosts for Tier B.
TIER_B_HOSTS = frozenset({
    "access.redhat.com",
    "bugzilla.redhat.com",
    "www.openssl.org", "openssl.org",
    "httpd.apache.org", "www.apache.org",
    "bugzilla.mozilla.org",
    "ubuntu.com", "usn.ubuntu.com",
    "lore.kernel.org",
    "security.snyk.io",
    "security-tracker.debian.org",
    "people.canonical.com",
    "www.kernel.org",
})

# Directory markers within a same-repo URL path that signal "this is a
# regression test, not an exploit". Conservative on purpose.
REGRESSION_DIR_MARKERS = ("/test/", "/tests/", "/testsuite/", "/regression/",
                          "/regressions/", "/corpus/", "/fuzz/", "/fuzzing/",
                          "/check/", "/checks/", "/qa/")

# Extensions we consider "data blobs" — safe to feed into a fuzzer corpus
# after the safety scanner gives the OK. Conservative: text formats are in
# here because most fuzz corpora are text or near-text; the safety scanner
# is the actual content gate.
BLOB_EXTENSIONS = frozenset({
    ".bin", ".raw", ".dat",
    ".xml", ".xhtml", ".svg", ".html", ".htm",
    ".json", ".yaml", ".yml", ".toml", ".ini", ".conf",
    ".pdf", ".png", ".jpg", ".jpeg", ".gif", ".bmp", ".tiff", ".tif",
    ".mp4", ".mp3", ".wav", ".ogg", ".webm", ".avi", ".mkv", ".flac",
    ".tar", ".tar.gz", ".tgz", ".tar.bz2", ".tbz2", ".tar.xz", ".txz",
    ".gz", ".bz2", ".xz", ".zip", ".7z",
    ".pcap", ".pcapng",
    ".der", ".pem", ".crt", ".key",
    ".txt", ".csv", ".tsv",
    ".asn1", ".cbor",
})

# Extensions that are code — retained as text reference material only.
CODE_EXTENSIONS = frozenset({
    ".c", ".cc", ".cpp", ".cxx", ".h", ".hpp", ".hxx",
    ".py", ".pyx",
    ".sh", ".bash",
    ".pl", ".pm",
    ".rb",
    ".js", ".mjs", ".cjs", ".ts",
    ".go",
    ".rs",
    ".java", ".kt", ".scala",
    ".php",
})


@dataclass
class PocTrust:
    url: str
    host: str
    path: str
    tier: str         # "A" | "B" | "C"
    rationale: str
    is_code: bool
    is_blob: bool

    def to_dict(self) -> dict:
        return asdict(self)


def _ext(path: str) -> str:
    """Lowercase compound or simple extension. e.g. 'tar.gz' beats 'gz'."""
    lower = path.lower()
    for compound in (".tar.gz", ".tar.bz2", ".tar.xz"):
        if lower.endswith(compound):
            return compound
    # Single dot-suffix
    dot = lower.rfind(".")
    if dot == -1:
        return ""
    return lower[dot:]


def _is_code(path: str) -> bool:
    return _ext(path) in CODE_EXTENSIONS


def _is_blob(path: str) -> bool:
    return _ext(path) in BLOB_EXTENSIONS


def _same_repo(parsed_host: str, parsed_path: str, patch_repo: Optional[str]) -> bool:
    """True iff the URL path is under the same owner/repo as the parsed patch.

    Accepts the standard GitHub web URL (`/owner/repo/...`),
    GitHub raw URL (`raw.githubusercontent.com/owner/repo/...`),
    GitLab web URL (`/owner/repo/-/...`).
    """
    if not patch_repo or "/" not in patch_repo:
        return False
    if parsed_host not in SAME_REPO_HOSTS:
        return False
    prefix = f"/{patch_repo}/"
    if parsed_path.startswith(prefix):
        return True
    # GitLab segments may include `/-/` between repo and refspec, but the
    # owner/repo prefix is still present.
    return False


def classify(url: str, patch_repo: Optional[str] = None) -> PocTrust:
    """Classify a PoC URL into A/B/C trust tiers.

    `patch_repo` is the `owner/repo` form (e.g. 'GNOME/libxml2') of the patch
    the PoC is associated with. Pass None to skip Tier-A checks.
    """
    parsed = urlparse(url)
    host = (parsed.hostname or "").lower()
    path = parsed.path or ""
    is_code = _is_code(path)
    is_blob = _is_blob(path)

    # Tier A: same repo + regression-style dir + data-blob extension.
    if _same_repo(host, path, patch_repo):
        marker_hit = next((m for m in REGRESSION_DIR_MARKERS if m in path), None)
        if marker_hit and is_blob:
            return PocTrust(url=url, host=host, path=path,
                            tier="A",
                            rationale=f"Same-repo data blob in {marker_hit.strip('/')}/ — regression-test pattern",
                            is_code=is_code, is_blob=is_blob)
        if marker_hit and is_code:
            # Code in a test dir of the same repo — Tier B-ish: trustworthy
            # provenance but we still don't auto-execute. Treat as B so it's
            # retained but not promoted.
            return PocTrust(url=url, host=host, path=path,
                            tier="B",
                            rationale=f"Same-repo CODE file in {marker_hit.strip('/')}/ — retain as reference only, never execute",
                            is_code=is_code, is_blob=is_blob)
        # Same repo but not under a test/regression dir — too broad to trust.
        return PocTrust(url=url, host=host, path=path,
                        tier="C",
                        rationale="Same-repo URL but not in a test/regression/corpus/fuzz directory",
                        is_code=is_code, is_blob=is_blob)

    # Tier B: recognised security-org host + acceptable extension.
    if host in TIER_B_HOSTS:
        if is_blob or is_code:
            return PocTrust(url=url, host=host, path=path,
                            tier="B",
                            rationale=f"Recognised security-org host: {host}",
                            is_code=is_code, is_blob=is_blob)
        # No extension — likely an advisory HTML page. Tier B for retain.
        return PocTrust(url=url, host=host, path=path,
                        tier="B",
                        rationale=f"Recognised security-org host: {host} (advisory page)",
                        is_code=is_code, is_blob=is_blob)

    # Default: Tier C — do not download.
    return PocTrust(url=url, host=host, path=path,
                    tier="C",
                    rationale=f"Untrusted host: {host or '(no host)'}",
                    is_code=is_code, is_blob=is_blob)


def main() -> int:
    if len(sys.argv) < 2:
        print("usage: cve-poc-trust.py <url> [<patch-repo owner/repo>]", file=sys.stderr)
        return 2
    url = sys.argv[1]
    patch_repo = sys.argv[2] if len(sys.argv) > 2 else None
    result = classify(url, patch_repo)
    print(json.dumps(result.to_dict(), indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main())
