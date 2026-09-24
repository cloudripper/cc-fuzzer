"""Sanitizer-output crash classifier (port of scripts/is-crash.sh).

classify(text, exit_code=None) -> Classification. The detection ladder is the
bash one, first match wins:

  1. a sanitizer SUMMARY line          (category from the SUMMARY)
  2. an ASan ERROR header              (no SUMMARY, e.g. stack overflow)
  3. a UBSan "runtime error:" line
  4. plain-text crash lines            (Segmentation fault, Aborted, ...)
  5. assertion failures
  6. OOM signatures
  7. libFuzzer timeout / DEADLYSIGNAL
  8. the exit code, when given         (134/139/137/135/132)

top_frame is the first non-infrastructure "in <function> <file:line>" frame,
column stripped. (is-crash.sh named its awk variable `func`, a gawk keyword,
so top_frame used to be empty under gawk; both implementations now fill it.)

Classification.to_json() is is-crash.sh's single output line, byte for byte:
its minimal string escaping and the exit code as given are kept.
"""
from __future__ import annotations

import re
from dataclasses import dataclass

_SUMMARY_RE = re.compile(r"^SUMMARY: (Address|UndefinedBehavior|Memory|Leak|Thread)Sanitizer:")
_SUMMARY_CAT_RE = re.compile(r"^SUMMARY: [A-Za-z]+Sanitizer: ([a-zA-Z-]+).*")
_ASAN_ERR_RE = re.compile(r"^==[0-9]+==ERROR: AddressSanitizer:")
_ASAN_ERR_CAT_RE = re.compile(r"^==[0-9]+==ERROR: AddressSanitizer: ([a-zA-Z-]+).*")
_PLAIN_RE = re.compile(r"^(Segmentation fault|Abort trap|Aborted|Bus error)")
_ASSERT_RE = re.compile(r"Assertion .* failed|g_assertion_message|__assert_fail")
_OOM_RE = re.compile(r"out of memory|MemoryError|allocator_may_return_null|requested allocation size .* exceeds")
_TIMEOUT_RE = re.compile(r"ERROR: libFuzzer: timeout|DEADLYSIGNAL")
_FRAME_RE = re.compile(r"^\s*(#[0-9]+\s+(0x[0-9a-f]+\s+)?in\s+|in\s+)", re.ASCII)
_COLUMN_RE = re.compile(r":[0-9]+$")

# Frames from sanitizer / fuzzer infrastructure (matched anywhere in "fn @ loc").
INFRA_RE = re.compile(r"__sanitizer_|__asan_|__ubsan_|__msan_|__lsan_|compiler-rt|asan_|ubsan_|msan_"
                      r"|fuzzer::|LLVMFuzzerTestOneInput")

_KNOWN_SUMMARY = {"heap-buffer-overflow", "stack-buffer-overflow", "global-buffer-overflow",
                  "heap-use-after-free", "use-of-uninitialized-value", "stack-overflow", "null-deref"}

_UBSAN = (("signed integer overflow", "signed-integer-overflow"),
          ("unsigned integer overflow", "integer-overflow"),
          ("shift exponent", "ubsan-shift"),
          ("division by zero", "ubsan-div-zero"),
          ("load of misaligned", "ubsan-alignment"),
          ("null pointer", "null-deref"))

_EXIT_CODES = {
    "134": ("abort", "exit=134 (SIGABRT)"),
    "139": ("segfault", "exit=139 (SIGSEGV)"),
    "137": ("oom", "exit=137 (SIGKILL — OOM or external)"),
    "135": ("generic-crash", "exit=135 (SIGBUS)"),
    "132": ("generic-crash", "exit=132 (SIGILL)"),
}


@dataclass(frozen=True)
class Classification:
    is_crash: bool
    category: str          # "none" when not a crash
    summary_line: str
    top_frame: str
    exit_code: str | None  # as passed (is-crash.sh prints it unquoted)

    def to_dict(self) -> dict:
        ec = self.exit_code
        if ec is not None:
            try:
                ec = int(ec)
            except ValueError:
                pass
        return {"is_crash": self.is_crash, "category": self.category,
                "summary_line": self.summary_line, "top_frame": self.top_frame, "exit_code": ec}

    def to_json(self) -> str:
        ec = "null" if self.exit_code is None else self.exit_code
        return ('{"is_crash":%s,"category":"%s","summary_line":"%s","top_frame":"%s","exit_code":%s}'
                % ("true" if self.is_crash else "false", _escape(self.category),
                   _escape(self.summary_line), _escape(self.top_frame), ec))


def _escape(s: str) -> str:
    """is-crash.sh's json_escape: backslash, quote, newline, tab, CR only."""
    return (s.replace("\\", "\\\\").replace('"', '\\"').replace("\n", "\\n")
            .replace("\t", "\\t").replace("\r", "\\r"))


def _first(lines, pattern) -> str | None:
    for ln in lines:
        if pattern.search(ln):
            return ln
    return None


def _category(line: str, pattern) -> str:
    # sed -E 's/<pattern>/\1/': the whole line when the pattern doesn't match.
    m = pattern.match(line)
    return m.group(1) if m else line


def top_frame(lines) -> str:
    """First non-infrastructure frame as "function @ file:line" ("" if none)."""
    for ln in lines:
        if not _FRAME_RE.search(ln):
            continue
        fields = ln.split()
        for i, f in enumerate(fields):
            if f == "in":
                fn = fields[i + 1] if i + 1 < len(fields) else ""
                loc = fields[i + 2] if i + 2 < len(fields) else ""
                frame = f"{fn} @ {_COLUMN_RE.sub('', loc, count=1)}"
                if not INFRA_RE.search(frame):
                    return frame
                break
    return ""


def classify(text: str, exit_code: str | int | None = None) -> Classification:
    """Classify captured sanitizer / fuzzer output (see module docstring)."""
    ec = None if exit_code is None or exit_code == "" else str(exit_code)
    # $(cat) semantics: trailing newlines dropped, then split into lines.
    lines = text.rstrip("\n").split("\n")
    is_crash, category, summary = False, "none", ""

    line = _first(lines, _SUMMARY_RE)
    if line is not None:
        is_crash, summary = True, line
        category = _category(line, _SUMMARY_CAT_RE)
        if category not in _KNOWN_SUMMARY and re.search(r"SEGV|null", line):
            category = "null-deref"

    if not is_crash:
        line = _first(lines, _ASAN_ERR_RE)
        if line is not None:
            is_crash, summary = True, line
            category = _category(line, _ASAN_ERR_CAT_RE)
            if category == "SEGV":
                category = "null-deref"

    if not is_crash:
        line = _first(lines, re.compile(": runtime error: "))
        if line is not None:
            is_crash, summary = True, line
            category = next((cat for needle, cat in _UBSAN if needle in line), "ubsan-other")

    if not is_crash:
        line = _first(lines, _PLAIN_RE)
        if line is not None:
            is_crash, summary = True, line
            if line.startswith("Segmentation fault"):
                category = "segfault"
            elif line.startswith(("Abort trap", "Aborted")):
                category = "abort"
            else:
                category = "generic-crash"

    if not is_crash:
        line = _first(lines, _ASSERT_RE)
        if line is not None:
            is_crash, summary, category = True, line, "assertion-failure"

    if not is_crash:
        line = _first(lines, _OOM_RE)
        if line is not None:
            is_crash, summary, category = True, line, "oom"

    if not is_crash:
        line = _first(lines, _TIMEOUT_RE)
        if line is not None:
            is_crash, summary = True, line
            category = "timeout" if "timeout" in line else "generic-crash"

    if not is_crash and ec in _EXIT_CODES:
        is_crash = True
        category, summary = _EXIT_CODES[ec]

    return Classification(is_crash, category, summary, top_frame(lines) if is_crash else "", ec)


def classify_file(path, exit_code=None) -> Classification:
    with open(path, encoding="utf-8", errors="replace") as f:
        return classify(f.read(), exit_code)
