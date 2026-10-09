"""Behaviour governor: nudge toward running inputs after long reading streaks."""
from __future__ import annotations

import json
import subprocess
import sys

import pytest

from cc_fuzzer_core import governor as g


@pytest.fixture(autouse=True)
def state(tmp_path, monkeypatch):
    monkeypatch.setenv("CC_FUZZER_HOOK_STATE", str(tmp_path))


def bash(cmd):
    return {"tool_name": "Bash", "tool_input": {"command": cmd}}


@pytest.mark.parametrize("call,kind", [
    ({"tool_name": "Read", "tool_input": {"file_path": "/src/a.c"}}, "read"),
    (bash("grep -n parse /src/file/src/*.c | head -20"), "read"),
    (bash("sed -n 1130,1150p src/apprentice.c; echo ---; grep -c x y"), "read"),
    (bash("awk '{printf \"%s\\n\", $1}' x | sort | uniq -c"), "read"),           # quoted ; inside awk
    (bash("objdump -d /out/h | head"), "read"),                                  # /out is not a run
    (bash("which crc-known-bugs && crc-known-bugs | head"), "read"),
    (bash("cat > q.ql <<'EOF'\nimport cpp\nselect 1\nEOF\ncrs-codeql run q.ql | tail"), "read"),
    (bash("crc-promote-pov /work/pov-candidates/x.bin | tail -5"), "run"),
    (bash("crs-fuzz add-seeds --harness h /tmp/s"), "run"),
    (bash("/out/magic_fuzzer_loaddb -runs=1 /tmp/in"), "run"),
    (bash("gdb -batch -ex run --args /out/h in"), "run"),
    (bash("python3 mk.py > in.bin"), "other"),
    ({"tool_name": "Write", "tool_input": {"file_path": "/tmp/in"}}, "other"),
])
def test_classify(call, kind):
    assert g.classify(call) == kind


def test_a_host_pattern_marks_running_the_harness():
    c = bash("./magic_fuzzer_loaddb crafted.bin")
    assert g.classify(c) == "other"
    assert g.classify(c, g.DEFAULT_RUN_PATTERNS + (r"\bmagic_fuzzer_loaddb\b",)) == "run"


def test_nudges_after_threshold_reads_then_only_after_another_streak():
    read = {"tool_name": "Read", "tool_input": {}}
    assert g.observe("s", [read] * 4, threshold=5) is None
    t = g.observe("s", [read], threshold=5, how="crc-promote-pov <file>")
    assert t and t.startswith("5 reading and search calls") and "crc-promote-pov <file>" in t
    assert g.observe("s", [read] * 4, threshold=5) is None          # not again at once
    assert g.observe("s", [read], threshold=5)                       # after another streak
    assert g.observe("s", [bash("crc-promote-pov x")], threshold=5) is None   # a run resets
    assert g.observe("s", [read] * 4, threshold=5) is None
    assert g.observe("other-session", [read] * 5, threshold=5)       # per session
    assert g.observe("s2", [read] * 50, threshold=0) is None         # off


def test_cli_reads_the_hook_input_and_never_fails(tmp_path):
    doc = {"session_id": "c1", "tool_calls": [{"tool_name": "Read", "tool_input": {}}] * 3}
    run = lambda raw, *a: json.loads(subprocess.run(
        [sys.executable, "-m", "cc_fuzzer_core", "governor", "observe", "--threshold", "3", *a],
        input=raw, capture_output=True, text=True, check=True).stdout)
    assert run(json.dumps(doc))["nudge"].startswith("3 reading")
    assert run("not json") == {"nudge": ""}
