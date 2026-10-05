"""Drive the real Claude Code CLI against tests/support/mock_anthropic.py.

A test scripts the model's turns (tool calls, then text) and gets back every
tool_result Claude Code produced, hooks included: hook behaviour is tested
against the shipped binary, offline and deterministic. The binary is the
contract's version from the claude-code-contract cache
(scripts/claude-code-contract.py fetch <version>) or $CC_FUZZER_CLAUDE_BIN;
without either, claude_binary() is None and the test skips.
"""
from __future__ import annotations

import json
import os
import socket
import subprocess
import sys
import tempfile
import time
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]
MOCK = Path(__file__).with_name("mock_anthropic.py")
last_requests: list = []     # the main-loop request bodies of the latest run()


def claude_binary():
    env = os.environ.get("CC_FUZZER_CLAUDE_BIN")
    if env and Path(env).is_file():
        return Path(env)
    v = json.loads((REPO / "claude-code.contract.json").read_text())["version"]
    cache = Path(os.environ.get("XDG_CACHE_HOME", Path.home() / ".cache")) / "claude-code-contract"
    b = cache / v / "claude"
    return b if b.is_file() else None


def _port() -> int:
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    p = s.getsockname()[1]
    s.close()
    return p


def run(script, *, settings: dict | None = None, workdir: Path | None = None,
        env: dict | None = None, timeout: int = 120):
    """(tool_results, result_event). tool_results: [{"is_error", "text"}]."""
    binary = claude_binary()
    work = Path(workdir or tempfile.mkdtemp(prefix="cc-drive-"))
    home = Path(tempfile.mkdtemp(prefix="cc-home-"))
    (home / ".claude.json").write_text(json.dumps({
        "hasCompletedOnboarding": True, "numStartups": 0, "autoUpdaterStatus": "disabled",
        "projects": {str(work): {"hasTrustDialogAccepted": True,
                                 "hasCompletedProjectOnboarding": True}}}))
    port, sp, log = _port(), home / "script.json", home / "requests.jsonl"
    sp.write_text(json.dumps(script))
    srv = subprocess.Popen([sys.executable, str(MOCK), str(port), str(sp), str(log)])
    deadline = time.time() + 10
    while time.time() < deadline:
        try:
            socket.create_connection(("127.0.0.1", port), timeout=0.2).close()
            break
        except OSError:
            time.sleep(0.05)
    run_env = {"PATH": os.environ.get("PATH", "/usr/bin:/bin"), "HOME": str(home), "IS_SANDBOX": "1",
               "ANTHROPIC_BASE_URL": f"http://127.0.0.1:{port}", "ANTHROPIC_AUTH_TOKEN": "x",
               "ANTHROPIC_API_KEY": "", "ANTHROPIC_MODEL": "unrecognized-model",
               "CLAUDE_CODE_MAX_RETRIES": "0", **(env or {})}
    cmd = [str(binary), "-p", "--verbose", "--output-format", "stream-json",
           "--dangerously-skip-permissions"]
    if settings is not None:
        sf = home / "settings.json"
        sf.write_text(json.dumps(settings))
        cmd += ["--settings", str(sf)]
    try:
        p = subprocess.run(cmd + ["go"], cwd=work, env=run_env, capture_output=True, text=True,
                           timeout=timeout, stdin=subprocess.DEVNULL)
    finally:
        srv.kill()
        srv.wait()
    last_requests[:] = [json.loads(l)["req"] for l in log.read_text().splitlines()
                        if l.strip() and json.loads(l).get("main")] if log.is_file() else []
    results, final = [], {}
    for line in p.stdout.splitlines():
        try:
            e = json.loads(line)
        except ValueError:
            continue
        if e.get("type") == "result":
            final = e
        if e.get("type") == "user":
            for b in (e.get("message") or {}).get("content") or []:
                if isinstance(b, dict) and b.get("type") == "tool_result":
                    c = b.get("content")
                    if isinstance(c, list):
                        c = "".join(x.get("text", "") for x in c if isinstance(x, dict))
                    results.append({"is_error": bool(b.get("is_error")), "text": c or ""})
    return results, final
