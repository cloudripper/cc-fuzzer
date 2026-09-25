#!/usr/bin/env python3
"""(Re)generate the synthetic fixture campaigns under tests/fixtures/.

    PYTHONPATH=src python3 tests/fixtures/build_fixtures.py [name ...]

Each fixture is a project dir whose fuzz/ tree is a hand-authored, current-schema
campaign (STATE_SCHEMA.md) — no real fuzzing, stub shell "binaries". The
derived views (current.json, tick-coverage roundups) are NOT hand-written:
they are produced by running the real scripts/update-current.sh on the
authored inputs under the golden harness's frozen clock, so they are exactly
what the plugin would write. Every fixture is then run through
scripts/validate-state.sh and the verdict is printed.

Fixtures (all timestamps are relative to tests/support/golden.FROZEN_NOW):
  campaign-cold      one harness built at COLD, seeds staged in quarantine,
                     no fuzzing yet (no current.json / fuzzers.json / snapshots)
  campaign-warm      two harnesses (libFuzzer + AFL++/cmplog), live-manifest
                     slots, coverage + gaps snapshots, tick roundups, events,
                     budget, a report, AFL++ cmplog output
  campaign-plateau   one harness, YOLO self_loop enabled, coverage flat for
                     many ticks (plateau / ceiling ladder territory)
  campaign-crashes   findings ledger (candidate + promoted finding),
                     crashes/{new,known,flaky}, dropped + corrections logs

The output is committed; tests never regenerate it. Rerun this script (and
then CC_FUZZER_UPDATE_GOLDEN=1 for the goldens) only when the schema changes.
"""
from __future__ import annotations

import hashlib
import json
from cc_fuzzer_core.schema.fields import SCHEMA_VERSION
import shutil
import subprocess
import sys
import time
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parents[1]))  # repo root, for tests.support
from tests.support.golden import FROZEN_NOW, REPO, Sandbox, bash  # noqa: E402

N = FROZEN_NOW
DEAD_PID = "2147480001"   # > any pid_max: kill -0 always fails


def iso(ts: int) -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(ts))


def sha16(text: str) -> str:
    return hashlib.sha256(text.encode()).hexdigest()[:16]


def dump(doc) -> str:
    return json.dumps(doc, indent=2) + "\n"


def jsonl(rows) -> str:
    return "".join(json.dumps(r, separators=(",", ":")) + "\n" for r in rows)


# ---------------------------------------------------------------------------
# Shared content
# ---------------------------------------------------------------------------

PARSER_C = r"""/* Synthetic target for cc-fuzzer fixtures. Never compiled. */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

struct chunk { char tag[4]; unsigned len; unsigned char *data; };

int parse_chunk(const unsigned char *buf, size_t n, struct chunk *out) {
    char name[16];
    if (n < 8) return -1;
    memcpy(out->tag, buf, 4);
    out->len = buf[4] | (buf[5] << 8);
    out->data = malloc(out->len);
    memcpy(out->data, buf + 8, out->len);          /* len not checked vs n */
    strcpy(name, (const char *)buf + 8);            /* unbounded copy */
    if (memcmp(out->tag, "eXIf", 4) == 0)
        return parse_exif(out->data, out->len);
    return 0;
}

int parse_exif(const unsigned char *p, unsigned len) {
    char msg[32];
    unsigned i;
    for (i = 0; i <= len; i++) {                   /* off-by-one */
        if (p[i] == 0xff) break;
    }
    sprintf(msg, "exif entries: %u", i);
    return (int)i;
}

void free_chunk(struct chunk *c) {
    free(c->data);
    if (c->len > 1024) free(c->data);               /* double free on big chunks */
}
"""

ENCODER_C = r"""/* Synthetic target for cc-fuzzer fixtures. Never compiled. */
#include <stdlib.h>
#include <string.h>

int encode_chunk(const unsigned char *in, size_t n, unsigned char **out) {
    unsigned char *buf = malloc(n * 2);
    size_t i, j = 0;
    for (i = 0; i < n; i++) {
        if (in[i] == 0x7d || in[i] == 0x7e) { buf[j++] = 0x7d; buf[j++] = in[i] ^ 0x20; }
        else buf[j++] = in[i];
    }
    *out = buf;
    return (int)j;
}
"""

STUB_HARNESS = """#!/bin/sh
# Fixture stub harness (stands in for a libFuzzer binary). Treats every
# non-flag argument as an input file: an input containing CRASH "crashes"
# (ASan-style report on stderr, exit 77); anything else runs clean.
for a in "$@"; do
  case "$a" in
    -*) ;;
    *)
      if [ -f "$a" ] && grep -q CRASH "$a" 2>/dev/null; then
        echo "==4242==ERROR: AddressSanitizer: heap-buffer-overflow on address 0x602000000011" >&2
        echo "    #0 0x4f1a2b in parse_chunk src/parser.c:14:5" >&2
        echo "SUMMARY: AddressSanitizer: heap-buffer-overflow src/parser.c:14:5 in parse_chunk" >&2
        exit 77
      fi
      ;;
  esac
done
exit 0
"""

BUILD_SH = """#!/bin/sh
# Fixture build script (never run).
clang -g -O1 -fsanitize=fuzzer,address,undefined -o "$OUT/{name}_fuzzer" {name}_fuzzer.c ../../../../src/{src}
"""

HARNESS_SRC = """#include <stddef.h>
#include <stdint.h>
int {entry}(const unsigned char *, size_t, void *);
int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {{
    {entry}(data, size, 0);
    return 0;
}}
"""


class Builder:
    def __init__(self, name: str):
        self.name = name
        self.root = HERE / name
        if self.root.exists():
            shutil.rmtree(self.root)
        self.root.mkdir(parents=True)

    def write(self, rel: str, content, mode: int | None = None):
        p = self.root / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        if isinstance(content, bytes):
            p.write_bytes(content)
        else:
            p.write_text(content)
        if mode is not None:
            p.chmod(mode)

    def keep(self, rel: str):
        """Commit an otherwise-empty directory (the sandbox drops .gitkeep)."""
        self.write(f"{rel}/.gitkeep", "")

    # -- campaign skeleton -------------------------------------------------

    def skeleton(self):
        self.write("fuzz/state/schema-version", f"{SCHEMA_VERSION}\n")
        self.keep("fuzz/state/snapshots")
        for d in ("new", "known", "flaky"):
            self.keep(f"fuzz/crashes/{d}")

    def source(self, rel: str, text: str) -> str:
        self.write(rel, text)
        return text

    def harness(self, name: str, entry: str, src_rel: str, *, built_at: int,
                cov=True, cmplog=False, seeds=()):
        """Build-output bundle + return the harness-built/v7 record."""
        base = f"fuzz/harnesses/{name}/harness"
        target = (self.root / src_rel).read_text()
        build = BUILD_SH.format(name=name, src=Path(src_rel).name)
        self.write(f"{base}/build.sh", build, 0o755)
        self.write(f"{base}/{name}_fuzzer.c", HARNESS_SRC.format(entry=entry))
        for suffix in ["", "_verify"] + (["_cov"] if cov else []) + (["_cmplog"] if cmplog else []):
            self.write(f"{base}/{name}_fuzzer{suffix}", STUB_HARNESS, 0o755)
        self.keep(f"fuzz/harnesses/{name}/coverage")
        if seeds:
            for fn, content in seeds:
                self.write(f"fuzz/harnesses/{name}/corpus/{fn}", content)
        else:
            self.keep(f"fuzz/harnesses/{name}/corpus")
        rec = {
            "schema": "harness-built/v7",
            "name": name,
            "build_backend": "legacy",
            "build_backend_decided_at": iso(built_at),
            "build_backend_decided_by": "write-harness-built",
            "harness_source": f"{base}/{name}_fuzzer.c",
            "harness_binary": f"{base}/{name}_fuzzer",
            "coverage_binary": f"{base}/{name}_fuzzer_cov" if cov else None,
            "coverage_tracking": cov,
            "verify_binary": f"{base}/{name}_fuzzer_verify",
            "cmplog_binary": f"{base}/{name}_fuzzer_cmplog" if cmplog else None,
            "cmplog_enabled": cmplog,
            "symcc_binary": None,
            "build_script": f"{base}/build.sh",
            "entry_function": entry,
            "input_encoding": "passthrough",
            "sanitizers": ["address", "undefined", "fuzzer"],
            "fuzzing_mode": "in_process",
            "dict_files": [],
            "target_source": src_rel,
            "target_source_hash": sha16(target),
            "build_command_hash": sha16(build),
            "harness_attempts": 1,
            "built_at": iso(built_at),
        }
        if not cov:
            rec["coverage_disabled_reason"] = "llvm-cov unavailable on build host"
        if not cmplog:
            rec["cmplog_disabled_reason"] = "libFuzzer-only harness (no AFL++ slot)"
        return rec

    def harness_set(self, records):
        self.write("fuzz/state/harnesses.json", dump({"schema": "harness-set/v1", "harnesses": records}))
        self.write("fuzz/state/harness-built.json", dump(records[0]))

    def config(self, harnesses, slots, **blocks):
        doc = {"schema": "fuzz-config/v3", "fuzz_forks": 2,
               "harnesses": harnesses, "fuzzer_slots": slots}
        doc.update(blocks)
        self.write("fuzz/state/fuzz-config.json", dump(doc))

    def manifest(self, slots):
        rows = []
        for s in slots:
            slot = s["slot"]
            rows.append({
                "slot": slot, "harness": s["harness"], "engine": s["engine"],
                "binary": f"fuzz/harnesses/{s['harness']}/harness/{s['harness']}_fuzzer",
                "pid": DEAD_PID, "pgid": DEAD_PID,
                "started_at": iso(s.get("started", N - 3600)),
                "log_file": f"fuzz/state/fuzzer-{slot}.log",
                "pid_file": f"fuzz/state/fuzzer-{slot}.pid",
                "engine_file": f"fuzz/state/fuzzer-{slot}.engine",
                "role": s.get("role"), "afl_power_schedule": s.get("afl_power_schedule"),
                "restart_count": s.get("restart_count", 0),
                "last_restart_at": s.get("last_restart_at"),
            })
            self.write(f"fuzz/state/fuzzer-{slot}.pid", DEAD_PID + "\n")
            self.write(f"fuzz/state/fuzzer-{slot}.engine", s["engine"] + "\n")
            self.write(f"fuzz/state/fuzzer-{slot}.log", "#1 INITED cov: 12 ft: 14 corp: 1/8b exec/s: 0 rss: 30Mb\n")
        self.write("fuzz/state/fuzzers.json", dump({"schema": "fuzzers/v2", "slots": rows}))

    def coverage(self, harness, ts, covered, total, *, engine="libfuzzer", execs=0,
                 prev=None, unreached=()):
        doc = {
            "schema": "coverage-snapshot/v2",
            "timestamp": ts,
            "harness": harness,
            "engine": engine,
            "fuzzer_stats": {"execs": execs, "paths": covered // 3, "crashes": 0,
                             "hangs": 0, "execs_per_sec": 500},
            "coverage": {"lines_covered": covered, "lines_total": total,
                         "line_pct": round(covered * 100.0 / total, 2)},
            "instrumentation": {"tracking_enabled": True, "coverage_build_present": True,
                                "llvm_cov_available": True, "coverage_run_ok": True,
                                "parsed_engine_log": True, "fork_mode": False,
                                "ok": True, "errors": []},
            "top_unreached_functions": list(unreached),
        }
        if prev is not None:
            doc["previous_snapshot_ts"] = prev
            doc["new_crashes_since_previous"] = []
        self.write(f"fuzz/state/snapshots/coverage-{harness}-{ts}.json", dump(doc))

    def gaps(self, harness, ts, cov_ts, gaps):
        doc = {"schema": "gaps-report/v1", "timestamp": ts, "harness": harness,
               "snapshot_file": f"fuzz/state/snapshots/coverage-{harness}-{cov_ts}.json",
               "gaps": gaps}
        self.write(f"fuzz/state/snapshots/gaps-{harness}-{ts}.json", dump(doc))

    def events(self, rows):
        self.write("fuzz/state/events.jsonl", jsonl(rows))

    def plan(self, harnesses):
        body = ["# Campaign plan (fixture)", "", "## Targets", ""]
        for name, entry in harnesses:
            body += [f"### {name} (entry: {entry})", "", "#### Harness", "Body-walk the chunk parser.", "",
                     "#### Seed Strategy", "Valid chunks with the eXIf tag.", ""]
        self.write("fuzz/state/plan.md", "\n".join(body))

    def budget(self, spent):
        self.write("fuzz/state/budget.json", dump({
            "schema": "budget/v1", "campaign_started": iso(N - 86400), "limit_usd": 25.0,
            "spent_usd": spent, "spent_per_model": {"sonnet": spent}, "tokens_in": 120000,
            "tokens_out": 30000, "last_updated": iso(N - 600)}))

    # -- derived state -----------------------------------------------------

    def run_script(self, script, *args, now):
        """Run a real plugin script against this fixture in place, under the
        frozen clock (via a Sandbox rooted at the fixture copy)."""
        sb = Sandbox(None, now=now)
        try:
            shutil.rmtree(sb.project)
            shutil.copytree(self.root, sb.project)
            for keep in sb.project.rglob(".gitkeep"):
                keep.unlink()
            res = sb.run(bash(script, *args))
            if res.exit_code != 0:
                raise SystemExit(f"{self.name}: {script} failed ({res.exit_code}):\n{res.stdout}\n{res.stderr}")
            # Copy back only what the script wrote (keeps .gitkeep markers).
            for rel in res.files:
                src = sb.project / rel
                dst = self.root / rel
                dst.parent.mkdir(parents=True, exist_ok=True)
                shutil.copy2(src, dst)
            return res
        finally:
            sb.cleanup()

    def validate(self):
        sb = Sandbox(self.name)
        try:
            for keep in sb.project.rglob(".gitkeep"):
                keep.unlink()
            res = sb.run(bash("scripts/validate-state.sh"))
            last = res.stdout.strip().splitlines()[-1] if res.stdout.strip() else ""
            print(f"{self.name}: validate-state exit={res.exit_code} ({last})")
            if res.exit_code != 0:
                print(res.stdout)
        finally:
            sb.cleanup()


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

def build_cold():
    b = Builder("campaign-cold")
    b.skeleton()
    b.source("src/parser.c", PARSER_C)
    rec = b.harness("parser", "parse_chunk", "src/parser.c", built_at=N - 1800,
                    seeds=[("seed-minimal.bin", "eXIf\x04\x00\x00\x00abcd")])
    b.harness_set([rec])
    b.config([{"name": "parser", "entry_function": "parse_chunk"}],
             [{"slot": "main", "harness": "parser", "engine": "libfuzzer"}])
    b.plan([("parser", "parse_chunk")])
    q = "fuzz/harnesses/parser/corpus-quarantine"
    b.write(f"{q}/seed-a.bin", "eXIf\x08\x00\x00\x00abcdefgh")
    b.write(f"{q}/seed-b.bin", "tEXt\x02\x00\x00\x00zz")
    b.write(f"{q}/seed-crash.bin", "eXIf\xff\xff\x00\x00CRASH-overlong")
    b.write(f"{q}/seed-destructive.sh", "#!/bin/sh\nrm -rf / --no-preserve-root\n")
    b.events([{"schema": "event/v1", "ts": N - 1700, "tick": 0, "event": "campaign_start"}])
    b.validate()


def build_warm():
    b = Builder("campaign-warm")
    b.skeleton()
    b.source("src/parser.c", PARSER_C)
    b.source("src/encoder.c", ENCODER_C)
    p = b.harness("parser", "parse_chunk", "src/parser.c", built_at=N - 20000,
                  seeds=[("seed-minimal.bin", "eXIf\x04\x00\x00\x00abcd"),
                         ("seed-text.bin", "tEXt\x05\x00\x00\x00hello")])
    e = b.harness("encoder", "encode_chunk", "src/encoder.c", built_at=N - 19000, cmplog=True,
                  seeds=[("seed-escape.bin", "\x7d\x7e\x01\x02")])
    b.harness_set([p, e])
    slots = [
        {"slot": "parser-main", "harness": "parser", "engine": "libfuzzer"},
        {"slot": "encoder-afl", "harness": "encoder", "engine": "aflpp", "role": "master",
         "afl_power_schedule": "explore", "timeout_ms": 1000},
    ]
    b.config([{"name": "parser", "entry_function": "parse_chunk"},
              {"name": "encoder", "entry_function": "encode_chunk"}],
             slots,
             tick={"consult_every_n": 5, "consult_on_coverage_stall": True},
             code_review={"enabled": True, "default_tier": "sonnet", "scan_paths": None,
                          "excluded_paths": ["tests/", "vendor/"], "max_functions_to_review": 20,
                          "sast": {"mode": "auto", "codeql_db": None}})
    b.manifest([dict(slots[0], started=N - 18000),
                dict(slots[1], started=N - 18000, restart_count=1, last_restart_at=iso(N - 9000))])
    b.plan([("parser", "parse_chunk"), ("encoder", "encode_chunk")])
    b.budget(3.75)
    b.write("fuzz/state/FINDINGS-REPORT-fixture.md", "# Findings report (fixture)\n\nNo findings yet.\n")

    # Coverage history: parser climbing, encoder slower.
    pts = [(N - 5400, 120), (N - 3600, 150), (N - 1800, 171)]
    prev = None
    for ts, cov in pts:
        b.coverage("parser", ts, cov, 400, execs=ts - (N - 18000), prev=prev,
                   unreached=["parse_exif", "free_chunk"])
        prev = ts
    b.coverage("encoder", N - 3500, 40, 90, engine="aflpp", execs=90000)
    b.coverage("encoder", N - 1700, 44, 90, engine="aflpp", execs=150000, prev=N - 3500)
    b.gaps("parser", N - 1750, N - 1800, [
        {"id": "g001", "file": "src/parser.c", "function": "parse_exif", "line_range": [22, 30],
         "reason": "format_barrier", "hint": "Chunk tag must be 'eXIf' to reach parse_exif",
         "recommended_agent": "seed-generator"},
        {"id": "g002", "file": "src/parser.c", "function": "free_chunk", "line_range": [32, 35],
         "reason": "harness_gap", "hint": "Harness never frees the chunk; call free_chunk after parse",
         "recommended_agent": "harness-writer", "harness_action": "extend"},
    ])
    b.gaps("encoder", N - 1650, N - 1700, [
        {"id": "g001", "file": "src/encoder.c", "function": "encode_chunk", "line_range": [7, 8],
         "reason": "direct_compare", "hint": "0x7d/0x7e escape bytes already seen by cmplog",
         "recommended_agent": "none"},
    ])

    # AFL++ output for the encoder slot (cmplog harvest input).
    out = "fuzz/harnesses/encoder/aflpp-out/encoder-afl"
    b.write(f"{out}/fuzzer_stats", "start_time        : %d\nexecs_done        : 150000\n" % (N - 18000))
    b.write(f"{out}/queue/id:000000,time:0,execs:0,orig:seed-escape.bin", b"\x7d\x7e\x01\x02")
    b.write(f"{out}/queue/id:000001,src:000000,time:812,execs:4410,op:havoc,rep:2,+cov",
            b"\x00\x01MAGIC_HEADER\x7dPAYLOADxx\x02")
    b.write(f"{out}/.cmplog/cmp-0001", b"\x00\x00\x00\x7eESCAPE_SEQ\x00\x10\x00\x00\x001234567890\x00ab\x00")
    b.write(f"{out}/.cmplog/cmp-0002", b"\x01\x02/usr/lib/libfoo.so\x00TAG=encoder\x00\xffDELIM\"q\\\x00")

    ev = [{"schema": "event/v1", "ts": N - 20000, "tick": 0, "event": "campaign_start"}]
    for i, (ts, branch, agent, ti, to) in enumerate([
        (N - 5300, "analyze_gaps", "coverage-analyst", 8000, 1500),
        (N - 3500, "generate_seeds", "seed-generator", 6000, 1200),
        (N - 1700, "analyze_gaps", "coverage-analyst", 7000, 1400),
    ], start=1):
        ev.append({"schema": "event/v1", "ts": ts, "tick": i, "event": "tick", "branch": branch,
                   "reason": f"fixture tick {i}", "duration_ms": 4000, "agent_called": agent,
                   "tokens_in": ti, "tokens_out": to})
        ev.append({"schema": "event/v1", "ts": ts + 5, "tick": i, "event": "agent_call",
                   "agent_called": agent, "tokens_in": ti, "tokens_out": to})
    b.events(ev)

    # Two roundups + the composed current.json, as the plugin would write them.
    b.run_script("scripts/update-current.sh", now=N - 3400)
    b.run_script("scripts/update-current.sh", now=N - 1600)
    b.validate()


def build_plateau():
    b = Builder("campaign-plateau")
    b.skeleton()
    b.source("src/parser.c", PARSER_C)
    rec = b.harness("parser", "parse_chunk", "src/parser.c", built_at=N - 40000,
                    seeds=[("seed-minimal.bin", "eXIf\x04\x00\x00\x00abcd")])
    b.harness_set([rec])
    slots = [{"slot": "main", "harness": "parser", "engine": "libfuzzer"}]
    b.config([{"name": "parser", "entry_function": "parse_chunk"}], slots,
             yolo={"enabled": True, "mode": "self_loop", "aggressiveness": "aggressive",
                   "interval_seconds": 1800, "max_ticks": 24, "max_cost_usd": 10.0,
                   "stop_on_no_progress_ticks": 10, "plateau_escalate_ticks": 4,
                   "crash_storm_threshold": 10, "redundancy_threshold": 2,
                   "soft_cost_fraction": 0.8, "cost_cap_enabled": True,
                   "max_backoff_multiplier": 4, "enabled_at_ts": N - 30000,
                   "enabled_at_tick": 1, "last_halt_reason": None})
    b.manifest([dict(slots[0], started=N - 36000)])
    b.plan([("parser", "parse_chunk")])
    b.budget(6.2)
    b.write("fuzz/state/FINDINGS-REPORT-fixture.md", "# Findings report (fixture)\n\nNo findings yet.\n")

    ev = [{"schema": "event/v1", "ts": N - 36000, "tick": 0, "event": "campaign_start"}]
    b.coverage("parser", N - 34000, 150, 400, execs=1_000_000, unreached=["parse_exif", "free_chunk"])
    prev = N - 34000
    tick_times = [N - 30000 + i * 2400 for i in range(12)]   # 12 ticks, 40 min apart
    branches = ["analyze_gaps", "generate_seeds", "mutator", "sleep"]
    agents = {"analyze_gaps": "coverage-analyst", "generate_seeds": "seed-generator",
              "mutator": "mutator", "sleep": None}
    for i, ts in enumerate(tick_times, start=1):
        # Coverage gains stop after tick 3: every later snapshot is flat.
        cov = 150 + min(i, 3) * 4
        b.coverage("parser", ts - 120, cov, 400, execs=1_000_000 + i * 400_000, prev=prev,
                   unreached=["parse_exif", "free_chunk"])
        prev = ts - 120
        br = branches[i % len(branches)]
        row = {"schema": "event/v1", "ts": ts, "tick": i, "event": "tick", "branch": br,
               "reason": f"fixture plateau tick {i}", "duration_ms": 3000}
        if agents[br]:
            row.update(agent_called=agents[br], tokens_in=9000, tokens_out=1800)
        ev.append(row)
        if agents[br]:
            ev.append({"schema": "event/v1", "ts": ts + 5, "tick": i, "event": "agent_call",
                       "agent_called": agents[br], "tokens_in": 9000, "tokens_out": 1800})
    b.gaps("parser", tick_times[-1] - 60, tick_times[-1] - 120, [
        {"id": "g001", "file": "src/parser.c", "function": "parse_exif", "line_range": [22, 30],
         "reason": "deep_path_condition", "hint": "Needs len-consistent eXIf chunk with 0xff terminator",
         "recommended_agent": "concolic-executor"},
        {"id": "g002", "file": "src/parser.c", "function": "free_chunk", "line_range": [32, 35],
         "reason": "harness_gap", "hint": "Unreachable from parse-only harness; add a lifecycle harness",
         "recommended_agent": "harness-writer", "harness_action": "new_harness",
         "proposed_entry": "free_chunk"},
    ])
    # Events are written progressively so each roundup sees the tick count it
    # had at the time (update-current derives tick_number from events.jsonl).
    for i, ts in enumerate(tick_times, start=1):
        upto = [e for e in ev if e["ts"] <= ts + 60]
        b.events(upto)
        b.run_script("scripts/update-current.sh", now=ts + 60)
    b.events(ev)
    b.validate()


def build_crashes():
    b = Builder("campaign-crashes")
    b.skeleton()
    b.source("src/parser.c", PARSER_C)
    rec = b.harness("parser", "parse_chunk", "src/parser.c", built_at=N - 50000,
                    seeds=[("seed-minimal.bin", "eXIf\x04\x00\x00\x00abcd")])
    b.harness_set([rec])
    slots = [{"slot": "main", "harness": "parser", "engine": "libfuzzer"}]
    b.config([{"name": "parser", "entry_function": "parse_chunk"}], slots)
    b.manifest([dict(slots[0], started=N - 45000)])
    b.plan([("parser", "parse_chunk")])
    b.budget(8.1)
    b.write("fuzz/state/FINDINGS-REPORT-fixture.md", "# Findings report (fixture)\n\n- f001 heap-buffer-overflow in parse_chunk\n")
    b.coverage("parser", N - 7200, 190, 400, execs=5_000_000, unreached=["free_chunk"])
    b.coverage("parser", N - 3600, 201, 400, execs=7_000_000, prev=N - 7200, unreached=["free_chunk"])

    # Known findings: one promoted, one still a candidate.
    b.write("fuzz/crashes/known/f001/repro.bin", b"eXIf\xff\xff\x00\x00CRASH-1")
    b.write("fuzz/crashes/known/f001/harnesses.txt", "parser\n")
    b.write("fuzz/crashes/known/f002/repro.bin", b"eXIf\x10\x00\x00\x00\xff\xff\xffCRASH-2")
    b.write("fuzz/crashes/known/f002/harnesses.txt", "parser\n")
    b.write("fuzz/crashes/known/f002/duplicates/parser__1122334455667788.bin", b"eXIf\x10\x00CRASH-2b")
    findings = [
        {"schema": "finding/v2", "id": "f001", "stack_hash": "a1b2c3d4e5f60718", "harnesses": ["parser"],
         "category": "heap-buffer-overflow", "subcategory": "READ-1024B",
         "location": "parse_chunk@src/parser.c:14", "exploitability": "likely",
         "root_cause": "chunk length taken from input without bounding it by the buffer size",
         "reproducer": "fuzz/crashes/known/f001/repro.bin", "first_seen": iso(N - 30000),
         "last_seen": iso(N - 4000), "dedup_count": 3, "status": "finding",
         "sanitizer_report_excerpt": "==4242==ERROR: AddressSanitizer: heap-buffer-overflow on address 0x602000000011",
         "cwe_id": "CWE-125",
         "realism_attestation": {
             "driver": "poc.c (public-API program, no harness)",
             "verifier": "fuzz/findings/f001/repro/verify.sh",
             "boundary": "confidentiality: attacker reads adjacent heap past the chunk buffer",
             "precondition": "attacker-supplied file reaches parse_chunk via the public loader",
             "projected_vs_demonstrated": "demonstrated (verify.sh exits 0 on the crossing)",
             "verifier_lines": 31, "verifier_tools": ["clang", "asan"],
             "promoted_at": iso(N - 20000)}},
        {"schema": "finding/v2", "id": "f002", "stack_hash": "0f1e2d3c4b5a6978", "harnesses": ["parser"],
         "category": "heap-buffer-overflow", "subcategory": "READ-1B",
         "location": "parse_exif@src/parser.c:25", "exploitability": "medium",
         "root_cause": "loop bound uses <= len, reading one byte past the exif buffer",
         "reproducer": "fuzz/crashes/known/f002/repro.bin", "first_seen": iso(N - 900),
         "last_seen": iso(N - 300), "dedup_count": 2, "status": "candidate"},
    ]
    b.write("fuzz/state/findings.jsonl", jsonl(findings))
    # Untriaged crashes waiting in new/, a flaky one, and the audit logs.
    b.write("fuzz/crashes/new/parser__deadbeefcafe0001.bin", b"eXIf\x00\x01\x00\x00CRASH-new-1")
    b.write("fuzz/crashes/new/parser__deadbeefcafe0002.bin", b"tEXt\xff\xff\x00\x00CRASH-new-2")
    b.write("fuzz/crashes/flaky/parser__0123456789abcdef.bin", b"eXIf\x00\x00flaky")
    b.write("fuzz/state/dropped_crashes.jsonl", jsonl([
        {"schema": "dropped-crash/v1", "ts": iso(N - 10000),
         "crash_file": "fuzz/crashes/new/parser__00000000aaaa0001.bin", "stack_hash_partial": "99887766",
         "stage": "artifact_filter", "principle": "harness_correctness",
         "reason": "harness passes a length larger than the buffer it allocated",
         "evidence": "fuzz/harnesses/parser/harness/parser_fuzzer.c:5"},
        {"schema": "dropped-crash/v1", "ts": iso(N - 8000),
         "crash_file": "fuzz/crashes/new/parser__00000000aaaa0002.bin",
         "stage": "deterministic_replay", "principle": None,
         "reason": "top frames differed across 3 replays"},
    ]))
    b.write("fuzz/state/harness-corrections.jsonl", jsonl([
        {"schema": "harness-correction/v1", "ts": N - 9000, "finding_id": "f001",
         "stack_hash": "a1b2c3d4e5f60718", "principle": "api_contract",
         "suggested_fix": "bound out->len by the input size before memcpy in the harness shim"},
    ]))
    ev = [{"schema": "event/v1", "ts": N - 45000, "tick": 0, "event": "campaign_start"}]
    for i, (ts, br, agent) in enumerate([(N - 30000, "triage", "crash-triager"),
                                         (N - 7000, "analyze_gaps", "coverage-analyst"),
                                         (N - 900, "triage", "crash-triager")], start=1):
        ev.append({"schema": "event/v1", "ts": ts, "tick": i, "event": "tick", "branch": br,
                   "reason": f"fixture tick {i}", "duration_ms": 5000, "agent_called": agent,
                   "tokens_in": 12000, "tokens_out": 3000})
        ev.append({"schema": "event/v1", "ts": ts + 5, "tick": i, "event": "agent_call",
                   "agent_called": agent, "tokens_in": 12000, "tokens_out": 3000})
    ev.append({"schema": "event/v1", "ts": N - 850, "tick": 3, "event": "error",
               "error_message": "fixture: slot main exited (crash)"})
    b.events(ev)
    b.run_script("scripts/update-current.sh", now=N - 600)
    b.validate()


BUILDERS = {
    "campaign-cold": build_cold,
    "campaign-warm": build_warm,
    "campaign-plateau": build_plateau,
    "campaign-crashes": build_crashes,
}


def main(argv):
    names = argv or list(BUILDERS)
    for n in names:
        BUILDERS[n]()
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
