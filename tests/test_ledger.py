"""UPDATE_ROADMAP.md §10: the agent_call ledger is written by the host.

  - ledger.append is idempotent on call_id; host sources must carry one
  - precedence: host-hook / driver rows supersede orchestrator rows for the
    same agent + tick; rows without `source` are orchestrator rows
  - ledger.spend prices through models (family pricing of full model ids,
    cache tokens, overrides) and never bills `tick` rows
  - usage_from_transcript counts each assistant message id once
  - events.sh is a shim (parity goldens: tests/support/cases.py EVENTS_CASES)
  - hooks/ledger-append.sh: no-op outside a campaign, never blocks, logs
    failures under the state dir
  - the roadmap's verification clause on a recorded session: host-hook rows ==
    the SubagentStop count, spend == the transcript usage sum
"""
from __future__ import annotations

import json
import shutil
import subprocess
import unittest
from pathlib import Path

from cc_fuzzer_core import events, ledger, models
from cc_fuzzer_core.ledger import Usage
from tests.support.cases import EVENTS_CASES, assert_core_case
from tests.support.golden import FIXTURES, FROZEN_NOW, REPO, GoldenTestCase, bash, core

HOOK = REPO / "hooks" / "ledger-append.sh"
RECORDED = FIXTURES / "recorded-session"
MM = models.load(None, env={})


def _rows(sd):
    return [r for r in events.read(sd) if r.get("event") == "agent_call"]


class TestEventsShim(GoldenTestCase):
    def test_parity(self):
        for case in EVENTS_CASES:
            with self.subTest(case=case.name):
                assert_core_case(self, case)

    def test_missing_required_args(self):
        for args, msg in ((("tick",), "branch required"), (("agent_call",), "agent name required"),
                          (("error", ""), "error message required")):
            with self.subTest(args=args):
                sb = self.sandbox("campaign-warm")
                before = sb.path("fuzz/state/events.jsonl").read_text()
                r = sb.run(bash("scripts/events.sh", *args))
                self.assertEqual(r.exit_code, 1)
                self.assertIn(msg, r.stderr)
                self.assertEqual(sb.path("fuzz/state/events.jsonl").read_text(), before)

    def test_shim_is_thin(self):
        text = (REPO / "scripts" / "events.sh").read_text()
        self.assertIn("exec python3 -m cc_fuzzer_core events", text)
        self.assertNotIn("<<'PY'", text)


class _Tmp(GoldenTestCase):
    def setUp(self):
        self.sb = self.sandbox("campaign-cold")
        self.sd = self.sb.path("fuzz/state")


class TestAppend(_Tmp):
    def test_idempotent_on_call_id(self):
        u = Usage(100, 20, 3000, 400, "claude-opus-4-1")
        a = ledger.append(self.sd, agent="crash-triager", usage=u, source="host-hook", call_id="x1")
        b = ledger.append(self.sd, agent="crash-triager", usage=Usage(999, 999), source="driver", call_id="x1")
        self.assertTrue(a.appended)
        self.assertFalse(b.appended)
        self.assertEqual(b.row, a.row)
        rows = _rows(self.sd)
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0], {"schema": "event/v1", "ts": rows[0]["ts"], "tick": 0, "event": "agent_call",
                                   "agent_called": "crash-triager", "tokens_in": 100, "tokens_out": 20,
                                   "cache_read": 3000, "cache_write": 400, "model": "claude-opus-4-1",
                                   "source": "host-hook", "call_id": "x1"})

    def test_larger_report_replaces_append_only(self):
        a = ledger.append(self.sd, agent="crash-triager", usage=Usage(10, 100, 1000, 0), source="host-hook",
                          call_id="c", transcript="/t/agent-c.jsonl")
        events.append(self.sd, "tick", branch="triage", reason="", duration_ms=1)
        same = ledger.append(self.sd, agent="crash-triager", usage=Usage(10, 100, 1000, 0), source="host-hook",
                             call_id="c")
        smaller = ledger.append(self.sd, agent="crash-triager", usage=Usage(10, 50, 1000, 0), source="driver",
                                call_id="c")
        self.assertFalse(same.appended)
        self.assertFalse(smaller.appended)
        self.assertEqual(same.row, a.row)
        before = (self.sd / "events.jsonl").read_text()
        big = ledger.append(self.sd, agent="crash-triager", usage=Usage(12, 400, 1000, 50), source="host-hook",
                            call_id="c", transcript="/t/agent-c.jsonl")
        self.assertTrue(big.appended)
        after = (self.sd / "events.jsonl").read_text()
        self.assertTrue(after.startswith(before))          # nothing rewritten
        self.assertEqual(big.row["tick"], a.row["tick"])   # the call's own tick, not the current one
        self.assertEqual(big.row["transcript"], "/t/agent-c.jsonl")
        again = ledger.append(self.sd, agent="crash-triager", usage=Usage(12, 400, 1000, 50), source="host-hook",
                              call_id="c")
        self.assertFalse(again.appended)
        self.assertEqual(again.row, big.row)
        self.assertEqual(len(_rows(self.sd)), 2)
        sp = ledger.spend(self.sd, model_map=MM)
        self.assertEqual((sp.calls, sp.replaced), (1, 1))
        self.assertEqual(sp.tokens["tokens_out"], 400)
        self.assertAlmostEqual(sp.usd, MM.cost(12, 400, agent="crash-triager", cache_read=1000, cache_write=50))

    def test_replacing_row_keeps_precedence_on_the_calls_tick(self):
        ledger.append(self.sd, agent="mutator", usage=Usage(500, 50), source="orchestrator")
        ledger.append(self.sd, agent="mutator", usage=Usage(5, 5), source="host-hook", call_id="h")
        events.append(self.sd, "tick", branch="mutator", reason="", duration_ms=1)
        ledger.append(self.sd, agent="mutator", usage=Usage(9, 9), source="host-hook", call_id="h")
        st = [x for _r, x in ledger.classify(events.read(self.sd))]
        self.assertEqual(st, ["superseded", "replaced", "counted"])

    def test_orchestrator_rows_are_not_deduped(self):
        for _ in range(2):
            ledger.append(self.sd, agent="mutator", usage=Usage(10, 1), source="orchestrator")
        self.assertEqual(len(_rows(self.sd)), 2)
        self.assertNotIn("call_id", _rows(self.sd)[0])

    def test_refusals(self):
        with self.assertRaises(ledger.LedgerError):
            ledger.append(self.sd, agent="mutator", usage=Usage(1, 1), source="host-hook")
        with self.assertRaises(ledger.LedgerError):
            ledger.append(self.sd, agent="mutator", usage=Usage(1, 1), source="model", call_id="c")
        with self.assertRaises(ledger.LedgerError):
            ledger.append(self.sd, agent="", usage=Usage(1, 1), source="orchestrator")
        self.assertEqual(_rows(self.sd), [])

    def test_events_append_routes_through_ledger(self):
        r = events.append(self.sd, "agent_call", agent_called="check-slot-liveness", tokens_in=0, tokens_out=0)
        self.assertEqual(r["source"], "orchestrator")
        r = events.append(self.sd, "error", error_message="boom")
        self.assertNotIn("source", r)

    def test_tick_is_the_tick_count(self):
        events.append(self.sd, "tick", branch="sleep", reason="", duration_ms=0)
        events.append(self.sd, "tick", branch="sleep", reason="", duration_ms=0)
        r = ledger.append(self.sd, agent="mutator", usage=Usage(1, 1), source="driver", call_id="d")
        self.assertEqual(r.row["tick"], 2)

    def test_cli(self):
        r = self.sb.run(core("ledger", "append", "--agent", "mutator", "--source", "host-hook",
                             "--call-id", "h1", "--tokens-in", "5", "--tokens-out", "7", "--json"))
        self.assertEqual(r.exit_code, 0, r.stderr)
        self.assertTrue(json.loads(r.stdout)["appended"])
        r = self.sb.run(core("ledger", "append", "--agent", "mutator", "--source", "host-hook",
                             "--call-id", "h1", "--tokens-in", "5"))
        self.assertEqual(r.exit_code, 0)
        self.assertIn("already recorded", r.stdout)
        r = self.sb.run(core("ledger", "append", "--agent", "mutator", "--source", "host-hook"))
        self.assertEqual(r.exit_code, 2)
        self.assertIn("requires a call_id", r.stderr)
        r = self.sb.run(core("ledger", "spend", "--json"))
        self.assertEqual(json.loads(r.stdout)["calls"], 1)
        r = self.sb.run(core("ledger", "show", "--json"))
        self.assertEqual([x["status"] for x in json.loads(r.stdout)], ["counted"])
        r = self.sb.run(core("ledger", "show"))
        self.assertIn("host-hook", r.stdout)
        r = self.sb.run(core("ledger", "spend"))
        self.assertIn("1 call(s)", r.stdout)


class TestPrecedence(_Tmp):
    def _write(self, *rows):
        with open(self.sd / "events.jsonl", "a") as f:
            for r in rows:
                f.write(json.dumps({"schema": "event/v1", "ts": FROZEN_NOW, "event": "agent_call", **r}) + "\n")

    def test_host_rows_supersede_orchestrator_rows(self):
        self._write(
            # legacy row (no source) + an orchestrator row, tick 4: superseded by the hook row
            {"tick": 4, "agent_called": "crash-triager", "tokens_in": 1000, "tokens_out": 100},
            {"tick": 4, "agent_called": "crash-triager", "tokens_in": 1000, "tokens_out": 100,
             "source": "orchestrator"},
            {"tick": 4, "agent_called": "crash-triager", "tokens_in": 50, "tokens_out": 900,
             "cache_read": 20000, "source": "host-hook", "call_id": "h1"},
            # a different agent in the same tick: kept
            {"tick": 4, "agent_called": "mutator", "tokens_in": 300, "tokens_out": 30, "source": "orchestrator"},
            # same agent, another tick with no host row: kept
            {"tick": 5, "agent_called": "crash-triager", "tokens_in": 2000, "tokens_out": 10},
            # a driver row supersedes too
            {"tick": 6, "agent_called": "seed-generator", "tokens_in": 1, "tokens_out": 1, "source": "orchestrator"},
            {"tick": 6, "agent_called": "seed-generator", "tokens_in": 70, "tokens_out": 7,
             "source": "driver", "call_id": "d1"},
            # the same report again (e.g. a hand-copied row): one counts
            {"tick": 6, "agent_called": "seed-generator", "tokens_in": 70, "tokens_out": 7,
             "source": "driver", "call_id": "d1"},
        )
        st = [s for _r, s in ledger.classify(events.read(self.sd))]
        self.assertEqual(st, ["superseded", "superseded", "counted", "counted", "counted",
                              "superseded", "counted", "replaced"])
        sp = ledger.spend(self.sd, model_map=MM)
        self.assertEqual((sp.calls, sp.superseded, sp.replaced), (4, 3, 1))
        self.assertEqual(sp.by_agent["crash-triager"]["calls"], 2)
        self.assertEqual(sp.by_agent["crash-triager"]["tokens_in"], 2050)
        self.assertEqual(set(sp.by_source), {"host-hook", "orchestrator", "driver"})
        want = (MM.cost(50, 900, agent="crash-triager", cache_read=20000)
                + MM.cost(300, 30, agent="mutator") + MM.cost(2000, 10, agent="crash-triager")
                + MM.cost(70, 7, agent="seed-generator"))
        self.assertAlmostEqual(sp.usd, want, places=12)

    def test_superseded_rows_are_not_dispatches(self):
        # The redundancy ledger must not count one dispatch twice because the
        # host and the orchestrator both reported it.
        self._write({"tick": 1, "agent_called": "mutator", "tokens_in": 1, "tokens_out": 1},
                    {"tick": 1, "agent_called": "mutator", "tokens_in": 9, "tokens_out": 9,
                     "source": "host-hook", "call_id": "h"})
        rows = events.read(self.sd)
        self.assertEqual(ledger.dropped(rows), {id(rows[-2])})


class TestSpendPricing(_Tmp):
    def test_family_and_cache_pricing(self):
        ledger.append(self.sd, agent="mutator", usage=Usage(10**6, 10**6, 10**6, 10**6, "claude-opus-4-1-20250805"),
                      source="host-hook", call_id="c1")
        sp = ledger.spend(self.sd, model_map=MM)
        # the reported model (opus family) wins over the agent's tier (haiku)
        self.assertAlmostEqual(sp.usd, 15 + 75 + 1.5 + 18.75, places=9)
        self.assertEqual(list(sp.by_model), ["claude-opus-4-1-20250805"])

    def test_unreported_model_uses_the_agent(self):
        ledger.append(self.sd, agent="poc-builder", usage=Usage(0, 10**6), source="orchestrator")
        sp = ledger.spend(self.sd, model_map=MM)
        self.assertAlmostEqual(sp.usd, 75.0)
        self.assertEqual(list(sp.by_model), ["opus"])
        self.assertAlmostEqual(sp.usd_for(frozenset({"poc-builder"})), 75.0)
        self.assertEqual(sp.calls_for(frozenset({"poc-builder"})), 1)

    def test_overrides_and_cache_rates(self):
        cfg = {"models": {"pricing": {"opus": {"input_per_mtok": 1, "output_per_mtok": 2,
                                               "cache_read_per_mtok": 0.5, "cache_write_per_mtok": 4}}}}
        m = models.load(cfg, env={})
        self.assertAlmostEqual(m.cost(10**6, 10**6, model="claude-opus-9", cache_read=10**6, cache_write=10**6),
                               1 + 2 + 0.5 + 4)
        self.assertEqual(m.as_dict()["pricing"]["opus"]["cache_write_per_mtok"], 4.0)
        self.assertEqual(MM.as_dict()["pricing"]["sonnet"]["cache_read_per_mtok"], 0.3)

    def test_tick_rows_and_markers_do_not_bill(self):
        events.append(self.sd, "tick", branch="triage", reason="", duration_ms=1,
                      agent_called="crash-triager", tokens_in=10**6, tokens_out=10**6)
        events.append(self.sd, "agent_call", agent_called="check-slot-liveness", tokens_in=0, tokens_out=0)
        sp = ledger.spend(self.sd, model_map=MM)
        self.assertEqual((sp.usd, sp.calls), (0.0, 0))

    def test_since(self):
        ledger.append(self.sd, agent="mutator", usage=Usage(10**6, 0), source="orchestrator", now=100)
        ledger.append(self.sd, agent="mutator", usage=Usage(10**6, 0), source="orchestrator", now=200)
        self.assertEqual(ledger.spend(self.sd, since_ts=150, model_map=MM).calls, 1)

    def test_cost_cap_reads_the_ledger(self):
        # A host-hook row that supersedes a cheap orchestrator report raises
        # the hard-cap estimate to the measured spend.
        sb = self.sandbox("campaign-warm")
        sb.edit_json("fuzz/state/fuzz-config.json", lambda d: d.update(yolo={
            "enabled": True, "mode": "guided", "max_cost_usd": 1.0, "enabled_at_ts": 0, "enabled_at_tick": 0}))
        sd = sb.path("fuzz/state")
        ledger.append(sd, agent="crash-triager", usage=Usage(10, 10), source="orchestrator")
        ledger.append(sd, agent="crash-triager", usage=Usage(0, 20000), source="host-hook", call_id="h")
        r = sb.run(core("state", "update-current"))
        self.assertEqual(r.exit_code, 0, r.stderr)
        ys = r.file_json("fuzz/state/current.json")["yolo_state"]
        want = ledger.spend(sd, model_map=MM).usd
        self.assertAlmostEqual(ys["estimated_cost_usd"], round(want, 4))
        self.assertAlmostEqual(ys["evaluation"]["cost"]["total_usd"], round(want, 4))
        self.assertTrue(ys["halt_conditions"]["cost_cap"])
        # 3 coverage-analyst/seed-generator agent_call rows + the host row
        self.assertEqual(ys["evaluation"]["cost"]["opus_calls"], 1)
        self.assertEqual(ys["evaluation"]["agent_ledger"]["crash-triager"]["dispatches"], 1)


class TestReconcile(GoldenTestCase):
    def test_reconcile_catches_up_a_grown_transcript(self):
        sb = self.sandbox("campaign-warm")
        sd = sb.path("fuzz/state")
        t = sb.tmp / "agent-x.jsonl"
        full = (RECORDED / "session/subagents/agent-a1c9e0f2b3d4.jsonl").read_text().splitlines(True)
        t.write_text("".join(full[:4]))   # the hook fired before the last turn was flushed
        r = sb.run(core("ledger", "append", "--agent", "crash-triager", "--source", "host-hook",
                        "--call-id", "x", "--transcript", str(t)))
        self.assertEqual(r.exit_code, 0, r.stderr)
        first = ledger.spend(sd, model_map=MM).by_source["host-hook"]
        self.assertEqual(first["tokens_out"], 410)
        # nothing grew yet: reconcile is a no-op
        r = sb.run(core("ledger", "reconcile", "--json"))
        self.assertEqual([x["appended"] for x in json.loads(r.stdout)], [False])
        t.write_text("".join(full))
        r = sb.run(core("ledger", "reconcile"))
        self.assertEqual(r.exit_code, 0, r.stderr)
        self.assertIn("1 grew", r.stdout)
        hh = ledger.spend(sd, model_map=MM).by_source["host-hook"]
        self.assertEqual((hh["calls"], hh["tokens_out"]), (1, 1360))
        self.assertEqual(ledger.usage_from_transcript(t).total,
                         Usage.of_row([x for x in _rows(sd) if x.get("call_id") == "x"][-1]).total)
        # idempotent: a second pass appends nothing
        n = len(_rows(sd))
        sb.run(core("ledger", "reconcile"))
        self.assertEqual(len(_rows(sd)), n)
        # a vanished transcript is reported, not fatal
        t.unlink()
        res = ledger.reconcile(sd)
        self.assertEqual(len(res), 1)
        self.assertIsNotNone(res[0].error)
        self.assertEqual(len(_rows(sd)), n)


class TestTickBriefing(GoldenTestCase):
    def test_dispatched_applies_precedence(self):
        sb = self.sandbox("campaign-warm")
        sd = sb.path("fuzz/state")
        ledger.append(sd, agent="crash-triager", usage=Usage(4000, 500), source="orchestrator")
        ledger.append(sd, agent="crash-triager", usage=Usage(30, 900), source="host-hook", call_id="h")
        ledger.append(sd, agent="crash-triager", usage=Usage(30, 1200), source="host-hook", call_id="h")
        r = sb.run(bash("scripts/tick-briefing.sh"))
        self.assertEqual(r.exit_code, 0, r.stderr)
        out = next(k for k in r.files if "tick-briefing-" in k)
        got = [d for d in r.file_json(out)["dispatched_since_last_consult"]
               if d["agent"] == "crash-triager"]
        self.assertEqual(got, [{"agent": "crash-triager", "tick": 3, "tokens_in": 30, "tokens_out": 1200}])


class TestTranscript(unittest.TestCase):
    def test_duplicate_message_ids_count_once(self):
        msgs = ledger.transcript_messages(RECORDED / "session/subagents/agent-a1c9e0f2b3d4.jsonl")
        self.assertEqual(len(msgs), 2)   # 3 streamed lines + 1 line; <synthetic> skipped
        u = ledger.usage_from_transcript(RECORDED / "session/subagents/agent-a1c9e0f2b3d4.jsonl")
        self.assertEqual(u, Usage(20, 1360, 18200, 19500, "claude-opus-4-1-20250805"))

    def test_partial_last_line(self):
        u = ledger.usage_from_transcript(RECORDED / "session/subagents/agent-c3f4a5b6d7e8.jsonl")
        self.assertEqual(u, Usage(3100, 1400, 9000, 4200, "claude-sonnet-4-5-20250929"))

    def test_growing_usage_takes_the_max(self, ):
        import tempfile
        with tempfile.NamedTemporaryFile("w", suffix=".jsonl", delete=False) as f:
            for out in (5, 80):
                f.write(json.dumps({"type": "assistant", "message": {
                    "id": "m1", "model": "claude-haiku-4-5", "usage": {"input_tokens": 3, "output_tokens": out}}}) + "\n")
            f.write(json.dumps({"type": "assistant", "message": {
                "model": "claude-sonnet-4-5", "usage": {"input_tokens": 1, "output_tokens": 1}}}) + "\n")
            f.write("[1, 2]\n")
        self.addCleanup(Path(f.name).unlink)
        self.assertEqual(ledger.usage_from_transcript(f.name), Usage(4, 81, 0, 0, "claude-haiku-4-5"))


# ---------------------------------------------------------------------------
# the SubagentStop hook
# ---------------------------------------------------------------------------

def _stops(session: Path, project: Path) -> list[dict]:
    out = []
    for line in (RECORDED / "subagent-stops.jsonl").read_text().splitlines():
        line = line.replace("<SESSION>", str(session)).replace("<PROJECT>", str(project))
        out.append(json.loads(line))
    return out


class TestHook(GoldenTestCase):
    def _session(self, sb) -> Path:
        dst = sb.tmp / "home" / ".claude" / "projects" / "p"
        shutil.copytree(RECORDED, dst)
        return dst / "session"

    def _fire(self, sb, payload, cwd=None):
        return sb.run(["bash", str(HOOK)], stdin=json.dumps(payload), cwd=cwd)

    def test_records_one_row_per_subagent(self):
        sb = self.sandbox("campaign-warm")
        session = self._session(sb)
        stop = _stops(session, sb.project)[0]
        for _ in range(2):
            r = self._fire(sb, stop)
            self.assertEqual((r.exit_code, r.stdout, r.stderr), (0, "", ""))
        rows = [x for x in _rows(sb.path("fuzz/state")) if x.get("source") == "host-hook"]
        self.assertEqual(len(rows), 1)
        self.assertEqual({k: rows[0][k] for k in ("agent_called", "call_id", "model", "tokens_out")},
                         {"agent_called": "crash-triager", "call_id": "a1c9e0f2b3d4",
                          "model": "claude-opus-4-1-20250805", "tokens_out": 1360})

    def test_noop_outside_a_campaign(self):
        sb = self.sandbox(None)   # an empty project dir: no fuzz/
        session = self._session(sb)
        stop = _stops(session, sb.project)[0]
        r = self._fire(sb, stop)
        self.assertEqual((r.exit_code, r.stdout, r.stderr, r.files, r.created_dirs), (0, "", "", {}, []))
        # fuzz/ without a state dir (e.g. a cargo-fuzz tree) is not a campaign either
        sb.path("fuzz").mkdir()
        r = self._fire(sb, stop)
        self.assertEqual((r.exit_code, r.stdout, r.files, r.created_dirs), (0, "", {}, []))

    def test_never_blocks(self):
        sb = self.sandbox("campaign-warm")
        session = self._session(sb)
        stop = _stops(session, sb.project)[0]
        for payload in ("", "not json", "[1]", json.dumps({**stop, "agent_transcript_path": "/nope.jsonl"}),
                        json.dumps({**stop, "agent_id": ""}), json.dumps({**stop, "cwd": "/nonexistent"})):
            with self.subTest(payload=payload[:40]):
                r = sb.run(["bash", str(HOOK)], stdin=payload)
                self.assertEqual((r.exit_code, r.stdout), (0, ""))
        self.assertEqual([x for x in _rows(sb.path("fuzz/state")) if x.get("source") == "host-hook"], [])
        log = sb.path("fuzz/state/ledger-hook.log").read_text()
        self.assertIn("/nope.jsonl' not found", log)
        self.assertIn("no agent_id", log)
        # a failing core call (unwritable ledger) is logged, still exit 0.
        # events.jsonl is replaced by a DIRECTORY rather than chmod 0: a test
        # must not assume it runs unprivileged, and root ignores the mode bits
        # (that is exactly how this assertion silently stopped testing
        # anything in a container).
        ev = sb.path("fuzz/state/events.jsonl")
        ev.unlink()
        ev.mkdir()
        self.addCleanup(lambda: (ev.rmdir(), ev.write_text("")))
        r = subprocess.run(["bash", str(HOOK)], input=json.dumps(stop), text=True, capture_output=True,
                           cwd=sb.project, env=sb.env(None))
        self.assertEqual((r.returncode, r.stdout), (0, ""))
        self.assertIn("ledger append failed", sb.path("fuzz/state/ledger-hook.log").read_text())

    def test_refire_after_the_transcript_grew(self):
        sb = self.sandbox("campaign-warm")
        session = self._session(sb)
        stop = _stops(session, sb.project)[0]
        path = Path(stop["agent_transcript_path"])
        full = path.read_text()
        path.write_text("".join(full.splitlines(True)[:4]))
        self.assertEqual(self._fire(sb, stop).exit_code, 0)
        path.write_text(full)
        self.assertEqual(self._fire(sb, {**stop, "stop_hook_active": True}).exit_code, 0)
        host = [x for x in _rows(sb.path("fuzz/state")) if x.get("source") == "host-hook"]
        self.assertEqual([x["tokens_out"] for x in host], [410, 1360])
        self.assertEqual(host[0]["transcript"], str(path))
        sp = ledger.spend(sb.path("fuzz/state"), model_map=MM)
        self.assertEqual((sp.by_source["host-hook"]["calls"], sp.by_source["host-hook"]["tokens_out"]), (1, 1360))

    def test_derives_the_subagent_transcript(self):
        sb = self.sandbox("campaign-warm")
        session = self._session(sb)
        stop = _stops(session, sb.project)[2]
        del stop["agent_transcript_path"]
        self.assertEqual(self._fire(sb, stop).exit_code, 0)
        rows = [x for x in _rows(sb.path("fuzz/state")) if x.get("source") == "host-hook"]
        self.assertEqual([x["agent_called"] for x in rows], ["seed-generator"])

    def test_hooks_json_registers_it(self):
        d = json.loads((REPO / "hooks" / "hooks.json").read_text())
        cmds = [h["command"] for m in d["hooks"]["SubagentStop"] for h in m["hooks"]]
        self.assertEqual(cmds, ["${CLAUDE_PLUGIN_ROOT}/hooks/ledger-append.sh"])


class TestRecordedCampaign(GoldenTestCase):
    """Verification (§10): the ledger accounts for every subagent call in a
    recorded campaign transcript -- host-hook rows equal the transcript's
    SubagentStop count, and spend matches the transcript usage sum."""

    def test_recorded_session(self):
        sb = self.sandbox("campaign-warm")
        sd = sb.path("fuzz/state")
        dst = sb.tmp / "home" / ".claude" / "projects" / "p"
        shutil.copytree(RECORDED, dst)
        stops = _stops(dst / "session", sb.project)
        # The orchestrator also reported (some of) the same calls, from memory.
        for agent, ti, to in (("crash-triager", 4000, 500), ("seed-generator", 100, 10)):
            r = sb.run(bash("scripts/events.sh", "agent_call", agent, str(ti), str(to)))
            self.assertEqual(r.exit_code, 0, r.stderr)
        before = ledger.spend(sd, model_map=MM)
        for stop in stops:
            r = sb.run(["bash", str(HOOK)], stdin=json.dumps(stop))
            self.assertEqual((r.exit_code, r.stdout), (0, ""), r.stderr)

        # Independent reference: the subagent stops, and their transcripts'
        # usage summed straight from the JSONL (each message id once).
        subagents = {s["agent_id"]: s for s in stops if s.get("agent_type")}
        ref_usd, ref_tokens = 0.0, [0, 0, 0, 0]
        for aid, s in subagents.items():
            seen = {}
            for line in Path(s["agent_transcript_path"]).read_text().splitlines():
                try:
                    d = json.loads(line)
                except ValueError:
                    continue
                m = d.get("message") or {}
                if d.get("type") == "assistant" and m.get("model") != "<synthetic>":
                    seen[m["id"]] = (m["model"], m["usage"])
            for model, u in seen.values():
                t = [u.get("input_tokens", 0), u.get("output_tokens", 0),
                     u.get("cache_read_input_tokens", 0), u.get("cache_creation_input_tokens", 0)]
                ref_tokens = [a + b for a, b in zip(ref_tokens, t)]
                ref_usd += MM.cost(t[0], t[1], model=model, cache_read=t[2], cache_write=t[3])

        host = [x for x in _rows(sd) if x.get("source") == "host-hook"]
        self.assertEqual(len(host), len(subagents))
        self.assertEqual(sorted(x["call_id"] for x in host), sorted(subagents))
        self.assertEqual(sorted(x["agent_called"] for x in host),
                         ["Explore", "coverage-analyst", "crash-triager", "seed-generator"])

        sp = ledger.spend(sd, model_map=MM)
        hh = sp.by_source["host-hook"]
        self.assertEqual([hh["tokens_in"], hh["tokens_out"], hh["cache_read"], hh["cache_write"]], ref_tokens)
        self.assertAlmostEqual(hh["usd"], ref_usd, places=9)
        # Every orchestrator report for a hooked agent in this tick is
        # superseded: the two above and the fixture's tick-3 coverage-analyst
        # row. Earlier ticks' orchestrator rows still count.
        tick = host[0]["tick"]
        hooked = {x["agent_called"] for x in host}
        orch = [x for x in _rows(sd) if x.get("source", "orchestrator") == "orchestrator"
                and x["tick"] == tick and x["agent_called"] in hooked]
        self.assertEqual(len(orch), 3)
        self.assertEqual(sp.superseded, 3)
        self.assertAlmostEqual(sp.usd, before.usd - sum(MM.event_cost(x) for x in orch) + ref_usd, places=9)
        self.assertEqual(sb.run(core("schema", "validate")).stdout, "ok\n")


if __name__ == "__main__":
    unittest.main()
