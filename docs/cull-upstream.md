# cull: expected upstream updates

What cc-fuzzer's cull integration (`cc_fuzzer_core.integrations.cull`) is waiting on from cull, and what switches on when each lands. Each item already has a working fallback on the cc-fuzzer side, so nothing is blocked.

Tracked against cull `main` at `9bd1266` (evidence `1.8.0`, package `0.3.0`), and cull's report `docs/downstream/cc-fuzzer.md`.

## Done

| # | cull update | Evidence | cc-fuzzer side |
|---|---|---|---|
| 1-7 | `reach_tier`, `confidence`, `sink_class`, `access`, `call_chain`, `why`, `position`, a single `degraded` flag, a frozen `candidate_id` | 1.7.0 | Read as cull's answers; a 1.7.0+ intake reports every source as `cull`. |
| 8 | **`input_hints`** in `cull/v1` and the evidence: `[{value, encoding, hex, kind, why, tainted}]` | 1.8.0 | `SINCE["input_hints"] = (1, 8)`. `cc-fuzzer cull hints --dict <harness.dict>` builds each token from `bytes.fromhex(hex)` (`value` is only a rendering; an escaped one would be escaped twice), drops an escaped hint with no `hex`, validates, dedups and tags `# cull`. Hints show on prompt cards. |
| 9 | **Engine mode**: `cull templates --json`, `cull query --db D --template T --params JSON --max-hits N --timeout S --json` answering `cull-query/v1` | package 0.3.0 | `cc-fuzzer cull engine` finds it and prints the `query.codeql_engine` command; `query.run` reads the real `cull-query/v1` (tested against the installed cull). No hits without a CodeQL database: cull answers `unavailable`. |
| 10 | **`cull rerank SARIF --feedback JSONL`** reads `cull-feedback/v1` | package 0.3.0 | Pass `fuzz/state/cull/feedback.jsonl` (written when `cull_feedback` is on). |

The fixture `tests/fixtures/cull/bug-candidates.sarif` is cull 0.3.0's writer output at evidence 1.8.0 (the eight-key `cull/v1` bag, with `diff_proximity` labels for `cull queue --delta`); `tests/fixtures/cull/make_fixture.py` regenerates it.

## Expected

| # | cull update | Shape cc-fuzzer expects | cc-fuzzer today | What switches on |
|---|---|---|---|---|
| 11 | **`cull rerank --coverage FILE`** | proposed `{"schema": "line-coverage/v1", "files": {"src/x.c": {"88": 1204}}}`; cull defines the final format | Nothing exported (deliberately: no private format ahead of cull's) | A coverage exporter from `snapshot-coverage` in cull's format |
| 12 | **Public validator**: `cull check <sarif>` (or `check_bug_candidates` documented as API) | exit 0 = valid; problems listed | `intake.validate()` reimplements `check_bug_candidates` plus the evidence contract | cc-fuzzer delegates to cull's checker so the two cannot drift |

## Contract cc-fuzzer relies on

- New fields arrive as a **minor** evidence bump (`1.x`). cc-fuzzer refuses major `2`; a major bump needs a cc-fuzzer change first.
- A field cull cannot establish is `null`, never absent. `reach_tier: null` (no entry point) and `call_chain: null` (no path) are answers.
- `candidate_id` stays `sha256(rule | path | line | function)[:16]`. Both repos pin the same three values in tests.
- `position` is cull's order (proofs first, then triage, diff bands before score); `rank` is a score, not the order.

## When an item lands

1. Regenerate `tests/fixtures/cull/bug-candidates.sarif` with `tests/fixtures/cull/make_fixture.py` (keep `bug-candidates-1.6.sarif` for the fallbacks).
2. Bump `SINCE` in `intake.py` for any new field.
3. Replace the no-op or `unavailable` test with one against the real output.
4. Update this table.
