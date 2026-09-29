# cull: expected upstream updates

What cc-fuzzer's cull integration (`cc_fuzzer_core.integrations.cull`) is waiting on from cull, and what switches on when each lands. Each item already has a working fallback on the cc-fuzzer side, so nothing is blocked.

Tracked against cull branch `claude/zealous-dirac-2rguih` at `95ade18` (evidence `1.7.0`, package `0.3.0`), and cull's report `docs/downstream/cc-fuzzer.md`.

## Done upstream (evidence 1.7.0)

`reach_tier`, `confidence`, `sink_class`, `access`, `call_chain`, `why`, `position`, a single `degraded` flag, and a frozen `candidate_id`. cc-fuzzer reads them (`d838aff`); a 1.7.0 intake reports every source as `cull` and `degraded_fields: []`.

## Expected

| # | cull update | Shape cc-fuzzer expects | cc-fuzzer today | What switches on |
|---|---|---|---|---|
| 8 | **`input_hints`** per result, in `properties["cull/v1"]` | `[{"value": "IHDR", "why": "tag compared at src/parse.c:88"}]`; `value` text or escaped bytes | `cc-fuzzer cull hints --dict <harness.dict>` merges nothing (no-op, tested) | Hints merged into the harness dictionary (escaped, validated, deduped, tagged `# cull`); shown on prompt cards |
| 9 | **Query engine mode**: `cull templates --json` and `cull query --db D --template T --params JSON --max-hits N --timeout S --json` | templates: `[{"name", "params", "question", "family"}]`; query: `{"schema": "cull-query/v1", "status": "ok\|unavailable\|timeout\|error", "hits": [{"path", "line", "message", "rule_id", "properties"}]}` | `cc-fuzzer cull engine` reports `unavailable`; with a `cull` config block the codeql engine stays off (no agent-written QL) | Set `query.codeql_engine` to the command `cull engine` prints and turn on `cull_query_engine`; query-analyst picks a cull template and fills params, recorded in `queries.jsonl` |
| 10 | **`cull rerank`** reads `cull-feedback/v1` | cc-fuzzer's `state/cull/feedback.jsonl` rows: `candidate_id`, `outcome` (confirmed / refuted / inconclusive), `match`, `stack_hash`, `category`, `evidence`, `cull_run` | Feedback written (append-only) when `cull_feedback` is on; nothing reads it | cull re-orders the next intake by what triage confirmed and refuted |
| 11 | **`cull rerank --coverage FILE`** | proposed `{"schema": "line-coverage/v1", "files": {"src/x.c": {"88": 1204}}}`; cull defines the final format | Nothing exported (deliberately: no private format ahead of cull's) | A coverage exporter from `snapshot-coverage` in cull's format |
| 12 | **Public validator**: `cull check <sarif>` (or `check_bug_candidates` documented as API) | exit 0 = valid; problems listed | `intake.validate()` reimplements `check_bug_candidates` plus the evidence contract | cc-fuzzer delegates to cull's checker so the two cannot drift |

## Contract cc-fuzzer relies on

- New fields arrive as a **minor** evidence bump (`1.x`). cc-fuzzer refuses major `2`; a major bump needs a cc-fuzzer change first.
- A field cull cannot establish is `null`, never absent. `reach_tier: null` (no entry point) and `call_chain: null` (no path) are answers.
- `candidate_id` stays `sha256(rule | path | line | function)[:16]`. Both repos pin the same three values in tests.
- `position` is cull's order (proofs first, then triage, diff bands before score); `rank` is a score, not the order.

## When an item lands

1. Regenerate `tests/fixtures/cull/bug-candidates.sarif` with cull's writer (keep `bug-candidates-1.6.sarif` for the fallbacks).
2. Bump `SINCE` in `intake.py` for any new field.
3. Replace the no-op or `unavailable` test with one against the real output.
4. Update this table.
