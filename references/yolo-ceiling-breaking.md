# YOLO ceiling-breaking — plateaus are a cue to reshape, not to stop

In `self_loop`/`aggressive` YOLO, a coverage plateau is **not** a stopping point. The
goal is to keep going autonomously — rewriting harnesses, adding harnesses, mocking
dependencies, switching engines — until every reachable area has been exercised. This
doc explains the machinery that makes that happen and how to steer it.

## The failure it fixes

The old `no_progress` halt was blunt: it watched `weighted_pct` and parked the campaign
after N flat ticks (default 30). It could not tell *"genuinely exhausted"* from *"the
current harness design simply can't reach the rest."* A real sd-bus campaign hit this —
it had ~10 gaps reachable only by changing the harness entry (e.g. the SASL **server**
verifier instead of the **client** one), rationalized them as a "structural ceiling,"
and disabled itself. The productive move was to reshape the harness and keep going.

## The escalation ladder

A deterministic probe (`scripts/ceiling-probe.sh` → `_lib/ceiling_probe.py`, also folded
into `current.json.yolo_state.evaluation.ceiling_probe` every tick) decides whether a
plateau is a real ceiling. It cross-references the uncovered functions against:

- gap **`harness_action`** tags from the coverage-analyst (`entry_swap` / `new_harness` /
  `mock` / `driver` / `extend` / `engine_swap`),
- **code-review** findings (high/medium confidence) still uncovered,
- **CVE hotspots** still uncovered,
- **engine fit** — a checksum/format-barrier-heavy gap mix while cmplog is inactive,

minus anything proved `dead`, to produce `structural_candidates[]`. From those it computes
`ladder_stage`:

| Stage | Meaning | Disposition | Halt? |
|---|---|---|---|
| **0** | climbing, or flat < `plateau_escalate_ticks` | normal toolbox flow | no |
| **1** | plateau + an untried structural candidate | `act` — take `recommended_structural` (the orchestrator dispatches `harness-writer` with the reshape) | suppressed |
| **2** | candidates attempted, no consult yet | `consult` — one pre-halt `planner-consult` (throttle-exempt) | suppressed |
| **3** | a consult ran, still flat | the `no_progress` halt fires, with a reason naming what was tried | **fires** |

`tick_cap` and `cost_cap` remain absolute backstops throughout, so the ladder can never
run cost away. `guided`/`hybrid` keep the legacy direct flat-count halt — this ladder is
`self_loop`-only.

The probe re-derives candidates from live coverage each tick: a reshape that actually
covered its target drops the candidate (back to stage 0/1 with the next move), and an
attempt that *didn't* help counts toward exhaustion (toward stage 3). "Attempted" is read
from `events.jsonl` since the last coverage gain — harness-writer dispatches plus the
`structural:<action>:<entry>` tick `reason` tag.

## Tuning

- `--plateau-escalate-ticks <N>` (default 8) — flat ticks before the ladder begins.
  Auto-clamped to `< --stop-on-no-progress`. Lower = react to plateaus sooner.
- `--stop-on-no-progress <N>` (default 30) — under `self_loop` this is now only the
  legacy fallback; the ladder governs the real halt.
- Want it to try harder before parking? Make sure the **coverage-analyst** tags reshape
  gaps with `harness_action` + `proposed_entry`/`mock_target` (it is instructed to), and
  drop domain hints in `fuzz/guidance.md` / `fuzz/docs/` — the probe and the pre-halt
  consult both fold those in.

## Engine choice (libFuzzer vs AFL++/Redqueen)

Engine fit is a first-class structural lever, and a decision the planner/harness-writer
must make deliberately at COLD too — **do not default to libFuzzer reflexively**:

- **libFuzzer** — fast leaf parsers/codecs with simple, flat inputs; maximum exec/s.
- **AFL++ + cmplog/Redqueen** (`cmplog_enabled: true`) — inputs gated by **magic bytes,
  checksums, length-prefix/TLV framing, multi-byte `==` comparisons, or nested format
  constraints**. Redqueen's input-to-state substitutes the comparison operand directly,
  walking through gates libFuzzer's mutator stalls on for hours. This is the single
  biggest lever for format-heavy targets.
- **Both** — run a libFuzzer slot for speed and an AFL++ cmplog slot for the gates.

On a plateau, if the remaining gaps are checksum/compare-heavy and the engine is
libFuzzer with cmplog off, the probe emits `engine_fit.recommendation:
add_aflpp_cmplog_slot` and the `engine_swap` lever lights up — the orchestrator rebuilds
with `--engine aflpp` or adds a cmplog slot. The campaign-planner's `## Harness` rubric
and `agents/harness-writer.md` (Structural reshapes) carry the full guidance.

## Reading the probe by hand

```bash
bash ${CLAUDE_PLUGIN_ROOT}/scripts/ceiling-probe.sh   # reads fuzz/state/current.json
```

prints the block and writes `fuzz/state/snapshots/ceiling-probe-<ts>.json`. `ladder_stage`
tells you where the campaign is; `recommended_structural` is the next move; `engine_fit`
is the Redqueen call; `attempted_since_plateau` is what's already been tried.
