# Changelog

Each entry says who notices: **host** (a program embedding the core, see `docs/EMBEDDING.md`), **plugin** (an interactive Claude Code user, see `README.md`), or both. Versions before 0.32.0 are in the git history.

## 0.48.0 (2026-10-25)

- **host:** delta mode (`queue.order(..., delta=True)`, `cull.delta_spread`, default on): inside each diff band the order is spread over functions, as a full scan's is over the whole queue (`queue.band_spread`): each function's best candidate in the band first, then the band's rest, and a repeat of the same (function, line, family) under another path is dropped. The bands keep their order. A large diff puts a thousand in-diff lines in a few functions, and a CPV in another changed function sat behind them. On cull 0.4.4's scans of the 38 delta databases, reranked with each task's own diff (70 CPVs with a candidate), the CPVs worked within 3 rounds of 10 cards go 49 to 56, within 10 rounds 56 to 61, and past round 300 2 to 0; 22 earlier, none later (held-out 67: 20 earlier, none later). Full mode is unchanged.

## 0.47.0 (2026-10-23)

- **host:** full mode (`queue.order`, `cull.entry_boost`, default on): before the per-function spread, each candidate's place is cull's position divided by `queue.boost(c)`, so cull's order holds wherever the boost is equal. The boost is (4 / max(call-chain length, 2)) ** 1.5, not applied to the fuzzer's own harness code; ×2 for cull confidence medium or high; ×0.5 for the fixed-offset and ambiguous-capacity tiers and for CWE-690. On cull 0.4.0's scans of the 16 full-mode survey benchmarks (38 CPVs with a candidate), CPVs in the first 30 queue places go 13 to 16 and the geometric mean of their first places 52 to 37 (at worst ×2.4, one benchmark later). On the 38 delta databases in full order (67 CPVs), the first 30 go 16 to 19 and the first 10 6 to 8. Delta order is unchanged.

## 0.46.0 (2026-10-12)

- **host:** delta mode, once the sweep is complete (`queue.order(..., sweep_done=True)`, `cull.rare_after_sweep`, default on): the best candidate of each rare class goes first, once per class. A rare class is a pattern with at most `cull.rare_class_max` (25) candidates, such as a hang, a lifetime or a null. After the sweep, delta order is cull's order for code far from the diff. On file's delta, the out-of-diff ReDoS CPV (the only hang candidate) moves from 88th to 2nd. libssh2's and libexif's CPVs keep their places. Before the sweep completes nothing moves; full mode is unchanged.

## 0.45.0 (2026-10-10)

- **host:** a cull alert on a hang libFuzzer reports (CWE-1333 ReDoS, 400, 407, 674, 835) is imported as an `infinite_loop` candidate (sink class `timeout`) instead of `other`, which the default `import_other: false` dropped. cull's new `redos` preset flags a regex compiled from a non-constant pattern, and file's ReDoS CPV is such a hang.

## 0.44.0 (2026-10-10)

- **both:** cull cards are written so the model can triage them without opening the file.
  - `cards.render(source_root=, pool=)` shows the sink line itself, and says how many more candidates the card's function has and on which lines.
  - cull's "no comparison is possible: missing sink.dest_capacity" (on 7 of sqlite3's first 10 cards) now reads as "cull could not determine the buffer size here …".
  - Input hints keep text first, then values the input reaches, drop an integer's second byte order, and stop at `cull.card_max_hints` (8).
  - `cull.cards_max_tokens` goes from 2,000 to 3,000; ten such cards measured 1,511 tokens on sqlite3.

## 0.43.0 (2026-10-10)

- **both:** the full-scan cull queue is spread over functions (`cull.per_function`, default on). Each function's best candidate comes first, in cull's order. A function with a candidate already done waits behind every function no round has looked at, because the queue is rebuilt each round. A repeat of the same (function, line, family) under another path is dropped. cull lists every sink line, so one function could fill the queue: sqlite3's generated parser `yy_reduce` held at least the first 25 places. Over the 35 full-mode CPVs cull has a candidate for, in rounds of 10 cards, the median round in which the CPV's candidate first appears goes from 24 to 8, and the number reached by round 10 from 14 to 23. None comes later. Delta mode keeps its diff-proximity order.

## 0.42.0 (2026-10-10)

- **both:** a sweep `unreachable` verdict for an item inside a function the fuzzer already executes needs `--input`: an input that reaches the function, and the guard that stops the line. Code reading alone is refused. The coverage comes from `$CC_FUZZER_SWEEP_COVERAGE` (`mark(executed=)`); without it nothing changes. On a libssh2 delta the agent marked the hunk holding the CPV "dead in this harness. Confirmed by code reading" while the fuzzer ran that function; a nested key exchange reaches the line. The `delta-sweep` skill says so.

## 0.41.0 (2026-10-10)

- **both:** minimization stops when its probe budget is spent. Before, ddmin went on after the last allowed run: every candidate then answered "no", so it doubled the granularity down to single bytes and built a full-size complement for each chunk. On a 131 KB sqlite3 crasher that was about 788,000 candidates and 30 minutes after the 400th run (a host holding a lock through triage waited all that time). The same inputs now finish in 28 s and 40 s with identical results. `ddmin(..., spent=)` takes the stop condition.

## 0.40.0 (2026-10-10)

- **both:** delta sweep class `macro-arg`: an added call to an ALL-CAPS function-like macro with an expression argument. Given the source tree (`sweep.build(..., src_root=)`, CLI `sweep init --src`), the item's `note` carries the macro's expansion from its `#define` (the calling file first, then its directory, then headers). An argument that regroups in the body makes the item `macro-precedence`, listed first: `CHECKOVERFLOW(off, size, 6+8+4)` with `size - structsize` in the body checks `size + 6`. On libexif delta-02 the agent reached that line and marked it "a pure refactor" without expanding the macro. Over the 47 benchmark deltas the class adds 7 items. A plain `macro-arg` sorts with the weakest sinks, and a macro name inside a string literal is not a call.
- **plugin:** the `delta-sweep` skill builds the sweep with `--src` and says to judge a macro call by its expansion.

## 0.39.0 (2026-10-10)

- **host:** `stoprules.Policy.min_round_s`: the in-round stall never ends a round younger than this. `Rounds.stall_due(round_s=, idle_s=, stall_s=)` makes the whole stall decision. `default_policy` sets it to 900 s (the stall is off in full mode, so it matters in delta). Before, with a bug known from an earlier round, the 300 s stall ended every later delta round while the model was still re-reading the code: in 6 of 6 delta model runs those rounds ran no input. A bare `Policy()` has no floor, and the `parity` after-round decisions are unchanged.

## 0.38.1 (2026-10-09)

Documentation and packaging; no behaviour change in the core.

- **plugin:** the quick start works. A `.claude-plugin/marketplace.json` makes the repository a one-plugin marketplace, so both `/plugin marketplace add cloudripper/cc-fuzzer` and a local clone install it; `claude plugin validate` passes. The README's quick start and prerequisites are rewritten as a path a new user can follow, and the README now describes every hook, the `cc-fuzzer` CLI, all 16 agents and all 24 skills, model routing, and troubleshooting.
- **plugin:** `MANIFEST.md5` is regenerated, including the plugin trees (`.claude-plugin/`, `agents/`, `skills/`). 0.36.4 to 0.38.0 shipped a stale one, so every session started with "DRIFT DETECTED". `tests/test_manifest_current.py` now fails when it is stale.
- **plugin:** hook commands quote `${CLAUDE_PLUGIN_ROOT}`, which broke on an install path containing a space. The hooks description names the findings gate.
- **host:** `docs/EMBEDDING.md` is brought up to 0.38: hangs and OOMs (`replay_args`, `screen`, `UNMINIMIZED`), a crash vocabulary appendix, agent-behaviour helpers (`hygiene`, `sweep`, `governor`, `stoprules`), an environment variable table and the full schema list. Sections are renumbered, and twelve stale passages are corrected, the verify build's sanitizer and the `builtin:memory-safety` reject list among them.

## 0.38.0 (2026-10-09)

- **host:** `stoprules`, the round policy for a host that runs model rounds beside a fuzzer. It covers three decisions: continue or stop after a round, the in-round stall, and, once stopped, idle, reopen or exit. `parity` reproduces ParallaxCRS's qualification rules (a test replays 3,000 random histories through both); `evidence` keeps rounds going while delta targets are open and reopens them on new evidence; `give_up_after_s` lets a run end once nothing progresses.

## 0.37.0 (2026-10-09)

- **host:** `governor`, a nudge toward running inputs after a long reading streak (default 30 calls). Replayed on 45 qualification rounds it counts 88.6% reading and 2.6% input runs. CLI: `cc-fuzzer governor observe` reads a PostToolBatch hook input on stdin. The plugin does not register it.

## 0.36.5 (2026-10-06)

- **both:** libFuzzer's own OOM report (`ERROR: libFuzzer: out-of-memory`) is now category `oom`; before, it read as no crash. The sanitizer runtime's C++ frames no longer name the site.
- **host:** a record may carry `replay_args`, libFuzzer flags placed before the reproducer. Pass the scorer's (CRSBench: `-timeout=25 -rss_limit_mb=2560`) and a hang is reported by libFuzzer with its stack instead of being killed silently.
- **host:** triage skips minimization and the byte map for `timeout` and `oom` (`crs.UNMINIMIZED`): every probe would run to the limit.

## 0.36.4 (2026-10-06)

- **both:** an abort or failed assertion is named by the target function that called it, not by libc's `raise`/`__assert_fail`, which made every abort in every target one site.

## 0.36.3 (2026-10-06)

- **host:** the sweep Stop gate's block cap (3) is per session: `sweep gate --session`. A CRS with one session per round got three blocks in all.

## 0.36.2 (2026-10-05)

- **host:** the cull queue follows cull's own order; the reach tier only breaks ties. The tiers had pushed CPVs from cull's 375th–816th place to ~1,600th–9,000th.

## 0.36.0 – 0.36.1 (2026-10-05)

- **both:** `hygiene`, the duplicate-call guard: a tool call repeated within one response runs once. On qualification, 32% of Reads and 28% of Bash calls were in-response duplicates. Hook: `hooks/dedup-calls.sh` (PreToolUse + PostToolBatch). 0.36.1: a copy carrying the original's call id counts as a duplicate, which every observed duplicate did.
- **host:** the core returns decisions and the hook scripts speak Claude Code's JSON (`sweep gate --json [--continuing]`).
- Tests drive the real Claude Code CLI against a scripted mock endpoint (`tests/support/claude_driver.py`).

## 0.35.0 – 0.35.1 (2026-10-05)

- **both:** `sweep` turns a diff into a checklist (`delta-sweep/v1`): one item per risky added line, each needing a verdict with a reason. CLI `cc-fuzzer sweep init|show|mark|gate`, the `delta-sweep` skill, and an opt-in Stop hook (`hooks/sweep-gate.sh`; the plugin does not register it). `CC_FUZZER_SWEEP_FILE` serves a host with no campaign. 0.35.1 measured the classes against 79 delta CPVs: 64 on the vulnerable line.

## 0.34.0 – 0.34.1 (2026-10-05)

- **host:** `crs.rank` orders confirmed crashes, most worth submitting first (`submission-rank/v1`); no crash ranks below every crash.
- **both:** `claude-code.contract.json` records the Claude Code version the plugin was tested on (2.1.285) and every name it relies on; `scripts/claude-code-contract.py` checks them against that version's binary.
- **host:** triage `screen=` labels raw fuzzer artifacts by cause (crash, leak, timeout, oom, exit, none) before a full triage, so an exit or a leak costs one run.
- **both:** an ASan SEGV is split into `null-deref`, `wild-read`/`wild-write`/`wild-access` and `format-string`.

## 0.33.0 (2026-09-29)

- **host:** public policy helpers (`crs.policy`, `crs.normalize`, `crs.resolve_policy`).

## 0.32.0 (2026-09-29)

- **host:** PoV clustering (`crs.cluster`, `crs.merge_by_patch`), a configurable gate, CI, and a consistency pass.

## Earlier fixes worth knowing (between 0.31 and 0.33)

- Replay runs UBSan builds with `silence_unsigned_overflow=1`, as OSS-Fuzz and its scorers do, and ASan with `handle_sigill=1` (AIxCC faad2 cpv_1 is judged by "AddressSanitizer: ILL").
- `patch`: a neighbours variant the runner cannot run leaves the gate unrun instead of failing it.
