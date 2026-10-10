# Changelog

Each entry says who notices: **host** (a program embedding the core, see `docs/EMBEDDING.md`), **plugin** (an interactive Claude Code user, see `README.md`), or both. Versions before 0.32.0 are in the git history.

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
