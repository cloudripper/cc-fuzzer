# cc-fuzzer

A Claude Code plugin for **LLM-in-the-loop coverage-guided fuzzing, concolic execution, and crash triage** of C/C++ source and binaries. It keeps a real fuzzer (libFuzzer / AFL++) fed and steered by model agents, then verifies and reports what it finds.

cc-fuzzer is **not** a Cyber Reasoning System. It covers the dynamic-analysis half of what a CRS does (fuzzing + concolic + triage + reporting) plus a static code-review pass; autonomous SAST is partial and patch generation is out of scope. The architecture reuses three named patterns from the DARPA AIxCC finalists — see [AIxCC patterns](#aixcc-patterns) and [Scope](#scope).

## Quick start

```
# 1. Install (one-time, inside Claude Code)
/plugin marketplace add ./cc-fuzzer
/plugin install cc-fuzzer

# 2. (Recommended) pinned-toolchain dev shell — see Prerequisites for the no-nix path
cd ~/projects/your-target
nix develop $CLAUDE_PLUGIN_ROOT
claude

# 3. Start a campaign and drive the loop
/cc-fuzzer:campaign src/parser.c parse_message
/loop 10m /cc-fuzzer:tick

# 4. Check progress (pure shell, no LLM call) / render findings / stop
/cc-fuzzer:status
/cc-fuzzer:report
/cc-fuzzer:stop
```

`/cc-fuzzer:campaign` runs COLD setup once (analyze → harness → 3 binaries → seed corpus → launch fuzzer). `/loop 10m /cc-fuzzer:tick` fires WARM ticks every 10 minutes. `/cc-fuzzer:report` re-runs every recorded reproducer against the current harness binary and writes `fuzz/state/FINDINGS-REPORT.md`. To pick a stopped campaign back up without re-analyzing, `/cc-fuzzer:resume-campaign`.

Prefer not to babysit the loop? `/cc-fuzzer:yolo on` opts into auto-ticking (off by default) — see [YOLO](#yolo-self-looping).

## How it works

The campaign splits into a one-time **COLD** setup and a steady-state **WARM** tick. The fuzzer runs continuously in the background; each WARM tick the orchestrator reads one file (`fuzz/state/current.json`) and either sleeps or dispatches **one** specialist. On a manual tick (and YOLO `guided` mode) the dispatch branch is computed **deterministically** by `update-current.sh` and the orchestrator just executes it; YOLO's `hybrid`/`self_loop` modes let the orchestrator reason over cost/redundancy/progress signals to decide instead.

```
COLD (once)
  PLAN (Opus) → HARNESS (3 binaries + opt cmplog) → SEED → LAUNCH
                                                       │
                                                       ▼
   ┌───────────────────────────────────────────────────────────┐
   │ FUZZ + CMPLOG (background, persistent)                    │
   │  AFL++ feeds cmplog operands into its own mutation queue. │
   │  Silent, no LLM.                                          │
   └───────────────────────────────────────────────────────────┘
                                  │
   snapshot-coverage.sh ──────────┤
   extract-cmplog-dict.sh ────────┘  (refreshed on gap analysis)
                                  │
                                  ▼
WARM tick (one per /cc-fuzzer:tick)
  update-current.sh → current.json.recommendation.branch
                                  │
   ┌──────────────────────────────┴───────────────────────────┐
   │ DISPATCH (one specialist, or sleep)                      │
   │   sleep              — coverage climbing, no work         │
   │   analyze_gaps     → coverage-analyst                     │
   │   generate_seeds   → seed-generator                       │
   │   concolic         → concolic-executor (SymCC, hard gaps) │
   │   mutator          → mutator (structure-aware input)      │
   │   triage           → crash-triager (verification pipeline)│
   │   restart_fuzzer   → kill + relaunch                      │
   │   fix_instrumentation → refuse to advance, surface errors │
   └────────────────────────────────────────────────────────────┘
```

The orchestrator's most important job is **knowing when not to do work**: token cost is dominated by re-walking source unnecessarily, so a steady tick where coverage is climbing should sleep.

### Three-mode state machine

Every orchestrator invocation begins with `check-campaign-state.sh`:

| State | Mode | Behavior |
|---|---|---|
| `none` | **COLD** | Full setup: analyze, harness, build 3 binaries (+ opt cmplog), bootstrap corpus, launch. |
| `stopped` | **RESUME** | Relaunch with the existing harness and corpus, then one tick. |
| `running` | **WARM** | Read `current.json`, decide, optionally dispatch one specialist. |
| `stale` | **REFUSE** | Target source changed since the harness was built → `/cc-fuzzer:reset` or `--reset`. |
| `corrupted` | **REFUSE** | Schema validation failed → fix or reset. |

## Components

### Subagents (model-routed)

| Subagent | Model | Role |
|---|---|---|
| `fuzz-orchestrator` | sonnet | Owns the loop. Dispatches COLD/RESUME/WARM; on warm ticks reads only `current.json`. |
| `campaign-planner` | **opus** | Writes `plan.md` (target, harness layout, seed/dict/concolic strategy, coverage targets). Fresh at COLD, revise mid-campaign. |
| `planner-consult` | **opus** | Per-tick strategic check-in: reads a small briefing, returns `stay_course` or `redirect` + tactic. Opus-in-the-loop without paying Opus on every tick. |
| `harness-writer` | sonnet | Writes the harness, builds **three** binaries (+ optional cmplog), iteratively repairs build failures (OSS-Fuzz-Gen pattern). |
| `seed-generator` | haiku | Bootstrap corpus + targeted seeds aimed at specific gaps. |
| `mutator` | haiku | Writes a `LLVMFuzzerCustomMutator` for highly-structured inputs the default mutator can't reach. |
| `coverage-analyst` | sonnet | Turns coverage + cmplog dict into a ranked `gaps-report/v1` with gap classes (`direct_compare`, `checksum_barrier`, `deep_path_condition`, …). |
| `concolic-executor` | haiku | Drives SymCC against `checksum_barrier` / `deep_path_condition` gaps (Atlantis-Multilang `concolic_input_gen` pattern). |
| `code-reviewer` | sonnet | Tier-2 static review: classifies dangerous-API candidates from the deterministic prescan. |
| `code-reviewer-deep` | **opus** | Tier-3 cross-file taint analysis on flagged candidates; adds findings the Sonnet pass missed. |
| `crash-triager` | **opus** | Runs the verification pipeline; only verified crashes become findings. |
| `poc-builder` | **opus** | Builds a verifiable exploit (not just a reproducer) whose impact is checked by a `verify.sh`. |
| `reporting-agent` | **opus** | Re-runs every reproducer and writes `FINDINGS-REPORT.md` (confirmed vs. false-positive, `git blame` provenance). |

### Skills (`/cc-fuzzer:<name>`)

Claude may auto-invoke the read-only utilities (`status`, `doctor`, `validate`, `delta`, `dictionaries`) and the `campaign` headline; the rest carry `disable-model-invocation: true`.

That flag gates **slash commands** only — it stops the *ambient* assistant from firing an expensive command (`/cc-fuzzer:triage`, `/cc-fuzzer:poc`, …) you didn't ask for. It does **not** gate **subagents**: once a campaign is running, the orchestrator dispatches the underlying agents — including Opus ones like `crash-triager` and `planner-consult` — directly via the Task tool. Each gated skill is just a thin wrapper that dispatches the same agent for one-off manual use. Starting the loop (`/cc-fuzzer:campaign`, `/cc-fuzzer:tick`, or `/cc-fuzzer:yolo on`) is your authorization for that autonomous dispatch; under YOLO the cost/redundancy ledger — not the skill gate — bounds how much Opus it spends.

- **Campaign loop** — `campaign` (headline; auto-detects COLD/RESUME/WARM), `tick`, `resume-campaign`, `run`, `stop`, `yolo`, `reset`
- **Analysis & corpus** — `plan`, `harness`, `seed`, `coverage`, `concolic`, `review`, `delta`, `dictionaries`
- **Findings** — `triage`, `poc`, `report`
- **Read-only** — `status`, `doctor`, `validate`

### State

All campaign state lives under `fuzz/state/`. The authoritative spec is **`STATE_SCHEMA.md`** at the plugin root (current schema **v9**). The orchestrator reads only `current.json` on warm ticks. Findings are written exclusively by `scripts/findings.sh` (which runs the verification pipeline); the report only by `reporting-agent`. Plugin scripts are read-only — your only writable scope is `fuzz/`.

## Key mechanisms

### Three binaries (plus one)

Every COLD start builds three mandatory binaries:

1. **Fuzzing** — libFuzzer + ASan + UBSan.
2. **Coverage** — `-fprofile-instr-generate -fcoverage-mapping`, no fuzzer driver; run as a normal program by `snapshot-coverage.sh`.
3. **Verify** — ASan + UBSan only, **no `-fsanitize=fuzzer`**; used to filter harness artifacts (a crash that reproduces in the fuzzer but not here is not a real target bug).

Optionally a **cmplog** binary (`AFL_LLVM_CMPLOG=1`, no sanitizers) when AFL++ + `afl-clang-fast` are present. Cmplog is purely additive — without it the campaign falls back to source-only gap reasoning.

### Crash verification

`crash-triager` runs a multi-step pipeline before any crash becomes a finding: an **artifact filter** (four-principle audit that catches harness-only crashes), **deterministic replay** (multiple runs under ASan with identical top frames), and a **target-realistic reproducer** (the target's own CLI rebuilt with ASan, or a small program using only public headers). Crashes that fail any step are logged to `fuzz/state/dropped_crashes.jsonl` (transparency log) and never filed. Confirmed findings ship as self-contained `fuzz/findings/<id>/repro/` bundles a maintainer can verify in their own environment; `/cc-fuzzer:report --mode pre-contact|maintainer|public` renders disclosure-aware reports.

### The cmplog / LLM / SymCC split

Constraint-solving work is routed to the cheapest tool that can handle it:

```
Easy   (linear, direct compares)  → cmplog       (AFL++ runtime, free)
Medium (transformations, math)    → LLM seed-gen  (semantic)
Hard   (checksums, multi-cond)    → SymCC + Z3    (expensive, last resort)
```

`extract-cmplog-dict.sh` also surfaces cmplog's runtime observations to the agents as a dictionary, so `coverage-analyst` can mark a gap `direct_compare` (cmplog already handling it) instead of paying for a concolic run, and `seed-generator` can ground its seeds in operands that actually exist in the binary. SymCC setup is one-time (`scripts/install-symcc.sh` then `scripts/build-symcc-target.sh`); if it's absent the orchestrator simply skips concolic gaps. SymCC caveats: no inline asm, limited C++ exceptions, path explosion on input-bounded loops (capped per-seed).

### Multi-fuzzer / multi-harness

Single-fuzzer is the default (one `main` slot, engine auto-detected). To run several fuzzers against a shared corpus, declare slots in `fuzz/state/fuzz-config.json`:

```json
{
  "schema": "fuzz-config/v3",
  "fuzzer_slots": [
    {"slot": "main",        "engine": "libfuzzer"},
    {"slot": "afl-explore", "engine": "aflpp", "role": "secondary", "afl_power_schedule": "explore"}
  ]
}
```

Each slot gets its own `fuzzer-<slot>.{pid,engine,log}`; the live manifest is `fuzzers.json`. The orchestrator treats all slots as one shared-corpus campaign (one recommendation, one triage pass, one coverage view). At the top of each tick, `check-slot-liveness.sh` silently relaunches any dead slot (anti-flap throttle: 3 restarts in 60s → marked deadlocked); `restart_fuzzer` only surfaces when *every* slot is dead. Schema v9 additionally supports multiple **harnesses** in one campaign, each with its own corpus/coverage under `fuzz/harnesses/<name>/`.

> **AFL++ on `process_based` harnesses:** the launcher auto-bumps the per-input timeout to 5000 ms and passes `-t <ms>+` (skip-on-timeout) so a fork-exec'ing CLI target can clear AFL's dry-run. Override per-slot with `"timeout_ms": <ms>`.

### YOLO (self-looping)

`/cc-fuzzer:yolo on [--mode guided|hybrid|self_loop] [--aggressiveness conservative|balanced|aggressive]` opts into auto-ticking (off by default; the orchestrator calls `ScheduleWakeup` at end-of-tick). All modes share hard halt caps (tick / cost / no-progress / crash-storm) and a deterministic per-tick **evaluation** block — cost posture (throttles Opus agents past a soft fraction of the cost cap), a per-agent **redundancy ledger** (suppresses an agent that loops without producing results), and a self-climbing signal.

| Mode | Default posture | Per-tick decision |
|---|---|---|
| `guided` | `conservative` | Legacy deterministic precedence table; `sleep` is the last resort; a self-climbing fuzzer means wait. |
| `hybrid` (default) | `balanced` | The orchestrator reasons over the evaluation signals to choose **wait / act / consult**, and acts on a concrete gap move *even while the fuzzer climbs*. Waits (with backoff) when there's no gap move, an agent is looping, or cost is throttling Opus. |
| `self_loop` | `aggressive` | Maximum autonomy: the orchestrator reasons freely toward the goal, pursuing multi-step strategy across ticks. A self-climbing fuzzer is **not** a reason to idle — when no gap move remains it pursues the strategic toolbox (harness/CVE/review/PoC/plan) in parallel; the backoff does not compound. Still fenced by the caps + redundancy/cost ledger. |

**Aggressiveness** decouples "how hard a tick pushes to act" from the mode and defaults from it (override with `--aggressiveness`). `aggressive` never idles on a self-climbing fuzzer, treats an empty gap-branch as "pursue the strategic toolbox", keeps the wait-backoff from compounding (so priorities never go stale), and raises the Opus-throttle point to 0.8 of the cost cap.

`/cc-fuzzer:stop` always disables YOLO.

## Steering with `fuzz/guidance.md`

Optional and user-controlled. Copy the template and fill in what you care about:

```bash
cp $CLAUDE_PLUGIN_ROOT/templates/guidance.md fuzz/guidance.md
```

When present, `seed-generator` (input classes, formats, dictionaries), `coverage-analyst` (coverage targets, out-of-scope code), and `fuzz-orchestrator` read it during the loop. Absent, all three fall back to default heuristics — guidance is purely additive.

For longer reference material — protocol specs, RFCs, format notes, prior advisories — drop files in **`fuzz/docs/`**. Under YOLO `self_loop`, the toolbox board's `references` signal surfaces `guidance.md` and `fuzz/docs/` (with a `changed_recently` flag) so the orchestrator re-reads them and reasons about moves the built-in lever catalog can't express. The board is explicitly a *floor, not a ceiling*: it guarantees no known lever is forgotten, while your steering drives the creative, open-ended reasoning on top.

## Reproducible toolchain (Nix)

The plugin ships a Nix flake that pins the whole toolchain (clang+compiler-rt, AFL++, SymCC, Z3, llvm-cov/profdata, gdb, addr2line, plus ripgrep/fd). The dev shell is wrapped in `buildFHSEnv` because AFL++ and SymCC assume a traditional `/usr/bin`, `/usr/lib` layout — the FHS wrapping is load-bearing, not cosmetic.

```bash
cd ~/projects/your-target
nix develop $CLAUDE_PLUGIN_ROOT     # exports CC_FUZZER_FHS=1; auto-binds $PWD
claude
```

The SessionStart hook (`scripts/env-check.sh`) reports whether you're in the cc-fuzzer FHS shell, some other nix shell, or on host tools — and only warns inside directories that contain a `fuzz/`. The plugin does **not** ship a `flake.lock`: run `nix flake update` once per project to get a lock you own, which pins your toolchain for the campaign. The plugin imposes the toolchain *shape*; you own the *version*.

No nix? Everything still works with host tools (see [Prerequisites](#prerequisites)); `scripts/install-symcc.sh` bootstraps SymCC, and preflight reports what's missing.

## Plugin integrity (`MANIFEST.md5`)

`MANIFEST.md5` fingerprints every shipped file. Agents are told plugin files are read-only, but in-place patches have happened — they silently vanish on `/plugin install` and leave mystery regressions. `scripts/integrity-check.sh` makes drift loud: it runs at SessionStart, in `/cc-fuzzer:doctor`, and is referenced by every subagent before it trusts its memory of a script. A "DRIFT DETECTED" warning is non-fatal — reinstall to restore canonical state, or, if you're a developer iterating, regenerate the manifest before cutting a release.

## Scope

A real CRS produces both proofs-of-vulnerability **and** patches, with autonomous SAST, ensemble orchestration, and submission infrastructure. cc-fuzzer covers the dynamic-analysis half plus a static review pass:

| Capability | cc-fuzzer | A real CRS |
|---|---|---|
| Coverage-guided fuzzing (libFuzzer / AFL++) | ✓ | ✓ |
| Concolic execution on hard constraints | ✓ | ✓ |
| LLM-guided harness / seed / mutator generation | ✓ | ✓ |
| Crash triage + verification + reporting | ✓ | ✓ |
| Static analysis | partial (LLM code-review pass) | ✓ |
| Patch generation, ensemble orchestration, cloud submission | out of scope | ✓ |

### AIxCC patterns

cc-fuzzer is not a port of any single AIxCC system, but it reuses three named patterns:

| Pattern | Source | Where it lives |
|---|---|---|
| LLM-augmented coverage fuzzer loop | [Buttercup](https://github.com/trailofbits/buttercup) (Trail of Bits) | `fuzz-orchestrator` + `seed-generator` + `mutator`, driven by the WARM loop |
| `concolic_input_gen` — SymCC against specific uncovered constraints | [Atlantis-Multilang](https://github.com/Team-Atlanta/atlantis-multilang-snapshot/tree/main/uniafl/src/concolic) (Team Atlanta) | `concolic-executor` + `run-concolic.sh` + `build-symcc-target.sh` |
| Iterative harness build-repair | [OSS-Fuzz-Gen](https://github.com/google/oss-fuzz-gen) (Google) | `harness-writer`'s repair loop |

Ensemble / inter-CRS exchange / container orchestration are intentionally **not** used (single-host, single-process). cc-fuzzer borrows a few organizing concepts from [OSS-CRS](https://github.com/ossf/oss-crs) loosely (plugin manifest ≈ `crs.yaml`, shared corpus dir, `budget.json` spend tracking) but doesn't aspire to CRS-hood.

## Cost

Typical token mix: ~60% Haiku (seeds, mutator, concolic dispatch), ~25% Sonnet (orchestrator, harness, coverage), ~15% Opus (one-shot planner, per-crash triager, per-report). Roughly an order of magnitude cheaper than running everything on Opus, with Opus reserved where its quality matters: the initial plan, root-cause analysis, exploit-building, and the verified report. `--budget` (default $20) caps total spend; near the cap the orchestrator drops lower-priority specialist calls and continues with the fuzzer alone. (YOLO has its own separate `--max-cost`, default $10.)

## Prerequisites

**Path A — nix (recommended).** Install nix once (e.g. the Determinate Systems installer); the flake provides everything else.

**Path B — host tools.** Install what you're missing (the SessionStart hook reports gaps): `clang`/`clang++` + `compiler-rt`, `afl-fuzz` + `afl-clang-fast`, `llvm-cov` + `llvm-profdata`, `gdb` + `addr2line`, and SymCC (`scripts/install-symcc.sh` for a build-from-source path).

## Customizing model routing

Each subagent's model is set in its frontmatter. To force a single model temporarily:

```bash
export CLAUDE_CODE_SUBAGENT_MODEL=claude-sonnet-4-6   # unset to restore defaults
```

## References

- Buttercup (Trail of Bits, AIxCC runner-up): https://github.com/trailofbits/buttercup
- Atlantis (Team Atlanta, AIxCC winner): https://team-atlanta.github.io/blog/post-afc/
- Atlantis-Multilang `concolic_input_gen`: https://github.com/Team-Atlanta/atlantis-multilang-snapshot/tree/main/uniafl/src/concolic
- OSS-Fuzz-Gen (Google): https://github.com/google/oss-fuzz-gen
- OSS-CRS: https://github.com/ossf/oss-crs
- Claude Code [plugins](https://code.claude.com/docs/en/plugins) · [subagents](https://code.claude.com/docs/en/sub-agents) · [skills](https://code.claude.com/docs/en/skills) · [hooks](https://code.claude.com/docs/en/hooks)
- [AFL++](https://aflplus.plus/docs/) · [libFuzzer](https://llvm.org/docs/LibFuzzer.html)

---

*cc-fuzzer was built collaboratively with Claude; architecture, schema, and shipped code were human-reviewed before release.*
