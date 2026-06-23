# cc-fuzzer

A Claude Code plugin for **LLM-in-the-loop coverage-guided fuzzing, concolic execution, and crash triage** of C/C++ source and binaries. It keeps a real fuzzer (libFuzzer / AFL++) fed and steered by model agents, then verifies and reports what it finds.

cc-fuzzer is **not** a Cyber Reasoning System. It covers the dynamic-analysis half of what a CRS does (fuzzing + concolic + triage + reporting) plus a static code-review pass; autonomous SAST is partial and patch generation is out of scope. The architecture reuses three named patterns from the DARPA AIxCC finalists — see [AIxCC patterns](#aixcc-patterns) and [Scope](#scope).

## Quick start

Install the plugin once, inside Claude Code:

```
/plugin marketplace add ./cc-fuzzer
/plugin install cc-fuzzer
```

Tier-1 SAST in `/fuzz-review` ships the bundled `rules/semgrep` pack offline by default — no setup needed. Additional cross-language rulesets (C/C++, Python, Go, Rust, etc.) can be pulled on demand from the semgrep registry via an explicit pack, e.g. `--sast-rules p/trailofbits` (requires network at scan time). (semgrep's `--config auto` is intentionally **not** supported: it requires semgrep telemetry, which this plugin keeps disabled for privacy — name an explicit pack instead.)

### Recommended companion plugin: ctxctl

For unattended campaigns pair cc-fuzzer with [**ctxctl**](https://github.com/cloudripper/ctxctl): it blocks the main thread from running Bash/Read/Write/etc., so real work lives in subagents whose context dies with them and the orchestrator stays at planning altitude across long runs. cc-fuzzer's v0.30 main-thread skills dispatch a Haiku `ops-runner` subagent for every Bash call when ctxctl is enforcing.

Set the allowlist to exactly:

```
Agent,Skill,TodoWrite,AskUserQuestion,ExitPlanMode,ScheduleWakeup
```

`ScheduleWakeup` is non-negotiable — the YOLO tick chain calls it on the main thread, and a subagent's `ScheduleWakeup` is a no-op. Drop it and the chain dies after the first tick.

Without ctxctl everything still works; main-thread context just bloats with script outputs. Fine for short or interactive sessions, not for unattended `--mode self_loop` runs over many ticks.

### v0.30 slash-command renames

Plugins no longer namespace their slash commands, so v0.23's `/stop`, `/status`, `/reset`, `/run` collided with built-ins. v0.30 renamed six commands with a `fuzz-` prefix. **No aliases — the old names are gone.**

| v0.23 (gone) | v0.30 (use this) |
|---|---|
| `/stop` | `/fuzz-stop` |
| `/status` | `/fuzz-status` |
| `/reset` | `/fuzz-reset` |
| `/run` | `/fuzz-run` |
| `/plan` | `/cc-fuzzer:fuzz-plan` |
| `/review` | `/cc-fuzzer:fuzz-review` |

Other skills (`/cc-fuzzer:campaign`, `/cc-fuzzer:tick`, `/cc-fuzzer:yolo`, etc.) didn't collide and stayed as they were.

### With nix (recommended): clone → bootstrap → set-and-forget

```bash
# 1. Clone the target you want to fuzz
git clone https://github.com/<owner>/<target> && cd <target>

# 2. Bootstrap the campaign shell. Builds cc-fuzzer's pinned toolchain + this
#    target's build deps (auto-detected by a headless scan) and locks the flake.
#    It does NOT launch Claude — it prints the launch commands when done.
nix run github:cloudripper/cc-fuzzer#init

# 3. Launch Claude into that shell and go full autonomous — ONE command.
#    The prompt arg fires the campaign the moment Claude starts; self_loop
#    auto-selects a target, builds the harness, and self-drives ticks unattended
#    (each schedules the next via ScheduleWakeup) until a hard halt or yolo off.
nix run .#claude -- --dangerously-skip-permissions "/cc-fuzzer:yolo on --mode self_loop --no-cap"
#    Then walk away. Check in any time with /fuzz-status or /cc-fuzzer:report.
```

`#init` flags: `--dep <nixpkgs-attr>` (seed a build dep, repeatable — suppresses the scan), `--no-scan` (skip dep auto-detect), `--force` (regenerate the flake and re-scan deps). It writes a project `flake.nix` + `fuzz/nix-deps.nix`; if a build later needs another system library, the harness-writer appends it and you re-run `#init`. An empty `nix-deps.nix` is fine for a self-contained target; re-run with `--force` to re-scan, or hand-edit it.

`nix run .#claude` launches Claude in the campaign shell: plain `nix run .#claude`, or `nix run .#claude -- <claude args>` (nix needs the `--` before any `--flag`). `nix develop` (or `nix run .#default`) opens the shell without Claude.

**Campaign-local Claude settings (optional).** Drop a `settings.json` at `./.claude-work/settings.json` and `nix run .#claude` layers it on automatically (`claude --settings`). Your system `~/.claude` is left untouched — the cc-fuzzer plugin, MCP servers, and your login all carry over; the file only *overlays* campaign-specific settings. To authenticate the campaign instance with an API key instead of your login, export it first: `export ANTHROPIC_API_KEY=sk-… ; nix run .#claude` (it's inherited into the sandbox). There's deliberately no separate config dir — that would orphan the plugin itself.

**Resuming a campaign — skip `#init`.** `#init` is a one-time bootstrap; re-running it re-resolves the plugin flake every time. To come back to an existing campaign, re-enter the shell directly — it uses the committed `flake.lock` + cached FHS env and is fast:

```bash
cd ~/projects/<target>
nix run .#claude -- --dangerously-skip-permissions   # launch Claude in the campaign shell
# plain:  nix run .#claude            interactive shell:  nix develop  (then run `claude`)
```

Only re-run `#init` to change build deps (`--force` re-scans) or bump the plugin version.

### Without nix: host tools

You provide the toolchain — clang + compiler-rt, AFL++, `llvm-cov`/`llvm-profdata`, gdb (SymCC optional). The SessionStart hook reports what's missing. Then:

```bash
git clone https://github.com/<owner>/<target> && cd <target>
claude --dangerously-skip-permissions            # unattended; or plain `claude`
/cc-fuzzer:yolo on --mode self_loop --no-cap      # autonomous: picks a target, fuzzes, self-drives
```

There's no composed dep shell off-nix, so if a harness build needs a system library, install it on the host — the harness-writer names the exact one.

### Drive it yourself (with or without nix)

Prefer to approve each step over full autonomy? Skip YOLO and run the loop by hand:

```bash
/cc-fuzzer:campaign src/parser.c parse_message   # COLD: plan → harness (3 binaries) → seed → launch
/cc-fuzzer:tick                                   # one LLM decision; repeat, or wrap in: /loop 10m /cc-fuzzer:tick
/fuzz-status           # progress — pure shell, no LLM call
/cc-fuzzer:report      # re-verify reproducers → fuzz/state/FINDINGS-REPORT-<target>.md
/fuzz-stop             # stop the fuzzer (also disables YOLO)
```

`/cc-fuzzer:campaign` runs COLD setup once (analyze → harness → 3 binaries → seed corpus → launch). To pick a stopped campaign back up without re-analyzing: `/cc-fuzzer:resume-campaign`. The full self-driving model is in [YOLO](#yolo-self-looping).

## How it works

The campaign splits into a one-time **COLD** setup and a steady-state **WARM** tick. The fuzzer runs continuously in the background; each WARM tick the orchestrator reads one file (`fuzz/state/current.json`) and either decides to wait or emits a directive selecting **one** specialist — the main thread owns the loop and performs the dispatch (see the decision-agent note below). On a manual tick (and YOLO `guided` mode) the branch is computed **deterministically** by `update-current.sh` and the orchestrator just emits its directive; YOLO's `hybrid`/`self_loop` modes let the orchestrator reason over cost/redundancy/progress signals to decide instead.

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
| `stale` | **REFUSE** | Target source changed since the harness was built → `/fuzz-reset` or `--reset`. |
| `corrupted` | **REFUSE** | Schema validation failed → fix or reset. |

## Components

### Subagents (model-routed)

| Subagent | Model | Role |
|---|---|---|
| `fuzz-orchestrator` | sonnet | The decision agent for COLD/RESUME/WARM: decides the next action and emits a directive; the main thread owns the loop and performs the dispatch. On warm ticks reads only `current.json`. |
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
| `poc-builder` | **opus** | Characterizes security impact of confirmed findings for responsible disclosure; impact checked by a `verify.sh`. |
| `reporting-agent` | **opus** | Re-runs every reproducer and writes `FINDINGS-REPORT-<target>.md` (confirmed vs. false-positive, `git blame` provenance). |
| `nix-builder` | sonnet | Builds or rebuilds harness binaries via nix derivations (requires `CC_FUZZER_FHS=1`). Runs the repair loop, promotes to nix backend, falls back to legacy on hard failure. |

### Skills (`/cc-fuzzer:<name>`)

Claude may model-invoke **every** skill except **`fuzz-reset`**, which alone carries `disable-model-invocation: true` because it destroys campaign state and must be a deliberate human action. (`fuzz-reset` is still available to you as a typed `/fuzz-reset`.)

The gate is about **slash-command auto-invocation**, not subagents. **The orchestrator does not dispatch other agents.** Under the recommended ctxctl configuration the top-level thread is the only context with the `Agent` tool, and no cc-fuzzer agent carries it — so no subagent can spawn another subagent. The orchestrator is a **decision agent**: it reads state, runs the deterministic evaluators, and returns a single `YOLO_NEXT:` next-action directive (its last line); the **main-thread skill** parses that directive and performs the action — dispatch a specialist (`crash-triager`, `planner-consult`, …) via `Agent`, run a bash lever via `ops-runner`, `ScheduleWakeup` to chain a tick, or stop — then re-enters the loop for the next decision. So COLD is a main-thread-driven chain (planner → harness-writer → seed-generator → launch), one decision-then-dispatch step at a time. The directive vocabulary lives in `STATE_SCHEMA.md` ("The `YOLO_NEXT:` next-action directive"). Each skill is a thin wrapper around this decide→dispatch loop, also usable for one-off manual or model-driven dispatches. Cost is bounded by `--budget` and, under YOLO, the cost/redundancy ledger — not by skill gating. Only the irreversible `reset` stays human-gated.

- **Campaign loop** — `campaign` (headline; auto-detects COLD/RESUME/WARM), `tick`, `resume-campaign`, `fuzz-run`, `fuzz-stop`, `yolo`, `fuzz-reset`
- **Analysis & corpus** — `fuzz-plan`, `harness`, `seed`, `coverage`, `concolic`, `fuzz-review`, `delta`, `dictionaries`
- **Findings** — `triage`, `poc`, `report`
- **Nix build** — `nix-build` (rebuild harness binaries via nix derivations; `--harness`, `--variant`, `--force`, `--fallback`), `nix-cleanup` (remove GC roots after campaign; `--gc`, `--dry-run`)
- **Read-only** — `fuzz-status`, `doctor`, `validate`

### State

All campaign state lives under `fuzz/state/`. The authoritative spec is **`STATE_SCHEMA.md`** at the plugin root (current schema **v12**, v0.30+). The orchestrator reads only `current.json` on warm ticks. Findings are written exclusively by `scripts/findings.sh` (which runs the verification pipeline); the report only by `reporting-agent`. Plugin scripts are read-only — your only writable scope is `fuzz/`.

## Key mechanisms

### Three binaries (plus one)

Every COLD start builds three mandatory binaries:

1. **Fuzzing** — libFuzzer + ASan + UBSan.
2. **Coverage** — `-fprofile-instr-generate -fcoverage-mapping`, no fuzzer driver; run as a normal program by `snapshot-coverage.sh`.
3. **Verify** — ASan + UBSan only, **no `-fsanitize=fuzzer`**; used to filter harness artifacts (a crash that reproduces in the fuzzer but not here is not a real target bug).

Optionally a **cmplog** binary (`AFL_LLVM_CMPLOG=1`, no sanitizers) when AFL++ + `afl-clang-fast` are present. Cmplog is purely additive — without it the campaign falls back to source-only gap reasoning.

### Nix build backend

When running inside the cc-fuzzer FHS shell (`CC_FUZZER_FHS=1`), harnesses can be built **declaratively** via nix derivations instead of bare compiler invocations. `harness-writer` auto-selects nix when the environment is available, writing a `manifest.json` per harness and delegating compilation to `nix-build.sh`. Each variant (fuzzer, coverage, verify, cmplog, symcc) gets its own derivation; outputs land in the nix store and are symlinked into the bundle at `fuzz/harnesses/<name>/harness/`.

Per-harness field `build_backend: "nix" | "legacy"` tracks which path was used. To force a rebuild: `/cc-fuzzer:nix-build [--harness <name>] [--variant <v>] [--force]`. To fall back to the legacy path: `harness-set.sh fallback-backend` (requires an explicit reason from a closed enum). `scripts/doctor.sh` checks 11 and 12 guard nix store GC and environment drift.

### Crash verification

`crash-triager` runs a multi-step pipeline before any crash becomes a finding: an **artifact filter** (four-principle audit that catches harness-only crashes), **deterministic replay** (multiple runs under ASan with identical top frames), and a **target-realistic reproducer** (the target's own CLI rebuilt with ASan, or a small program using only public headers). Crashes that fail any step are logged to `fuzz/state/dropped_crashes.jsonl` (transparency log) and never filed. Confirmed findings ship as self-contained `fuzz/findings/<id>/repro/` bundles a maintainer can verify in their own environment; `/cc-fuzzer:report --mode pre-contact|maintainer|public` renders disclosure-aware reports.

### Logic-bug oracles

Coverage + sanitizers only find **crashes** — they are blind to **logic bugs** that return the wrong answer without crashing (auth bypass, parser differentials, canonicalization mismatches, silent integer truncation, state-machine confusion). cc-fuzzer makes the *oracle* a first-class, pluggable campaign concept: `oracle_type ∈ {crash, invariant, roundtrip, differential, metamorphic}`. Beyond the always-on crash oracle, a harness can check a property that must hold for every input and trap when it doesn't:

- **invariant** — a property of the output (bounds, ordering, "success ⇒ well-formed", idempotence);
- **roundtrip** — `consumer(producer(x))` preserves `x` (parse∘serialize, decode∘encode) — no second implementation needed;
- **differential** — target vs a user-supplied reference (`--reference`) agree on the same input; checks both value divergence (both accept, outputs differ) and accept/reject divergence (the parser-differential class — smuggling, filter bypass), compared **normalized**, reference run as a subprocess by default;
- **metamorphic** — the target is invariant under a meaning-preserving transform (whitespace, field reorder, equivalent encoding) — catches canonicalization bugs with no second implementation.

Two orthogonal harness shapes round it out: **stateful-sequence** harnesses drive an op-bytecode against one live object to reach order-dependent / state-machine bugs and check cross-op invariants; and the opt-in **UBSan integer/implicit-conversion suite** catches silent numeric corruption (unsigned wrap, truncation) gated behind a wraparound allowlist.

The crux is the **accept-gate rule**: a logic harness never traps because the target *rejected* malformed input (that's correct behavior) — only when an invariant is violated on *accepted* input, or two oracles diverge. The code review surfaces inverse pairs and validation/auth gates as `oracle_candidates`; the planner auto-selects an oracle (override with `/cc-fuzzer:campaign --oracle <type>`); the harness compiles it in and emits a structured marker on violation; the triager's false-positive filter inverts to *"is the oracle itself wrong?"*. Logic findings carry a **divergence record** (observed vs expected) in place of a sanitizer trace and dedup on a property-divergence hash. See `STATE_SCHEMA.md` → "Oracle-Driven Fuzzing".

### The cmplog / LLM / SymCC split

Constraint-solving work is routed to the cheapest tool that can handle it:

```
Easy   (linear, direct compares)  → cmplog       (AFL++ runtime, free)
Medium (transformations, math)    → LLM seed-gen  (semantic)
Hard   (checksums, multi-cond)    → SymCC + Z3    (expensive, last resort)
```

`extract-cmplog-dict.sh` also surfaces cmplog's runtime observations to the agents as a dictionary, so `coverage-analyst` can mark a gap `direct_compare` (cmplog already handling it) instead of paying for a concolic run, and `seed-generator` can ground its seeds in operands that actually exist in the binary. SymCC setup is one-time (`scripts/install-symcc.sh` then `scripts/build-symcc-target.sh`); if it's absent the orchestrator simply skips concolic gaps. SymCC caveats: no inline asm, limited C++ exceptions, path explosion on input-bounded loops (capped per-seed).

### Multi-fuzzer / multi-harness

One libFuzzer slot is the default (`main`, bound to the campaign's single harness). To run several fuzzers against that harness's shared corpus, add slots in `fuzz/state/fuzz-config.json` — each slot binds to a declared harness:

```json
{
  "schema": "fuzz-config/v3",
  "harnesses": [
    {"name": "parser", "entry_function": "parse_input"}
  ],
  "fuzzer_slots": [
    {"slot": "main",        "harness": "parser", "engine": "libfuzzer"},
    {"slot": "afl-explore", "harness": "parser", "engine": "aflpp", "role": "secondary", "afl_power_schedule": "explore"}
  ]
}
```

Each slot gets its own `fuzzer-<slot>.{pid,engine,log}`; the live manifest is `fuzzers.json`. The orchestrator treats all slots as one shared-corpus campaign (one recommendation, one triage pass, one coverage view). At the top of each tick, `check-slot-liveness.sh` silently relaunches any dead slot (anti-flap throttle: 3 restarts in 60s → marked deadlocked); `restart_fuzzer` only surfaces when *every* slot is dead.

**Multiple harnesses.** Every campaign uses the multi-harness layout from COLD — each harness gets its own corpus/coverage/binaries under `fuzz/harnesses/<name>/`, declared in `fuzz-config.json:harnesses[]`. A single-harness campaign is just the one-entry degenerate case, so adding a second harness later (`/cc-fuzzer:campaign --add-harness <name> --entry <fn>`) only appends. The singular layout from earlier versions is no longer supported (v0.30+ requires schema v12).

> **AFL++ on `process_based` harnesses:** the launcher auto-bumps the per-input timeout to 5000 ms and passes `-t <ms>+` (skip-on-timeout) so a fork-exec'ing CLI target can clear AFL's dry-run. Override per-slot with `"timeout_ms": <ms>`.

### YOLO (self-looping)

`/cc-fuzzer:yolo on [--mode guided|hybrid|self_loop] [--aggressiveness conservative|balanced|aggressive]` opts into a **self-driving loop** (off by default). All modes share hard halt caps (tick / cost / no-progress / crash-storm) and a deterministic per-tick **evaluation** block — cost posture (throttles Opus agents past a soft fraction of the cost cap), a per-agent **redundancy ledger** (suppresses an agent that loops without producing results), and a self-climbing signal.

**Set-and-forget, one command.** `/cc-fuzzer:yolo on` runs a tick immediately and then chains: each tick, the orchestrator recommends the next delay (a `YOLO_NEXT:` line), and the main-thread `/cc-fuzzer:tick` skill calls `ScheduleWakeup` to fire the next one. The chain re-invokes the conversation while it's idle — no `/loop`, no cron, no babysitting — and runs until a hard halt or `/cc-fuzzer:yolo off` / `/fuzz-stop`. (The orchestrator runs as a subagent and can't self-schedule, so the main-thread skill owns the `ScheduleWakeup`; a hard halt simply doesn't reschedule, ending the chain.) If you'd rather drive it yourself, `/loop /cc-fuzzer:tick` works too — but YOLO doesn't need it.

| Mode | Default posture | Per-tick decision |
|---|---|---|
| `guided` | `conservative` | Legacy deterministic precedence table; `sleep` is the last resort; a self-climbing fuzzer means wait. |
| `hybrid` (default) | `balanced` | The orchestrator reasons over the evaluation signals to choose **wait / act / consult**, and acts on a concrete gap move *even while the fuzzer climbs*. Waits (with backoff) when there's no gap move, an agent is looping, or cost is throttling Opus. |
| `self_loop` | `aggressive` | Maximum autonomy: the orchestrator reasons freely toward the goal, pursuing multi-step strategy across ticks. A self-climbing fuzzer is **not** a reason to idle — when no gap move remains it pursues the strategic toolbox (harness/CVE/review/PoC/plan) in parallel; the backoff does not compound. Still fenced by the caps + redundancy/cost ledger. |

**Aggressiveness** decouples "how hard a tick pushes to act" from the mode and defaults from it (override with `--aggressiveness`). `aggressive` never idles on a self-climbing fuzzer, treats an empty gap-branch as "pursue the strategic toolbox", keeps the wait-backoff from compounding (so priorities never go stale), and raises the Opus-throttle point to 0.8 of the cost cap.

`/fuzz-stop` always disables YOLO.

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
