# cc-fuzzer

A Claude Code plugin for **LLM-in-the-loop coverage-guided fuzzing, concolic execution, and crash triage** of C/C++ source and binaries. The architecture borrows specific, named patterns from the DARPA AIxCC finalists — see [Which AIxCC patterns are used](#which-aixcc-patterns-are-used) below.

cc-fuzzer is **not** a Cyber Reasoning System. It covers the dynamic-analysis half of what a CRS does (DAST + concolic + triage + reporting); SAST is planned, patching is out of scope. See [Scope: what cc-fuzzer is and isn't](#scope-what-cc-fuzzer-is-and-isnt) for the explicit in/out list.

## Quick start

**1. Install the plugin** (one-time, from inside Claude Code)

```
/plugin marketplace add ./cc-fuzzer
/plugin install cc-fuzzer
```

**2. (Recommended) enter the pinned-toolchain dev shell**

```bash
cd ~/projects/your-target
nix develop $CLAUDE_PLUGIN_ROOT
claude
```

Skip if you don't have nix — see [Prerequisites](#prerequisites) for the host-tools path. Without nix, `afl-clang-fast` / SymCC may not be available and the campaign falls back to libFuzzer-only.

**3. Inside Claude, start a campaign and drive the loop**

```
/cc-fuzzer:campaign src/parser.c parse_message
/loop 10m /cc-fuzzer:tick
```

`/cc-fuzzer:campaign` runs COLD setup once (analyze → harness → 3 binaries → seed corpus → launch fuzzer). `/loop 10m /cc-fuzzer:tick` then fires WARM ticks every 10 minutes at Claude Code's loop cadence. The orchestrator picks the dispatch branch deterministically each tick — sleep, analyze gaps, generate seeds, run SymCC, triage crashes, etc.

**4. Check progress without spending LLM tokens**

```
/cc-fuzzer:status
```

Pure shell — safe to run anytime, no agent call.

**5. Render the findings report and stop**

```
/cc-fuzzer:report
/cc-fuzzer:stop
```

`/cc-fuzzer:report` re-runs every recorded reproducer against the current harness binary and writes `fuzz/state/FINDINGS-REPORT.md` with confirmed bugs and copy-pasteable repro commands.

To resume the campaign, run `/cc-fuzzer:resume`. The campaign will be restarted and resumed based off of the campaign's saved state.

For details on what each tick actually does, see [What "LLM-guided" means here](#what-llm-guided-means-here) below.

## What "LLM-guided" means here

The LLM does not just write a harness and walk away. The campaign is split into a one-time **COLD** setup and a steady-state **WARM** tick. The orchestrator runs one tick per invocation (no self-looping); the user closes the loop via `/loop` or repeated `/cc-fuzzer:tick`. The dispatch branch on each tick is picked **deterministically** by `update-current.sh`, not by the LLM — the orchestrator only executes it.

```
COLD (once per campaign)
  PLAN (Opus)  →  HARNESS (3 binaries + opt cmplog)  →  SEED  →  LAUNCH
                                                              │
                                                              ▼
       ┌─────────────────────────────────────────────────────────┐
       │  FUZZ + CMPLOG  (background, persistent)                │
       │  ─ runtime input-to-state: AFL++ feeds cmplog operands  │
       │    into its own mutation queue. Silent, no LLM.         │
       └─────────────────────────────────────────────────────────┘
                                  │
       snapshot-coverage.sh ──────┤
       extract-cmplog-dict.sh ────┘   (refreshed on analyze_gaps)
                                  │
                                  ▼
WARM tick (one per /cc-fuzzer:tick)
  update-current.sh  →  current.json.recommendation.branch
                                  │
   ┌──────────────────────────────┴───────────────────────────────┐
   │ DISPATCH  (deterministic, picked by shell, not the LLM)      │
   │                                                              │
   │   sleep             — coverage climbing, no work             │
   │   analyze_gaps   →  coverage-analyst                         │
   │                       reads coverage + cmplog dict;          │
   │                       emits gaps-<ts>.json (entries marked   │
   │                       `direct_compare` = cmplog handling)    │
   │   generate_seeds →  seed-generator                           │
   │                       reads gaps + latest cmplog dict for    │
   │                       grounded operands                      │
   │   concolic       →  concolic-executor (SymCC on hard gaps)   │
   │   mutator        →  mutator (structure-aware input)          │
   │   triage         →  crash-triager (Stage 1 + Stage 2)        │
   │   restart_fuzzer →  kill + relaunch                          │
   │   fix_instrumentation → refuse to advance, surface errors    │
   │   stop                                                       │
   └──────────────────────────────────────────────────────────────┘
```

The fuzzer (libFuzzer or AFL++) runs continuously in the background. Cmplog has two channels in the flow above: a **runtime channel** inside the FUZZ box (AFL++ uses the cmplog binary directly, no LLM involvement) and an **offline channel** where `extract-cmplog-dict.sh` writes a libFuzzer-format dict that `coverage-analyst` and `seed-generator` read. The offline channel is what lets the LLM avoid spending tokens on branches cmplog has already claimed. libFuzzer campaigns get neither channel — input-to-state is an AFL++-only feature in this plugin.

## Which AIxCC patterns are used

cc-fuzzer is not a port of any single AIxCC system — it's a single-host Claude Code plugin. But it deliberately reuses three named patterns from the AIxCC finalists, and explicitly omits a fourth.

| Pattern | Source | Where it lives here |
|---|---|---|
| **LLM-augmented coverage fuzzer loop** (the LLM keeps libFuzzer/AFL++ fed with seeds and mutators instead of replacing the fuzzer) | [Buttercup](https://github.com/trailofbits/buttercup) (Trail of Bits, AIxCC runner-up) | `fuzz-orchestrator` + `seed-generator` + `mutator` agents, driven by the WARM-tick loop |
| **`concolic_input_gen`** — dispatch SymCC against specific uncovered constraints flagged by coverage analysis, write the resulting inputs back into the corpus | [Atlantis-Multilang](https://github.com/Team-Atlanta/atlantis-multilang-snapshot/tree/main/uniafl/src/concolic) (Team Atlanta, AIxCC winner) | `concolic-executor` agent + `scripts/run-concolic.sh` + `scripts/build-symcc-target.sh` |
| **Iterative harness build-repair** — write harness, build, feed compiler errors back to the LLM, retry | [OSS-Fuzz-Gen](https://github.com/google/oss-fuzz-gen) (Google) | `harness-writer` agent's repair loop |
| ~~Ensemble / inter-CRS data exchange / Kubernetes orchestration~~ | OSS-CRS, Buttercup, Atlantis | **Not used.** Single-host, single-process; see [Scope](#scope-what-cc-fuzzer-is-and-isnt). |

What this means in practice: the orchestrator agent owns a state machine modeled on Buttercup's campaign driver, the concolic agent's I/O contract mirrors Atlantis-Multilang's `concolic_input_gen` (read corpus seed → SymCC run → write new corpus seeds), and the harness-writer's repair loop is the OSS-Fuzz-Gen pattern restricted to a single target.

[OSS-CRS](https://github.com/ossf/oss-crs) provides a framework for shaping CRSs. cc-fuzzer borrows a couple of its organizing concepts (plugin manifest as `crs.yaml`, shared corpus directory, budget tracking) but doesn't aspire to CRS-hood — see [Scope](#scope-what-cc-fuzzer-is-and-isnt) for the in/out list.

## Components

### Subagents (model-routed)

| Subagent | Role | Model |
|---|---|---|
| `fuzz-orchestrator` | Owns the campaign loop. Dispatches via `check-campaign-state.sh` into one of three modes (COLD / RESUME / WARM). On warm ticks it reads only `fuzz/state/current.json`. | sonnet |
| `campaign-planner` | Writes `fuzz/state/plan.md`: target description, harness layout, seed strategy, dictionary picks, concolic strategy, coverage targets. Two modes — fresh (COLD start) and revise (mid-campaign, folds in live coverage / findings / gap data; archives prior plan to `snapshots/plan-{ts}.md`). Every downstream specialist consults this plan. | **opus** |
| `harness-writer` | Writes the libFuzzer/AFL++ harness and builds **three** binaries (fuzzing, coverage, verify) plus an optional cmplog binary. Iteratively repairs build failures (OSS-Fuzz-Gen pattern). Reads `plan.md` for harness layout decisions. | sonnet |
| `seed-generator` | Bootstrap corpus + targeted seeds aimed at specific gaps. | haiku |
| `mutator` | Writes a `LLVMFuzzerCustomMutator` for highly-structured inputs the default mutator can't reach. | haiku |
| `coverage-analyst` | Turns coverage snapshots + cmplog dictionary into a ranked `gaps-report/v1` with gap classes (`magic_bytes`, `direct_compare`, `checksum_barrier`, `deep_path_condition`, `delta_target`, …). Reads the latest `delta-*.json` when present to weight recently-changed code higher. | sonnet |
| `concolic-executor` | Drives SymCC against `checksum_barrier` / `deep_path_condition` gaps. Models Atlantis-Multilang's `concolic_input_gen`. | haiku |
| `crash-triager` | Two-stage triage: Stage 1 reproduces in the fuzzer harness (2/3), Stage 2 reproduces in `verify_binary` (2/3). Stage-2 failures are routed to `crashes/flaky/` and never recorded. | **opus** |
| `reporting-agent` | Re-runs every recorded reproducer against the current harness and writes `fuzz/state/FINDINGS-REPORT.md` with confirmed vs. false-positive classification. Annotates each finding with `git blame`-based provenance (likely-introduced commit, in-delta-range flag) when the project is a git repo. | **opus** |

### Slash commands

All commands are prefixed `/cc-fuzzer:`.

| Command | Purpose |
|---|---|
| `/cc-fuzzer:campaign <target>` | **Headline.** Auto-detects state and either starts (COLD), resumes (RESUME), or reports (WARM). |
| `/cc-fuzzer:plan <target>` | Run the Opus `campaign-planner`. Fresh mode at COLD; revise mode mid-campaign (folds live coverage / findings / gap data into a revised plan and archives the prior version to `snapshots/plan-{ts}.md`). Auto-detects which mode. |
| `/cc-fuzzer:resume` | Force-resume a stopped campaign without re-analyzing. |
| `/cc-fuzzer:tick` | Advance the loop by one iteration manually. |
| `/cc-fuzzer:stop` | Clean shutdown (uses PGID-aware `kill-harness-processes.sh`). |
| `/cc-fuzzer:status` | Pure-shell campaign status — no LLM call, safe to run between ticks. |
| `/cc-fuzzer:harness` | Single-shot harness generation (3 builds). |
| `/cc-fuzzer:seed` | Single-shot seed generation. |
| `/cc-fuzzer:coverage` | Snapshot + gap analysis. |
| `/cc-fuzzer:concolic [gap-id]` | Force a SymCC run against current corpus and gaps. |
| `/cc-fuzzer:triage` | One-off triage of a crashes directory. |
| `/cc-fuzzer:report` | Re-run every reproducer and write `FINDINGS-REPORT.md`. |
| `/cc-fuzzer:run` | Launch a built harness in the background without the LLM loop. |
| `/cc-fuzzer:dictionaries [list\|add\|remove\|show]` | Manage bundled and project-local libFuzzer/AFL++ dictionaries. |
| `/cc-fuzzer:delta [--range <git-range>]` | Compute git-diff delta targets (on demand, no LLM). Biases `coverage-analyst` toward recently-changed code. |
| `/cc-fuzzer:doctor` | Read-only diagnostic for state corruption, modified plugin files, stray processes, etc. |
| `/cc-fuzzer:validate` | Validate `fuzz/state/` against `STATE_SCHEMA.md`. |
| `/cc-fuzzer:reset` | Wipe campaign state (backs up findings to `fuzz/reset-backup-<ts>.tar.gz`). |

### Infrastructure scripts

| Script | Purpose |
|---|---|
| `scripts/check-campaign-state.sh` | The state-machine dispatcher. Returns `none\|running\|stopped\|stale\|corrupted`. |
| `scripts/run-fuzzer.sh` | Launch fuzzer in background, write PID file. Auto-passes `-c <cmplog_binary>` to AFL++ when available. Supports in-process and process-based fuzzing modes. |
| `scripts/stop-fuzzer.sh` | Clean shutdown via `kill-harness-processes.sh` (PGID-aware). |
| `scripts/kill-harness-processes.sh` | Deterministic teardown of harness processes by process group. Used before any relaunch. |
| `scripts/snapshot-coverage.sh` | Materializes a `coverage-<ts>.json` snapshot for the LLM. |
| `scripts/extract-cmplog-dict.sh` | Harvests AFL++ cmplog runtime observations into a libFuzzer-format dict for `coverage-analyst` and `seed-generator`. |
| `scripts/find-delta-targets.sh` | On-demand: parses `git diff <range>` into per-hunk records (file + line range + function context). Consumed by `coverage-analyst` for `delta_target` gap priority. |
| `scripts/blame-finding.sh` | On-demand (called by `reporting-agent`): runs `git blame` on a finding's crash line, returns commit/date/author plus whether the blamed commit is inside the latest delta range. |
| `scripts/install-symcc.sh` | One-shot installer for SymCC (build from source) with `/nix/store` PATH fallback. |
| `scripts/build-symcc-target.sh` | Build a SymCC-instrumented harness binary. |
| `scripts/run-concolic.sh` | Run SymCC against a single seed (called by `concolic-executor`). |
| `scripts/findings.sh` | The only sanctioned writer of `findings.jsonl`. Runs the two-stage verification. |
| `scripts/status.sh` | Pure-shell campaign status (no LLM). |
| `scripts/doctor.sh` | Read-only state/plugin diagnostics. |
| `scripts/validate-state.sh` | Schema validation against `STATE_SCHEMA.md`. |
| `scripts/migrate-state.sh` | Schema migration runner (current schema is v7). |
| `scripts/integrity-check.sh` | Verifies plugin files match `MANIFEST.md5`. Run before trusting your memory of plugin internals. |
| `scripts/env-check.sh` | SessionStart hook: reports tool availability and FHS / nix-shell status. |
| `scripts/detect-crashes.sh` | PostToolUse hook: nudges the orchestrator on new crashes. |

### State files (`fuzz/state/`)

Authoritative spec: `STATE_SCHEMA.md` at the plugin root. Current schema version is **v7**.

| File | Lifecycle | Purpose |
|---|---|---|
| `schema-version` | plain text | Pinned schema version for migrations. |
| `plan.md` | rewritable-with-archival | Campaign strategy document. Written by `campaign-planner` (Opus) at COLD; can be revised mid-campaign via `/cc-fuzzer:plan` — each prior version is archived to `snapshots/plan-{ts}.md`. Read by every specialist on dispatch. |
| `current.json` | rewritable | Compact, agent-friendly campaign snapshot. The orchestrator reads **only this** on warm ticks. |
| `harness-built.json` | rewritable (`harness-built/v5`) | Records the three built binaries, `fuzzing_mode` (`in_process` \| `process_based`), `cmplog_enabled`, `verify_binary`. |
| `findings.jsonl` | append-only | Two-stage-verified unique crashes. Only `scripts/findings.sh` writes here. |
| `events.jsonl` | append-only | Every loop tick, structured. |
| `snapshots/coverage-<ts>.json` | immutable | Periodic coverage snapshots. |
| `snapshots/gaps-<ts>.json` | immutable | Ranked gap report from `coverage-analyst`. |
| `snapshots/concolic-<ts>.json` | immutable | Per-run SymCC results from `concolic-executor`. |
| `cmplog-dict-<ts>.dict` | immutable | Cmplog observations, libFuzzer dict format. |
| `FINDINGS-REPORT.md` | rewritable | Human-readable report. Only `reporting-agent` writes here. |
| `budget.json` | rewritable | Running LLM-spend estimate. |
| `crashes/flaky/` | — | Stage-2-failed crashes (harness artifacts). Not recorded in `findings.jsonl`. |

## Steering the campaign with `fuzz/guidance.md`

Optional, user-controlled. The plugin ships a template at `${CLAUDE_PLUGIN_ROOT}/templates/guidance.md` with sections for target description, input classes to emphasize, recommended bundled dictionaries, format expectations, known irrelevant classes, coverage targets, and out-of-scope code. Copy it into your project to steer the LLM agents:

```bash
cp $CLAUDE_PLUGIN_ROOT/templates/guidance.md fuzz/guidance.md
# edit the sections — leave the ones you don't care about empty or delete them
```

When `fuzz/guidance.md` is present, three agents read it during the WARM loop:

| Agent | What it uses |
|---|---|
| `seed-generator` | Input classes, format expectations, recommended dictionaries — shapes targeted seeds. |
| `coverage-analyst` | Coverage targets (weight higher), Out-of-scope code (skip), Input classes (route to the right specialist). |
| `fuzz-orchestrator` | Checks for the file at COLD start; if missing, tells you about the template (never auto-creates the file). |

When the file is absent, all three fall back to default heuristics — `harness-built.json.input_encoding`, the harness source itself, and built-in classifiers. So guidance is purely additive: a way to spend extra human attention upfront in exchange for the agents not having to guess.

## The three-mode state machine

Every orchestrator invocation begins with `check-campaign-state.sh`, which returns one of:

| State | Mode | Behavior |
|---|---|---|
| `none` | **COLD** | Full setup: analyze, write harness, build 3 binaries (+ optional cmplog), bootstrap corpus, launch fuzzer. |
| `stopped` | **RESUME** | Relaunch the fuzzer with the existing harness and corpus, then a single tick. |
| `running` | **WARM** | Tick: read `current.json`, decide, optionally dispatch one specialist, sleep. |
| `stale` | **REFUSE** | Target source changed since the harness was built. Operator must `/cc-fuzzer:campaign --reset` or `/cc-fuzzer:reset`. |
| `corrupted` | **REFUSE** | Schema validation failed. Operator must fix or reset. |

The orchestrator's most important job is **knowing when not to do work**: on a steady warm tick where coverage is climbing, the right answer is "sleep". Token cost is dominated by re-walking source unnecessarily.

## Three binaries (plus one)

Every COLD start produces **three mandatory** binaries:

1. **Fuzzing binary** — `fuzz/harness/<target>_fuzzer` with libFuzzer + ASan + UBSan.
2. **Coverage binary** — `<target>_fuzzer_cov` with `-fprofile-instr-generate -fcoverage-mapping`, no fuzzer driver. Run as a normal program by `snapshot-coverage.sh`.
3. **Verify binary** — `<target>_fuzzer_verify` with ASan + UBSan only, **no `-fsanitize=fuzzer`**. Used by `crash-triager` for Stage 2 cross-verification: a crash that reproduces in the harness but *not* here is a harness artifact and is never written to `findings.jsonl`.

Optionally, when the engine is AFL++ and `afl-clang-fast` is installed:

4. **Cmplog binary** — `<target>_fuzzer_cmplog` built with `AFL_LLVM_CMPLOG=1`, **no sanitizers**. Passed to `afl-fuzz` via `-c` for Redqueen-style input-to-state mutations.

If the cmplog build is skipped (libFuzzer engine, or `afl-clang-fast` missing), `coverage-analyst` falls back to source-only reasoning and `seed-generator` skips cmplog-grounded seeds. The campaign continues — cmplog is purely additive.

## Two-stage crash triage

The `crash-triager` agent enforces a two-stage verification before any crash becomes a finding:

- **Stage 1** — Reproduce in the fuzzer harness binary, 2 of 3 attempts. Filters flakes.
- **Stage 2** — Reproduce in `verify_binary` (no libFuzzer driver), 2 of 3 attempts. Stage-2 failures are routed to `crashes/flaky/` and never recorded in `findings.jsonl`.

This is what catches harness-artifact false positives like libFuzzer-side allocations OOMing, fuzzer-init races, or sanitizer/driver interactions that don't reproduce against the underlying target code. Only `scripts/findings.sh add` writes `findings.jsonl`, and it runs both stages internally.

## Concolic execution (SymCC, Atlantis-Multilang pattern)

`concolic-executor` is modeled on Atlantis-Multilang's `concolic_input_gen` module. The orchestrator dispatches it when `coverage-analyst` produces a gap classified as:

- **`checksum_barrier`** — branch needs a CRC, hash, or other computed field.
- **`deep_path_condition`** — branch requires multiple constraints satisfied simultaneously.

For simpler gap classes (`magic_bytes`, `direct_compare`), the LLM + `seed-generator` is faster and cheaper. For `direct_compare` specifically, cmplog usually solves the branch before anyone is dispatched. The split is intentional: cmplog handles linear runtime input-to-state, the LLM handles semantic understanding, SymCC + Z3 handle constraint solving — only the expensive solver gets called on actually hard constraints.

### Setup (one-time)

```bash
${CLAUDE_PLUGIN_ROOT}/scripts/install-symcc.sh
source ~/.bashrc

# After /cc-fuzzer:campaign has built the harness:
${CLAUDE_PLUGIN_ROOT}/scripts/build-symcc-target.sh
```

After this, `fuzz/state/harness-built.json` gains a `symcc_binary` field and the orchestrator uses SymCC automatically on appropriate gaps.

### Manual invocation

```
/cc-fuzzer:concolic            # all eligible gaps
/cc-fuzzer:concolic g003       # specific gap id
```

### Limitations

- **No inline assembly.** Targets that use inline asm in hot paths (some crypto code) lose symbolic state at those points.
- **Limited C++ exception support.** Heavy exception-throwing code can produce incorrect path conditions.
- **Path explosion.** Loops bounded only by input size will consume the timeout. Mitigated by the per-seed cap in `run-concolic.sh`.
- **Concrete fallback.** When SymCC can't symbolize an operation, it falls back to concrete execution. Still valid output, just less exploratory.

If SymCC isn't installed, the orchestrator skips this branch and continues with seed/dictionary-based fixes for all gaps. The plugin works fine without it.

## Cmplog (AFL++ Redqueen-style input-to-state)

When AFL++ is the engine and `afl-clang-fast` is installed, the harness-writer builds a cmplog binary instrumented with `AFL_LLVM_CMPLOG=1`. `run-fuzzer.sh` passes it to `afl-fuzz` via `-c`, enabling Redqueen-style input-to-state mutations at runtime.

This sits in a principled split between the LLM and SymCC:

```
Easy constraints  (linear, direct compares)  → cmplog          (runtime, free)
Medium            (transformations, math)    → LLM seed-gen    (semantic)
Hard              (checksums, multi-cond)    → SymCC + Z3      (expensive, last resort)
```

For branches like `if (magic == 0xDEADBEEF)` or `if (memcmp(buf, "PNG", 3) == 0)`, cmplog typically solves them without any LLM or solver involvement.

The plugin also surfaces cmplog observations to the LLM agents: `extract-cmplog-dict.sh` harvests AFL++'s cmplog runtime output into `fuzz/state/cmplog-dict-<ts>.dict`. `coverage-analyst` reads it to classify gaps as `direct_compare` (cmplog already handling) instead of dispatching them to the more expensive `concolic-executor`. `seed-generator` reads it to ground its targeted seeds in operands that actually exist in the binary, rather than LLM guesses.

When `afl-clang-fast` is missing or the engine is libFuzzer, the cmplog build is skipped with a loud warning. The campaign continues normally.

## Scope: what cc-fuzzer is and isn't

A real Cyber Reasoning System (Buttercup, Atlantis, the AIxCC finalists generally) produces both **POVs** (proofs of vulnerability) *and* **patches** for them, with autonomous SAST, ensemble orchestration, container packaging, and competition-submission infrastructure. cc-fuzzer covers only the dynamic-analysis half:

| Capability | cc-fuzzer | A real CRS |
|---|---|---|
| Coverage-guided fuzzing (libFuzzer / AFL++) | ✓ | ✓ |
| Concolic execution on hard constraints | ✓ | ✓ |
| LLM-guided harness, seed, and mutator generation | ✓ | ✓ |
| Crash triage + deduplication + reporting | ✓ | ✓ |
| Static analysis (SAST) | **planned** | ✓ |
| Patch generation | **out of scope** | ✓ |
| Ensemble / multi-CRS orchestration | **out of scope** | ✓ |
| Containerization / cloud submission | **out of scope** | ✓ |

For a full CRS, look at [Buttercup](https://github.com/trailofbits/buttercup) or [Atlantis](https://team-atlanta.github.io/blog/post-afc/). cc-fuzzer borrows specific patterns from them (see [Which AIxCC patterns are used](#which-aixcc-patterns-are-used)) but is intentionally narrower: DAST + concolic + triage inside a single Claude Code session.

### Relationship to OSS-CRS

[OSS-CRS](https://github.com/ossf/oss-crs) is a framework for orchestrating CRSs over OSS-Fuzz-format projects. cc-fuzzer is not one, but it borrows a few of OSS-CRS's organizing concepts loosely:

| OSS-CRS concept | cc-fuzzer's analogue |
|---|---|
| `crs.yaml` (CRS manifest) | `.claude-plugin/plugin.json` |
| Containerized modules (fuzzer + analyzer) | Background `run-fuzzer.sh` + orchestrator subagent |
| Shared corpus directory | `fuzz/corpus/` shared between agent and fuzzer |
| LLM budget tracking via LiteLLM | `budget.json` updated by orchestrator |
| `libCRS submit pov` | Append to `findings.jsonl` via `findings.sh` (local-only, no submission endpoint) |

What's missing to call this a CRS: SAST, patch generation, POV submission infrastructure, ensemble / FETCH_DIR data exchange, container orchestration. SAST is on the roadmap; the rest is out of scope. Wrapping the existing scripts in an `oss-crs/crs.yaml` and Dockerfile per the [OSS-CRS development guide](https://github.com/ossf/oss-crs/blob/main/docs/crs-development-guide.md) would be the path if someone wanted to graduate this into a containerized CRS, but that's a separate project.

## Reproducible toolchain (Nix)

cc-fuzzer ships a Nix flake at the plugin root that pins the entire toolchain — clang+compiler-rt (libFuzzer), AFL++, SymCC, Z3, llvm-cov, llvm-profdata, gdb, addr2line, plus dev conveniences like ripgrep and fd. The dev shell is wrapped in `buildFHSEnv`, which exposes a traditional FHS layout (`/usr/bin`, `/usr/lib`, `/lib64`) inside the sandbox. AFL++ and SymCC were both written assuming this layout; running them under pure nix without FHSEnv hits hardcoded path expectations and fragile cc-wrapper interactions, so the FHS wrapping is load-bearing, not cosmetic.

Recommended workflow:

```bash
cd ~/projects/your-target           # your project, anywhere under $HOME
nix develop $CLAUDE_PLUGIN_ROOT     # one-time per session; auto-binds $PWD
claude                              # toolchain is now the pinned set
/cc-fuzzer:campaign target.c
```

Inside the dev shell, `CC_FUZZER_FHS=1` is exported. The plugin's SessionStart hook (`scripts/env-check.sh`) reads this and reports one of three states:

- **`cc_fuzzer_fhs_active`** — pinned toolchain in use. Builds are reproducible across machines that use the same `flake.lock`.
- **`nix_shell_other`** — you're inside *some* nix shell, but not the cc-fuzzer one. The hook prints a loud warning and the campaign continues with whatever's on PATH.
- **`host_tools`** — neither nix shell nor cc-fuzzer FHS. The hook prints a loud warning and the campaign continues with host tools. AFL++/SymCC may be missing entirely; preflight will report what's available.

Warnings only fire in directories that contain a `fuzz/` subdirectory — the hook is silent during regular Claude sessions where the user isn't engaging with cc-fuzzer.

### Reproducibility tradeoffs

The plugin does **not** ship a `flake.lock`. Pinning a specific nixpkgs commit in the plugin would make every user's first session expensive (downloading ~500MB of toolchain matching that exact commit) and would mean the plugin maintainer has to chase nixpkgs versions to stay current with security fixes. Instead, the user runs `nix flake update` once per project, gets a `flake.lock` they own, and that lock pins their toolchain for the duration of the campaign.

This means: two users on the same project with the same `flake.lock` get bit-identical toolchains. Two users with different locks may not. The plugin imposes the toolchain *shape*; the user owns the toolchain *version*.

### What's not pinned (Layer 2, on roadmap)

The harness build itself currently uses imperative `bash build.sh` invoking the (pinned) clang. This means the toolchain is reproducible but the build process is still imperative — the harness binary's hash depends on file ordering, environment variables, and host details inside the FHSEnv. A future release would offer an opt-in `--derivation` mode where harness-writer emits a Nix derivation instead, giving content-addressed harness binaries. That refactor is significant enough to stage separately; it's explicitly out of scope for v0.15.

### When the host-tools fallback still makes sense

- You're on a system without nix and don't want to install it.
- You're rapidly iterating on harness logic and the per-build latency of nix's eval cache is annoying.
- You're adapting cc-fuzzer to an environment where bubblewrap (FHSEnv's underlying mechanism) isn't available — some hardened containers, certain CI runners.

In all these cases, run `scripts/install-symcc.sh` to bootstrap SymCC and let preflight report what else you need. The plugin will print a loud reminder that nix is preferred, but it won't refuse to operate.

## Plugin integrity (`MANIFEST.md5`)

`MANIFEST.md5` at the plugin root is a release-time-generated list of `<md5>  <relative-path>` lines covering every shipped file (`scripts/*.sh`, `agents/*.md`, `commands/*.md`, `STATE_SCHEMA.md`, `.claude-plugin/plugin.json`, etc.). It's the canonical fingerprint of what the plugin looked like when it shipped. Where the Nix flake pins your toolchain, the manifest pins the plugin itself — together they bound the moving parts of a campaign.

### Why drift detection exists

Every subagent's prompt enforces a read-only rule: *"Plugin files are read-only. Your only writable scope is `fuzz/`."* But agents have patched plugin files in place at least three documented times, defeating the rule. In-place patches silently disappear on `/plugin install` and leave mystery regressions behind. The manifest makes drift loud enough that it can't be ignored.

### Three checkpoints run the check

| Checkpoint | Where | When it fires |
|---|---|---|
| SessionStart hook | `scripts/env-check.sh` → `scripts/integrity-check.sh` | Every Claude Code session start. Produces a "DRIFT DETECTED" warning at the top of the session if any file's hash doesn't match. |
| `/cc-fuzzer:doctor` | `scripts/doctor.sh` | On demand, as one diagnostic category among several. |
| Every subagent | Agent prompt frontmatter | Before trusting its memory of any plugin script's contents. If the check returns "ok", the disk is canonical and the agent's memory is stale. |

### When you see "DRIFT DETECTED"

The check is non-fatal — campaigns continue regardless. But the warning means at least one file under the plugin root no longer matches its release hash. Options:

- **Reinstall** to restore canonical state:
  ```
  /plugin marketplace update <your-marketplace>
  /plugin install cc-fuzzer@<your-marketplace>
  ```
- **Inspect first**: `bash $CLAUDE_PLUGIN_ROOT/scripts/integrity-check.sh` lists the specific drifted files.
- **Plugin developer iterating?** The drift is intentional. Regenerate the manifest before cutting a release — the existing format is `<md5>  <relative-path>` (two spaces), one line per file, produced by `find` + `md5sum` against the shipped tree.

## Cost

Expected token mix during a typical campaign:

- ~60% Haiku (seed generation each tick, mutator scaffolding, concolic dispatch)
- ~25% Sonnet (orchestrator decisions, harness writing, coverage analysis)
- ~15% Opus (one-shot `campaign-planner` at COLD, `crash-triager` per unique crash, `reporting-agent` per `/cc-fuzzer:report`)

Roughly an order of magnitude cheaper than running everything on Opus, with Opus reserved for the three places its quality really matters: the initial campaign plan (`campaign-planner`, one shot at COLD start), root-cause analysis on unique crashes (`crash-triager`), and the final reproducer-verified report (`reporting-agent`). The planner's cost is amortized across the entire campaign because every downstream specialist reads its output.

The `--budget` flag (default $20) caps total LLM spend for the campaign. When approaching the cap, the orchestrator skips lower-priority specialist calls and continues with the fuzzer alone.

## Prerequisites

Two paths. Pick one:

**Path A: nix (recommended for reproducibility).** Install nix once via the Determinate Systems installer (`curl -fsSL https://install.determinate.systems/nix | sh -s -- install`) or your distro's nix package. Everything else is provided by the plugin's flake. Total host requirements: nix.

**Path B: host tools (faster to start, less reproducible).** Install whichever of the following you don't have. The SessionStart hook reports what's missing:

- `clang` + `clang++` with `compiler-rt` (libFuzzer + sanitizers)
- `afl-fuzz` and `afl-clang-fast` from AFL++
- `llvm-cov`, `llvm-profdata` for source coverage
- `gdb`, `addr2line` for triage
- SymCC (run `scripts/install-symcc.sh` for a build-from-source path)

## Install

```bash
# As a local plugin during development
/plugin marketplace add ./cc-fuzzer
/plugin install cc-fuzzer
```

For team distribution, wrap this directory in a marketplace repo with a `.claude-plugin/marketplace.json`, push to GitHub, then `/plugin marketplace add <org>/<repo>`.

## Typical session

```
/cc-fuzzer:campaign src/parser.c parse_message --budget=20 --tick-seconds=120

# orchestrator runs the loop, prints status each tick:
# [tick #1 | t=0h 0m | $0.04 of $20.00]
# Mode:      COLD → 3 binaries built, fuzzer launched
# Coverage:  142 lines (+142) | 8400 execs/sec
# Crashes:   0 unique / 0 total (+0)
# Next tick: in 120 seconds
#
# [tick #2 | t=0h 2m | $0.07 of $20.00]
# Mode:      WARM
# Coverage:  391 lines (+249) | 12100 execs/sec
# Decision:  coverage climbing → sleep
# ...
# [tick #14 | t=0h 28m | $0.61 of $20.00]
# Mode:      WARM
# Coverage:  1842 lines (+0) | 14000 execs/sec
# Crashes:   2 unique / 7 total (+3)
# Decision:  new crashes → dispatched crash-triager (Stage 1 + Stage 2)
# ...

/cc-fuzzer:report     # re-run reproducers, write FINDINGS-REPORT.md
/cc-fuzzer:stop
```

To inspect a running campaign cheaply at any point: `/cc-fuzzer:status` (pure shell, no LLM). To diagnose corruption: `/cc-fuzzer:doctor` and `/cc-fuzzer:validate`.

## Customizing model routing

Each subagent's model is set in its frontmatter. To force everything to a single model temporarily:

```bash
export CLAUDE_CODE_SUBAGENT_MODEL=claude-sonnet-4-6
```

This overrides per-agent settings. Unset to restore defaults.

## Development note

cc-fuzzer was built collaboratively using Claude. Architecture decisions, schema design, and all shipped code were human-reviewed before release. 

## References

- OSS-CRS framework: https://github.com/ossf/oss-crs
- OSS-CRS dev guide: https://github.com/ossf/oss-crs/blob/main/docs/crs-development-guide.md
- Buttercup (Trail of Bits, AIxCC runner-up): https://github.com/trailofbits/buttercup
- Atlantis (Team Atlanta, AIxCC winner): https://team-atlanta.github.io/blog/post-afc/
- Atlantis-Multilang `concolic_input_gen`: https://github.com/Team-Atlanta/atlantis-multilang-snapshot/tree/main/uniafl/src/concolic
- OSS-Fuzz-Gen (Google, LLM-driven harness generation): https://github.com/google/oss-fuzz-gen
- Claude Code plugins: https://code.claude.com/docs/en/plugins
- Claude Code subagents: https://code.claude.com/docs/en/sub-agents
- Claude Code hooks: https://code.claude.com/docs/en/hooks
- AFL++: https://aflplus.plus/docs/
- libFuzzer: https://llvm.org/docs/LibFuzzer.html
