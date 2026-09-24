# cc-fuzzer: carve out a host-independent core

## Context

cc-fuzzer is a Claude Code plugin today. The main thread drives everything, the loop is re-fired by `ScheduleWakeup`, prompts hard-code `${CLAUDE_PLUGIN_ROOT}/scripts/...` (144 lines) plus nix and host-toolchain instructions, and the deterministic logic is spread over ~12k lines of bash, ~7.4k of `_lib` Python and ~1.9k of heredoc Python.

A downstream repo needs to run the same engine from a container entrypoint. That means an OSS-Fuzz builder, the evaluator's oracle as the last verification step, approved model aliases, some subsystems switched off, and no external scheduler. The goal is a `cc_fuzzer_core` Python package that anything can import, with the plugin as its first consumer. Nothing gets deleted: the plugin keeps every current capability.

Decisions already made:
- The core is a real Python API, ported one subsystem at a time. Bash scripts become shims over `python3 -m cc_fuzzer_core`.
- This is a design document only. It will be delivered later as staged commits, one per deliverable, each leaving the plugin working.

Facts that shape the design:
- There is no test suite.
- The campaign dir is `fuzz/`.
- Root and state paths are resolved six different ways.
- `MANIFEST.md5` has no generator and is already stale (48 files modified).
- `yolo-route.sh` exists but nothing calls it.
- Cost tracking is inert: no agent emits token counts.
- `cve.enabled` and `code_review.enabled` gate only toolbox levers.

## Target layout

```
pyproject.toml                  # hatchling; console script `cc-fuzzer`; package data below
src/cc_fuzzer_core/
  paths.py        # root + campaign resolution (replaces path-anchor.sh, harness-path.sh logic)
  enums.py        # moved from scripts/_lib/enums.py (SSOT, unchanged API)
  config.py       # fuzz-config.json read/write incl. nested blocks (replaces fuzz-config.sh python -c)
  features.py     # feature flags (§9)
  models.py       # model aliasing (§8)
  schema/         # state_checks.py + validate-state.sh field lists → validate(state_dir) -> [Problem]
  state/          # build_current.py, derive_tick.py, yolo_evaluate.py, toolbox.py, ceiling.py, yolo_state.py
  slots/          # launcher.py, liveness.py
  cmplog.py  coverage.py  quarantine.py  delta.py
  prescan/        # code_review_prescan.py, sast_scan.py, merge.py
  crash/          # classify.py (port of is-crash.sh), detect.py, pipeline.py, verifiers/ (§4)
  findings.py     # findings_ops.py + the findings.sh subcommand logic
  variants.py  builders/ (§6)
  query/          # §5
  loop.py         # §7 scheduler-free driver
  prompts.py      # §3 prompt renderer
  data/           # STATE_SCHEMA.md, rules/, dictionaries/, templates/, references/verifier-template.sh, models.json
  __main__.py     # argparse dispatcher: `cc-fuzzer <subsystem> <verb>`
scripts/*.sh       # shims: source _lib/root.sh; exec python3 -m cc_fuzzer_core <cmd> "$@"
agents/, skills/, hooks/  # plugin-only (Claude Code adapter)
prompts/           # host-neutral prompt sources (§3); agents/*.md are rendered from these
```

Hard rule: nothing under `src/cc_fuzzer_core` reads `CLAUDE_*` env vars or emits Claude hook JSON. It also never refers to `agents/`, `skills/` or `hooks/`. A test enforces this by grepping the source and importing in a clean venv.

## Stage 0: safety net (before any port)

- Add `tests/` with pytest and small fixture campaigns under `tests/fixtures/campaign-*/fuzz/`. These are synthetic state files; no real fuzzing.
- Add differential tests: run each current bash entry point against a fixture, snapshot its stdout, exit code and written files as golden output, then assert the Python port matches.
  - Covers `validate-state.sh`, `update-current.sh` (→ `current.json`), `derive-tick-state.py`, `yolo-state.sh next-tick`, `is-crash.sh`, `find-delta-targets.sh` (fixture git repo), `extract-cmplog-dict.sh`, `corpus-quarantine.sh` (stub harness), `check-slot-liveness.sh` (fake PIDs), and `code-review-run.sh` prescan.
- Add `scripts/gen-manifest.sh` (→ `cc-fuzzer manifest write`) and regenerate `MANIFEST.md5`. `integrity-check` skips when the root is a site-packages install, since pip's `RECORD` covers that case.

## §1 Root path from one env var

- **Variable:** `CC_FUZZER_ROOT`.
- **`paths.plugin_root()` resolution order:**
  1. `$CC_FUZZER_ROOT`
  2. `$CLAUDE_PLUGIN_ROOT` (compat, read only by the plugin shim layer, not by the core)
  3. `importlib.resources.files("cc_fuzzer_core") / "data"`
- **Bash:** new `scripts/_lib/root.sh`, sourced first by every script. It sets `CC_FUZZER_ROOT` from the env, falling back to `BASH_SOURCE/../..`, and prepends `$CC_FUZZER_ROOT/src` to `PYTHONPATH` when the package isn't installed. It replaces all six mechanisms:
  - `SCRIPT_DIR` sibling calls
  - `PLUGIN_ROOT` in `enforce-readonly.sh`, `doctor.sh` and `dictionaries.sh`
  - `dirname $SCRIPT_DIR` in `integrity-check.sh` and `cve-context-build.sh`
  - `CLAUDE_PLUGIN_ROOT` in `code_review_prescan.py:641` and `campaign-header.sh:49`
  - `__file__`/`sys.path.insert` in `_lib`
  - `CCFUZZER_SRC` in `flake.nix` and `campaign-init.sh`, which will export `CC_FUZZER_ROOT` instead
- **`paths.campaign()`:** a port of `path-anchor.sh` returning `Campaign(project_root, fuzz_root, state_dir)`.
  - `state_dir` honours `FUZZ_STATE_DIR` everywhere. This fixes the three inconsistent groups the survey found, including `validate-state.sh`, `corpus-quarantine.sh`, `extract-cmplog-dict.sh` and `fuzz-config.sh`.
  - No implicit `cd`; everything takes explicit paths. The old copies of the root-walk in `doctor.sh`, `capture-nix-env.sh` and `detect-crashes.sh` call it.
- **Harness layout:** `harness-path.sh` functions become `paths.HarnessLayout` methods. The bash CLI stays as a shim because agents call it.

## §2 Core package (ported subsystem by subsystem)

For each subsystem: lift the `_lib` module plus the heredoc Python into `cc_fuzzer_core`, expose `fn(campaign, ...) -> dataclass`, add a CLI verb, reduce the `.sh` to a shim, and make the golden test pass.

| Order | Subsystem | Sources to lift |
|---|---|---|
| 1 | enums, config, paths | `enums.py`, `fuzz-config.sh`, `path-anchor.sh`, `harness-path.sh` |
| 2 | schema validation | `state_checks.py` and field lists in `validate-state.sh:222-227`, schema version constant |
| 3 | state machine | `build_current_multi.py`, `derive-tick-state.py`, `yolo_evaluate.py`, `toolbox_eval.py`, `ceiling_probe.py`, `yolo-state.sh` heredocs, `tick-coverage-roundup.sh` heredoc. Deduplicate the YOLO defaults, which are repeated in 3 places. |
| 4 | crash classification | `is-crash.sh` (pure bash → `crash/classify.py`); `detect-crashes.sh` → `crash/detect.py`. The hook wrapper that prints `hookSpecificOutput` stays in the plugin. |
| 5 | slot launcher, liveness | `launch-fuzzer-slot.sh`, `launch_slot.py`, `check-slot-liveness.sh`. Fixes the `$CONFIG`/`$MANIFEST` interpolation into the Python source. |
| 6 | cmplog dict, coverage snapshot, quarantine, delta | `extract-cmplog-dict.sh`, `snapshot-coverage.sh` + `snapshot_helpers.py`, `corpus-quarantine.sh` (fixes the `set -e` leak), `find-delta-targets.sh` |
| 7 | prescan | `code_review_prescan.py`, `sast_scan.py`, `code_review_merge.py`; rules come from `paths.data("rules")` |
| 8 | findings | `findings_ops.py` plus `findings.sh` subcommands. Needed by §4. |

Tool lookup (`llvm-cov`, `afl-fuzz`, …) goes through one `core.tools.which(name)`. It tries `$CC_FUZZER_TOOL_<NAME>`, then the `nix-env.json` pin (plugin nix profile only), then PATH. This replaces `nix-tools.sh` inside the core. No `/usr/lib/llvm-*` or `/nix/store` scans live in the core; the nix-specific fallbacks move into a plugin-side tool provider.

## §3 Prompts with no host assumptions

- **Source and render:** host-neutral prompt sources live in `prompts/<agent>.md`. `cc_fuzzer_core.prompts.render(agent, profile, features)` produces the final text.
- **Commands:** every `${CLAUDE_PLUGIN_ROOT}/scripts/x.sh ...` becomes `cc-fuzzer x ...`. The console script is on PATH in the container; the plugin ships `bin/cc-fuzzer` → `scripts/_lib/root.sh` + `python3 -m cc_fuzzer_core`.
- **Environment fragments:** nix, the reproducible shell, host toolchain lines, `command -v` discovery, `apt install` and "on PATH" move out of task prompts into `prompts/profiles/{nix,host,oss-fuzz}.md`. The renderer splices one in at `<!-- profile:environment -->`. Task prompts say "request the `verify` variant" or "resolve tools with `cc-fuzzer tool which`", not how to compile.
  - Heaviest files: `harness-writer.md` (lines 112-147, 404-420, 486-509), `nix-builder.md`, `poc-builder.md:230`, `reporting-agent.md:493`, `concolic-executor.md:59`, `references/nix-monolithic.md`.
  - `nix-builder.md` stays plugin-only and is not a core prompt.
- **Claude Code tool vocabulary:** `Agent(`, `ScheduleWakeup`, `TodoWrite`, `SendMessage` and ctxctl main-thread wording are removed from `prompts/`. They stay only in `skills/`, which is the Claude Code adapter. The orchestrator ends with a `YOLO_NEXT:` directive, which is already host-neutral.
- **Plugin agents:** `agents/*.md` is rendered with profile `nix` or `host` and all features on, then committed. `cc-fuzzer prompts check` (run by `doctor.sh` and a test) fails if they drift from the sources. The frontmatter model comes from §8.
- **Downstream:** calls `render(agent, profile="oss-fuzz", features=...)` at runtime.

## §4 Pluggable final verification step

The pipeline in `crash/pipeline.py` has three named stages and records its verdicts in the finding. The first two are fixed and portable:

1. **filter** (portable)
   - Deterministic pre-checks in the core: the frame is in the harness, and the crash touches private symbols (`internal/`, `_priv.h`).
   - The LLM four-principle verdicts (`crash-triager.md:121-142`) are recorded through `cc-fuzzer findings filter-verdict`.
   - A failure calls `findings drop artifact_filter`, as today.
2. **replay** (portable, now fully deterministic in the core)
   - Three runs on `harness_binary` and `verify_binary` (`crash-triager.md:144-192`), then `classify`, stack hash and dedup (Step 3.5).
   - `cc-fuzzer crash replay <file>` returns JSON; the triager reads it instead of hand-running `ASAN_OPTIONS`.
3. **final_verify** (swappable) — a `Verifier` protocol: `verify(finding, ctx) -> Verdict{status: confirmed|rejected|inconclusive, evidence: [paths], attestation: dict}`. It is selected by `fuzz-config.json: verification.final_step`:
   - `"poc-realism"` (default): the current poc-builder path plus the 3-point gate in `findings.sh promote` (`findings.sh:554-662`, `findings_ops.py:199`). It is agent-backed, so the loop dispatches poc-builder.
   - `"command:<path>"`: an external executable. It receives `verify-request/v1` JSON on stdin (finding, crash input, binaries, harness) and returns `verify-verdict/v1` on stdout, with a timeout from `verification.timeout_s`. This is how the downstream repo plugs in the evaluator's oracle.
   - `"python:<module>:<callable>"`, or an entry point registered under the `cc_fuzzer.verifiers` group.

Consequences:
- `promote` becomes `pipeline.finalize(id)`. It runs the configured verifier and writes `finding.verification = {step, status, evidence, at}`.
- `realism_attestation` is required only when `step == "poc-realism"`. Schema goes to v13 across `enums`, `state_checks` and `STATE_SCHEMA.md`.
- The orchestrator gets a `verify` action. It dispatches poc-builder only when the step is agent-backed; otherwise it runs `cc-fuzzer verify <id>` inline.

## §5 Self-authored query dispatch branch

- **Loop hooks:**
  - `REC_BRANCHES` gains `query`, `HARNESS_ACTIONS` gains `query-analyst`, `SNAPSHOT_PREFIXES` gains `query-result`, and a new toolbox lever `query` is added (cost tier `standard`).
- **New agent:** `prompts/query-analyst.md`. Its only job is: state a hypothesis tied to a gap or candidate, write a fresh semgrep rule (or a CodeQL query when a DB exists), run it, then triage the hits into one of:
  - gap annotations
  - `findings import-cr` candidates
  - seed hints
- **Core runner:** `cc-fuzzer query run --engine semgrep|codeql --rule <file> --hypothesis "..."`.
  - It enforces `query.per_query_timeout_s`, the result cap and `query.max_queries_per_dispatch`.
  - It records each run in `fuzz/state/queries.jsonl` (rule, hypothesis, hits, disposition) and writes `snapshots/query-result-<ts>.json`.
  - It reuses the engine invocation in `sast_scan.py`.
- **Own budget:** `fuzz-config.json: query {enabled, per_dispatch_seconds, max_queries_per_dispatch, max_dispatches_per_campaign, engines}`. `yolo_evaluate` suppresses the lever when the budget is spent.
- **Emission:** `build_current` emits `query` at plateau when a gap with reason `deep_path_condition`, `unreached_function` or `value_constraint` has had no query within N ticks, or when a code-review candidate is waiting for cross-file evidence.
  - It is inserted ahead of `reanalyze_gaps` in the priority list at `build_current_multi.py:164-179`.
  - This also fixes the `GAP_REASONS` drift found in the survey.
- **Existing prompts:** the "grep callers" asides in the reviewer prompts get a pointer to request a `query` action instead of querying inline.

## §6 Builder-agnostic variant declarations

- **Declarations:** `variants.py` declares each variant as needs, not flags:
  - `purpose`: fuzz, coverage, verify, cmplog or symcc
  - `sanitizers`
  - `instrumentation`: libfuzzer, afl, source-coverage, cmplog, symcc or none
  - `link_mode`: fuzzer-main, standalone-main or afl
  - `debug_info`
  - `required`
  - The defaults are lifted from `nix-build.sh:249-272` (fuzzer/coverage/verify on; cmplog/symcc opt-in).
- **Per-harness overrides:** in `fuzz-config.json: harnesses[].variants` (`build-spec/v1`).
- **Builders:** adapters in `builders/` implement `build(spec, harness) -> build-result/v1 {variant: {status, binary, reason}}`.
  - `nix`: `nix-build.sh` renders the spec into today's derivation cflags; its output is unchanged.
  - `script`: the legacy `build.sh`, which gets the spec in env vars.
  - `oss-fuzz`: maps fuzz, verify and coverage to `SANITIZER=address|undefined|coverage`, and cmplog to `FUZZING_ENGINE=afl` with cmplog. symcc is reported as `unsupported`. It reads outputs from `$OUT`.
- **Recording:** `write-harness-built` ingests `build-result/v1` and fills the existing `harness_binary`, `coverage_binary`, `verify_binary`, `cmplog_binary`, `symcc_binary` and `*_disabled_reason` fields. Consumers (launcher, coverage, replay) don't change. `build_backend` gains `oss-fuzz` and `script`.
- **Prompt:** `harness-writer` declares its variant needs and calls `cc-fuzzer build --harness X`. It no longer writes clang lines.

## §7 Scheduler-free loop driver

- **Core entry point:** `loop.step(campaign, runner: AgentRunner, *, now=None) -> TickResult`.
  - Returns `directive` (typed: dispatch, run, wait(delay_hint_s), halt, done, inactive), `events`, `halted_reason` and `state_digest`.
  - Advances exactly one tick and returns. It never sleeps, schedules or expects to be woken.
- **Deterministic work runs in process:**
  1. campaign-state check
  2. COLD/RESUME routing (wires in the orphaned `yolo-route.sh` logic)
  3. liveness
  4. crash detect (replaces reliance on the PostToolUse hook)
  5. coverage snapshot
  6. `update_current`
  7. derive and evaluate
  8. halts
- **LLM decisions:** go through `AgentRunner.run(agent, inputs, model=models.resolve(agent), budget) -> AgentResult{text, tokens_in, tokens_out}`. The driver parses `YOLO_NEXT:`. Executing `run script=` is done in process by the driver.
- **Token accounting:** the driver records `agent_call` events with real token counts from `AgentResult`. This finally makes `cost_cap` live.
- **CLI:** `cc-fuzzer tick --once --json`. The container calls `step()` in a loop and decides for itself whether to honour `wait`.
- **Plugin:** the `tick` skill stays the Claude Code adapter. It maps `wait` → `ScheduleWakeup` and `dispatch` → `Agent()`. The skill does not reuse `step()`'s runner, because the main thread must dispatch; it uses the same deterministic pre and post phases through `cc-fuzzer tick prepare` / `tick apply`.

## §8 Model aliasing in one place

- **Mapping file:** `data/models.json`:
  - `tiers`: deep → `opus`, standard → `sonnet`, fast → `haiku`
  - `agents`: each agent → a tier (preserves today's frontmatter)
  - `pricing`: per model id
- **Overrides:** a file named by `$CC_FUZZER_MODELS`, or the `fuzz-config.json: models` block. Tier-level and agent-level overrides are both allowed.
- **Resolver:** `models.resolve(agent) -> model_id`. It replaces:
  - `yolo_evaluate.py` `OPUS_AGENTS` (lines 49-52) and `_RATE` (lines 73-77, 186)
  - `derive-tick-state.py:141`
  - `toolbox_eval.py` `COST_TIER` strings (lines 43-63), which become tiers
- **Plugin:** frontmatter `model:` is written by the renderer (§3) from the mapping, and the drift check covers it. The model restatements in skills prose are removed.

## §9 Feature flags for unscored subsystems

- **Flags:** `features.py` reads `fuzz-config.json: features {impact_tiering, disclosure_reporting, logic_oracles, advisory_lookup}`. All default to `true`. The override `CC_FUZZER_FEATURES="-advisory_lookup,-disclosure_reporting"` wins. CLI: `cc-fuzzer feature enabled <name>`, which sets the exit code.
- **What each flag gates** (everything is gated, not deleted):
  - **`advisory_lookup`:**
    - `cve-context-build` exits early with a skip.
    - The `cve_refresh` lever becomes ineligible.
    - The planner's CVE step is skipped.
    - `cross-ref-findings`, `ceiling_probe` and the prescan hotspots tolerate a missing cve-context.
    - The existing `cve.enabled` gate becomes an alias.
  - **`logic_oracles`:**
    - `ORACLE_TYPE` is restricted to `crash`.
    - `oracle-smoke-test` is a no-op.
    - `--oracle` on the campaign skill is rejected.
    - The oracle sections of the reviewer and triager prompts are stripped.
  - **`impact_tiering`:**
    - The exploit-tier, CVSS and weaponization sections of the poc-builder and triager prompts are stripped.
    - The `impact_review` lever and `_weak_poc` go quiet.
    - The promote gate's boundary fields are not required.
  - **`disclosure_reporting`:**
    - `reporting-agent` disclosure modes and the `report` skill are gated.
    - `campaign-header` stops requiring `authorization.json`.
    - This also fixes the missing `authorization.json.example` and the template copy.
- **Prompt blocks:** `<!-- feature:X -->…<!-- /feature -->`, stripped by `prompts.render`. The committed plugin agents keep every block. At runtime `campaign-header` prints `Features disabled: …` so plugin agents skip those sections.

## Stage order (for later implementation)

0. Safety net
1. §1 root
2. §2 core ports, in table order, with §8 folded into the state port
3. §9 flags
4. §3 renderer and prompt cleanup
5. §6 variants
6. §4 verification
7. §7 driver
8. §5 query branch

Each stage ends with `pytest`, `validate-state.sh` on the fixtures, `cc-fuzzer prompts check` and a regenerated manifest. The version goes to 0.31.0 when the package is introduced.

## Verification

- **Unit and differential:** `pytest tests/`. Golden bash-vs-Python parity for every ported subsystem, run against fixture campaigns.
- **Isolation:** create a venv, `pip install .`, `env -u CLAUDE_PLUGIN_ROOT CC_FUZZER_ROOT= python -c "import cc_fuzzer_core, cc_fuzzer_core.loop"` from `/tmp`, then `cc-fuzzer tick --once --json` against a fixture campaign using a stub `AgentRunner`. Include a grep test that finds no `CLAUDE_` strings in `src/`.
- **Plugin regression:**
  - In a small real target (e.g. a toy C parser), run `/cc-fuzzer:campaign` COLD → WARM ticks → a crash → triage → promote, and confirm the outputs match the pre-refactor behaviour (findings, `current.json` branches).
  - Run `doctor.sh` and `integrity-check.sh` clean.
- **Downstream contract smoke:**
  - `verification.final_step="command:./stub-oracle.sh"`: promotion follows the stub verdict.
  - `CC_FUZZER_FEATURES=-advisory_lookup,-disclosure_reporting,-logic_oracles,-impact_tiering`: the tick still completes, with no CVE fetch and no oracle smoke.
  - The `oss-fuzz` builder against a prebuilt `$OUT` fills `harness_built` correctly.
  - The `query` branch is emitted on a plateau fixture and respects `max_queries_per_dispatch`.
