# cc-fuzzer State Schema (v1)

This document is the **single source of truth** for the cc-fuzzer plugin's filesystem layout, JSON schemas, and lifecycle rules. Every subagent, command, and script must conform to what's defined here. If a subagent's prompt and this document disagree, this document wins.

Schema version: **v10** (cc-fuzzer plugin v0.22+)

v10 adds the **Nix build backend** — per-harness `build_backend` commitment, `nix-build/v1` audit log, `nix-fallback/v1` demotion log, `nix-environment/v1` live env-vs-commitment reconciliation, and `harness-built/v7` (adds `build_backend` + `nix` sub-object). The nix backend is the default when `$CC_FUZZER_FHS=1`; legacy `build.sh` is unchanged for non-Nix environments.

v9 introduces **multi-harness mode** — a single campaign may target several entry functions in the same library, each with its own harness binary, corpus, and coverage state, while sharing a single findings DB, plan, and budget. Multi-harness mode is **opt-in**: it activates only when `state/fuzz-config.json` declares `harnesses[]`. Campaigns without that declaration continue to run in singular mode exactly as they did in v8 — no filesystem changes, no schema differences. See [Multi-Harness Mode](#multi-harness-mode-schema-v9) for the full contract.

## Filesystem Layout

All campaign state lives under a single root directory, conventionally `./fuzz/` relative to the project root. The orchestrator's working directory is the project root, never anywhere inside `fuzz/`.

```
fuzz/
├── state/                          # all orchestrator state
│   ├── schema-version              # plain text file, contains "v1\n"
│   ├── plan.md                     # REWRITABLE-with-archival; written by campaign-planner
│   ├── harness-built.json          # rewritten only on rebuild
│   ├── current.json                # replaced atomically every update
│   ├── findings.jsonl              # APPEND ONLY for new findings; in-place edit allowed for dedup count
│   ├── FINDINGS-REPORT-<target>.md    # REWRITABLE markdown; rewritten by /cc-fuzzer:report
│   ├── events.jsonl                # APPEND ONLY, never edited
│   ├── budget.json                 # replaced atomically
│   ├── cmplog-dict-<ts>.dict       # IMMUTABLE per timestamp; cmplog runtime observations
│   ├── fuzz-config.json            # REWRITABLE; user-editable launch config (incl. fuzzer_slots)
│   ├── fuzzers.json                # REWRITABLE; live per-slot manifest (pid, role, started_at)
│   ├── findings-legacy.jsonl       # APPEND-ONLY; tombstoned legacy findings records
│   ├── nix-build-log.jsonl         # APPEND-ONLY; per-variant nix build audit (nix-build/v1)
│   ├── nix-fallback-log.jsonl      # APPEND-ONLY; backend demotion records (nix-fallback/v1)
│   ├── nix-environment-issues.json # REWRITABLE; live env-vs-commitment reconciliation (nix-environment/v1)
│   ├── snapshots/                  # all IMMUTABLE timestamped state lives here
│   │   ├── coverage-<ts>.json      # IMMUTABLE once written
│   │   ├── gaps-<ts>.json          # IMMUTABLE once written
│   │   ├── concolic-<ts>.json      # IMMUTABLE once written
│   │   ├── delta-<ts>.json         # IMMUTABLE once written (on-demand, optional)
│   │   └── plan-<ts>.md            # IMMUTABLE archive of prior plan.md (one per revise)
│   ├── fuzzer-<slot>.pid           # session-only, one per slot ("main" by default)
│   ├── fuzzer-<slot>.engine        # session-only, one per slot
│   └── fuzzer-<slot>.log           # session-only, append while slot runs
│
├── harness/                        # all build artifacts
│   ├── <target>_fuzzer.cc          # harness source (or .c)
│   ├── <target>_fuzzer             # main fuzzer binary — symlink to /nix/store/... when build_backend=nix
│   ├── <target>_fuzzer_cov         # coverage-instrumented binary (symlink when nix)
│   ├── <target>_fuzzer_cmplog      # AFL++ cmplog binary (optional, AFL++ only; symlink when nix)
│   ├── <target>_fuzzer_symcc       # SymCC-instrumented binary (optional; symlink when nix)
│   ├── mutator.c                   # custom mutator source (optional)
│   ├── build.sh                    # legacy build command (build_backend=legacy only)
│   ├── build.sh.pre-nix            # archived legacy build.sh when promoted to nix
│   └── dict.txt                    # libFuzzer dictionary (optional)
│
├── nix/                            # Nix derivation bundle (build_backend=nix only)
│   ├── manifest.json               # build manifest (written by harness-writer; read by nix-builder)
│   ├── common.nix                  # mkCcFuzzerBinary helper (generated once, editable)
│   ├── fuzzer.nix                  # fuzzing variant derivation
│   ├── coverage.nix                # coverage variant derivation
│   ├── verify.nix                  # verify variant derivation
│   ├── cmplog.nix                  # cmplog variant (optional)
│   ├── symcc.nix                   # symcc variant (optional)
│   └── mocks/
│       └── <name>.nix              # per-mock static-library derivation
│
├── corpus/                         # active corpus; fuzzer reads from here
├── corpus-quarantine/              # candidate inputs pending validation
│
├── crashes/                        # all crash artifacts
│   ├── new/                        # crashes pending triage
│   ├── known/                      # already triaged, deduped
│   │   └── <finding-id>/           # one directory per unique finding
│   │       ├── repro.bin           # canonical reproducer
│   │       └── duplicates/         # additional inputs hashing to this finding
│   └── flaky/                      # didn't reproduce; kept for inspection
│
└── coverage/                       # llvm-cov profdata + reports
    ├── default.profraw
    └── default.profdata
```

### Path Rules

- **Use `${FUZZ_ROOT:-fuzz}` in scripts.** Default is `fuzz/` but allow override.
- **Never use `${FUZZ_ROOT}/known-crashes/`, `out/default/crashes/`, or any other legacy path.** All crashes live under `${FUZZ_ROOT}/crashes/`.
- **Never write outside `${FUZZ_ROOT}/`** with one exception: the fuzzer process itself writes to its engine-specific output (libFuzzer to `./crash-*` in cwd, AFL++ to `${FUZZ_ROOT}/crashes/aflpp-staging/` per launch config). The detect-crashes hook hard-links these into `${FUZZ_ROOT}/crashes/new/` immediately.
- **All immutable timestamped state files live in `${FUZZ_ROOT}/state/snapshots/`.** This includes `coverage-<ts>.json`, `gaps-<ts>.json`, and `concolic-<ts>.json`. The orchestrator never writes timestamped files directly to `${FUZZ_ROOT}/state/`.

### Retention Policy

**Keep all snapshots.** No automatic pruning. The orchestrator and analysts only need the latest few snapshots for plateau detection and gap analysis, but the rest are preserved for forensic and trend analysis. A single long campaign may accumulate thousands of snapshot files; this is expected and acceptable. If filesystem pressure becomes an issue, the user can manually archive `${FUZZ_ROOT}/state/snapshots/` with `tar` — but no plugin script will ever delete a snapshot automatically.

## File Lifecycles

Every file in `${FUZZ_ROOT}/` falls into exactly one of these categories:

| Category | Rules |
|---|---|
| **IMMUTABLE** | Written once. Never modified, never deleted (except by `/cc-fuzzer:reset`). Examples: `coverage-<ts>.json`, `gaps-<ts>.json`, `plan-<ts>.md`. |
| **REWRITABLE** | Replaced atomically (write to `.tmp`, `mv`). Single canonical version. Examples: `harness-built.json`, `current.json`, `budget.json`. |
| **REWRITABLE-with-archival** | Replaced atomically, but the prior version is first frozen into `snapshots/` as IMMUTABLE history. The current file is canonical; the archives preserve revision history. Example: `plan.md` (archives go to `snapshots/plan-<ts>.md`). |
| **APPEND-ONLY** | Lines are added, never removed. Existing lines may be edited in-place ONLY for the specific cases enumerated in the schema below. Examples: `findings.jsonl`, `events.jsonl`. |
| **SESSION** | Created when a fuzzer process starts, deleted when it stops. Examples: `fuzzer.pid`, `fuzzer.log`. |

Any agent or script that violates a file's lifecycle category is a bug. The validator (`validate-state.sh`) detects most violations.

## JSON Schemas

All schemas use a `schema` field at the top level identifying the schema name and version: `"<name>/v<n>"`. Validators use this to dispatch.

### `state/schema-version` (plain text)

```
v10
```

A single line containing the framework schema version. The orchestrator reads this on session start and refuses to operate if it doesn't match the plugin's expected version. Migration is handled by `scripts/migrate-state.sh`.

Migration chain: `v0` → `v1` → `v2` → `v3` → `v4` → `v5` → `v6` → `v7` → `v8` → `v9` → `v10`.

- **v0** pre-schema, flat layout
- **v1** subdirectory layout, schema fields
- **v2** mandatory coverage builds, instrumentation field
- **v3** multiple dictionary files
- **v4** coverage_disabled_reason required; schema field on all events
- **v5** verified_against_build; crashes/stale/; fuzz-config.json
- **v6** harness-built/v4: cmplog_enabled/binary/disabled_reason; direct_compare gap reason
- **v7** harness-built/v5: fuzzing_mode; FINDINGS-REPORT-<target>.md; current.json last_report_at
- **v8** multi-fuzzer slots: fuzz-config/v2 fuzzer_slots[]; fuzzers/v1; per-slot pid/engine/log; findings-legacy.jsonl
- **v9** multi-harness opt-in: harness-set/v1 at harnesses.json; harness-built/v6 adds name; current/v2 adds harnesses[]+active_harness; fuzz-config/v3; fuzzers/v2; finding/v2; per-harness snapshot prefixes
- **v10** Nix build backend: harness-built/v7 adds build_backend+nix sub-object; new nix-build-log.jsonl; nix-fallback-log.jsonl; nix-environment-issues.json; harness-set/v2; fuzz-config/v4 optional nix block. Migration is additive: existing harnesses get build_backend="legacy".

**v0.18 release notes — additive within schema v9, no migration required.** v0.18 is backward-compatible: a v0.17 campaign on v9 state runs under v0.18 without rewriting state. Additions are:

- New REWRITABLE artifact `state/nix-env.json` (`nix-env/v1`) — session-start snapshot.
- New IMMUTABLE artifacts: `state/snapshots/tick-coverage-<ts>.json` (`tick-coverage/v1`), `state/snapshots/tick-briefing-<ts>.json` (`tick-briefing/v1`), `state/snapshots/planner-consult-<ts>.json` (`planner-consult/v1`), `state/snapshots/cve-context-<ts>.json` (`cve-context/v1`).
- New APPEND-ONLY artifact `state/dropped_crashes.jsonl` (`dropped-crash/v1`).
- New per-finding REWRITABLE bundle directory `fuzz/findings/<id>/repro/`.
- New optional `fuzz-config.json` blocks: `tick`, `cve`, `yolo`.
- New `current.json` optional fields: `tick_coverage`, `consult_state`, `yolo_state`.
- New `finding/v1` and `finding/v2` optional fields: `poc_kind`, `poc_path`, `cvss_v3_1`, `cwe_id`, `principles_audit`, `verification`, `disclosure_state`, `weaponization`.
- New `gaps-report/v1` allowed `reason` value: `cve_hotspot`.

Older readers that don't understand the new fields/files gracefully degrade — they ignore unknown fields and unknown snapshot kinds (validator runs in lenient mode for snapshot files). Forward path is clean: v0.18 fields populate as the campaign runs the v0.18 code.

### `state/nix-env.json` — REWRITABLE (session-start snapshot)

```json
{
  "schema": "nix-env/v1",
  "captured_at": 1779100000,
  "in_nix_shell": true,
  "cc_fuzzer_fhs": true,
  "flake_rev": "abc123...",
  "path": "/nix/store/...-clang/bin:/nix/store/.../bin:...",
  "tools": {
    "clang":         "/nix/store/.../bin/clang",
    "symcc":         "/nix/store/.../bin/symcc",
    "afl-fuzz":      "/nix/store/.../bin/afl-fuzz",
    "llvm-cov":      "/nix/store/.../bin/llvm-cov",
    "llvm-profdata": "/nix/store/.../bin/llvm-profdata",
    "...":           "..."
  },
  "env": {
    "PKG_CONFIG_PATH":   "...",
    "LD_LIBRARY_PATH":   "...",
    "CMAKE_PREFIX_PATH": "...",
    "C_INCLUDE_PATH":    "...",
    "CPLUS_INCLUDE_PATH":"...",
    "NIX_LDFLAGS":       "...",
    "NIX_CFLAGS_COMPILE":"..."
  }
}
```

Written by `scripts/capture-nix-env.sh`, invoked once per session by the `env-check.sh` SessionStart hook (only when `fuzz/` exists in cwd). Consumed by `scripts/_lib/nix-tools.sh` — agents and scripts call `nix_tool <name>` to get an absolute path for a Nix-provisioned tool without grepping `/nix/store`.

**Required fields**: schema, captured_at, in_nix_shell, cc_fuzzer_fhs, flake_rev, path, tools, env.

**`tools` map**: every key is a curated tool name from the capture script's `TOOLS_LIST`. Values are absolute paths from `PATH` resolution at capture time, or `""` when the tool wasn't on `PATH`. An empty value is not an error — it just means that tool isn't part of the current environment (e.g. `symcc` will be empty outside the cc-fuzzer Nix dev shell, in which case concolic-executor work cannot run).

**`cc_fuzzer_fhs`**: `true` when `CC_FUZZER_FHS=1` was set by the flake's profile block — the load-bearing marker that distinguishes "user is in our pinned dev shell" from "user is in some other shell that happens to have IN_NIX_SHELL set."

**Freshness**: rewritten on every session start. Scripts that consume it after a `nix develop` re-entry should not need to re-run capture manually — the next session start picks up the new environment.

### `state/plan.md` — REWRITABLE-with-archival (campaign plan)

Human-readable Markdown campaign plan produced by the `campaign-planner` subagent. Two write paths:

- **Fresh** (COLD start): plan.md does not yet exist; planner composes it from scratch.
- **Revise** (mid-campaign, user-triggered via `/cc-fuzzer:plan`): plan.md already exists; planner reads it plus the live campaign state (`current.json`, latest gap report, `findings.jsonl`, recent coverage snapshots), archives the existing plan to `fuzz/state/snapshots/plan-{ts}.md` (IMMUTABLE), then writes a revised plan that folds in what the campaign has learned. Harness-locked decisions (`fuzzing_mode`, sanitizers, `entry_function`, `cmplog_enabled`) cannot change in revise mode; the planner restates them verbatim from `harness-built.json`. If empirical state suggests one of them should change, the planner says so explicitly and recommends `/cc-fuzzer:campaign --reset`.

There is no JSON schema — this is freeform Markdown. **Required H2 sections** (the validator checks for these as warnings; specialists `grep` for the headings and fall back to defaults if missing):

- `## Target` — entry function, input encoding, top functions of interest
- `## Harness` — `fuzzing_mode`, sanitizer set, entry-point notes (read by `harness-writer`)
- `## Seed Strategy` — bootstrap pass spec, per-`reason` posture (read by `seed-generator`)
- `## Dictionaries` — bundled and project-local dictionary picks (read by `seed-generator` and surfaced to the user)
- `## Concolic Strategy` — hot/cold regions for SymCC, expected productivity (read by `concolic-executor`)
- `## Coverage Targets` — high-priority files/functions (read by `coverage-analyst`)
- `## Out-of-Scope` — explicit exclusions (read by `coverage-analyst`)
- `## Plateau & Dispatch` — informational; orchestrator may consult for context
- `## References` — links read by every specialist

**Required in revise mode only**: `## Campaign Status & Revisions` (placed immediately after `## Target`). Three subsections: `### Status snapshot`, `### Lessons learned`, `### Revisions in this plan`. Closes with a "Harness-locked decisions" verbatim block sourced from `harness-built.json`.

**Optional H2 sections** (include only if relevant): `## Delta Range`, `## Mutator Notes`, `## Known Caveats`.

**Writer**: `campaign-planner` (Opus). Writes fresh at COLD; rewrites on each user-triggered `/cc-fuzzer:plan` mid-campaign. Always archives the prior plan before replacing.

**Readers**:
- `harness-writer` — `## Target` + `## Harness` (COLD step 6/HARNESS)
- `seed-generator` — `## Seed Strategy` + `## Dictionaries` + `## Target` (bootstrap and per-tick targeted dispatch)
- `coverage-analyst` — `## Coverage Targets` + `## Out-of-Scope` + `## Concolic Strategy` (each gap-analysis dispatch)
- `concolic-executor` — `## Concolic Strategy` (each SymCC dispatch)
- `reporting-agent` — may read `## Target` for context in the executive summary (optional)

**Lifecycle**: REWRITABLE — replaced atomically (`.tmp` → `mv`). Each prior version is preserved in `fuzz/state/snapshots/plan-{ts}.md` (IMMUTABLE). May be deleted only by `/cc-fuzzer:reset`. The `fuzz-orchestrator` does **not** read `plan.md` on WARM ticks — the dispatched specialists read it themselves on demand.

### `state/snapshots/plan-<ts>.md` — IMMUTABLE (plan archive)

Frozen copy of a prior `plan.md`, made by `campaign-planner` immediately before a revise-mode rewrite. The `<ts>` is the Unix timestamp at archival time and must be unique within the directory. These archives are read-only history; they enable `diff fuzz/state/snapshots/plan-<earlier>.md fuzz/state/plan.md` to inspect how the campaign's strategy evolved.

Lifecycle: IMMUTABLE once written. Never modified, never deleted (except by `/cc-fuzzer:reset`). Filename `ts` is the only convention enforced by the validator; the file itself is freeform Markdown matching whatever version of `plan.md` it captures.

### `state/harness-built.json` — REWRITABLE

```json
{
  "schema": "harness-built/v5",
  "harness_source": "fuzz/harness/<target>_fuzzer.cc",
  "harness_binary": "fuzz/harness/<target>_fuzzer",
  "coverage_binary": "fuzz/harness/<target>_fuzzer_cov",
  "verify_binary": "fuzz/harness/<target>_fuzzer_verify",
  "coverage_tracking": true,
  "cmplog_binary": "fuzz/harness/<target>_fuzzer_cmplog",
  "cmplog_enabled": true,
  "symcc_binary": "fuzz/harness/<target>_fuzzer_symcc",
  "mutator_source": "fuzz/harness/mutator.c",
  "build_script": "fuzz/harness/build.sh",
  "dict_files": [
    "fuzz/dictionaries/my-grammar.dict",
    "/path/to/plugin/dictionaries/utf-edge-cases.dict"
  ],
  "entry_function": "<target_function>",
  "input_encoding": "passthrough",
  "sanitizers": ["address", "undefined", "fuzzer"],
  "fuzzing_mode": "in_process",
  "target_source": "/abs/path/to/target/source.c",
  "target_source_hash": "<first 16 chars sha256>",
  "build_command_hash": "<first 16 chars sha256>",
  "harness_attempts": 1,
  "built_at": "2026-05-04T13:42:00Z"
}
```

**Required**: schema, harness_source, harness_binary, build_script, entry_function, target_source, target_source_hash, build_command_hash, built_at, coverage_tracking, cmplog_enabled, fuzzing_mode.
**Required when `coverage_tracking: true`**: coverage_binary.
**Required when `coverage_tracking: false`**: coverage_disabled_reason (string explaining why coverage was disabled — e.g. "user opted out via --no-coverage" or "build failed - see fuzz/state/coverage-build-failed.log" or "v3 migration: existing campaign predates mandatory coverage").
**Required when `cmplog_enabled: true`**: cmplog_binary (must be an executable path). Setting `cmplog_enabled: true` with no binary is a validation error; setting it true with a non-executable binary is a warning (run-fuzzer.sh will continue without `-c`).
**Required when `cmplog_enabled: false`**: cmplog_disabled_reason (string explaining why cmplog was disabled — typical values: `"afl-clang-fast not in PATH; install AFL++ to enable Redqueen-style input-to-state"`, `"engine is libFuzzer; cmplog is AFL++-only"`, or the v5→v6 migration reason).
**Optional** (set to `null`/empty/omitted): verify_binary, symcc_binary, mutator_source, dict_files (default `[]`), oracle (default: crash oracle — see below).

**Oracle config** (additive-optional, oracle-driven fuzzing): when the harness compiles in a logic oracle, `harness-writer` records the choice so the planner, triager, and reporter can read it. Written via `write-harness-built.sh --oracle-config '<json>'`.

```json
"oracle": {
  "type": "roundtrip",
  "property_id": "json_roundtrip",
  "functions": {"consumer": "json_parse", "producer": "json_serialize"},
  "comparison": "normalized_serialization_equal",
  "reference": null,
  "execution": "in_process"
}
```

`type` ∈ `crash | invariant | roundtrip | differential | metamorphic` (absent ⇒ `crash`). For `differential`: `reference` names the second implementation and `execution` ∈ `subprocess | in_process` (default `subprocess`). For `metamorphic`: `transform` names the semantics-preserving transform applied (e.g. `insignificant_whitespace`, `field_reorder`). A stateful-sequence harness additionally sets `"stateful": true` and `"operations": [...]` (the op vocabulary). The crash oracle is always additionally active — logic oracles are layered on top of sanitizers, never instead of them.
**Allowed values**:
- `input_encoding`: one of `passthrough | fdp | length_prefixed_records | custom`
- `sanitizers`: subset of `address | undefined | memory | thread | fuzzer | leak | integer | implicit-conversion` (the last two = the opt-in UBSan integer suite — see "UBSan integer/implicit-conversion suite")
- `coverage_tracking`: boolean. When true, `coverage_binary` is required and must be a separate `-fprofile-instr-generate -fcoverage-mapping` build (no `-fsanitize=fuzzer`).
- `cmplog_enabled`: boolean. When true, `cmplog_binary` must point at a separate `AFL_LLVM_CMPLOG=1 afl-clang-fast` build with no sanitizers. cmplog is AFL++-only; libFuzzer campaigns always have `cmplog_enabled: false`.
- `fuzzing_mode`: one of `in_process | process_based`. `in_process` (default) means the harness defines `LLVMFuzzerTestOneInput` and calls the target library directly (standard libFuzzer mode, or AFL++ persistent mode with `__AFL_LOOP`). `process_based` means the target is a CLI binary that the harness invokes per-input via `fork`/`exec`, writing the input to a temp file passed as `argv[1]` (libFuzzer fork-mode shim), or via AFL++ `@@` placeholder. When `process_based` and the engine is AFL++, `harness_binary` may be the target binary itself. v5 (introduced by schema-version v7 / plugin v0.15) adds this field. Migration backfills `fuzzing_mode: "in_process"` on existing campaigns.
- `verify_binary`: path to the ASan-only standalone binary (`-fsanitize=address,undefined`, no `-fsanitize=fuzzer`, uses `cov_main.c` shim). Built by harness-writer in COLD mode. Used by crash-triager for Stage 2 cross-verification to filter harness artifacts. `null` means the build was not attempted or failed (see `fuzz/state/verify-build-failed.log`).
- `dict_files`: array of paths to libFuzzer-format dictionary files. Both project-local (`fuzz/dictionaries/`) and plugin-bundled (absolute paths under `${CLAUDE_PLUGIN_ROOT}/dictionaries/`) are accepted.

**Note**: in v2 this was a single `dict_file: string`. v3 changed this to `dict_files: string[]`. v4 (introduced by schema-version v6 / plugin v0.13) adds the cmplog fields. The migration converts scalar to array automatically and backfills cmplog fields with `enabled=false`. v5 (introduced by schema-version v7 / plugin v0.15) adds `fuzzing_mode`. Migration backfills `fuzzing_mode: "in_process"` on existing campaigns.

### `state/current.json` — REWRITABLE

The single file the orchestrator reads on warm ticks. Schema is already documented in `update-current.sh` output; reproduced here for completeness.

```json
{
  "schema": "cc-fuzzer-current/v1",
  "now": 1714789234,
  "tick_number": 14,
  "fuzzer": {
    "pid": "13014",
    "running": true,
    "engine": "libfuzzer"
  },
  "fuzzers": [
    {"slot": "main",        "engine": "libfuzzer", "pid": "13014", "running": true, "started_at": "2026-05-14T08:00:00Z", "restart_count": 0},
    {"slot": "afl-explore", "engine": "aflpp",     "pid": "13050", "running": true, "started_at": "2026-05-14T08:00:01Z", "restart_count": 1}
  ],
  "harness": {
    "binary": "fuzz/harness/less_fuzzer",
    "symcc_binary": "fuzz/harness/less_fuzzer_symcc",
    "symcc_available": true
  },
  "coverage": {
    "snapshot_file": "fuzz/state/snapshots/coverage-1714789200.json",
    "snapshot_ts": 1714789200,
    "lines_covered": 845,
    "lines_total": 4613,
    "line_pct": 18.3,
    "plateau": true,
    "seconds_since_progress": 1800
  },
  "fuzzer_stats": {
    "execs": 158653,
    "execs_per_sec": 603,
    "paths": 890,
    "crashes_total": 7,
    "new_crashes_since_previous": 0
  },
  "findings": {
    "unique_count": 2,
    "file": "fuzz/state/findings.jsonl"
  },
  "gaps": {
    "latest_report": "fuzz/state/snapshots/gaps-1714789100.json",
    "total_pending": 6,
    "for_concolic": 2,
    "for_seedgen": 3,
    "for_harness": 1,
    "for_mutator": 0,
    "direct_compare": 0
  },
  "recommendation": {
    "branch": "concolic",
    "reason": "plateau, 2 concolic-eligible gaps, SymCC available"
  },
  "last_report_at": 1714789999
}
```

**`recommendation.branch` allowed values**: `sleep | restart_fuzzer | triage | analyze_gaps | reanalyze_gaps | generate_seeds | concolic | mutator | stop`.

**Optional fields**: `last_report_at` (integer unix timestamp, set by reporting-agent after writing `FINDINGS-REPORT-<target>.md`).

**`yolo_state` block** (v0.18+) — computed by `update-current.sh` from `fuzz-config.json:yolo` + campaign signals (coverage roundups, events.jsonl token totals, findings.jsonl). Drives the end-of-tick decision: the orchestrator (a subagent) reads it and emits a `YOLO_NEXT:` directive; the main-thread `/cc-fuzzer:tick` skill turns that into a `ScheduleWakeup` for the next tick (the orchestrator never calls `ScheduleWakeup` itself — a subagent's wakeup can't re-fire the main conversation):
```json
"yolo_state": {
  "active": true,
  "enabled_at_tick": 42,
  "enabled_at_ts":   1779200000,
  "ticks_since_enable":      3,
  "tick_quota_used":         3,
  "tick_quota_remaining":    21,
  "estimated_cost_usd":          0.42,
  "cost_quota_remaining_usd":    9.58,
  "consecutive_no_progress_ticks": 0,
  "new_findings_last_interval":    0,
  "halt_conditions": {
    "tick_cap":     false,
    "cost_cap":     false,
    "no_progress":  false,
    "crash_storm":  false
  },
  "halt_triggered":   false,
  "halt_reason":      null,
  "interval_seconds": 1800,
  "evaluation": {
    "mode": "hybrid",
    "aggressiveness": "balanced",
    "cost": {
      "total_usd": 0.42, "opus_usd": 0.10, "opus_calls": 1,
      "fraction_of_cap": 0.042, "posture": "normal", "soft_cost_fraction": 0.6, "cost_cap_enabled": true
    },
    "agent_ledger": {
      "concolic-executor": {"dispatches": 3, "consecutive_unproductive": 2, "suppressed": true}
    },
    "suppressed_agents": ["concolic-executor"],
    "progress": {"fuzzer_self_climbing": true, "ticks_since_coverage_gain": 0, "consecutive_waits": 0},
    "suggested_disposition": "wait",
    "suggested_wait_seconds": 1800,
    "redundancy_threshold": 2,
    "rationale": "fuzzer still climbing; let it run",
    "toolbox": {
      "non_exhaustive": true,
      "note": "Floor, not ceiling: also reason creatively beyond these; fold in `references`.",
      "eligible_levers": [
        {"lever": "harness_extend", "agent": "harness-writer", "evidence": "for_harness=2 (also check uncovered CVE hotspots)", "cost_tier": "sonnet", "idle_ticks": 6, "suppressed": false},
        {"lever": "poc_build", "agent": "poc-builder", "evidence": "1 confirmed finding(s) without an exploit bundle", "cost_tier": "opus", "idle_ticks": 9, "suppressed": false}
      ],
      "eligible_count": 2,
      "neglected_levers": ["harness_extend", "poc_build"],
      "recent_lever_families": ["seedgen", "seedgen", "concolic", "seedgen"],
      "distinct_recent_families": 2,
      "tunnel_vision": false,
      "suggested_lever": null,
      "references": {
        "guidance_md": {"path": "fuzz/guidance.md", "mtime": 1779200000, "changed_since_enable": false},
        "docs": [{"path": "fuzz/docs/protocol.md", "mtime": 1779190000}],
        "changed_recently": false
      }
    }
  }
}
```
When `active=false` the orchestrator treats yolo as off (other fields may be absent). When `halt_triggered=true` the orchestrator MUST NOT schedule the next wake; instead it runs `scripts/yolo-state.sh disable --reason "<halt_reason>"` and surfaces the reason in the tick output.

**`evaluation`** (v0.18+, computed by `_lib/yolo_evaluate.py`) is the **advisory** dynamic-YOLO signal block — it never halts (the hard caps above own that). `posture` ∈ {`normal`, `throttle`, `halt`} engages Opus-throttling at `soft_cost_fraction` of `max_cost_usd` (unless `cost_cap_enabled` is `false`, in which case cost is not a constraint at all — posture stays `normal`, and the hard cost halt in `compute_yolo_state` is suppressed too). `agent_ledger[agent].suppressed` flags an agent that has been dispatched `≥ redundancy_threshold` times with no result (concolic → 0 inputs promoted; coverage agents → no weighted-coverage gain; triager → no new finding). `suggested_disposition` ∈ {`wait`, `act`, `consult`} and `suggested_wait_seconds` (adaptive backoff) are recommendations; how strictly the orchestrator follows them depends on `mode` (see the `yolo` config block). `aggressiveness` ∈ {`conservative`, `balanced`, `aggressive`} (defaults from `mode`; overridable) shapes the disposition: under `aggressive` a self-climbing fuzzer no longer forces `wait`, an empty/`sleep` gap-branch becomes `act` ("pursue strategic toolbox"), and `suggested_wait_seconds` does not compound across consecutive waits.

**`toolbox`** (v0.19+, computed by `_lib/toolbox_eval.py`) is the **materialized lever board** — the whole known orchestrator toolbox computed deterministically each tick so the model doesn't tunnel-vision on the gap-closing agents the recommendation engine happens to surface. `eligible_levers[]` lists every actionable lever (`lever`, `agent`, `evidence`, `cost_tier` ∈ {cheap, haiku, sonnet, opus}, `idle_ticks`, `suppressed`); ineligible levers are omitted to keep the block compact (`eligible_count` is the total). `neglected_levers[]` are eligible+affordable levers idle ≥3 ticks (opus levers drop out under `posture: throttle`). `tunnel_vision` is true when the last ≥3 *act* ticks rode ≤1 distinct lever family while ≥2 levers (or ≥1 neglected lever) were eligible; `suggested_lever` is the highest-priority neglected lever, and under `aggressive` the disposition is steered to `act` on it (or to `consult` if none is affordable). **`non_exhaustive` is always `true`**: the board is a floor, not a ceiling — it captures only deterministically-detectable moves. `references` reports operator steering (`fuzz/guidance.md`, `fuzz/docs/*`) with `changed_recently`, so the orchestrator re-reads it and pursues moves the catalog can't express. The lever set maps to the Action menu in `agents/fuzz-orchestrator.md`: instrumentation, coverage_reanalysis, seedgen, concolic, mutator, dictionary, harness_extend, cve_refresh, code_review, verification_fill, poc_build, poc_upgrade, plan_revise, slot_engine.

**`consult_state` block** (v0.18+) — signals whether a strategic check-in is due this tick:
```json
"consult_state": {
  "last_consult_ts": 1779099000,
  "last_consult_tick": 37,
  "ticks_since_last_consult": 5,
  "due": true,
  "trigger": "scheduled" | "coverage_stall" | null,
  "consult_every_n": 5
}
```
Computed by `update-current.sh` from the latest `planner-consult-*.json`, `tick-coverage-*.json` history, and `fuzz-config.json:tick.*` settings. The orchestrator reads `due` + `trigger` to decide whether to dispatch `campaign-planner` in consult mode for this tick. Singular and multi modes both populate this block.

**Multi-fuzzer (v8)**:
- `fuzzers` is the canonical per-slot status array. Every running slot appears here with its current pid + liveness.
- `fuzzer` (singular) is a **backward-compat convenience** for legacy readers — it always mirrors the first slot. New code reads `fuzzers[]`; the singular field will be removed in a future schema bump.
- `fuzzer_stats` is **aggregated across all slots** when multiple are running. The orchestrator's recommendation logic doesn't distinguish slot ownership; if any single slot finds a new crash, `new_crashes_since_previous` reflects that, and triage runs once for the combined crash set.
- `recommendation.branch="restart_fuzzer"` fires only when *all* slots are dead. Per-slot restarts happen invisibly via `check-slot-liveness.sh` and never reach the recommendation field.

The orchestrator dispatches based on this field exactly.

### `state/fuzz-config.json` — REWRITABLE (user-editable)

Schema: **`fuzz-config/v2`** (introduced by schema-version v8 / plugin v0.17). Bumped from v1 to add `fuzzer_slots`.

```json
{
  "schema": "fuzz-config/v2",
  "fuzz_forks": 2,
  "fuzzer_slots": [
    {"slot": "main",        "engine": "libfuzzer"},
    {"slot": "afl-explore", "engine": "aflpp", "role": "secondary", "afl_power_schedule": "explore"},
    {"slot": "afl-fast",    "engine": "aflpp", "role": "secondary", "afl_power_schedule": "fast"}
  ]
}
```

**Required**: `schema`, `fuzz_forks`.
**Optional**: `fuzzer_slots` — when missing or empty, `run-fuzzer.sh` falls back to launching a single slot named `main` with engine auto-detected from the harness binary (preserving v0.15/v0.16 behavior). When present, every entry launches a separate fuzzer process.

**Per-slot fields**:
- `slot` (required, kebab-case) — unique identifier within this campaign. Must match `^[a-z0-9-]{1,32}$`. Used in file names (`fuzzer-<slot>.pid`) and the manifest.
- `engine` (required) — one of `libfuzzer | aflpp`.
- `role` (optional, AFL++ only) — one of `master | secondary`. AFL++ multi-fuzzer requires exactly one master per shared-corpus campaign; secondaries pull from the master's queue. Default `null` (single-instance AFL++ run).
- `afl_power_schedule` (optional, AFL++ only) — one of `explore | exploit | fast | coe | quad | lin | seek | rare`. Maps to AFL++'s `-p` flag.
- `libfuzzer_forks` (optional, libFuzzer only) — overrides the top-level `fuzz_forks` for this slot. Useful when one slot should be single-process while another uses fork-mode.
- `timeout_ms` (optional, v0.18+) — per-input timeout passed to the engine. AFL: maps to `-t <ms>+` (the `+` instructs AFL to skip-on-timeout during dry-run rather than abort — without this, slow-start `process_based` harnesses can't get past AFL's calibration phase). libFuzzer: maps to `-timeout=<sec>` (rounded up from ms). **Default**: `5000` when `engine=aflpp` AND the bound harness's `fuzzing_mode=process_based`; `1000` otherwise. The auto-default exists specifically because `process_based` targets (CLI fork-exec, daemon startup, init-heavy libs) routinely exceed AFL's 1000 ms default dry-run timeout and AFL would otherwise refuse to launch the secondary. Override per-slot when the target's per-input wall time is materially different.

**`tick` block** (optional, v0.18+) — controls strategic check-in cadence:
```json
"tick": {
  "consult_every_n": 5,
  "consult_on_coverage_stall": true
}
```
- `consult_every_n` — every Nth WARM tick, the orchestrator writes a briefing and calls `campaign-planner` in consult mode (default 5).
- `consult_on_coverage_stall` — when true (default), additionally forces a consult any tick where the overall `weighted_pct` has not increased across the last 5 tick-coverage roundups.

**`cve` block** (optional, v0.18+) — controls the CVE intelligence layer:
```json
"cve": {
  "enabled": true,
  "query": "libxml2",
  "version_hint": "2.11",
  "cache_ttl_days": 30,
  "max_cves": 200,
  "fetch_timeout_seconds": 300,
  "github_token_env": "GITHUB_TOKEN",
  "include_pocs_as_seeds": true,
  "promote_tier_b": false,
  "poc_size_cap_bytes": 5242880
}
```
- `query` — NVD keyword (required when `enabled: true`). No auto-detect; if absent at COLD, the orchestrator prompts the user.
- `include_pocs_as_seeds` — when true (default), Tier-A PoC blobs are auto-promoted to `fuzz/corpus/cve_<id>.<ext>` after passing `check-seed-safety.sh`.
- `promote_tier_b` — when true, Tier-B blob PoCs are also promotion-eligible. Default false (recognised-security-org sources are retained as reference, not auto-fed to the fuzzer).
- `poc_size_cap_bytes` — hard cap on any PoC artifact fetch (default 5 MiB; oversized fetches are skipped).
- See `scripts/_lib/cve_poc_trust.py` for the A/B/C trust-tier rules.

**`code_review` block** (optional, v0.18+) — three-tier static review of the target source:
```json
"code_review": {
  "enabled": true,
  "default_tier": "sonnet",
  "scan_paths": null,
  "excluded_paths": ["tests/", "docs/", "examples/", "third_party/", "vendor/"],
  "max_functions_to_review": 50,
  "refresh_on_source_hash_change": true,
  "deep_pass_cost_cap_usd": 3.0
}
```
- `default_tier` — `"prescan"` | `"sonnet"` | `"opus"`. Sonnet is the recommended default ($0.20–$0.50 per run).
- `scan_paths` — explicit override. When `null`, auto-detect from `harness-built.json:target_source`.
- `excluded_paths` — list of path fragments to skip during the prescan. The defaults exclude tests, docs, examples, vendor trees, build outputs.
- `max_functions_to_review` — Tier-2 caps. Top-N from the prescan are reviewed.
- `deep_pass_cost_cap_usd` — hard cap on the Tier-3 Opus pass; refuses to start if the estimate exceeds.

Toggled via `/cc-fuzzer:review [--deep] [--refresh] [--delta]`. Auto-runs at COLD between `cve-context-build` and `campaign-planner`; never auto-runs on WARM ticks (deliberate one-time-ish cost).

**`yolo` block** (optional, v0.18+, **off by default**) — config for the self-driving loop (`/cc-fuzzer:yolo on` runs a tick and chains the next via the main-thread tick skill's `ScheduleWakeup`):
```json
"yolo": {
  "enabled": true,
  "mode": "hybrid",
  "aggressiveness": "balanced",
  "interval_seconds": 1800,
  "max_ticks": 24,
  "max_cost_usd": 10.0,
  "stop_on_no_progress_ticks": 30,
  "crash_storm_threshold": 10,
  "redundancy_threshold": 2,
  "soft_cost_fraction": 0.6,
  "cost_cap_enabled": true,
  "max_backoff_multiplier": 4,
  "enabled_at_ts": 1779200000,
  "enabled_at_tick": 42,
  "last_halt_reason": null
}
```
- An absent `yolo` block — or `enabled: false` — means yolo is off and the campaign is driven manually by `/cc-fuzzer:tick`. Yolo is a deliberate user opt-in via `/cc-fuzzer:yolo on`.
- `enabled` — when true, each WARM tick emits a `YOLO_NEXT:` next-tick directive (consumed by the main-thread `/cc-fuzzer:tick` skill, which chains the next tick via `ScheduleWakeup`) AND the orchestrator follows the operator stance for the active `mode` (see `agents/fuzz-orchestrator.md`). `/cc-fuzzer:yolo on` starts the chain (runs the first tick immediately); it then self-advances unattended until a halt or `off`.
- `mode` — how each tick decides what to do (default `hybrid`):
  - `guided` — the legacy deterministic precedence table; `sleep` is the last resort. No per-tick reasoning beyond the table.
  - `hybrid` — the orchestrator (Sonnet) reasons over `yolo_state.evaluation` (cost posture, redundancy ledger, progress) to choose **wait / act / consult** and which action; the precedence table is a fallback prior. `wait` is first-class.
  - `self_loop` — the orchestrator reasons freely from the evaluation signals + `plan.md`; the precedence table is a menu, not a mandate. It may chain a multi-step strategy across ticks. The hard caps and the redundancy/cost ledger still bind.
- `aggressiveness` — `conservative` / `balanced` / `aggressive`; how readily a tick acts vs waits, decoupled from `mode`. Defaults from `mode` when absent (guided→conservative, hybrid→balanced, self_loop→aggressive). Under `aggressive`: a self-climbing fuzzer never forces `wait`; an empty/`sleep` gap-branch maps to `act` (pursue the strategic toolbox the gap engine can't see — harness/CVE/review/PoC/plan); the wait-backoff does not compound; and the `soft_cost_fraction` default rises to 0.8. Written by `scripts/yolo-state.sh enable` (from `--aggressiveness` or derived from `--mode`).
- `interval_seconds` — base delay between auto-scheduled ticks (default 1800 = 30 min). Hard floor: 60s. Under `hybrid`/`self_loop` a `wait` disposition applies adaptive backoff up to `max_backoff_multiplier × interval_seconds` — except under `aggressiveness: aggressive`, where the backoff does not compound (stays at `interval_seconds`) so priorities never go stale across a long idle stretch.
- `max_ticks` — hard tick cap (default 24 ≈ 12 hours at the 30-min interval). Counted from `enabled_at_tick`.
- `max_cost_usd` — soft cost cap (default 10.0). Estimated from `events.jsonl:agent_call` token totals; not a billing source of truth. The hard halt fires at 100%.
- `stop_on_no_progress_ticks` — halt after N consecutive zero-delta tick-coverage roundups (default 30 ≈ 15 hours stuck).
- `crash_storm_threshold` — halt when one interval yields ≥ N new findings (default 10).
- `redundancy_threshold` — (hybrid/self_loop) suppress an agent after this many consecutive unproductive dispatches (default 2). Surfaced in `yolo_state.evaluation.agent_ledger`.
- `soft_cost_fraction` — (hybrid/self_loop) fraction of `max_cost_usd` at which cost `posture` becomes `throttle`: prefer cheap/deterministic actions and defer Opus agents (default 0.6; default 0.8 when `aggressiveness: aggressive`, so strategic Opus levers stay available longer).
- `cost_cap_enabled` — when `false` (set by `/cc-fuzzer:yolo on --no-cap`), cost is removed as a constraint entirely: the soft `throttle` posture is never entered **and** the hard `max_cost_usd` halt is suppressed, so the campaign runs regardless of spend until a non-cost halt fires (tick cap / no-progress / crash-storm) or the operator stops it. Default `true`. Surfaced in `yolo_state.evaluation.cost.cost_cap_enabled`; the hard-halt gate lives in `_lib/derive-tick-state.py`.
- `max_backoff_multiplier` — (hybrid/self_loop) cap on adaptive wait backoff (default 4).
- `enabled_at_ts` / `enabled_at_tick` — written by `scripts/yolo-state.sh enable`; used to scope halt-condition + evaluation computation.
- `last_halt_reason` — human-readable reason from the most recent auto-halt (or null when never halted / freshly enabled).

Toggled via `/cc-fuzzer:yolo on [--mode ...] [--aggressiveness ...]|off|status` which wraps `scripts/yolo-state.sh`. `/cc-fuzzer:stop` always sets `enabled=false` (escape hatch).

**Operator stance during yolo**: see the corresponding section in `agents/fuzz-orchestrator.md`. The short version: under `guided`/`conservative`, `sleep` is the last resort and a self-climbing fuzzer means wait. Under `hybrid`/`balanced`, the orchestrator acts on a concrete gap move even while the fuzzer climbs, and waits (with backoff) only when there's no gap move, every actionable agent is suppressed, or cost is throttling Opus. Under `self_loop`/`aggressive`, a self-climbing fuzzer is **not** a reason to idle — when no gap move remains it pursues the strategic toolbox (harness/CVE/review/PoC/plan) in parallel, and waits only when a hard constraint binds.

**Lifecycle**: REWRITABLE. Single canonical version. Replaced atomically.

### `state/fuzzers.json` — REWRITABLE (live manifest)

Schema: **`fuzzers/v1`** (introduced by schema-version v8 / plugin v0.17). Records the *live* state of each running slot — what `fuzz-config.json` declared is what *should* run; this file records what *is* running.

```json
{
  "schema": "fuzzers/v1",
  "slots": [
    {
      "slot": "main",
      "engine": "libfuzzer",
      "binary": "fuzz/harness/<target>_fuzzer",
      "pid": "13014",
      "pgid": "13014",
      "started_at": "2026-05-14T08:00:00Z",
      "log_file": "fuzz/state/fuzzer-main.log",
      "pid_file": "fuzz/state/fuzzer-main.pid",
      "engine_file": "fuzz/state/fuzzer-main.engine",
      "role": null,
      "afl_power_schedule": null,
      "restart_count": 0,
      "last_restart_at": null
    }
  ]
}
```

**Required per slot**: `slot`, `engine`, `binary`, `pid`, `pgid`, `started_at`, `log_file`, `pid_file`, `engine_file`, `restart_count`.
**Optional per slot**: `role`, `afl_power_schedule`, `last_restart_at`.

**Writer**: `launch-fuzzer-slot.sh` writes/updates entries on each (re)launch. `check-slot-liveness.sh` updates `restart_count` and `last_restart_at` on each detected death-and-relaunch.

**Lifecycle**: REWRITABLE. Slot entries are removed only when the user runs `stop-fuzzer.sh --slot <name>` (or `/cc-fuzzer:reset` for the whole manifest). A slot whose PID is dead but whose entry remains is just "expected slot, currently down" — the next `check-slot-liveness.sh` tick will relaunch it.

### `state/findings.jsonl` — APPEND-ONLY (with one in-place edit case)

One finding per line. JSONL format. Strictly append-only for **new** findings; in-place editing is permitted **only** to update the dedup count and last-seen timestamp on existing findings (the explicit answer to Q1).

```json
{"schema":"finding/v1","id":"f001","stack_hash":"a1b2c3d4e5f6g7h8","category":"heap-buffer-overflow","subcategory":"READ-1B","location":"get_wchar@charset.c:661","exploitability":"medium","root_cause":"multi-byte UTF-8 lead byte at last allocated byte triggers OOB read of continuation bytes","reproducer":"fuzz/crashes/known/f001/repro.bin","first_seen":"2026-05-03T13:42:00Z","last_seen":"2026-05-03T18:14:22Z","dedup_count":4,"sanitizer_report_excerpt":"==13355==ERROR: AddressSanitizer: heap-buffer-overflow on address ..."}
```

**Required fields**: schema, id, stack_hash, category, location, exploitability, root_cause, reproducer, first_seen, last_seen, dedup_count.
**Optional fields**: subcategory, sanitizer_report_excerpt.

**v0.18 additive optional fields** (written by the v0.18 triager; legacy records remain valid without them; promoted to required at the next schema-version bump):

- `poc_kind`: `c_program | python_ctypes | cli_invocation | ipc_replay | poc_unverified` — the form of the target-realistic reproducer.
- `poc_path`: relative path to the `fuzz/findings/<id>/repro/` directory.
- `cvss_v3_1`: object — `{ vector_string, base_score, severity_label, source: "triager_estimate" }`. The `source` field is mandatory and exists so the maintainer-facing report can disclaim our score as a starting estimate, not authoritative.
- `cwe_id`: e.g., `"CWE-787"`.
- `principles_audit`: object capturing the artifact-filter outcome — `{ harness_correctness, api_contract, public_api_reachability, entry_point_currency }`, each `{ verdict: "pass"|"fail"|"n/a", note: string }`.
- `verification`: object — `{ deterministic_replay: "pass"|"fail"|"n/a", target_realistic_reproducer: "pass"|"fail"|"n/a", route: "A"|"B"|null, weakly_verified: bool }`. `weakly_verified: true` is set when neither Route A (target CLI) nor Route B (minimal public-API program) was buildable; the finding still files but the report surfaces the limitation honestly.
  - **Exploit sub-fields** (written by `poc-builder` into the same `verification` object; absent until a PoC is built): `exploit_built: bool`; `exploit_tier: "A"|"B"|"C"`; `exploit_tier_reason: string` (free-form for A/B — e.g. `control_flow_hijack`; for C one of `bug_class_caps_impact | principles_audit_constrains | no_boundary_crossed | cost_exhausted`; or `realism_dispute` when the finding doesn't hold against the real target); `reproducibility_tier: 1|2|3` (1 in-the-wild binary, 2 downstream consumer, 3 public-API driver); `chained_findings: [<id>...]` (demonstrated-chain upstream finding ids); `chain_dependencies_valid: bool`; `attempts: int`; `verify_script_path: string`.
  - **`boundary_crossed`** (poc-builder; the trust boundary the `verify.sh` *demonstrated* the bug crossing): `{ type: "confidentiality"|"privilege"|"integrity"|"authentication"|"isolation"|"none", from: string, to: string, evidence: string }`. This is the false-positive gate — **Tier A/B require a `type` other than `none`**; `type: "none"` means the primitive crossed no boundary the attacker couldn't otherwise cross (e.g. a read of self-planted adjacent memory) and the finding must be Tier C. Projected (un-demonstrated) escalations are documented in `EXPLOIT.md`, never recorded here. See `references/threat-model.md` and `poc-builder` "Trust boundaries".
- `disclosure_state`: `pre_contact | maintainer_engaged | cve_requested | cve_assigned | published`. Drives the `/cc-fuzzer:report --mode` rendering.
- `weaponization`: optional object, present only when the triager attempted weaponization after the verification pipeline passed — `{ attempted: bool, achieved: bool, level: "trigger"|"control"|"exploit", notes: string }`. Failure here does NOT invalidate the trigger-level finding.

**Oracle-driven (logic) finding fields** (additive-optional; absent ⇒ `oracle_type == "crash"`, the historical memory-safety/sanitizer finding — see "Oracle-Driven Fuzzing"):

- `oracle_type`: `crash | invariant | roundtrip | differential | metamorphic`. Omitted entirely on crash findings for back-compat; present on logic findings. Identifies *how the bug was detected*, not its bug class (that's `category`).
- `divergence`: object, present only when `oracle_type != "crash"`. Records the evidence a logic finding stands on, in place of a sanitizer stack trace: `{ property_id: string, comparison: string, observed: string, expected: string, reference?: string, input_form?: string }`. `property_id` names the violated invariant / round-trip pair / reference comparison; `observed`/`expected` are the divergent values (truncated/normalized); `reference` names the second implementation for `differential`.

**For logic findings, `stack_hash` is the property-divergence hash** — `sha256(oracle_type | property_id | divergence_class)[:16]` — not a stack trace hash. This keeps the `findings.sh dedup` / `find-by-hash` machinery unchanged: two violations of the same property on the same oracle dedup together regardless of input.

**Allowed values**:
- `category`: crash classes — `heap-buffer-overflow | heap-use-after-free | stack-buffer-overflow | global-buffer-overflow | stack-overflow | null-deref | assertion-failure | ubsan-<kind> | oom | timeout | flaky | harness-artifact`; logic classes (oracle-driven) — `invariant-violation | roundtrip-mismatch | differential-divergence | parser-differential | auth-bypass | access-control | incorrect-validation | canonicalization | state-confusion | integer-truncation | logic-error`
- `exploitability`: `likely | medium | unlikely | harness-artifact`

**ID assignment rule**: monotonically increasing zero-padded `f001`, `f002`, etc. The next ID is determined by counting lines in `findings.jsonl` + 1. IDs are never reused.

**In-place edit rule** (the only permitted mutation):
When a duplicate crash is observed, the triager **must** update the matching finding's line atomically:
1. Read all lines, find the line where `stack_hash` matches.
2. Increment `dedup_count` by 1.
3. Update `last_seen` to the current ISO 8601 timestamp.
4. Rewrite the entire file atomically (write to `.tmp`, `mv`).
No other fields may be modified after the finding is first recorded.

**Implementation helper**: `scripts/findings.sh add|dedup|count|list` — abstracts the read-modify-write so subagents don't have to.

### `state/events.jsonl` — APPEND-ONLY (strict)

```json
{"schema":"event/v1","ts":1714789234,"tick":14,"event":"tick","branch":"concolic","reason":"plateau, 2 concolic-eligible gaps","duration_ms":3540,"agent_called":"concolic-executor","tokens_in":2104,"tokens_out":487}
```

**Required**: schema, ts, tick, event.
**Conditionally required by `event` value**:
- `event="tick"`: branch, reason, duration_ms.
- `event="agent_call"`: agent_called, tokens_in, tokens_out.
- `event="error"`: error_message.
- `event="campaign_start"`, `event="campaign_resume"`, `event="campaign_stop"`: no extra fields required.

**Strict append-only**: never edit existing lines. Add new lines only.

### `state/harness-corrections.jsonl` — APPEND-ONLY (v0.18 triager → harness-writer feedback)

One record per line, schema `harness-correction/v1`. Written by `crash-triager` when a high-dup-count finding (default threshold: `dedup_count >= 5`) fails a re-audit of the four-principle artifact filter. The triager is signalling: "the existing finding was filed in good faith, but the pattern of repeats clarifies that this is actually a harness artifact — the harness needs a correction." `harness-writer` reads this log on its next invocation to refine the harness.

```json
{
  "schema": "harness-correction/v1",
  "ts": 1779200000,
  "finding_id": "f005",
  "stack_hash": "abcdef0123456789",
  "principle": "harness_correctness" | "api_contract" | "public_api_reachability" | "entry_point_currency",
  "suggested_fix": "harness:42 memcpy(dst, data, len-1) — drop the off-by-one OR validate len ≥ 1 first",
  "evidence": "<optional: file:line citation>"
}
```

**Required fields**: schema, ts, finding_id, stack_hash, principle, suggested_fix.
**Optional fields**: evidence.

**Strict append-only**. The triager also updates the corresponding finding's `category` and `exploitability` to `harness-artifact` via the dedup-write exception in `findings.jsonl`, so the reclassification is visible in both files.

### `state/dropped_crashes.jsonl` — APPEND-ONLY (v0.18 transparency log)

One record per line, schema `dropped-crash/v1`. Records every crash candidate the triager filtered out before it became a finding — with the reason, the verification stage that rejected it, and (when applicable) the principle that was violated. Lets a maintainer who asks "why didn't you report X?" get a deterministic answer with a citation, instead of "we just didn't think it counted."

```json
{
  "schema": "dropped-crash/v1",
  "ts": "2026-05-18T14:00:00Z",
  "crash_file": "fuzz/crashes/new/abcdef1234567890.bin",
  "stack_hash_partial": "abcdef12",
  "stage": "artifact_filter" | "deterministic_replay" | "target_realistic_reproducer",
  "principle": "harness_correctness" | "api_contract" | "public_api_reachability" | "entry_point_currency" | null,
  "reason": "fuzz bytes do not reach the crash site; harness threads them through a length-mismatched memcpy that itself is the trigger",
  "evidence": "see harness lines 42-58: memcpy(dst, data, len-1) with len from raw input — UB independent of target"
}
```

**Required fields**: schema, ts, crash_file, stage, reason.
**Optional fields**: stack_hash_partial, principle, evidence.

**`stage` values**:
- `artifact_filter` — failed one of the four principles (artifact-filter step).
- `deterministic_replay` — crash was flaky; top stack frames not identical across ≥3 replays.
- `target_realistic_reproducer` — verification step 3 couldn't produce a reproducer outside the harness.

`principle` is required only when `stage == artifact_filter`. For the other stages it's `null`.

**Strict append-only**. Maintainer-visible artifact when included with a finding bundle.

### `findings/<id>/repro/` — REWRITABLE per-finding reproducer bundle (v0.18)

Self-contained directory created by `scripts/build-poc-repro.sh` for every finding that passes the verification pipeline:

```
fuzz/findings/<finding_id>/repro/
├── README.md          # auto-generated — finding id, CVSS estimate, CWE, brief description
├── build.sh           # compiles the reproducer in the cc-fuzzer Nix dev shell
├── run.sh             # executes; expects an ASan crash with the recorded top frames
├── poc.c              # Route B: ~30-line program using public headers only
│   poc.cc / poc.py    # (or Python ctypes/cffi if more appropriate)
│   poc.sh             # (or shell wrapper invoking the target's CLI for Route A)
├── input.bin          # the minimised crashing input
└── asan.log           # ASan output captured from a successful run, for cross-check
```

Goal: a maintainer can `tar czf` this directory and verify the crash with no other artifacts from the campaign repo. The reproducer **must not** reference the fuzz harness binary; that's the entire point of the verification pipeline.

The finding's `poc_path` field points at this directory. `poc_kind` records which file is the entry point (`c_program` → `poc.c`/`poc.cc`, `python_ctypes` → `poc.py`, `cli_invocation` → `poc.sh`, `ipc_replay` → `poc.py` or `poc.sh`).

### `state/snapshots/coverage-<ts>.json` — IMMUTABLE

Already produced by `snapshot-coverage.sh`. Schema is **`coverage-snapshot/v2`** (bumped from v1 to add the `instrumentation` field — see "Strict Instrumentation" below).

```json
{
  "schema": "coverage-snapshot/v2",
  "timestamp": 1714789200,
  "engine": "libfuzzer",
  "fuzzer_stats": {"execs": 158653, "paths": 890, "crashes": 7, "hangs": 0, "execs_per_sec": 603},
  "coverage": {"lines_covered": 845, "lines_total": 4613, "line_pct": 18.3},
  "instrumentation": {
    "tracking_enabled": true,
    "coverage_build_present": true,
    "llvm_cov_available": true,
    "coverage_run_ok": true,
    "parsed_engine_log": true,
    "fork_mode": false,
    "ok": true,
    "errors": []
  },
  "previous_snapshot_ts": 1714789140,
  "new_crashes_since_previous": ["fuzz/crashes/new/abc123.bin"],
  "top_unreached_functions": ["parse_extended_chunk", "store_ansi_err"]
}
```

**Required**: schema, timestamp, engine, fuzzer_stats, coverage, instrumentation.
**Optional**: previous_snapshot_ts, new_crashes_since_previous, top_unreached_functions.

Filename ts must equal the `timestamp` field. Once written, the file is never modified.

#### Strict Instrumentation

The `instrumentation` block records whether the snapshot's numbers can be trusted:

| Field | Meaning |
|---|---|
| `tracking_enabled` | `coverage_tracking` from harness-built.json — was the user opted in? |
| `coverage_build_present` | Does `coverage_binary` exist and is it executable? |
| `llvm_cov_available` | Did `snapshot-coverage.sh` find both `llvm-cov` and `llvm-profdata`? |
| `coverage_run_ok` | Did the coverage binary actually run and produce parseable profdata? |
| `parsed_engine_log` | Did fuzzer-engine log parsing produce non-zero exec stats? |
| `fork_mode` | Is libFuzzer running with `-fork=N`? Affects log parsing path. |
| `ok` | Roll-up: true iff all the above are consistent given `tracking_enabled`. |
| `errors` | Human-readable list of what went wrong, if anything. |

If `tracking_enabled` is true but `ok` is false, the snapshot's coverage numbers should not be trusted. The orchestrator's `update-current.sh` reads this and sets `recommendation.branch = "fix_instrumentation"` instead of acting on bogus zeros.

### `state/snapshots/gaps-<ts>.json` — IMMUTABLE

Produced by `coverage-analyst`. Shape:

```json
{
  "schema": "gaps-report/v1",
  "timestamp": 1714789100,
  "snapshot_file": "fuzz/state/snapshots/coverage-1714789100.json",
  "gaps": [
    {
      "id": "g001",
      "file": "src/parser.c",
      "function": "parse_extended_chunk",
      "line_range": [482, 510],
      "reason": "format_barrier",
      "hint": "Add the 4-byte magic 'eXIf' to dict.txt",
      "recommended_agent": "seed-generator"
    }
  ]
}
```

**Required gap fields**: id, file, function, line_range, reason, hint, recommended_agent.
**Allowed `reason` values**: `harness_gap | format_barrier | state_precondition | value_constraint | direct_compare | checksum_barrier | deep_path_condition | delta_target | cve_hotspot | code_review_target | dead`.
**Allowed `recommended_agent` values**: `harness-writer | seed-generator | mutator | concolic-executor | none`.

The `delta_target` reason marks gaps whose enclosing function appears in the latest `state/snapshots/delta-*.json` (recently-changed code per the user's chosen git range). It's a priority signal layered on top of the underlying root cause. Only assigned when a `delta-*.json` exists; absence of a delta artifact means delta weighting is disabled.

The `direct_compare` reason (introduced in v6) marks branches whose comparison operands cmplog has already observed at runtime; the operand will be present in the most recent `fuzz/state/cmplog-dict-<ts>.dict`. These gaps are reported for visibility but the orchestrator does NOT dispatch a specialist for them — `recommended_agent` must be `none`. `update-current.sh` excludes them from `for_concolic` / `for_seedgen` / `for_harness` / `for_mutator` and counts them under `gaps.direct_compare` instead.

**Cap**: max 15 gaps per report. Validator enforces.

Filename ts equals `timestamp` field. Immutable once written.

### `state/snapshots/tick-coverage-<ts>.json` — IMMUTABLE

Produced by `scripts/tick-coverage-roundup.sh` (auto-invoked from `update-current.sh`). Aggregates the newest per-harness `coverage-*.json` snapshot into a single tick-level view. Shape:

```json
{
  "schema": "tick-coverage/v1",
  "timestamp": 1779100000,
  "mode": "singular" | "multi",
  "harnesses": [
    {
      "name": "polkit",
      "lines_covered": 482,
      "lines_total": 3010,
      "pct": 16.01,
      "delta_since_last_tick": 7,
      "first_seen": false,
      "instrumentation_ok": true,
      "snapshot_file": "fuzz/state/snapshots/coverage-polkit-1779099800.json",
      "snapshot_ts": 1779099800,
      "snapshot_age_seconds": 200,
      "stale": false
    }
  ],
  "overall": {
    "lines_covered": 980,
    "lines_total": 6020,
    "weighted_pct": 16.28
  },
  "stale_harnesses": [],
  "stale_threshold_seconds": 600
}
```

**Required fields**: schema, timestamp, mode, harnesses, overall.

**Per-harness fields**: name, lines_covered, lines_total, pct, delta_since_last_tick, first_seen, instrumentation_ok, snapshot_file, snapshot_ts, snapshot_age_seconds, stale.

**`stale`** is true when `snapshot_age_seconds > stale_threshold_seconds` (default 600). A stale harness usually means instrumentation broke between snapshots — silent zeros that the orchestrator would otherwise miss. The roundup surfaces this in `stale_harnesses[]` so the orchestrator can flag it in the tick output.

**`delta_since_last_tick`** compares against the previous `tick-coverage-*.json` (same harness name match). For a harness's first appearance, `first_seen=true` and `delta=0`.

**`overall.weighted_pct`** = `sum(lines_covered) / sum(lines_total) * 100`. Useful for "is the campaign making progress overall?" without summing per-harness percentages (which would be wrong).

Embedded inline as `current.json.tick_coverage` so consumers reading `current.json` get the aggregate without a second file read. Validator runs in lenient mode (same rationale as the other snapshot files: forward-compat for evolving fields).

### `state/snapshots/tick-briefing-<ts>.json` — IMMUTABLE (v0.18 consult input)

Produced by `scripts/tick-briefing.sh`. The orchestrator writes this on consult ticks (every Nth tick or on coverage stall) and hands the path to `campaign-planner` in consult mode. The briefing is intentionally small (~1 KB) so the Opus call stays cheap.

```json
{
  "schema": "tick-briefing/v1",
  "ts": 1779100000,
  "tick_number": 42,
  "trigger": "scheduled" | "coverage_stall" | "manual",
  "last_consult_ts": 1779099000,
  "last_consult_tick": 37,
  "ticks_since_last_consult": 5,
  "coverage": {
    "current_overall_pct": 16.28,
    "history": [
      {"ts": 1779098000, "weighted_pct": 14.10, "stale_harnesses": []},
      {"ts": 1779098500, "weighted_pct": 15.20, "stale_harnesses": []},
      {"ts": 1779099000, "weighted_pct": 15.90, "stale_harnesses": []},
      {"ts": 1779099500, "weighted_pct": 16.10, "stale_harnesses": []},
      {"ts": 1779100000, "weighted_pct": 16.28, "stale_harnesses": []}
    ],
    "delta_across_window": 2.18,
    "stale_harnesses": []
  },
  "active_gaps": {
    "total_pending": 12,
    "mix_by_reason": {
      "checksum_barrier": 3,
      "format_barrier": 2,
      "deep_path_condition": 4,
      "value_constraint": 3
    },
    "examples": [
      {"id": "g012", "reason": "checksum_barrier",
       "file": "src/parser.c", "function": "validate_crc",
       "recommended_agent": "concolic-executor",
       "hint": "16-bit CRC check at offset 0x4..."}
    ]
  },
  "dispatched_since_last_consult": [
    {"agent": "seed-generator", "tick": 39, "tokens_in": 8200, "tokens_out": 1100},
    {"agent": "coverage-analyst", "tick": 41, "tokens_in": 15400, "tokens_out": 2200}
  ],
  "findings_since_last_consult": {"count": 0, "ids": []},
  "sonnet_recommendation": {
    "branch": "generate_seeds",
    "reason": "plateau, 3 seedgen-eligible gaps pending"
  }
}
```

**Required fields**: schema, ts, tick_number, trigger, coverage, active_gaps, sonnet_recommendation.

**`trigger`** values:
- `scheduled` — periodic consult per `fuzz-config.json:tick.consult_every_n` (default 5).
- `coverage_stall` — `tick_coverage.overall.weighted_pct` has not increased across the last 5 roundups; forces an early consult when configured.
- `manual` — user-triggered via `/cc-fuzzer:plan --consult` (future hook).

**`examples`** is capped at 8 entries by the briefing script — one example per gap reason to give the planner concrete texture without ballooning token cost. `dispatched_since_last_consult` is capped at 15.

Validator runs in lenient mode — schema may grow.

### `state/snapshots/planner-consult-<ts>.json` — IMMUTABLE (v0.18 consult output)

Produced by `campaign-planner` in consult mode. The orchestrator reads it, applies the verdict, and includes a one-line summary in the tick output.

```json
{
  "schema": "planner-consult/v1",
  "ts": 1779100050,
  "tick_number": 42,
  "briefing_file": "fuzz/state/snapshots/tick-briefing-1779100000.json",
  "verdict": "stay_course" | "redirect",
  "reason": "one-line summary surfaced in the tick output",
  "tactic": null | "force_concolic_on:g012" | "force_seedgen:g015" | "force_mutator" | "widen_scope" | "revise_plan" | "escalate_to_user",
  "rationale": "5-10 line explanation the planner wrote for the audit trail"
}
```

**Required fields**: schema, ts, verdict, reason.
**`tactic`** is required when `verdict == "redirect"`; null/absent when `verdict == "stay_course"`.

**Allowed tactics** (orchestrator applies inline; `revise_plan` triggers a full planner-revise pass; `escalate_to_user` halts the tick and asks the user for direction):

| Tactic | Orchestrator action |
|---|---|
| `force_concolic_on:<gap_id>` | Dispatch concolic-executor with the named gap, regardless of `recommendation.branch`. |
| `force_seedgen:<gap_id>` | Dispatch seed-generator with the named gap. |
| `force_mutator` | Dispatch mutator agent. |
| `widen_scope` | Print the planner's scope-widening note for the user; do NOT modify the plan automatically. |
| `revise_plan` | Dispatch campaign-planner in revise mode in this same tick (heavier). |
| `escalate_to_user` | Surface the rationale and stop. User decides what to do next. |

Validator runs in lenient mode.

### `state/code-review.md` — REWRITABLE (v0.18 code-review narrative)

Rendered by the `code-reviewer` Sonnet agent at the tail of the Tier-2 pass. The human/LLM-readable companion to `state/snapshots/code-review-<ts>.json`. Contains:

- Scope summary (files scanned, functions reviewed, LOC).
- Top focus areas (3–7), each with rationale + fuzzing recommendation + the findings clustered into that area.
- Top findings (medium + high confidence only) sorted by confidence then file. Each finding shows: file:line, function, pattern, evidence, exploitability hint, fuzzing recommendation, CVE pattern overlap, hotspot match.
- How-to-use-this guidance for each consuming agent.

**Purpose framing**: this is a starting map for the fuzzer, NOT a security audit and NOT a checklist of bugs to verify. The findings are PATTERNS the campaign should investigate by directing the fuzzer at the flagged regions.

**Lifecycle**: REWRITABLE, overwritten by every `code-reviewer` invocation. The structured JSON snapshot is the immutable record.

### `state/snapshots/code-review-prescan-<ts>.json` — IMMUTABLE (v0.18 Tier-1 output)

Produced by `scripts/_lib/code_review_prescan.py` (invoked via `scripts/code-review-run.sh`). Deterministic, no LLM. Ranks the target's functions by suspicion score so Tier-2 (Sonnet) reviews the most promising candidates.

```json
{
  "schema": "code-review-prescan/v1",
  "ts": 1779200000,
  "target_root": "/path/to/target",
  "scope": {
    "files_scanned": 47,
    "functions_inventoried": 312,
    "loc_total": 28453,
    "excluded_paths": ["tests/", "docs/", ...],
    "cve_context_consumed": "fuzz/state/snapshots/cve-context-1779100000.json",
    "recently_changed_files": 18
  },
  "top_candidates": [
    {
      "file": "src/parser.c",
      "name": "parse_chunk",
      "line_start": 142, "line_end": 198, "loc": 57,
      "suspicion_score": 22,
      "score_breakdown": {"strcpy_call": 5, "memcpy_call": 4,
                          "cve_hotspot_function": 10, "recently_changed": 3},
      "pattern_hits": {"strcpy_call": 1, "memcpy_call": 2, "indexed_write": 3},
      "cve_hotspot_match": true,
      "cve_pattern_hints": ["oob_write", "int_overflow"],
      "file_recently_changed": true
    }
  ],
  "full_inventory_summary": [
    {"file": "...", "name": "...", "line_start": N, "loc": N, "suspicion_score": N}
  ]
}
```

**Required fields**: schema, ts, target_root, scope, top_candidates.
**Optional fields**: full_inventory_summary.

### `state/snapshots/code-review-<ts>.json` — IMMUTABLE (v0.18 code-review output)

Produced by the `code-reviewer` agent (Tier-2 Sonnet pass; Tier-3 Opus deep pass merges into this same file).

```json
{
  "schema": "code-review/v1",
  "ts": 1779200000,
  "target": "polkit",
  "scope": {
    "files_scanned": 47,
    "functions_inventoried": 312,
    "loc_total": 28453,
    "candidates_reviewed": 50,
    "excluded_paths": ["tests/", "docs/", ...]
  },
  "tiers_run": ["prescan", "sonnet"],
  "findings": [
    {
      "id": "cr001",
      "file": "src/polkit/polkitdetails.c",
      "function": "polkit_details_lookup",
      "line_range": [142, 165],
      "pattern": "oob_read",
      "confidence": "high" | "medium" | "low",
      "tier_classified": "sonnet" | "opus",
      "evidence": "...",
      "exploitability_hint": "...",
      "fuzzing_recommendation": "...",
      "cve_pattern_match": ["oob_read"],
      "hotspot_match": true
    }
  ],
  "focus_areas": [
    {"rank": 1, "scope": "src/polkit/polkitauthority.c",
     "rationale": "...", "fuzzing_recommendation": "..."}
  ],
  "model_costs": {
    "prescan_tokens_in": 0, "prescan_tokens_out": 0,
    "sonnet_tokens_in": 58200, "sonnet_tokens_out": 6800,
    "opus_tokens_in": 0, "opus_tokens_out": 0,
    "estimated_cost_usd": 0.27
  }
}
```

**Required fields**: schema, ts, target, scope, tiers_run, findings, focus_areas.
**Optional fields**: model_costs.

**Per-finding required**: id, file, function, line_range, pattern, confidence, tier_classified, evidence.
**Per-finding optional**: exploitability_hint, fuzzing_recommendation, cve_pattern_match, hotspot_match.

**Allowed `pattern` values**: any bug class from `cve-patterns.md`'s vocabulary (`oob_write | oob_read | stack_overflow | uaf | double_free | null_deref | int_overflow | format_string | type_confusion | race | uninit_read | divide_by_zero | infinite_loop`).

**Allowed `confidence` values**: `high | medium | low`.

**Allowed `tier_classified` values**: `sonnet | opus`.

**`id` format**: `cr<NNN>` where NNN is zero-padded ≥3 digits, monotonic within one review run. Re-runs reset to `cr001`.

Validator runs in lenient mode (forward-compat for the schema growing in later releases).

### `state/cve-patterns.md` — REWRITABLE (v0.18 pattern guidance)

Rendered by `scripts/_lib/cve_patterns.py:render_guidance()` at the tail of `scripts/cve-context-build.sh`. The human/LLM-readable companion to `state/snapshots/cve-context-<ts>.json`. Contains:

- **Top patterns by frequency** — for each bug class observed across the target's CVE history, the historical locations, patch idioms, representative CVEs, generic seed strategies (rule-based), and coverage-target hints.
- **Hotspot locations** — per-file rollups: top affected functions, pattern mix, why-it-matters paragraph.
- **Reference PoCs cached for this campaign** — short list of Tier-A (promoted) and Tier-B (reference-only) PoCs.
- **How agents should use this document** — explicit role guidance for seed-generator / planner / coverage-analyst / mutator.

**Purpose framing (load-bearing)**: the document declares itself as PATTERN guidance, NOT a presence check. None of the listed CVEs are claimed to be present in the current codebase — they're studied to extract failure modes worth probing for NEW bugs in adjacent code.

**Lifecycle**: REWRITABLE, overwritten by every `cve-context-build.sh` run. The structured backing data in the `cve-context-<ts>.json` snapshot remains the immutable record. Consumers should ALWAYS read this markdown when available (it's the cheaper, narrative-driven entry point) and only descend into the JSON when a structured field is needed.

### `state/snapshots/cve-context-<ts>.json` — IMMUTABLE (v0.18 CVE intelligence)

Produced by `scripts/cve-context-build.sh`. The orchestrator runs the script at COLD start (synchronously, with a 300s timeout); `campaign-planner` reads it to populate the `## Known prior art` plan section, and every downstream specialist (harness-writer, seed-generator, coverage-analyst, reporter) consults it for hotspots and patterns.

```json
{
  "schema": "cve-context/v1",
  "ts": 1779200000,
  "target": "libxml2",
  "nvd_query": "libxml2",
  "fetch_stats": {"total": 167, "with_patch": 89, "parsed": 67, "with_poc": 8},
  "hotspots": {
    "by_file":     [{"path": "parse.c", "cve_count": 12, "top_funcs": ["xmlParseDoc","xmlParseContent"]}],
    "by_function": [{"name": "xmlParseDoc", "cve_count": 6}]
  },
  "pattern_frequency": {"oob_write": 23, "oob_read": 18, "uaf": 12, "int_overflow": 9},
  "patch_idioms":     [{"pattern": "bounds_check_added", "count": 18, "example_cves": ["CVE-2023-1234"]}],
  "time_since_last_high_cve_days": 89,
  "cves": [
    {"id": "CVE-2023-1234",
     "cvss_v3_1": {"vector_string": "...", "base_score": 7.5, "severity": "HIGH"},
     "cwe_id": "CWE-787",
     "description_summary": "OOB write in xmlParseDoc when ...",
     "patches": [{"url":"...", "source":"github", "commit_sha":"...", "repo":"GNOME/libxml2",
                  "files_changed":["parse.c"], "functions_changed":["xmlParseDoc"]}],
     "advisories": [...],
     "raw_references": [...],
     "poc": {"available": true, "tier": "A", "kind": "blob",
             "path": "fuzz/state/cve-cache/CVE-2023-1234/poc/test.xml",
             "source_url": "...", "promoted_to_corpus": true},
     "tags": ["oob_write"], "patch_idioms": ["bounds_check_added"],
     "published": "...", "last_modified": "..."}
  ]
}
```

**Required fields**: schema, ts, target, nvd_query, fetch_stats, hotspots, pattern_frequency, cves.
**Optional fields**: patch_idioms, time_since_last_high_cve_days.

`target` is the campaign's configured `cve.query`; `nvd_query` is the keyword that **actually** ran. NVD's `keywordSearch` ANDs every space-separated term, so an over-specific `target` ("<product> <format> parser config validation …") matches nothing — the builder then auto-broadens to the product token (e.g. `openssl`) and records *that* in `nvd_query`. When the two differ, the query was too narrow; prefer a one-token `cve.query`.

**Per-CVE required**: id, description_summary, patches.
**Per-CVE optional**: cvss_v3_1, cwe_id, advisories, raw_references, poc, tags, patch_idioms, published, last_modified.

**`poc.tier`** is one of `"A"` (auto-promote eligible, same-repo regression-test pattern + data blob), `"B"` (recognised security-org host, retain as reference only), or `"C"` (not downloaded). See the trust evaluator at `scripts/_lib/cve_poc_trust.py` for the exact classification rules. **No PoC URL is fetched until classified**; Tier C is recorded but never downloaded. Tier-B blob promotion to corpus requires explicit `--promote-tier-b` opt-in.

**Cache backing store**: `~/.cache/cc-fuzzer/cve/<sanitized-query>/` (cross-campaign shared) with a `fuzz/state/cve-cache` symlink for inspection. Cache TTL defaults to 30 days; re-runs are idempotent.

Validator runs in lenient mode (consistent with other snapshot files: forward-compat as the schema grows in v0.19+).

### `state/snapshots/delta-<ts>.json` — IMMUTABLE (OPTIONAL)

Produced by `scripts/find-delta-targets.sh`, invoked by `/cc-fuzzer:delta`. **On-demand only** — never auto-generated, never required. The campaign runs fine without this artifact; coverage-analyst simply skips delta weighting when none exists.

Shape:

```json
{
  "schema": "delta-targets/v1",
  "timestamp": 1714789400,
  "range": "main..HEAD",
  "commits": ["abc123def456...", "789abcdef012..."],
  "files_changed": 3,
  "targets": [
    {
      "file": "src/parser.c",
      "function_context": "static int parse_extended_chunk(buf_t *b)",
      "lines_changed": [482, 510],
      "kind": "modified"
    }
  ]
}
```

**Required fields**: schema, timestamp, range, commits, files_changed, targets.

`function_context` may be `null` when git can't determine the enclosing function (no `xfuncname` regex configured for the file's language). `kind` is one of `added | modified | deleted`. `range` accepts any git range syntax `<base>..<tip>` or `<base>...<tip>`.

Lifecycle: immutable once written. The latest file (newest mtime) is the canonical source for the campaign's current "view of what changed". Re-running `/cc-fuzzer:delta` writes a fresh artifact; older ones remain on disk but are not consumed.

**Consumers** (read-only):
- `coverage-analyst` — uses `targets` to boost ranking of recently-changed unreached functions; tags gaps with `reason: delta_target` when appropriate.
- `reporting-agent` — uses `range` to mark each finding's blamed commit as in-range or not in the FINDINGS-REPORT-<target>.md.

### `state/snapshots/concolic-<ts>.json` — IMMUTABLE

Produced by `concolic-executor`. Shape:

```json
{
  "schema": "concolic-result/v1",
  "timestamp": 1714789300,
  "gaps_targeted": ["g001", "g003"],
  "seeds_used": ["fuzz/corpus/seed_03.bin"],
  "inputs_generated": 47,
  "inputs_validated": 31,
  "inputs_promoted_to_corpus": 31,
  "symcc_timeouts": 1,
  "symcc_errors": 0
}
```

### `state/cmplog-dict-<ts>.dict` — IMMUTABLE

Produced by `scripts/extract-cmplog-dict.sh`, normally invoked by `coverage-analyst` at the start of each gap-classification run. Plain text, libFuzzer/AFL-format dictionary (one quoted entry per line, with C-style escapes for non-ASCII bytes), prefixed by a `#`-commented provenance header.

This file is the v0.13 surface for cmplog observations. AFL++'s cmplog already feeds these operands back into the fuzzer's mutation queue at runtime via `-c`; the dictionary file additionally exposes them to the LLM agents so they can:

- Classify gaps as `direct_compare` when the operand is already in the dict (cheap, no specialist dispatch).
- Avoid dispatching `concolic-executor` for branches cmplog has already solved.
- Use higher-confidence operand values when crafting targeted seeds (`seed-generator`).

Lifecycle: written by `extract-cmplog-dict.sh`, immutable once written, never modified or deleted by other scripts. The latest one (newest mtime) is the canonical source for this tick. Older ones are kept for trend analysis but not consumed.

If no AFL++ cmplog directories exist (libFuzzer engine, AFL++ launched without `-c`, or AFL++ version too old), the file is still produced but contains only the header explaining why no entries are present. This is normal and expected for libFuzzer campaigns; the dict file's existence is not gated on cmplog actually running.

### `state/FINDINGS-REPORT-<target>.md` — REWRITABLE

Human-readable Markdown report produced by `/cc-fuzzer:report` (the reporting-agent). Replaced atomically (`.tmp`, `mv`). Single canonical version.

There is no JSON schema — this is freeform Markdown. Required H2 sections (the validator checks for these headings; missing headings is a **warning**, not an error):

- `## Executive Summary`
- `## Findings` (one H3 per finding, e.g. `### f001 — heap-buffer-overflow`)
- `## Reproducer Commands`
- `## Evidence`
- `## False-Positive Analysis`

The reporting-agent re-runs every reproducer in `findings.jsonl` against the current harness binary before writing this file. Findings are classified as confirmed (still crashes) or false-positive (no longer crashes). Only confirmed findings appear in `## Findings` and `## Reproducer Commands`. Unconfirmed findings appear under `## False-Positive Analysis`.

**Per-finding provenance** (optional): when the project is a git repository, each finding section may carry a "Likely introduced" subsection sourced from `scripts/blame-finding.sh`. Provenance is computed at report-time only — it never lives in `findings.jsonl` (the immutable record), because blame can shift across rebases. Fields: `blamed_commit`, `blamed_date`, `blamed_author`, `blamed_summary`, `function_first_added`, `in_delta_range`, `delta_range`. `in_delta_range` is non-null only when a `delta-*.json` artifact exists at report time. When the project is not a git repository the entire provenance block is omitted; the report is still valid.

Lifecycle: REWRITABLE. May be deleted only by `/cc-fuzzer:reset`.

### `state/budget.json` — REWRITABLE

```json
{
  "schema": "budget/v1",
  "campaign_started": "2026-05-03T11:00:00Z",
  "limit_usd": 20.0,
  "spent_usd": 1.47,
  "spent_per_model": {
    "claude-haiku-4-5-20251001": 0.12,
    "claude-sonnet-4-6": 0.85,
    "claude-opus-4-7": 0.50
  },
  "tokens_in": 156000,
  "tokens_out": 41200,
  "last_updated": 1714789234
}
```

## Multi-Harness Mode (schema v9)

A "campaign" in multi-harness mode targets N entry functions in the same library, each with its own harness binary, corpus, and coverage state, while sharing a single findings DB, plan, and budget. Mode is decided by one signal: multi-harness mode is on iff `state/fuzz-config.json` declares a non-empty `harnesses[]` array.

**Since v0.19.2, every new campaign declares `harnesses[]` at COLD (via `scripts/harness-set.sh init`) and therefore runs in multi-harness mode from the start — even with a single harness, which is just the degenerate one-entry case.** This is deliberate: a campaign's on-disk layout and schemas never have to migrate when a second harness is added later (`harness-set.sh add` simply appends). **Singular mode is the legacy layout** — it is what pre-v0.19.2 campaigns (which have no `harnesses[]` array) use, and it remains fully supported and unchanged. The v8→v9 migration does NOT convert an existing singular campaign to multi; it stays singular until the user runs the explicit singular→multi upgrade below. The two modes coexist.

### Activation

Multi-harness mode is on iff `fuzz-config.json:harnesses` is a non-empty array. Every plugin script and agent dispatches on this single signal via the helper `_lib/harness-path.sh is_multi`.

### Singular → multi upgrade (in-place)

A singular campaign can be upgraded at any time via:

```
/cc-fuzzer:campaign --add-harness <new-name> --entry <new-fn>   \
                    [--rename-existing <name>]
```

The upgrade is mechanical, idempotent, and reversible until new artifacts are written:

1. Existing singular paths are moved under a per-harness bundle:
   - `fuzz/harness/`   → `fuzz/harnesses/<existing-name>/harness/`
   - `fuzz/corpus/`    → `fuzz/harnesses/<existing-name>/corpus/`
   - `fuzz/corpus-quarantine/` → `fuzz/harnesses/<existing-name>/corpus-quarantine/`
   - `fuzz/coverage/`  → `fuzz/harnesses/<existing-name>/coverage/`
2. `state/harness-built.json` is wrapped into `state/harnesses.json` as the first entry, gaining a `name` field.
3. `state/fuzz-config.json` gains `harnesses: [{name: "<existing>", entry_function: "<existing-entry>"}, {name: "<new>", entry_function: "<new-fn>"}]`.
4. Existing snapshot files (`coverage-<ts>.json`, `gaps-<ts>.json`, `concolic-<ts>.json`, `cmplog-dict-<ts>.dict`) are renamed in place to insert the existing harness name: `coverage-<existing>-<ts>.json`, etc.
5. Existing crashes under `fuzz/crashes/known/f*/repro.bin` keep their location; each finding line gets `harnesses: ["<existing>"]` appended via the standard in-place finding update.
6. The new harness is then built by `harness-writer --harness <new-name>`.
7. `state/harness-built.json` becomes a back-compat **mirror file** of `harnesses.json[0]` (read-only — writes go to `harnesses.json`).

`<existing-name>` defaults to the entry function name from the prior `harness-built.json`. The user may override with `--rename-existing`.

The reverse (multi → singular) is not supported; once a campaign has multiple harnesses with attributed findings, collapsing back loses information. The user can `/cc-fuzzer:reset` if they want to start over.

### Filesystem Layout (multi-harness mode)

```
fuzz/
├── state/                          # campaign-level shared state
│   ├── schema-version              # "v9"
│   ├── plan.md                     # one plan, ## Targets enumerates harnesses
│   ├── harnesses.json              # NEW: harness-set/v1, array of harness-built/v6
│   ├── harness-built.json          # back-compat MIRROR of harnesses.json[0] (read-only)
│   ├── fuzz-config.json            # fuzz-config/v3: harnesses[] + fuzzer_slots[].harness
│   ├── fuzzers.json                # fuzzers/v2: slot entries gain `harness`
│   ├── current.json                # current/v2: harnesses[] + active_harness
│   ├── findings.jsonl              # GLOBAL; each finding gains harnesses[]
│   ├── findings-legacy.jsonl       # unchanged
│   ├── FINDINGS-REPORT-<target>.md    # unchanged (rewritten by reporting-agent; per-harness breakdowns)
│   ├── events.jsonl                # unchanged
│   ├── budget.json                 # unchanged (campaign-level)
│   ├── snapshots/
│   │   ├── coverage-<harness>-<ts>.json      # per-harness; filename prefix
│   │   ├── gaps-<harness>-<ts>.json          # per-harness
│   │   ├── concolic-<harness>-<ts>.json      # per-harness
│   │   └── plan-<ts>.md                      # unchanged (campaign-level plan archive)
│   ├── cmplog-dict-<harness>-<ts>.dict       # per-harness
│   ├── fuzzer-<slot>.{pid,engine,log}        # unchanged (slot names already unique)
│   └── delta-<ts>.json                       # unchanged (campaign-level; tags gaps for all harnesses)
│
├── harnesses/                      # per-harness bundles
│   ├── <name-1>/
│   │   ├── harness/                # source + binaries + build.sh + dict.txt
│   │   │   ├── <name-1>_fuzzer.cc
│   │   │   ├── <name-1>_fuzzer
│   │   │   ├── <name-1>_fuzzer_cov
│   │   │   ├── <name-1>_fuzzer_verify
│   │   │   ├── <name-1>_fuzzer_cmplog          (optional)
│   │   │   ├── <name-1>_fuzzer_symcc           (optional)
│   │   │   ├── build.sh
│   │   │   ├── cov_main.c
│   │   │   └── dict.txt                        (optional, harness-local)
│   │   ├── corpus/                 # per-harness; seeds aren't interchangeable across entries
│   │   ├── corpus-quarantine/
│   │   └── coverage/               # per-harness profdata
│   │       ├── default.profraw
│   │       └── default.profdata
│   └── <name-2>/                   # ...same structure
│
└── crashes/                        # GLOBAL — a library bug is one bug regardless of source
    ├── new/                        # filename: <harness>__<sha256>.bin (double-underscore separator)
    ├── known/
    │   └── f<NNN>/
    │       ├── repro.bin
    │       ├── harnesses.txt       # NEW: one-line-per-harness mirror of finding.harnesses[]
    │       └── duplicates/         # filenames keep <harness>__ prefix
    ├── flaky/                      # filenames keep <harness>__ prefix
    └── stale/                      # unchanged (rebuild-invalidated)
```

**Singular-mode layout is unchanged** from v8. The validator dispatches on activation: if multi mode is on, the singular paths `fuzz/harness/`, `fuzz/corpus/`, etc. must NOT exist as regular directories (the upgrade moves them); if multi mode is off, the `fuzz/harnesses/` directory must NOT exist.

### `state/harnesses.json` — REWRITABLE

Schema: **`harness-set/v1`** (introduced by schema-version v9 / plugin v0.17).

```json
{
  "schema": "harness-set/v1",
  "harnesses": [
    {
      "schema": "harness-built/v6",
      "name": "parser",
      "harness_source": "fuzz/harnesses/parser/harness/parser_fuzzer.cc",
      "harness_binary": "fuzz/harnesses/parser/harness/parser_fuzzer",
      "coverage_binary": "fuzz/harnesses/parser/harness/parser_fuzzer_cov",
      "verify_binary":   "fuzz/harnesses/parser/harness/parser_fuzzer_verify",
      "coverage_tracking": true,
      "cmplog_binary": "fuzz/harnesses/parser/harness/parser_fuzzer_cmplog",
      "cmplog_enabled": true,
      "symcc_binary": null,
      "mutator_source": null,
      "build_script": "fuzz/harnesses/parser/harness/build.sh",
      "dict_files": ["fuzz/dictionaries/png-magic.dict"],
      "entry_function": "parse_extended_chunk",
      "input_encoding": "passthrough",
      "sanitizers": ["address","undefined","fuzzer"],
      "fuzzing_mode": "in_process",
      "target_source": "/abs/path/src/parser.c",
      "target_source_hash": "abc123def4567890",
      "build_command_hash": "0123456789abcdef",
      "harness_attempts": 1,
      "built_at": "2026-05-17T09:00:00Z"
    }
  ]
}
```

**Required**: `schema`, `harnesses` (non-empty array).

Each element is a `harness-built/v6` record (see below). The `name` field is the per-harness identifier; it must be unique within the campaign and match `^[a-z0-9][a-z0-9_-]{0,31}$`. It is referenced from `fuzz-config.json:fuzzer_slots[].harness`, from snapshot filenames, from finding records, and from per-harness paths.

**Writer**: `harness-writer` is the only writer. It performs atomic read-modify-write — reads current `harnesses.json`, modifies the targeted entry (or appends a new one for `--add-harness`), writes atomically.

**Back-compat mirror**: `state/harness-built.json` is rewritten to mirror `harnesses[0]` after every change. Singular-mode-only readers continue to work transparently. **Do not write to the mirror directly in multi mode** — the validator detects mirror drift and reports it as an error.

### `harness-built/v6` (per-harness record)

Identical to v5 except for the addition of the **required** `name` field:

```diff
+ "name": "<kebab-case-slug>",
  "schema": "harness-built/v6",
  "harness_source": "...",
  ...
```

In singular mode, `state/harness-built.json` continues to be a top-level `harness-built/v5` record (no `name` field). In multi mode, every record inside `harnesses.json:harnesses[]` is `v6` and carries `name`; the mirror file at `state/harness-built.json` is also v6 (it carries the `name` of `harnesses[0]`).

The migration v8 → v9 does NOT rewrite existing `harness-built/v5` files; it only sets `schema-version` to v9. A singular-mode campaign keeps using v5 forever.

### `state/fuzz-config.json` — `fuzz-config/v3`

```json
{
  "schema": "fuzz-config/v3",
  "fuzz_forks": 2,
  "harnesses": [
    {"name": "parser",  "entry_function": "parse_extended_chunk"},
    {"name": "encoder", "entry_function": "encode_chunk"}
  ],
  "fuzzer_slots": [
    {"slot": "parser-main", "harness": "parser",  "engine": "libfuzzer"},
    {"slot": "parser-afl",  "harness": "parser",  "engine": "aflpp", "role": "secondary", "afl_power_schedule": "explore"},
    {"slot": "encoder-main","harness": "encoder", "engine": "libfuzzer"}
  ]
}
```

**Required when multi mode is active**: `harnesses` (non-empty array, each entry has `name` + `entry_function`); every `fuzzer_slots[].harness` must reference an existing `harnesses[].name`.

**Required when multi mode is inactive**: `harnesses` is absent or empty; `fuzzer_slots[].harness` is absent (the implicit harness is the campaign's only one).

**Per-harness fields** (under `harnesses[]`): `name`, `entry_function`. Optional: `target_source` (defaults to whatever harness-writer infers if absent).

**Validator rule**: `harnesses[].name` matches `^[a-z0-9][a-z0-9_-]{0,31}$` and is unique within the array.

### `state/fuzzers.json` — `fuzzers/v2`

Each slot entry gains a **required** `harness` field in multi mode (omitted in singular mode):

```diff
{
  "slot": "parser-main",
+ "harness": "parser",
  "engine": "libfuzzer",
  "binary": "fuzz/harnesses/parser/harness/parser_fuzzer",
  ...
}
```

`launch-fuzzer-slot.sh` resolves `binary` from `harnesses[<harness>].harness_binary` rather than from the singular `harness-built.json`. The `--harness <name>` flag is required when multi mode is on.

### `state/current.json` — `current/v2`

```json
{
  "schema": "cc-fuzzer-current/v2",
  "now": 1714789234,
  "tick_number": 14,
  "active_harness": "parser",
  "harnesses": [
    {
      "name": "parser",
      "harness": {
        "binary":       "fuzz/harnesses/parser/harness/parser_fuzzer",
        "symcc_binary": null,
        "symcc_available": false
      },
      "coverage": {
        "snapshot_file": "fuzz/state/snapshots/coverage-parser-1714789200.json",
        "snapshot_ts":   1714789200,
        "lines_covered": 845, "lines_total": 4613, "line_pct": 18.3,
        "plateau": true, "seconds_since_progress": 1800
      },
      "fuzzer_stats": {
        "execs": 158653, "execs_per_sec": 603, "paths": 890,
        "crashes_total": 7, "new_crashes_since_previous": 0
      },
      "gaps": {
        "latest_report": "fuzz/state/snapshots/gaps-parser-1714789100.json",
        "total_pending": 6, "for_concolic": 2, "for_seedgen": 3,
        "for_harness": 1, "for_mutator": 0, "direct_compare": 0
      },
      "recommendation": {
        "branch": "concolic",
        "reason": "plateau, 2 concolic-eligible gaps, SymCC available"
      }
    },
    {
      "name": "encoder",
      "harness": { ... },
      "coverage": { ... },
      "fuzzer_stats": { ... },
      "gaps": { ... },
      "recommendation": { "branch": "sleep", "reason": "still climbing" }
    }
  ],
  "fuzzers": [
    {"slot": "parser-main",  "harness": "parser",  "engine": "libfuzzer", "pid": "13014", "running": true,  "started_at": "...", "restart_count": 0},
    {"slot": "parser-afl",   "harness": "parser",  "engine": "aflpp",     "pid": "13050", "running": true,  "started_at": "...", "restart_count": 0},
    {"slot": "encoder-main", "harness": "encoder", "engine": "libfuzzer", "pid": "13099", "running": true,  "started_at": "...", "restart_count": 0}
  ],
  "findings": {
    "unique_count": 2,
    "file": "fuzz/state/findings.jsonl",
    "by_harness": {"parser": 2, "encoder": 0}
  },
  "recommendation": {
    "branch": "concolic",
    "reason": "plateau on parser, 2 concolic-eligible gaps, SymCC available",
    "harness": "parser"
  },
  "last_report_at": 1714789999,

  "coverage":       "<mirror of harnesses[active].coverage — back-compat>",
  "fuzzer_stats":   "<mirror of harnesses[active].fuzzer_stats — back-compat>",
  "gaps":           "<mirror of harnesses[active].gaps — back-compat>",
  "fuzzer":         "<mirror of fuzzers[0] — back-compat>"
}
```

**New fields**:
- `active_harness` — the harness whose recommendation the orchestrator should act on this tick. Picked by `update-current.sh` as the harness whose recommendation has the highest priority (see "Tick discipline" below).
- `harnesses[]` — per-harness state (coverage, fuzzer_stats, gaps, recommendation).
- `recommendation.harness` — which harness this tick's dispatch should target.
- `findings.by_harness` — count of unique findings attributed to each harness (a finding attributed to multiple harnesses counts once per harness).

**Back-compat shims** (read-only mirrors of `harnesses[active]`): `coverage`, `fuzzer_stats`, `gaps`, `fuzzer`. These exist so v8-era readers keep working without immediate rewriting. They are removed in schema v10.

**Single-harness in multi mode**: a multi-mode campaign with exactly one harness still emits `harnesses[]` (with one element). `active_harness` is set; `recommendation.harness` is set. The shims mirror `harnesses[0]`.

### `state/findings.jsonl` — `finding/v2`

Each finding gains a **required** `harnesses` array listing every harness that has reproduced this stack hash:

```diff
{
  "schema": "finding/v2",
  "id": "f001",
  "stack_hash": "a1b2c3d4e5f6g7h8",
+ "harnesses": ["parser", "encoder"],
  "category": "heap-buffer-overflow",
  ...
}
```

In singular mode (no `harnesses.json`), each finding remains `finding/v1`; `harnesses[]` is absent. In multi mode, every finding line is `finding/v2`; `harnesses[]` is non-empty and every entry is an existing harness name.

**In-place edit rule, extended**: when a duplicate crash from harness X arrives for an existing finding f<NNN>, the triager updates the finding line:
1. Increment `dedup_count` by 1.
2. Update `last_seen`.
3. If `X` is not in `harnesses[]`, append it.
4. Atomic rewrite.

If `harnesses[]` grows, `fuzz/crashes/known/f<NNN>/harnesses.txt` is also rewritten to match (one harness name per line).

**Upgrade migration**: when singular → multi runs, existing `finding/v1` records are rewritten in place to `finding/v2` with `harnesses: ["<original-name>"]`. Back-compat for v1 records in multi mode is NOT supported — the upgrade is atomic.

### Per-Harness Snapshot Filename Rules

In multi mode, all per-harness state files carry the harness name as a filename prefix:

| Singular filename | Multi-mode filename |
|---|---|
| `coverage-<ts>.json` | `coverage-<harness>-<ts>.json` |
| `gaps-<ts>.json` | `gaps-<harness>-<ts>.json` |
| `concolic-<ts>.json` | `concolic-<harness>-<ts>.json` |
| `cmplog-dict-<ts>.dict` | `cmplog-dict-<harness>-<ts>.dict` |

Each multi-mode snapshot file additionally carries a top-level `"harness": "<name>"` field. The validator checks that the prefix matches the JSON field and that both reference a declared harness.

`fuzz/state/snapshots/plan-<ts>.md` is **not** per-harness — the plan is campaign-level.
`fuzz/state/snapshots/delta-<ts>.json` is **not** per-harness — delta target weighting applies across the campaign; `coverage-analyst` filters per harness at gap-classification time.

### Crash Lifecycle (multi-harness deltas)

The flow in [Crash Lifecycle](#crash-lifecycle-the-canonical-flow) below is the canonical singular-mode flow. In multi mode, the following deltas apply:

**Step 1 (fuzzer detects crash)** — unchanged. libFuzzer slots write to `./crash-*`, AFL++ slots write to their per-slot staging dir.

**Step 2 (detect-crashes.sh)** — the slot's `harness` field (resolved from `fuzzers.json`) becomes a filename prefix on the staged file:

```
fuzz/crashes/new/<harness>__<sha256>.bin     # double-underscore separator
```

The harness is determined from the slot directory (libFuzzer cwd → slot → harness) or the AFL++ output path. The detect-crashes hook resolves this via the helper `_lib/harness-path.sh slot_to_harness <slot>`.

**Step 3 (update-current.sh)** — `new_crashes_since_previous` is computed per-harness from the prefix. The crash counter under `harnesses[*].fuzzer_stats` is updated for the source harness only.

**Step 5 (crash-triager)** — for each `<harness>__<hash>.bin`:
- Parse the harness prefix.
- Reproduce against `harnesses[<harness>].verify_binary` (NOT the singular path).
- Compute stack hash from the sanitizer output.
- Look up in `findings.jsonl`:
  - **MATCH (existing finding f<NNN>)**: increment dedup_count, update last_seen, append `<harness>` to `harnesses[]` if not present, rewrite `f<NNN>/harnesses.txt`. Move staged file to `f<NNN>/duplicates/<harness>__<hash>.bin` (prefix retained for forensic value).
  - **NO MATCH (new finding)**: allocate `f<NNN+1>`, initialize `harnesses: ["<harness>"]`, write `harnesses.txt` with that one line, move staged file to `f<NNN+1>/repro.bin`. (The repro file itself has no prefix — `harnesses.txt` carries the source.)

The triager dispatches per-harness verify-binary lookups; a crash from a no-longer-declared harness (e.g. user removed it from `fuzz-config.json` mid-campaign) is moved to `fuzz/crashes/flaky/<harness>__<hash>.bin` with an event `{"event":"crash_orphaned_harness", ...}`.

### Slot ↔ Harness Binding

Every entry in `fuzz-config.json:fuzzer_slots[]` MUST declare a `harness` in multi mode. The (slot, harness) tuple is the unit of:

- Liveness checking and auto-restart (`check-slot-liveness.sh`).
- Stats attribution (each slot's execs/sec etc. roll up under `harnesses[<harness>].fuzzer_stats`).
- Crash provenance (the harness prefix on staged crash files).

There is no fixed N:1 mapping between slots and harnesses. A campaign may declare 4 libFuzzer slots on a hot harness and 1 AFL++ master on a cold one. AFL++ master/secondary roles are scoped per-harness — each harness has at most one master across its own slots, but two different harnesses each have their own master.

### Plan Structure (multi-harness)

`plan.md` in multi mode has a required `## Targets` section instead of the singular `## Target` / `## Harness` / `## Seed Strategy` / `## Dictionaries` / `## Concolic Strategy` / `## Coverage Targets` / `## Out-of-Scope` sections. Each harness gets one H3 block:

```markdown
## Targets

### parser (entry: parse_extended_chunk)

#### Harness
fuzzing_mode: in_process; sanitizers: address+undefined+fuzzer; ...

#### Seed Strategy
...

#### Dictionaries
...

#### Concolic Strategy
...

#### Coverage Targets
...

#### Out-of-Scope
...

### encoder (entry: encode_chunk)
...
```

Campaign-level sections that remain at top-level: `## Plateau & Dispatch`, `## References`. Optional sections (`## Delta Range`, `## Mutator Notes`, `## Known Caveats`) may be top-level or per-harness as appropriate.

The campaign-planner is the sole writer; specialists `grep` for their own section under the targeted harness. In revise mode the `## Campaign Status & Revisions` block stays at top level.

### Tick Discipline (cost cap)

A multi-harness tick still dispatches **at most one specialist** (across all harnesses). `update-current.sh` selects `active_harness` as the harness with the highest-priority recommendation per a fixed priority table:

```
triage           > restart_fuzzer > fix_instrumentation >
analyze_gaps     > reanalyze_gaps > concolic >
generate_seeds   > mutator         > stop > sleep
```

Ties broken by `harnesses[]` declaration order. Other harnesses' recommendations are recorded in `current.json:harnesses[*].recommendation` but not acted on this tick — they get their turn next tick. This preserves the v8 cost discipline: a 5-harness campaign does not 5x the LLM cost per tick.

The orchestrator may consult the per-harness recommendations to surface a brief status line to the user, but its dispatch decision is always `recommendation.harness` + `recommendation.branch` at the top level.

### Validation (multi mode adds)

`validate-state.sh` in multi mode additionally enforces:

- `harnesses.json` is well-formed `harness-set/v1`; `harnesses[]` is non-empty; every `name` matches the slug pattern and is unique.
- `state/harness-built.json` is a byte-or-field mirror of `harnesses.json[0]`. Mirror drift is an error.
- `state/harnesses/` does not exist (typo guard — the directory is `fuzz/harnesses/`, not under state).
- For every declared harness, `fuzz/harnesses/<name>/harness/`, `fuzz/harnesses/<name>/corpus/`, `fuzz/harnesses/<name>/coverage/` exist (warn if missing for a harness that has not yet been built).
- Every `fuzz-config.json:fuzzer_slots[].harness` references an existing harness name.
- Every per-harness snapshot file's filename prefix references an existing harness name; the file's `harness` field matches the prefix.
- Every `findings.jsonl` record is `finding/v2`; `harnesses[]` is non-empty; every entry is an existing harness name.
- `fuzz/crashes/new/*` filenames have the `<harness>__<sha256>.bin` shape with a known harness prefix.

In singular mode, these checks are skipped; the existing v8 validator runs unchanged.

### Migration v8 → v9

By default the migration is a **no-op for singular campaigns**: it only bumps `state/schema-version` from `v8` to `v9`. Nothing else changes on disk. Existing campaigns continue running in singular mode indefinitely; their `harness-built.json` stays at `harness-built/v5`; their snapshots keep their existing filenames; their findings stay at `finding/v1`.

There is **no auto-upgrade**. The transition to multi mode is always explicit, via `/cc-fuzzer:campaign --add-harness <name> --entry <fn>` (see "Singular → multi upgrade" above). That command performs the file moves, wraps `harness-built/v5` into a `harness-built/v6` record inside `harnesses.json`, rewrites findings to `finding/v2`, renames existing snapshots to insert the harness prefix, and updates `fuzz-config.json` to `fuzz-config/v3`.

The migration backup (`state/migrations/v8-v9-backup-<ts>.tar.gz`) is written by `migrate-state.sh` only if the upgrade command actually runs file moves; the version-only bump produces no backup tarball.

---

## Crash Lifecycle (the canonical flow)

This is deterministic. Every crash has exactly one location at any moment.

```
1. Fuzzer detects crash.
   - libFuzzer writes  ./crash-<sha1>  to cwd
   - AFL++ writes      <out_dir>/default/crashes/id:N,sig:M,...
              (where <out_dir> is fuzz/crashes/aflpp-staging by run-fuzzer.sh config)

2. detect-crashes.sh hook (PostToolUse) sees the new file.
   For each new file:
     a. Compute sha256 of file contents → <hash>
     b. Hard-link (or copy if cross-fs) into  fuzz/crashes/new/<hash>.bin
     c. Leave the original file alone (libFuzzer/AFL++ may still want it)

3. update-current.sh notices files in fuzz/crashes/new/.
   Sets current.json.recommendation.branch = "triage".

4. Orchestrator dispatches crash-triager.

5. crash-triager processes each file in fuzz/crashes/new/:
   For each <hash>.bin:
     a. Reproduce against harness:
        timeout 10 ./fuzz/harness/<harness_bin> fuzz/crashes/new/<hash>.bin
     b. If no crash → mv to fuzz/crashes/flaky/<hash>.bin
        Append event: {"event": "crash_flaky", "hash": "<hash>"}
        continue
     c. Compute stack hash from sanitizer output
     d. Look up stack hash in findings.jsonl:
        - MATCH (existing finding f<NNN>):
          - Update finding line in-place: dedup_count += 1, last_seen = now
          - mv fuzz/crashes/new/<hash>.bin → fuzz/crashes/known/f<NNN>/duplicates/<hash>.bin
          - Append event: {"event": "crash_dup", "finding_id": "f<NNN>", "hash": "<hash>"}
        - NO MATCH (new finding):
          - Allocate next ID f<NNN+1>
          - Create dir: fuzz/crashes/known/f<NNN+1>/
          - mv fuzz/crashes/new/<hash>.bin → fuzz/crashes/known/f<NNN+1>/repro.bin
          - Append finding line to findings.jsonl
          - Append event: {"event": "crash_new", "finding_id": "f<NNN+1>"}

6. fuzz/crashes/new/ is now empty.
   update-current.sh recomputes; recommendation likely becomes "sleep".
```

**Invariants**:
- A file in `fuzz/crashes/new/` has not been triaged.
- A file in `fuzz/crashes/known/<id>/repro.bin` is the canonical reproducer for finding `<id>`.
- A file in `fuzz/crashes/known/<id>/duplicates/` is a redundant input that produces the same stack hash as `<id>`.
- A file in `fuzz/crashes/flaky/` did not reproduce when triaged; not necessarily a non-bug (could be timing-dependent), kept for inspection.

**Hard rules**:
- Never delete crash files. They are evidence. `/cc-fuzzer:reset` is the only thing that does, and only with explicit user confirmation.
- Never modify `repro.bin`. The bytes the fuzzer found are sacred.
- Never re-triage files in `fuzz/crashes/known/`. They are settled.

## Oracle-Driven Fuzzing (logic findings)

Coverage-guided fuzzing with sanitizers finds **crashes**: memory-safety violations, aborts, UB. It is structurally blind to **logic bugs** — wrong answers that don't crash (auth bypass, parser differentials, canonicalization mismatches, silent integer truncation, state-machine confusion). These are often the higher-severity, real-world-exploitable bugs. Oracle-driven fuzzing adds the missing oracle: the harness, after driving the input through the target, *checks a property that must hold* and traps (`__builtin_trap()` / `abort()`) when it doesn't. A trap raises a deadly signal, so the existing crash pipeline (detect → triage → findings) carries logic findings end-to-end with only additive schema changes.

### The oracle types

`oracle_type` ∈ `crash | invariant | roundtrip | differential | metamorphic`. The crash oracle is always on; logic oracles are layered on top (sanitizers stay enabled).

| Oracle | The harness checks | Needs a second implementation? |
|---|---|---|
| `crash` | sanitizer / abort fired (implicit, always active) | no |
| `invariant` | a property of the output holds (bounds, ordering, "success ⇒ well-formed", conservation, idempotence) | no |
| `roundtrip` | `consumer(producer(x))` preserves `x` (parse∘serialize, decode∘encode, decompress∘compress) | no |
| `differential` | target and a reference agree on the same input (two libs / prior version / equivalent path) | yes — user-supplied `--reference` |
| `metamorphic` | a relation holds between outputs for *related* inputs `x` and `T(x)` — e.g. an insignificant transform `T` (whitespace, field reorder, equivalent encoding) leaves the result unchanged | no |

`metamorphic` is a relation across **two runs on related inputs** (vs `invariant`'s single-run property); the harness applies a semantics-preserving transform `T`, runs the target on both `x` and `T(x)`, and traps when the relation breaks. It catches canonicalization / normalization bugs without a second implementation.

**Orthogonal: stateful-sequence harnesses.** A *stateful* harness decodes the fuzz input into a **sequence of API operations** (an op-bytecode driven by FuzzedDataProvider) and runs them against one live target object, checking invariants across the sequence (e.g. "get after put returns the put value", "close-after-close is rejected, not a crash"). It reaches order-dependent / state-machine bugs a single-call harness cannot. It is an input-*driving* pattern (`input_encoding: custom`), not a new `oracle_type` — it carries any oracle (`crash` for sanitizer faults across the sequence, `invariant` for the cross-op properties). See `harness-writer` "Stateful-sequence harnesses".

### The accept-gate rule (the crux)

A logic oracle must **never** trap because the target *rejected* the input — rejecting malformed input is correct behavior, not a bug. It traps **only** when, *given the target accepted the input*, the invariant is violated or two oracles diverge. Every oracle harness gates the check on acceptance:

```c
auto parsed = tgt_parse(data, size);
if (!parsed.ok) return 0;                       // rejection is correct — NOT a finding
/* ... run the oracle on the ACCEPTED input ... */
if (!oracle_holds(parsed)) __builtin_trap();    // logic finding
```

This gate is what keeps a logic harness from drowning the campaign in false positives. It is a hard rule for `harness-writer`.

### The oracle marker

Before trapping, an oracle harness prints a structured marker to stderr so the triager can tell a logic-oracle violation apart from a memory crash and read the divergence without re-deriving it:

```
CCFUZZ_ORACLE_VIOLATION oracle=<invariant|roundtrip|differential|metamorphic> property=<property_id>
CCFUZZ_ORACLE_OBSERVED <short printable string>
CCFUZZ_ORACLE_EXPECTED <short printable string>
```

The triager keys on `CCFUZZ_ORACLE_VIOLATION`: present ⇒ logic finding (use `oracle_type`/`property`/`observed`/`expected` to build `divergence` and the property-divergence `stack_hash`); absent ⇒ ordinary crash finding via the normal stack-hash path. The marker plus the deadly signal from `__builtin_trap()` means the standard detect/verify/dedup pipeline carries the finding unchanged.

### Differential execution

`differential` defaults to **subprocess** execution: the reference runs out-of-process (no symbol clash, works for CLI tools), outputs are normalized, and the harness traps on divergence. In-process linking is an opt-in for clean libraries with distinct symbols. Outputs are compared **normalized**, never raw `memcmp` — two correct implementations legitimately differ in in-memory layout; the comparison function (named in `oracle.comparison`) canonicalizes first.

### Reference sourcing

The comparison oracle for `differential` is **user-supplied** via `/cc-fuzzer:campaign --reference <lib|path|nix-attr>`. (Prior-version auto-build and nixpkgs-proposed references are future work.) Without a `--reference`, the planner will not select `differential`; it falls back to `roundtrip`/`invariant`/`crash`.

### Oracle selection

The `campaign-planner` auto-selects oracle(s) from the prescan's `oracle_candidates` (inverse pairs → `roundtrip`; validation/auth gates → `invariant`/`differential`) and the target shape, recording the choice in `plan.md ## Oracle`. `/cc-fuzzer:campaign --oracle <type>` forces a specific oracle. Default with no signal and no `--reference` is `crash` (historical behavior — zero change to existing campaigns).

### COLD oracle smoke-test

Before a campaign with a logic oracle launches, `scripts/oracle-smoke-test.sh` (run by the orchestrator's COLD step 9, between SEED and LAUNCH) validates the oracle cheaply: it runs the **seed corpus** (known-good inputs) through the `verify_binary` and watches for the oracle marker. Because the accept-gate only emits the marker on an *accepted* input, a marker on a seed means the target accepted an ordinary valid input yet the oracle property still failed — the smoking gun for a mis-specified oracle.

- **No trip** → launch (the common case; native runs, no LLM).
- **Trip** → the tripping seed(s) are staged into `fuzz/crashes/new/` and the orchestrator dispatches `crash-triager` **before launch**. The triager's oracle-validity gate (below) decides bad-oracle vs genuine-early-finding — so a real day-0 logic bug is recorded rather than discarded, and a bad oracle is killed (harness-correction → rebuild crash-only) before any fuzzing cycles are spent. Skipped when the oracle is `crash`, no `verify_binary` exists, or the corpus is empty (the last two warn: "oracle unvalidated").

This converts "discovered after the fuzzer floods the triager" into "discovered at COLD time, adjudicated once," reusing the existing triage gate rather than inventing new judgment.

### Triage: the oracle-validity gate

For a logic finding, the triager's false-positive filter **inverts**. Instead of "is this a harness artifact?", it asks **"is the oracle itself wrong?"** — did the harness assert a property the target's contract never actually guarantees? (E.g. asserting key-order preservation across a round-trip when the format explicitly does not promise it.) A finding survives only if the violated property is genuinely required by the target's documented/intended contract. The triager records logic findings via `findings.sh add` with `ORACLE_TYPE` / `DIVERGENCE` set in the environment and `stack_hash` = the property-divergence hash.

### Differential: two divergence properties

A `differential` harness checks two properties, both respecting the accept-gate:
- `value_divergence` — both implementations accept the input but their **normalized** outputs differ. High-confidence semantic disagreement.
- `accept_divergence` — the implementations disagree on validity (one accepts, one rejects). The parser-differential class (request smuggling, filter/WAF bypass, auth evasion). The triager scrutinizes whether the disagreement is a real bug or **both-valid latitude** the spec leaves undefined (e.g. duplicate-key handling) — the latter is an oracle false positive.

Comparison is always **normalized**, never raw `memcmp`. The reference is user-supplied (`--reference`), not built by cc-fuzzer; the harness reads it from `CCFUZZ_REFERENCE_CMD` at runtime with the plan's value compiled in.

### UBSan integer/implicit-conversion suite

Beyond ASan+UBSan, the fuzzing and verify builds can opt into `-fsanitize=integer,implicit-conversion` — the checks that catch **silent numeric corruption** (unsigned wraparound, implicit truncation of a wider value into a narrower one feeding a length/index). These are an *extension of the crash oracle*: a violation prints `runtime error:` / a UBSan SUMMARY and is triaged through the normal stack-hash path, recorded as `ubsan-implicit-conversion` / `ubsan-integer` (the `ubsan-<kind>` category) or the `integer-truncation` logic class.

Gated, because `-fsanitize=integer` flags *defined* unsigned wraparound that is frequently intentional (hashing, counters, ring buffers):
- Enable only when the target shape warrants it (length/size arithmetic on attacker-controlled values) — the planner decides.
- The harness writes a UBSan **suppressions allowlist** (`fuzz/harnesses/<name>/harness/ubsan-int.supp`, `UBSAN_OPTIONS=suppressions=…`) and/or `__attribute__((no_sanitize("integer")))` notes for known-intentional wrap sites, so the signal isn't drowned.
- Built with `-fno-sanitize-recover=integer,implicit-conversion` so a surviving violation is a hard, deduplicable signal rather than a logged-and-continued warning.
- Recorded by adding `integer` / `implicit-conversion` to the harness record's `sanitizers[]`.

### Phasing note

Phases 1–4 are shipped (v0.23.0): the schema + finding fields + prescan `oracle_candidates` + triage path (1); `roundtrip`/`invariant` harness generation + planner oracle selection (2); `differential` subprocess harnesses with user-supplied reference + behavioral-impact PoC in `poc-builder` (3); stateful-sequence harnesses, the UBSan `integer`/`implicit-conversion` suite, and `metamorphic` relations (4). The logic-oracle capability is complete.

## Concurrency Rules

- **Single writer per file.** Every state file has exactly one writer (one script or one agent). No locking needed because there are no concurrent writers by design.
- **Atomic replacements.** REWRITABLE files are written to `<file>.tmp` then `mv`'d into place.
- **Append safety.** APPEND-ONLY files use `>>` from a single process. The orchestrator is the only writer of `events.jsonl`; `crash-triager` is the only writer of `findings.jsonl`.
- **No subagent ever writes to another's files.** `crash-triager` doesn't touch `events.jsonl`; the orchestrator doesn't touch `findings.jsonl`.

## Nix Build Backend (schema v10)

### Build Backend Commitment

Each harness record in `harnesses.json` carries `build_backend: "nix" | "legacy"`. Once written it can only change via `scripts/harness-set.sh fallback-backend` or `scripts/harness-set.sh promote-to-nix`. Agents and orchestrators must **never** modify this field as a side-effect of a normal rebuild.

**Discriminator rule:** `harness-writer` sets `build_backend` on first build only. Decision: if `$CC_FUZZER_FHS=1` AND `fuzz/nix-deps.nix` exists AND all nix variants build successfully → `"nix"`. Otherwise → `"legacy"`. After first build, the committed value is honored on every rebuild.

### `state/nix-build-log.jsonl` — APPEND-ONLY (nix build audit)

```json
{"schema":"nix-build/v1","id":"nb_0001","ts":"2026-05-26T16:00:00Z","tick_number":0,"harness":"parser","variant":"fuzzer","event":"attempt_ok","drv_hash":"abc...","store_path":"/nix/store/abc...-parser-fuzzer","out_link":"fuzz/harnesses/parser/harness/parser_fuzzer","nix_deps_hash":"7f8e...","flake_rev":"abc123...","duration_ms":14820,"cache_hit":true,"fallback_record_id":null}
```

`event` is one of: `attempt_start`, `attempt_ok`, `attempt_fail`, `terminal_fallback`, `reconstruct_ok`. Written by `scripts/nix-build.sh` only. Rotated to `nix-build-log-<ts>.jsonl.gz` on `/cc-fuzzer:reset`.

**Required fields**: schema, id, ts, harness, variant, event. All others optional.

### `state/nix-fallback-log.jsonl` — APPEND-ONLY (backend demotion audit)

```json
{"schema":"nix-fallback/v1","id":"nf_0001","ts":"2026-05-26T15:30:00Z","tick_number":0,"harness":"vendor","phase":"cold","reason":"external_blob_dependency","reason_class":"blocker","decided_by":"harness-writer","evidence":{"kind":"nix_build_error","summary":"vendor SDK download gated by EULA","log_path":"fuzz/state/nix-build-log.jsonl","log_record_id":"nb_0003"},"remediation_hint":{"audience":"plugin_user","category":"informational","human_message":"Legacy build.sh used; vendor SDK cannot be reproduced under Nix.","machine_hints":{}}}
```

**`reason` closed enum** (validator rejects any other value):
- `unfree_license_blocked` — required package is unfree and policy refuses it
- `no_nix_expr_for_target` — no working `.nix` expression exists for this target yet
- `platform_unsupported` — target requires a platform Nix cannot provide
- `external_blob_dependency` — build requires a non-reproducible vendor blob
- `host_lockfile_required` — build depends on system-level host state
- `manual_override` — user explicitly invoked `harness-set.sh fallback-backend`

Any nix failure that doesn't map to one of the above is a **hard refuse** — campaign halts; no silent demotion.

**Required fields**: schema, id, ts, harness, phase, reason, reason_class, decided_by, evidence, remediation_hint.

### `state/nix-environment-issues.json` — REWRITABLE (env reconciliation)

```json
{"schema":"nix-environment/v1","checked_at":"2026-05-26T16:00:00Z","campaign_commitment":{"any_harness_nix":true,"nix_harnesses":["parser"],"legacy_harnesses":[]},"environment":{"cc_fuzzer_fhs":false,"nix_binary_on_path":true,"fuzz_nix_deps_present":true,"flake_rev_runtime":null},"issues":[{"id":"env001","severity":"error","code":"fhs_shell_absent","affected_harnesses":["parser"],"summary":"Campaign committed to build_backend=nix but $CC_FUZZER_FHS is unset.","audience":"plugin_user","remediation":{"category":"reenter_dev_shell","human_message":"Re-enter the cc-fuzzer Nix dev shell: exit Claude, run 'nix run $CLAUDE_PLUGIN_ROOT#claude'.","fix_locus":"user_shell"}}]}
```

Written by `scripts/nix-env-reconcile.sh` at every session start. Empty `issues[]` = compatible. Orchestrator refuses to tick on `severity:"error"` issues for nix-committed harnesses.

**`code` closed enum**: `fhs_shell_absent`, `nix_binary_missing`, `nix_deps_missing`, `nix_deps_drift`, `flake_rev_drift`, `store_path_gc`, `manifest_drift`, `tool_missing`.

### `harness-built/v7`

Extends `harness-built/v6` with `build_backend` (required) and `nix` (required when nix, forbidden when legacy):

```json
{
  "schema": "harness-built/v7",
  "name": "parser",
  "build_backend": "nix",
  "build_backend_decided_at": "2026-05-26T14:00:00Z",
  "build_backend_decided_by": "harness-writer",
  "nix": {
    "manifest_path": "fuzz/harnesses/parser/nix/manifest.json",
    "manifest_hash": "8e9a1c2b3d4e5f60",
    "variants": {
      "fuzzer":  {"nix_file":"fuzz/harnesses/parser/nix/fuzzer.nix",   "store_path":"/nix/store/abc...", "out_link":"fuzz/harnesses/parser/harness/parser_fuzzer",       "drv_hash":"abc..."},
      "cov":     {"nix_file":"fuzz/harnesses/parser/nix/coverage.nix", "store_path":"/nix/store/def...", "out_link":"fuzz/harnesses/parser/harness/parser_fuzzer_cov",   "drv_hash":"def..."},
      "verify":  {"nix_file":"fuzz/harnesses/parser/nix/verify.nix",   "store_path":"/nix/store/ghi...", "out_link":"fuzz/harnesses/parser/harness/parser_fuzzer_verify","drv_hash":"ghi..."}
    },
    "flake_rev_used": "abc123def456",
    "nix_deps_hash": "7f8e9d0a1b2c3d4e"
  }
}
```

When `build_backend=="legacy"`, `nix` must be absent. `harness_binary`/`coverage_binary`/`verify_binary` are regular files (build.sh) or symlinks to store paths (nix).

### Nix Build Manifest (`fuzz/harnesses/<name>/nix/manifest.json`)

Input to the build, not campaign state. Written by `harness-writer`, read by `nix-builder`. Shape:

```json
{
  "schema": "nix-build-manifest/v1",
  "generated_by": "harness-writer",
  "harness": "parser",
  "target_source": "/abs/path/src/parser.c",
  "target_extra_sources": [],
  "harness_source": "fuzz/harnesses/parser/harness/parser_fuzzer.cc",
  "cov_main": "fuzz/harnesses/parser/harness/cov_main.c",
  "out_prefix": "fuzz/harnesses/parser/harness",
  "variants": {
    "fuzzer":   {"enabled": true, "sanitizers": ["address","undefined","fuzzer"]},
    "coverage": {"enabled": true},
    "verify":   {"enabled": true},
    "cmplog":   {"enabled": true},
    "symcc":    {"enabled": false}
  },
  "extra_compile_flags": [],
  "extra_link_flags": [],
  "extra_pkgconfig_modules": [],
  "mocks": []
}
```

`generated_by: "user-edit"` signals nix-builder to treat the file as authoritative and not overwrite without `--force`.

## Validation

`scripts/validate-state.sh` runs **strict** validation (your Q2 answer):

- Every JSON file must have a `schema` field matching a known schema name and version.
- Every required field per schema must be present.
- Every value must be in the allowed-values set per schema.
- **Any unrecognized field is an error.** This forces explicit schema bumps.
- Filesystem layout must match the spec — no stray files in `fuzz/state/`, no files outside the documented directories, no legacy paths like `known-crashes/`.

When validation fails, the orchestrator refuses to operate and prints the validation report. The user must either:
- Fix the issue manually
- Run `/cc-fuzzer:reset` to wipe state
- Run `scripts/migrate-state.sh` if the schema version mismatch is from a known migration path

## Migration Policy

When the plugin's expected schema version differs from `state/schema-version`:

1. `scripts/migrate-state.sh` is called automatically before any agent runs.
2. It reads `state/schema-version`, looks up the migration chain to the current version, and runs each step.
3. Each migration step must:
   - Be idempotent (safe to run twice).
   - Update `state/schema-version` only after all transformations succeed.
   - Write a backup to `state/migrations/<old>-<new>-backup-<ts>.tar.gz` first.
4. If no migration path exists, the orchestrator refuses to run and tells the user to either upgrade/downgrade the plugin or reset.

For v1 (initial release), there are no migrations yet. Future versions add them.

## Subagent Compliance

Every subagent prompt must be updated to reference this document. Specifically:

- **campaign-planner** is the only writer of `fuzz/state/plan.md` and `fuzz/state/snapshots/plan-<ts>.md`. Operates in two modes: fresh (COLD start, no prior plan) and revise (mid-campaign, `/cc-fuzzer:plan` invoked with an existing plan). In revise mode it always archives the prior `plan.md` to `snapshots/plan-<ts>.md` before replacing. Harness-locked decisions are restated verbatim from `harness-built.json` and cannot change without `/cc-fuzzer:campaign --reset`.
- **harness-writer** writes to `fuzz/harness/`, not arbitrary paths. Builds both fuzzing binary and coverage binary by default. Reads `fuzz/state/plan.md` for harness layout decisions.
- **seed-generator** writes to `fuzz/corpus/` for promoted seeds, `fuzz/corpus-quarantine/` for unvalidated.
- **mutator** writes `mutator.c` to `fuzz/harness/`.
- **coverage-analyst** writes `gaps-<ts>.json` to `fuzz/state/snapshots/`. Filename ts must equal the `timestamp` field.
- **concolic-executor** writes to `fuzz/corpus-quarantine/` first, validates, then promotes to `fuzz/corpus/`. Status JSON to `fuzz/state/snapshots/concolic-<ts>.json`.
- **crash-triager** is the only writer of `findings.jsonl`. Moves crash files between `fuzz/crashes/new/`, `fuzz/crashes/known/<id>/`, and `fuzz/crashes/flaky/` per the lifecycle above.
- **fuzz-orchestrator** is the only writer of `events.jsonl`. Reads `current.json` only on warm ticks.
- **reporting-agent** is the only writer of `fuzz/state/FINDINGS-REPORT-<target>.md`. It must also invoke `${CLAUDE_PLUGIN_ROOT}/scripts/update-current.sh` after writing.

If a subagent needs to write somewhere this document doesn't permit, the document must be updated first, then the agent. Not the other way around.

## Plugin Read-Only Rule

**No subagent may modify files under `${CLAUDE_PLUGIN_ROOT}/`.** This includes scripts, agent prompts, hook configs, and STATE_SCHEMA.md itself. The plugin is read-only at runtime; only `/plugin update` or upstream changes update plugin files.

If a subagent encounters a bug in a plugin script (e.g. `snapshot-coverage.sh` produces wrong output), the correct response is:

1. Document the bug clearly: what was expected, what happened, repro steps.
2. Write the report to `fuzz/state/plugin-issues.md` (append, never replace).
3. Surface it to the user: "I found a bug in plugin script X. I have NOT patched it. Should I (a) work around it locally for this campaign, (b) wait for a plugin update, or (c) something else?"
4. Stop. Do not modify the plugin file.

The reason: plugin files are reinstalled by `/plugin update`. Any in-place patches silently disappear, leaving the user with a campaign whose fixes evaporated. Working around in `fuzz/` is fine; modifying `${CLAUDE_PLUGIN_ROOT}/` is not.

This rule applies to all subagents without exception.
