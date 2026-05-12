# cc-fuzzer State Schema (v1)

This document is the **single source of truth** for the cc-fuzzer plugin's filesystem layout, JSON schemas, and lifecycle rules. Every subagent, command, and script must conform to what's defined here. If a subagent's prompt and this document disagree, this document wins.

Schema version: **v7** (cc-fuzzer plugin v0.15+)

## Filesystem Layout

All campaign state lives under a single root directory, conventionally `./fuzz/` relative to the project root. The orchestrator's working directory is the project root, never anywhere inside `fuzz/`.

```
fuzz/
├── state/                          # all orchestrator state
│   ├── schema-version              # plain text file, contains "v1\n"
│   ├── plan.md                     # IMMUTABLE after cold start
│   ├── harness-built.json          # rewritten only on rebuild
│   ├── current.json                # replaced atomically every update
│   ├── findings.jsonl              # APPEND ONLY for new findings; in-place edit allowed for dedup count
│   ├── FINDINGS-REPORT.md          # REWRITABLE markdown; rewritten by /cc-fuzzer:report
│   ├── events.jsonl                # APPEND ONLY, never edited
│   ├── budget.json                 # replaced atomically
│   ├── cmplog-dict-<ts>.dict       # IMMUTABLE per timestamp; cmplog runtime observations
│   ├── snapshots/                  # all IMMUTABLE timestamped state lives here
│   │   ├── coverage-<ts>.json      # IMMUTABLE once written
│   │   ├── gaps-<ts>.json          # IMMUTABLE once written
│   │   └── concolic-<ts>.json      # IMMUTABLE once written
│   ├── fuzzer.pid                  # session-only, deleted on stop
│   ├── fuzzer.engine               # session-only
│   └── fuzzer.log                  # session-only, append while fuzzer runs
│
├── harness/                        # all build artifacts
│   ├── <target>_fuzzer.cc          # harness source (or .c)
│   ├── <target>_fuzzer             # main fuzzer binary (libFuzzer or AFL++)
│   ├── <target>_fuzzer_cov         # coverage-instrumented binary
│   ├── <target>_fuzzer_cmplog      # AFL++ cmplog binary (optional, AFL++ only)
│   ├── <target>_fuzzer_symcc       # SymCC-instrumented binary (optional)
│   ├── mutator.c                   # custom mutator source (optional)
│   ├── build.sh                    # canonical build command
│   └── dict.txt                    # libFuzzer dictionary (optional)
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
| **IMMUTABLE** | Written once. Never modified, never deleted (except by `/cc-fuzzer:reset`). Examples: `plan.md`, `coverage-<ts>.json`. |
| **REWRITABLE** | Replaced atomically (write to `.tmp`, `mv`). Single canonical version. Examples: `harness-built.json`, `current.json`, `budget.json`. |
| **APPEND-ONLY** | Lines are added, never removed. Existing lines may be edited in-place ONLY for the specific cases enumerated in the schema below. Examples: `findings.jsonl`, `events.jsonl`. |
| **SESSION** | Created when a fuzzer process starts, deleted when it stops. Examples: `fuzzer.pid`, `fuzzer.log`. |

Any agent or script that violates a file's lifecycle category is a bug. The validator (`validate-state.sh`) detects most violations.

## JSON Schemas

All schemas use a `schema` field at the top level identifying the schema name and version: `"<name>/v<n>"`. Validators use this to dispatch.

### `state/schema-version` (plain text)

```
v7
```

A single line containing the framework schema version. The orchestrator reads this on session start and refuses to operate if it doesn't match the plugin's expected version. Migration is handled by `scripts/migrate-state.sh`.

Migration chain: `v0` (pre-schema, flat layout) → `v1` (subdirectory layout, schema fields) → `v2` (mandatory coverage builds, instrumentation field) → `v3` (multiple dictionary files) → `v4` (coverage_disabled_reason required when tracking off, schema field on all events) → `v5` (findings carry verified_against_build; crashes/stale/ for rebuild-invalidated findings; fuzz-config.json for per-project settings) → `v6` (harness-built/v4 with cmplog_enabled / cmplog_binary / cmplog_disabled_reason; new gap.reason `direct_compare` for cmplog-handled branches; current.json.gaps gains `direct_compare` counter) → `v7` (harness-built/v5 adds `fuzzing_mode: in_process | process_based`; `state/FINDINGS-REPORT.md` filesystem entry; `current.json` optional `last_report_at` field).

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
**Optional** (set to `null`/empty/omitted): verify_binary, symcc_binary, mutator_source, dict_files (default `[]`).
**Allowed values**:
- `input_encoding`: one of `passthrough | fdp | length_prefixed_records | custom`
- `sanitizers`: subset of `address | undefined | memory | thread | fuzzer | leak`
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

**Optional fields**: `last_report_at` (integer unix timestamp, set by reporting-agent after writing `FINDINGS-REPORT.md`).

The orchestrator dispatches based on this field exactly.

### `state/findings.jsonl` — APPEND-ONLY (with one in-place edit case)

One finding per line. JSONL format. Strictly append-only for **new** findings; in-place editing is permitted **only** to update the dedup count and last-seen timestamp on existing findings (the explicit answer to Q1).

```json
{"schema":"finding/v1","id":"f001","stack_hash":"a1b2c3d4e5f6g7h8","category":"heap-buffer-overflow","subcategory":"READ-1B","location":"get_wchar@charset.c:661","exploitability":"medium","root_cause":"multi-byte UTF-8 lead byte at last allocated byte triggers OOB read of continuation bytes","reproducer":"fuzz/crashes/known/f001/repro.bin","first_seen":"2026-05-03T13:42:00Z","last_seen":"2026-05-03T18:14:22Z","dedup_count":4,"sanitizer_report_excerpt":"==13355==ERROR: AddressSanitizer: heap-buffer-overflow on address ..."}
```

**Required fields**: schema, id, stack_hash, category, location, exploitability, root_cause, reproducer, first_seen, last_seen, dedup_count.
**Optional fields**: subcategory, sanitizer_report_excerpt.

**Allowed values**:
- `category`: `heap-buffer-overflow | heap-use-after-free | stack-buffer-overflow | global-buffer-overflow | stack-overflow | null-deref | assertion-failure | ubsan-<kind> | oom | timeout | flaky | harness-artifact`
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
**Allowed `reason` values**: `harness_gap | format_barrier | state_precondition | value_constraint | direct_compare | checksum_barrier | deep_path_condition | dead`.
**Allowed `recommended_agent` values**: `harness-writer | seed-generator | mutator | concolic-executor | none`.

The `direct_compare` reason (introduced in v6) marks branches whose comparison operands cmplog has already observed at runtime; the operand will be present in the most recent `fuzz/state/cmplog-dict-<ts>.dict`. These gaps are reported for visibility but the orchestrator does NOT dispatch a specialist for them — `recommended_agent` must be `none`. `update-current.sh` excludes them from `for_concolic` / `for_seedgen` / `for_harness` / `for_mutator` and counts them under `gaps.direct_compare` instead.

**Cap**: max 15 gaps per report. Validator enforces.

Filename ts equals `timestamp` field. Immutable once written.

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

### `state/FINDINGS-REPORT.md` — REWRITABLE

Human-readable Markdown report produced by `/cc-fuzzer:report` (the reporting-agent). Replaced atomically (`.tmp`, `mv`). Single canonical version.

There is no JSON schema — this is freeform Markdown. Required H2 sections (the validator checks for these headings; missing headings is a **warning**, not an error):

- `## Executive Summary`
- `## Findings` (one H3 per finding, e.g. `### f001 — heap-buffer-overflow`)
- `## Reproducer Commands`
- `## Evidence`
- `## False-Positive Analysis`

The reporting-agent re-runs every reproducer in `findings.jsonl` against the current harness binary before writing this file. Findings are classified as confirmed (still crashes) or false-positive (no longer crashes). Only confirmed findings appear in `## Findings` and `## Reproducer Commands`. Unconfirmed findings appear under `## False-Positive Analysis`.

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

## Concurrency Rules

- **Single writer per file.** Every state file has exactly one writer (one script or one agent). No locking needed because there are no concurrent writers by design.
- **Atomic replacements.** REWRITABLE files are written to `<file>.tmp` then `mv`'d into place.
- **Append safety.** APPEND-ONLY files use `>>` from a single process. The orchestrator is the only writer of `events.jsonl`; `crash-triager` is the only writer of `findings.jsonl`.
- **No subagent ever writes to another's files.** `crash-triager` doesn't touch `events.jsonl`; the orchestrator doesn't touch `findings.jsonl`.

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

- **harness-writer** writes to `fuzz/harness/`, not arbitrary paths. Builds both fuzzing binary and coverage binary by default.
- **seed-generator** writes to `fuzz/corpus/` for promoted seeds, `fuzz/corpus-quarantine/` for unvalidated.
- **mutator** writes `mutator.c` to `fuzz/harness/`.
- **coverage-analyst** writes `gaps-<ts>.json` to `fuzz/state/snapshots/`. Filename ts must equal the `timestamp` field.
- **concolic-executor** writes to `fuzz/corpus-quarantine/` first, validates, then promotes to `fuzz/corpus/`. Status JSON to `fuzz/state/snapshots/concolic-<ts>.json`.
- **crash-triager** is the only writer of `findings.jsonl`. Moves crash files between `fuzz/crashes/new/`, `fuzz/crashes/known/<id>/`, and `fuzz/crashes/flaky/` per the lifecycle above.
- **fuzz-orchestrator** is the only writer of `events.jsonl`. Reads `current.json` only on warm ticks.
- **reporting-agent** is the only writer of `fuzz/state/FINDINGS-REPORT.md`. It must also invoke `${CLAUDE_PLUGIN_ROOT}/scripts/update-current.sh` after writing.

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
