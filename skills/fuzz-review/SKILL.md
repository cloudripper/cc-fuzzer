---
name: fuzz-review
description: "Run a static code review of the target source — three-tier pipeline (deterministic prescan → Sonnet review → Opus deep pass). Tier 1 now folds in external SAST (semgrep, optional CodeQL) as a real-tool signal on top of the grep heuristics. Deep pass is the default; use --no-deep to skip it. --sweep reviews EVERY function via batched dispatch. — usage: [--no-deep] [--refresh] [--delta] [--sweep] [--batch-size <N>] [--target-root <path>] [--max-functions <N>|all] [--cost-cap <USD>] [--sast off|auto|on] [--no-sast] [--sast-rules <dir,dir>] [--codeql-db <path>] [natural-language guidance...]"
argument-hint: "[--no-deep] [--refresh] [--delta] [--sweep] [--batch-size <N>] [--target-root <path>] [--max-functions <N>|all] [--cost-cap <USD>] [--sast off|auto|on] [--no-sast] [--sast-rules <dir,dir>] [--codeql-db <path>] [natural-language guidance...]"
---

Runs the code review pipeline:

1. **Tier 1 — prescan** (free, ~seconds; +SAST adds seconds-to-minutes): file inventory + dangerous-API grep + **external SAST (semgrep, optional CodeQL)** + CVE-hotspot cross-reference + suspicion scoring → `fuzz/state/snapshots/code-review-prescan-<ts>.json`. Rules come from the bundled `rules/semgrep` set (TOCTOU + C/C++ memory; ships offline, the default) — every immediate `rules/*` subdir holding rule files is auto-loaded — plus any extra packs passed via `--sast-rules`, which accepts both local rule dirs and explicit semgrep **registry refs** (`p/trailofbits` for the cross-language Trail of Bits pack, other `p/…`/`r/…` packs, or rule URLs; fetched on demand, needs network). semgrep's `--config auto` is not supported (it requires telemetry, kept disabled for privacy) — name an explicit pack. SAST findings are attributed to the enclosing function by line range and bump its suspicion score harder than a grep hit (a real check/use rule beats a token match), so functions with no dangerous APIs but a real flaw — classic TOCTOU — get pulled into the candidate window instead of ranking at the bottom. Self-skips with a recorded reason when no analyzer is installed; the campaign continues on grep alone.
2. **Tier 2 — `code-reviewer`** (Sonnet, $0.30-0.50): classifies candidates as `high` / `medium` / `needs_deep_pass` / `low` → `fuzz/state/snapshots/code-review-<ts>.json` + `fuzz/state/code-review.md`
3. **Tier 3 — `code-reviewer-deep`** (Opus, $1-3, default): resolves `needs_deep_pass` questions via cross-file taint analysis, refines high findings with chain-fuel context, and ADDS new findings discovered during deep reading. Updates the same artifact in place.

Under ctxctl the top-level thread cannot run Bash directly. This skill dispatches **ops-runner** for the deterministic prescan and **code-reviewer** / **code-reviewer-deep** subagents for the LLM tiers.

## Steps (main-thread batch loop)

This is a windowed flow: prescan → N reviewer windows → merge → deep pass. The default (no `--sweep`) is 1 window at the cap, then a trivial merge, then deep — i.e. the existing behavior plus loud coverage disclosure.

1. **Refresh header + run Tier 1 prescan.** Dispatch ops-runner:
   ```
   Agent(subagent_type: "ops-runner",
         prompt: "Run two scripts in sequence:
                  Step 1: ${CLAUDE_PLUGIN_ROOT}/scripts/campaign-header.sh > ${FUZZ_STATE_DIR}/header.txt
                  Step 2: ${CLAUDE_PLUGIN_ROOT}/scripts/code-review-run.sh [--target-root <path>] [--max-functions <N>|all] [--sweep] [--batch-size <N>]
                  Return BOTH the `BATCH_PLAN ...` line and the `READY: <prescan-path>` line (last non-blank).")
   ```
   It auto-detects the source root from `harness-built.json` (or `code_review.scan_paths`), cross-links the latest `cve-context-*.json`, writes the prescan JSON, and prints a machine-readable plan: `BATCH_PLAN windows=<n> batch_size=<S> candidates=<c> mode=<capped|sweep>`. **Parse `windows` and `batch_size` from that line.** For binary-only targets it cannot resolve a source root — exit without dispatching agents.
2. **Tier 2 — windowed reviewer dispatch.** For each window `i` in `0..windows-1`, dispatch the `code-reviewer` subagent over its slice:
   ```
   code-reviewer --prescan <prescan-path> \
                 --window-start <i*batch_size> --window-count <batch_size> \
                 [--guidance "<text>"]
   ```
   Each window writes a PARTIAL snapshot `code-review-<ts>-w<NN>.json` (window-scoped, honest per-window `candidates_reviewed`) and does NOT write `code-review.md` — the merge owns that. In the default capped case this is a single window. Collect the partial paths the reviewers return.
3. **Merge.** Dispatch ops-runner to consolidate the window partials into the canonical snapshot + the loud markdown:
   ```
   ${CLAUDE_PLUGIN_ROOT}/scripts/code-review-run.sh merge-code-review \
       --prescan <prescan-path> \
       --out <snapshots>/code-review-<ts>.json \
       --md ${FUZZ_STATE_DIR}/code-review.md \
       --target <name> -- <partial-1> <partial-2> ...
   ```
   The merge dedups by `cr_hash`, reassigns stable `cr<NNN>` ids, aggregates `scope` (`candidates_reviewed`, `not_reviewed`, `coverage_complete`), and writes the LOUD coverage header. The single-window (capped) case passes through trivially. The merge prints the coverage header line + the canonical snapshot path.
4. **Tier 3** — unless `--no-deep`, dispatch the `code-reviewer-deep` subagent on the MERGED snapshot to resolve `needs_deep_pass` findings and add new ones, honoring `--cost-cap` (default `code_review.deep_pass_cost_cap_usd`). A `--sweep` run may warrant a higher `--cost-cap` since the merged snapshot can carry far more findings.

## Flags

- `--no-deep` — skip Tier 3. Saves $1-3; loses cross-file taint and Opus-discovered findings
- `--refresh` — force re-run even if source-hash matches the last review
- `--delta` — review only files changed since the last review
- `--sweep` — review EVERY inventoried function via batched reviewer windows (sugar for `--max-functions all` + sweep mode). Opt-in; the default per-tick review stays capped for cost discipline. Coverage disclosure is loud in both modes.
- `--batch-size <N>` — reviewer window size (default 30). Small enough that one window fits a single Sonnet pass within its ~50k-token budget; raising it risks a window silently under-reviewing (which the merge reports honestly, dropping `coverage_complete`).
- `--target-root <path>` — override auto-detected source root
- `--max-functions <N>|all` — cap Tier 2 to N candidates (default 50). `all` (or `0`) reviews everything (= `--sweep`); negatives are rejected.
- `--cost-cap <USD>` — override `code_review.deep_pass_cost_cap_usd` for this run (raise it for `--sweep`)
- `--sast off|auto|on` — control Tier-1 external SAST. `auto` (default) runs whatever analyzer is on PATH and self-skips loudly when none is; `off` disables; `on` is `auto` with a louder status. Also settable via `code_review.sast` in `fuzz-config.json`.
- `--no-sast` — shorthand for `--sast off`
- `--sast-rules <spec,spec>` — extra semgrep rule sources, appended to the default (the bundled `rules/semgrep` pack — TOCTOU + C/C++ memory — auto-discovered from every `rules/*` subdir, shipped offline). Each spec is either a **local rule dir** OR an explicit **semgrep registry ref** fetched on demand (needs network): `p/trailofbits` (cross-language Trail of Bits pack), other `p/…`/`r/…` registry shorthands, or an `http(s)://` rule URL. Each source runs in its own isolated pass, so a bad/unreachable spec only loses itself. semgrep's `auto` config is **unsupported** — it requires semgrep telemetry (`--metrics on`), which this plugin keeps disabled for privacy; passing `auto` is skipped with that note (no scan, no telemetry). Name an explicit pack like `p/trailofbits` instead.
- `--codeql-db <path>` — analyze a PREBUILT CodeQL database. CodeQL is skipped unless this (or `code_review.sast.codeql_db`) points at an existing DB; the prescan never builds one implicitly, to preserve its fast-and-free contract.

## Loud coverage disclosure

Both modes always disclose coverage. `code-review.md`'s header is the first content line: `⚠ COVERAGE: reviewed X of Y functions (Z%). N functions were NOT reviewed...` when incomplete, or `✓ COVERAGE: swept all Y functions.` after a complete sweep. `coverage_complete` is true ONLY when a sweep reviewed every inventoried function. A capped review (the per-tick default) is always reported incomplete so it never reads as a complete audit. `campaign-header.sh` surfaces a one-line `code-review:` digest each tick.

Additional text in `$ARGUMENTS` is natural-language guidance passed to both agents (scope focus, finding callouts, hypothesis hints).

## When this runs

- **At COLD**, between CVE-context build and `campaign-planner`
- **Mid-campaign on demand** via this command
- Never auto-runs from a WARM tick — this is a deliberate ~$1-3 step

For binary-only targets (no readable source), the command exits without invoking any agent.

Arguments: $ARGUMENTS
