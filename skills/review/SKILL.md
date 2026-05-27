---
name: review
description: "Run a static code review of the target source — three-tier pipeline (deterministic prescan → Sonnet review → Opus deep pass). Deep pass is the default; use --no-deep to skip it. — usage: [--no-deep] [--refresh] [--delta] [--target-root <path>] [--max-functions <N>] [--cost-cap <USD>] [natural-language guidance...]"
argument-hint: "[--no-deep] [--refresh] [--delta] [--target-root <path>] [--max-functions <N>] [--cost-cap <USD>] [natural-language guidance...]"
---

Runs the code review pipeline:

1. **Tier 1 — prescan** (free, ~seconds): file inventory + dangerous-API grep + CVE-hotspot cross-reference + suspicion scoring → `fuzz/state/snapshots/code-review-prescan-<ts>.json`
2. **Tier 2 — `code-reviewer`** (Sonnet, $0.30-0.50): classifies candidates as `high` / `medium` / `needs_deep_pass` / `low` → `fuzz/state/snapshots/code-review-<ts>.json` + `fuzz/state/code-review.md`
3. **Tier 3 — `code-reviewer-deep`** (Opus, $1-3, default): resolves `needs_deep_pass` questions via cross-file taint analysis, refines high findings with chain-fuel context, and ADDS new findings discovered during deep reading. Updates the same artifact in place.

## How it runs

The skill drives the pipeline (there is no single review-orchestrator agent):

1. **Tier 1** — run the prescan, which prints `READY: <prescan-path>`:
   ```
   ${CLAUDE_PLUGIN_ROOT}/scripts/code-review-run.sh [--target-root <path>] [--max-functions <N>]
   ```
   It auto-detects the source root from `harness-built.json` (or `code_review.scan_paths`), cross-links the latest `cve-context-*.json`, and writes the prescan JSON. For binary-only targets it cannot resolve a source root — exit without dispatching agents.
2. **Tier 2** — dispatch the `code-reviewer` subagent with the prescan path and any natural-language guidance from `$ARGUMENTS`: `code-reviewer --prescan <prescan-path> [--guidance "<text>"]`.
3. **Tier 3** — unless `--no-deep`, dispatch the `code-reviewer-deep` subagent to resolve the `needs_deep_pass` findings and add new ones, honoring `--cost-cap` (default `code_review.deep_pass_cost_cap_usd`).

## Flags

- `--no-deep` — skip Tier 3. Saves $1-3; loses cross-file taint and Opus-discovered findings
- `--refresh` — force re-run even if source-hash matches the last review
- `--delta` — review only files changed since the last review
- `--target-root <path>` — override auto-detected source root
- `--max-functions <N>` — cap Tier 2 to N candidates (default 50)
- `--cost-cap <USD>` — override `code_review.deep_pass_cost_cap_usd` for this run

Additional text in `$ARGUMENTS` is natural-language guidance passed to both agents (scope focus, finding callouts, hypothesis hints).

## When this runs

- **At COLD**, between CVE-context build and `campaign-planner`
- **Mid-campaign on demand** via this command
- Never auto-runs from a WARM tick — this is a deliberate ~$1-3 step

For binary-only targets (no readable source), the command exits without invoking any agent.

Arguments: $ARGUMENTS
