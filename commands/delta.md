---
description: Compute git-diff-based delta targets for the campaign. Runs on demand only — the orchestrator does not call this automatically. Pure local tooling, no LLM, no fuzzer interruption.
argument-hint: [--range <git-range>]
allowed-tools: Bash
---

Run `${CLAUDE_PLUGIN_ROOT}/scripts/find-delta-targets.sh $ARGUMENTS`.

The script writes `fuzz/state/snapshots/delta-<ts>.json` (schema `delta-targets/v1`) with per-hunk records: file path, post-state line range, optional enclosing-function context from the git hunk header, and change kind (`added` / `modified` / `deleted`).

**Default range** (when no `--range` is supplied):

- `main..HEAD` if `main` exists and HEAD is on another branch.
- `master..HEAD` if `master` exists and HEAD is on another branch.
- `HEAD~30..HEAD` otherwise.

**Common usage:**

- `/cc-fuzzer:delta` — pick the default range.
- `/cc-fuzzer:delta --range main..HEAD` — fuzz everything on this branch vs. `main`.
- `/cc-fuzzer:delta --range HEAD~50..HEAD` — last 50 commits.
- `/cc-fuzzer:delta --range v1.2.0..HEAD` — since the last release tag.
- `/cc-fuzzer:delta --range <base>..<fix>` — n-day analysis on a specific fix commit.

**How it enters the loop.** On its next run, `coverage-analyst` reads the latest `delta-*.json` if one exists and weights any changed-but-uncovered function higher under the new gap reason `delta_target`. If no delta artifact exists, the campaign runs without delta weighting — there is no implicit enabling. Re-run `/cc-fuzzer:delta` whenever you push new commits and want the campaign to see them.

The `reporting-agent` also reads the latest `delta-*.json` to mark each finding as in-delta-range or not (when `/cc-fuzzer:report` is run).

This command is safe to run mid-campaign. It does not stop or restart the fuzzer.
