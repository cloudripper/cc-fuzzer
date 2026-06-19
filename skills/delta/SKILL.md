---
name: delta
description: "Compute git-diff-based delta targets for the campaign. Runs on demand only — the orchestrator does not call this automatically. Pure local tooling, no LLM, no fuzzer interruption. — usage: [--range <git-range>]"
argument-hint: "[--range <git-range>]"
---

Under ctxctl the top-level thread cannot run Bash directly. Dispatch **ops-runner** to compute delta targets.

## Steps

1. Dispatch `Agent(subagent_type: "ops-runner", prompt: "Run ${CLAUDE_PLUGIN_ROOT}/scripts/find-delta-targets.sh $ARGUMENTS and return the resulting path + summary. The script writes fuzz/state/snapshots/delta-<ts>.json (schema delta-targets/v1).")`.
2. Read the Agent's return.
3. Print to the user: the path of the new snapshot + a one-line summary of how many hunks were classified.

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

**How it enters the loop.** On its next run, `coverage-analyst` reads the latest `delta-*.json` if one exists and weights any changed-but-uncovered function higher under the gap reason `delta_target`. If no delta artifact exists, the campaign runs without delta weighting — there is no implicit enabling. Re-run `/cc-fuzzer:delta` whenever you push new commits and want the campaign to see them.

The `reporting-agent` also reads the latest `delta-*.json` to mark each finding as in-delta-range or not (when `/cc-fuzzer:report` is run).

Safe to run mid-campaign. Does not stop or restart the fuzzer.

No header.txt refresh is needed — `find-delta-targets.sh` reads state directly.
