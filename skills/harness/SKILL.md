---
name: harness
description: "Generate a libFuzzer/AFL++ harness for a target. Building block — for a full campaign use /cc-fuzzer:campaign. — usage: <path-to-target-source-or-header> [entry-function]"
argument-hint: "<path-to-target-source-or-header> [entry-function]"
---

Dispatches the **harness-writer** subagent.

Standalone harness build, always in the canonical multi-harness layout (since v0.30 there is no singular layout). Before dispatching harness-writer, register a single harness slot so the build writes into `fuzz/harnesses/<name>/`:

1. Derive the entry function from `$ARGUMENTS` (second token; if absent, the agent infers it from the source). Run:
   ```
   scripts/harness-set.sh init --entry <entry-function>
   ```
   This is idempotent — if the campaign already has a declared harness set, it is a no-op and the existing set is reused. It stamps `fuzz/state/schema-version` (v12) and activates multi mode (`fuzz-config.json:harnesses[]`).
2. Dispatch **harness-writer** with `--harness <name>` (the name printed on the `HARNESS_SET name=… ` line). The agent reads `fuzz/state/plan.md` if present (otherwise source-only), writes the harness, builds three binaries (fuzzing + coverage + verify, plus optional cmplog when AFL++ is available), and iteratively repairs build failures (up to 5 attempts). Writes the per-harness record into `fuzz/state/harnesses.json` (mirrored to `harness-built.json`) via `write-harness-built.sh --harness <name>`.

Use this when iterating on harness logic alone, repairing a build after editing target source, or comparing entry points. For end-to-end campaigns (harness + seeds + live feedback + triage), use `/cc-fuzzer:campaign`. To add a *second* harness to an existing campaign, use `scripts/harness-set.sh add --entry <fn>` then dispatch harness-writer with the new `--harness` name.

Target: $ARGUMENTS
