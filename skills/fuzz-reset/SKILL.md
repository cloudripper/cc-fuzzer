---
name: fuzz-reset
description: Wipe campaign state and start over. Use after major target source changes or to recover from corrupted state. Requires explicit confirmation.
argument-hint: "(no arguments — wipes state, prompts to confirm)"
disable-model-invocation: true
---

This command wipes the campaign:

1. Stop the fuzzer if running.
2. Tar up `fuzz/state/` and `fuzz/crashes/known/` to `fuzz/reset-backup-<ts>.tar.gz` (so findings are not silently lost).
3. Remove `fuzz/state/`, `fuzz/harness/`, `fuzz/corpus/`, `fuzz/corpus-quarantine/`, `fuzz/crashes/`, `fuzz/coverage/`.
4. Print confirmation.

Under ctxctl the top-level thread cannot run Bash directly. Dispatch **ops-runner** to run the reset script.

## Steps

1. Dispatch `Agent(subagent_type: "ops-runner", prompt: "Run ${CLAUDE_PLUGIN_ROOT}/scripts/reset-campaign.sh and return the full output verbatim. The script asks for confirmation before deleting anything — surface the prompt to the user.")`.
2. Read the Agent's return.
3. Print to the user; if a confirmation prompt is surfaced, relay it.

After reset, run `/cc-fuzzer:campaign <target>` to start a fresh campaign.

No header.txt refresh is needed (state is about to be wiped anyway).
