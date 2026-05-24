---
name: reset
description: Wipe campaign state and start over. Use after major target source changes or to recover from corrupted state. Requires explicit confirmation.
argument-hint: "(no arguments — wipes state, prompts to confirm)"
allowed-tools: Bash
disable-model-invocation: true
---

This command wipes the campaign:

1. Stop the fuzzer if running.
2. Tar up `fuzz/state/` and `fuzz/crashes/known/` to `fuzz/reset-backup-<ts>.tar.gz` (so findings are not silently lost).
3. Remove `fuzz/state/`, `fuzz/harness/`, `fuzz/corpus/`, `fuzz/corpus-quarantine/`, `fuzz/crashes/`, `fuzz/coverage/`.
4. Print confirmation.

Run `${CLAUDE_PLUGIN_ROOT}/scripts/reset-campaign.sh` to do all of this. The script asks for confirmation before deleting anything.

After reset, run `/cc-fuzzer:campaign <target>` to start a fresh campaign.
