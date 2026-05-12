---
description: Advance the fuzzing loop by one tick. Use when running a campaign manually instead of as a continuous background loop.
---

Use the **fuzz-orchestrator** subagent to perform exactly one iteration of the fuzzing loop:

1. Read the latest state in `fuzz/state/`
2. Run `scripts/snapshot-coverage.sh`
3. Decide which branch to take (keep going / coverage-analyst / mutator / triager / stop)
4. Execute that branch
5. Print the per-tick status line

Do not loop. Return after one tick. The user will call `/fuzz:tick` again when they want the next iteration.

This mode is useful for:
- Inspecting each LLM decision before the next one fires
- Running on a server where you cannot leave a long-running session
- Debugging the orchestrator's decision logic
