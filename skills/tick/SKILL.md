---
name: tick
description: Advance the fuzzing loop by one tick. Use when running a campaign manually instead of as a continuous background loop.
argument-hint: "(no arguments — advance one WARM tick)"
disable-model-invocation: true
---

Dispatches the **fuzz-orchestrator** subagent to perform exactly one WARM-tick iteration (its WARM-mode procedure owns the steps). **Do not loop** — return after one tick. The user calls `/cc-fuzzer:tick` again for the next iteration, or uses `/loop` / YOLO mode to automate it.

Useful for inspecting each LLM decision before the next fires, running where you can't leave a long session open, or debugging the orchestrator's decision logic.
