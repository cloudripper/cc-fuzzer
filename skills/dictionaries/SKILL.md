---
name: dictionaries
description: "Manage libFuzzer/AFL++ dictionaries for the active campaign. List, add, remove, or inspect bundled and project-local dictionaries. — usage: [list|available|active|add <name>|remove <name>|show <name>]"
argument-hint: "[list|available|active|add <name>|remove <name>|show <name>]"
---

Under ctxctl the top-level thread cannot run Bash directly. Dispatch **ops-runner** to manage dictionaries.

## Steps

1. Dispatch `Agent(subagent_type: "ops-runner", prompt: "Run ${CLAUDE_PLUGIN_ROOT}/scripts/dictionaries.sh $ARGUMENTS and return the full output verbatim.")`.
2. Print the Agent's return verbatim.

Common usage:
- `/cc-fuzzer:dictionaries list` — show all available + which are active
- `/cc-fuzzer:dictionaries add unicode-variation-selectors` — add a bundled dictionary
- `/cc-fuzzer:dictionaries add fuzz/dictionaries/my-grammar.dict` — add project-local
- `/cc-fuzzer:dictionaries show utf-edge-cases` — inspect contents
- `/cc-fuzzer:dictionaries remove utf-edge-cases` — remove from active set

After adding/removing, the fuzzer must be restarted (`/fuzz-stop` then `/cc-fuzzer:resume-campaign`) for the change to take effect.

Bundled dictionaries are described in `${CLAUDE_PLUGIN_ROOT}/dictionaries/INDEX.md`. Read that for guidance on which apply to your target.

No header.txt refresh is needed — `dictionaries.sh` reads state directly.
