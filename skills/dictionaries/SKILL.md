---
name: dictionaries
description: "Manage libFuzzer/AFL++ dictionaries for the active campaign. List, add, remove, or inspect bundled and project-local dictionaries. — usage: [list|available|active|add <name>|remove <name>|show <name>]"
argument-hint: "[list|available|active|add <name>|remove <name>|show <name>]"
allowed-tools: Bash
---

Run `${CLAUDE_PLUGIN_ROOT}/scripts/dictionaries.sh $ARGUMENTS`.

Common usage:
- `/cc-fuzzer:dictionaries list` — show all available + which are active
- `/cc-fuzzer:dictionaries add unicode-variation-selectors` — add a bundled dictionary
- `/cc-fuzzer:dictionaries add fuzz/dictionaries/my-grammar.dict` — add project-local
- `/cc-fuzzer:dictionaries show utf-edge-cases` — inspect contents
- `/cc-fuzzer:dictionaries remove utf-edge-cases` — remove from active set

After adding/removing, the fuzzer must be restarted (`/cc-fuzzer:stop` then `/cc-fuzzer:resume`) for the change to take effect.

Bundled dictionaries are described in `${CLAUDE_PLUGIN_ROOT}/dictionaries/INDEX.md`. Read that for guidance on which apply to your target.
