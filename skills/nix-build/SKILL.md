---
name: nix-build
description: "Build or rebuild harness binaries via nix derivations. Requires CC_FUZZER_FHS=1. — usage: [--harness <name>] [--variant fuzzer|coverage|verify|cmplog|symcc] [--force] [--fallback]"
argument-hint: "[--harness <name>] [--variant <v>] [--force] [--fallback]"
---

Dispatches the **nix-builder** subagent to (re)build harness binaries via nix derivations.

**Requires `CC_FUZZER_FHS=1`** (run inside `nix run ${CLAUDE_PLUGIN_ROOT}#claude` or `nix develop`).

Flags:
- `--harness <name>`: target harness (defaults to the primary harness from harnesses.json)
- `--variant <v>`: build only one variant — `fuzzer`, `coverage`, `verify`, `cmplog`, or `symcc`
- `--force`: regenerate `.nix` files even if they already exist (picks up manifest edits)
- `--fallback`: if the nix build fails after repair attempts, demote the harness to `build_backend=legacy` and run the legacy build path

Arguments: $ARGUMENTS
