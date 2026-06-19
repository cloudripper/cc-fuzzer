---
name: nix-build
description: "Build or rebuild harness binaries via nix derivations. Two modes: per-harness (compiles target source; needs CC_FUZZER_FHS=1) and monolithic (builds the project's own derivation for whole-library targets). — usage: [--harness <name>] [--variant fuzzer|coverage|verify|cmplog|symcc] [--force] [--fallback]"
argument-hint: "[--harness <name>] [--variant <v>] [--force] [--fallback]"
---

Dispatches the **nix-builder** subagent to (re)build harness binaries via nix derivations.

This is **not** a universal build button — it has two modes, chosen by the harness's `manifest.json:build_mode`:

- **per-harness** (default) — compiles `target_source` + the harness with the FHS clang (`clang src/*`). Right for leaf targets (a parser, a codec). **Requires `CC_FUZZER_FHS=1`** (run inside `nix run ${CLAUDE_PLUGIN_ROOT}#claude` or `nix develop`).
- **monolithic** — for a whole **instrumented library** (e.g. a large shared library produced by the project's own meson/cmake build) that only the project's OWN build system can produce. The manifest declares the derivation + a variant→output mapping + instrumented `.so`s for coverage; the build delegates to `nix build` (so **FHS is not required**). Full recipe + the mandatory toolchain-pin contract: `${CLAUDE_PLUGIN_ROOT}/references/nix-monolithic.md`.

Flags:
- `--harness <name>`: target harness (defaults to the primary harness from harnesses.json)
- `--variant <v>`: build only one variant — `fuzzer`, `coverage`, `verify`, `cmplog`, or `symcc` (also filters monolithic `outputs`)
- `--force`: regenerate `.nix` files even if they already exist (picks up manifest edits; per-harness mode only)
- `--fallback`: if the nix build fails after repair attempts, demote the harness to `build_backend=legacy` and run the legacy build path (per-harness mode only)

Arguments: $ARGUMENTS
