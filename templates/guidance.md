# Campaign guidance

> This is a **template** shipped with cc-fuzzer at `${CLAUDE_PLUGIN_ROOT}/templates/guidance.md`.
> To use it, copy this file to your project as `fuzz/guidance.md` and edit the sections.
> The plugin's subagents (`seed-generator`, `mutator`, `coverage-analyst`) will read it
> when present and shape their behavior accordingly.
>
> If `fuzz/guidance.md` does not exist, the plugin runs with no special guidance.

---

## Target description

A few sentences describing what the target is, what it does, and what the harness exercises. Be specific. Example:

> Fuzzing the `parse_message()` function in libfoo. Inputs are length-prefixed binary records with a 4-byte magic header `FOO!`. Internally the parser maintains state across calls and supports nested records up to 8 levels deep.

(Replace this block with your actual description.)

## Input classes to emphasize

List the *categories* of input you want the LLM to generate seeds and mutators for. Be specific about why — the agents use these reasons to prioritize.

Examples:

- **UTF-8 edge cases**: target uses `wchar_t` internally and calls `mbtowc`, so transcoding bugs are likely. See https://en.wikipedia.org/wiki/UTF-8#Invalid_sequences.
- **Unicode variation selectors (VS15/VS16, IVS)**: this is a terminal emulator, so emoji presentation modifiers and the smuggling channel from https://paulbutler.org/2025/smuggling-arbitrary-data-through-an-emoji/ are in scope.
- **Bidi controls**: target renders user-supplied text in a TTY, so Trojan Source style attacks (CVE-2021-42574) are relevant.
- **Length-prefixed framing**: deeply nested records, off-by-one in length math, integer overflow in size calculations.

(Replace with your target-specific list. Delete sections that don't apply.)

## Recommended bundled dictionaries

If any of cc-fuzzer's bundled dictionaries fit your target, list them here. The orchestrator will suggest adding them at COLD start; you can also add them manually with `/cc-fuzzer:dictionaries add <name>`.

Available bundled dictionaries:

- [ ] `unicode-variation-selectors`
- [ ] `utf-edge-cases`
- [ ] `bidi-controls`
- [ ] `c-strings`
- [ ] `path-traversal`

(Check the boxes for the ones you want.)

## Format expectations

What shape does input take?

- **Encoding**: e.g. "UTF-8 only", "raw binary", "either UTF-8 or UTF-16 with BOM detection", "ASCII-only by spec but tolerated UTF-8 in practice"
- **Framing**: e.g. "length-prefixed records", "newline-terminated", "fixed 1024-byte chunks", "free-form"
- **State**: e.g. "stateless per-call", "accumulates state across calls", "requires init() before parsing"
- **Maximum size**: e.g. "PATH_MAX", "16 MB hard limit", "no documented limit"

## Known irrelevant classes

What categories should the LLM **not** waste time on? This is just as important as what to emphasize, because it stops Haiku from generating useless seeds.

Examples:

- This target is text-only; binary mutations (random byte flips) are usually rejected immediately by the magic-byte check.
- Network framing is not in scope; the harness does not call any socket APIs.
- Compression formats are not relevant; the harness operates on already-decompressed input.

## Coverage targets

Optional. List specific functions or files you most want to exercise. The `coverage-analyst` will weight gaps in these areas higher.

- `src/parser.c::parse_extended_chunk` — newer code, less battle-tested
- `src/charset.c::*` — recently rewritten for UTF-8 support
- `src/auth/*.c` — security-sensitive

## Out-of-scope code

Optional. Functions or files you want to avoid spending coverage analysis on (e.g., dead code, debug-only paths, third-party deps that already have their own fuzzing).

- `src/debug/*.c`
- `vendor/zlib/` — fuzzed separately
- `*_test.c` — test code, not under fuzz

## References

Drop any relevant links here for the agents' use. They will be read during gap analysis and seed generation.

- (paper or blog post on bugs in this domain)
- (CVE that targets a similar component)
- (project's own bug tracker)
