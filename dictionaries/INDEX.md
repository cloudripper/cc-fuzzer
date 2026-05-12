# cc-fuzzer bundled dictionaries

These are libFuzzer-format dictionaries that ship with the plugin. They are **opt-in** — `harness-writer` does not add them automatically, but the agent will suggest the relevant ones during COLD start based on your target's apparent input class.

Add a dictionary to your active campaign with:

```
/cc-fuzzer:dictionaries add unicode-variation-selectors
/cc-fuzzer:dictionaries add utf-edge-cases
```

List active and available:

```
/cc-fuzzer:dictionaries list
```

Inspect a dictionary's contents:

```
/cc-fuzzer:dictionaries show unicode-variation-selectors
```

## Available

| Name | Use when target | References |
|---|---|---|
| `unicode-variation-selectors` | accepts text input, especially anything with emoji/CJK rendering, terminal escape parsing, or Unicode normalization | https://paulbutler.org/2025/smuggling-arbitrary-data-through-an-emoji/ |
| `utf-edge-cases` | accepts UTF-8 or UTF-16 input, transcodes between encodings, uses `iconv`, `mbstate_t`, `wchar_t` | RFC 3629, Unicode 15.1 |
| `bidi-controls` | parses or displays user-controlled text (source code, comments, identifiers, log lines) | CVE-2021-42574, https://trojansource.codes/ |
| `c-strings` | takes string input via C string functions; uses `printf`-family or fixed-size buffers | classics |
| `path-traversal` | accepts paths, URLs, archive entries, symlinks | OWASP path traversal cheatsheet |

## Format

Each `.dict` file follows the libFuzzer dictionary format ([documented here](https://llvm.org/docs/LibFuzzer.html#dictionaries)):

```
# comments start with #
"a token"
"with \xNN hex escapes"
name="optional named token"
```

Both libFuzzer (via `-dict=path/to.dict`) and AFL++ (via `-x path/to.dict`) read this format directly. No LLM involvement on any tick — these tokens are mixed into mutations by the fuzzer engine itself.

## Adding your own

Project-local dictionaries go in `fuzz/dictionaries/` (not the plugin tree). They are picked up by `harness-built.json`'s `dict_files` array. Typical workflow:

```bash
mkdir -p fuzz/dictionaries
$EDITOR fuzz/dictionaries/my-target-grammar.dict
/cc-fuzzer:dictionaries add fuzz/dictionaries/my-target-grammar.dict
```

The plugin will not modify your project-local dictionaries. They survive `/plugin update` and reset operations.
