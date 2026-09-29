# query-pack

Parametric query templates for the `query` lever. The agent fills in names;
it does not write the query. Models write semgrep reliably and QL
unreliably, and a fixed pack keeps reruns deterministic: the same template
with the same names is the same query.

    cc-fuzzer query template list
    cc-fuzzer query template fill <name> --param function=parse_chunk \
        --param sink=memcpy -o fuzz/state/queries/q1.yaml

Placeholders are `{{name}}`. Values must be C/C++ identifiers (letters,
digits, `_`, and `::` for C++ scopes); anything else is refused, so a
filled template can never carry injected query text.

| template | engine | params | asks |
|---|---|---|---|
| `unchecked-length` | semgrep | function, sink | does `function` pass a length to `sink` with no comparison on it? |
| `callers` | semgrep | function | who calls `function` (is it reachable from anything)? |
| `sink-in-function` | codeql | function, sink | does `function` call `sink`? |
| `callers` | codeql | function | which functions call `function`? |
