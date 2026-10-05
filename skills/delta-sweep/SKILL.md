---
name: delta-sweep
description: "Work a diff line by line: every changed sink (format calls, copies, size arithmetic, pointer arithmetic, indexes, string scans, integer types, frees, loops) gets a verdict backed by an input you ran. Use when looking for the bug a change introduced. — usage: <diff file | git range>"
argument-hint: "<diff file | git range>"
---

A change can plant more than one flaw. Reading the diff, finding the first suspicious call and chasing it is how the one that matters gets skipped. The sweep turns the diff into a checklist and keeps it until every item has a verdict.

Run `cc-fuzzer` (in the plugin: `${CLAUDE_PLUGIN_ROOT}/bin/cc-fuzzer`):

1. **Build it once:** `cc-fuzzer sweep init $ARGUMENTS`. Files that are not C/C++ source are closed up front. If a sweep already exists, `cc-fuzzer sweep show` continues it.
2. **Work the list in the order shown.** `format-string` items come first: a call whose format is not a literal lets input supply `%n`/`%s`. For each item, decide whether the harness reaches the line and with what input, then craft that input and run it.
3. **Record each verdict:**
   `cc-fuzzer sweep mark <id> <verdict> "<why>" [--input <file>]`
   - `crash`: an input reached it and crashed. Give `--input`.
   - `reached`: an input reached it and did not crash. Give `--input`.
   - `unreachable`: the harness cannot reach it. Say why: which check or option is in the way.
   - `safe`: reachable, but bounded or checked. Say by what.
   Marking a hunk id (`h3`) gives all its lines the same verdict. Use that only when one reason really covers them all.
4. `cc-fuzzer sweep show` lists what is still open. `cc-fuzzer sweep gate` exits 1 while anything is.

A crash on one item is not the end. Others in the same change may be the bug that matters, so finish the list.

`hooks/sweep-gate.sh` is an opt-in Stop hook that refuses to end a turn while items are open. A CRS installs it; interactively, add it to your settings only while you work a sweep.
