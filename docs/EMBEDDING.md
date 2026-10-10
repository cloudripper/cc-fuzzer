# Embedding cc-fuzzer in a CRS

`cc_fuzzer_core` is the deterministic driver for the analysis. The Claude Code
plugin is one consumer; a CRS is another. Both call the same code, and where
they differ the difference is data — a profile, a config block, a runner — not
a second implementation.

**You almost certainly do not want the tick loop.** It exists because the
plugin has no scheduler of its own. A CRS already owns scheduling, fuzzer
lifecycle, corpus sync and a listener that hears about crashes. What is worth
importing is the judgement either side of the fuzzer, in two request/response
seams:

```
   your listener ──► crs.triage(record, crash)      ──► a minimized, verified PoV
   your patcher  ──► crs.check_patch(record, patch) ──► fixes / does_not_fix /
                                                        breaks_tests / stale
```

Both exist because the expensive mistake in a scored run is submitting
something that is not true. `triage` protects the finding; `check_patch`
protects the fix. Neither needs a tick, a `current.json`, or a scheduler —
`triage` needs one dict saying where the binaries are.

---

## 1. Install

```bash
pip install /path/to/cc-fuzzer          # from a checkout
pip wheel --no-deps -w vendor/ /path/to/cc-fuzzer   # a wheel to vendor into an offline image
cc-fuzzer --version
```

The package is stdlib-only and needs Python 3.10 or newer. The wheel carries
its own data (prompts, rules and the query pack, dictionaries, templates,
`STATE_SCHEMA.md`, `models.json`). `CC_FUZZER_ROOT` is **not** required. Pin
it by commit and wheel sha256 when you vendor it. What changed between
versions, and whether a host notices, is in `CHANGELOG.md`.

The plugin's hook scripts (`hooks/*.sh`) are **not** in the wheel: they are
the plugin's translation of Claude Code's hook JSON. A host calls the same
decisions through the CLI or the API instead (§14).

## 2. Seam one: a crash arrives

```python
from cc_fuzzer_core import crs

record = {"verify_binary": "/out/parser_verify"}     # all the state it needs
cfg    = {"verification": {"final_step": "command:/opt/crs/oracle.sh"}}

r = crs.triage(record, "/crashes/x.bin", harness="parser", config=cfg)
if r.should_submit:                     # submittable AND the submission policy
    submit(r.pov, r.stack_hash)        # r.pov is the MINIMIZED input
```

`triage` does these, in this order, and stops as soon as the answer is
known:

| | |
|---|---|
| **replay** | deterministically, 3×, on the binary §10 selects — never an instrumented build |
| **minimize** | smallest input reproducing **the same bug** (see §3); skipped for `timeout` and `oom` (`crs.UNMINIMIZED`: every probe would run to the limit), so `pov` is the original |
| **verify** | your oracle, via `verification.final_step` |
| **byte map** | only if confirmed, and not for `timeout`/`oom`: which bytes of the PoV decide the bug (see §3.1) |
| **marker** | only if confirmed, and only if you pass a campaign |
| **delta relevance** | only if you pass `delta_range` (reported, never a filter) |
| **policy** | always: `policy_verdict`, and so `should_submit` |

`status` is one of `confirmed`, `rejected`, `inconclusive`, `not_a_crash`,
`flaky`. Read **`r.submittable`** rather than `status == "confirmed"`: it also
requires `evidence_grade == "strong"`. A crash shown only on the fuzzing
binary — because no verify binary was built — is good enough to triage and not
good enough to submit.

**Raw fuzzer artifacts: screen them.** libFuzzer saves a harness that called
`exit()`, and a leak report, as `crash-*` too, and in `-fork` mode its log
does not say which file is which. `screen=` labels each input by one run and
stops there unless its cause is one you want:

```python
r = crs.triage(record, crash, harness="parser", config=cfg, screen=("crash",))
r.cause      # "crash" | "leak" | "timeout" | "oom" | "exit" | "none"
```

An exit costs one run (`not_a_crash`), a leak one run (`rejected`, a real
crash of a kind you screened out). Without `screen` every input is replayed
`replay_attempts` times — which is what tells `flaky` from `not_a_crash`, so
an input that fired on the fuzzer but not on the screening run is worth one
unscreened retry if you can spare it.

**Hangs and OOMs, if your scorer counts them.** CRSBench, for one, replays a
PoV through OSS-Fuzz's base-runner with `-timeout=25 -rss_limit_mb=2560`, and
counts any non-zero exit as a crash, so an input running past 25 s or 2,560 MB
scores unless the harness's `.options` neutralise it (`timeout_exitcode=0`).
To replay as the scorer does, put its flags in the record; libFuzzer then
reports a hang with its stack instead of the replay killing it silently, and
its own OOM report (`ERROR: libFuzzer: out-of-memory`) classifies as `oom`:

```python
record = {"harness_binary": "/out/parser",
          "replay_args": ["-timeout=25", "-rss_limit_mb=2560"]}   # placed before the input
r = crs.triage(record, crash, harness="parser", config=cfg,
               screen=("crash", "timeout", "oom"))               # let them reach triage
```

Hangs and slow inputs are easy to confuse: a host that submits hangs should
confirm one outlasts a margin (ParallaxCRS replays at twice the timeout) and
cap how many it submits. Minimization's own probes call `run_once` without
`replay_args`, which is one more reason `timeout`/`oom` are not minimized.

**Delta: sweep every changed sink**, and **duplicate tool calls**: see §14,
which covers the sweep checklist and its Stop gate, the duplicate-call guard,
the behaviour governor and the round policy, and how to wire each one.

**If your oracle is the scoring oracle, say so.** In OSS-CRS every binary is a
libFuzzer build, so local replay always grades `weak` and nothing would ever
be submittable. Declare the oracle authoritative and its confirmation upgrades
the grade:

```python
cfg = {"verification": {"final_step": "command:/opt/crs/run-pov-oracle.sh",
                        "authoritative": True}}      # literally true, not "yes"
r = crs.triage({"harness_binary": "/out/parser"}, crash, harness="parser", config=cfg)
r.replay_grade, r.evidence_grade, r.evidence_source  # "weak", "strong", "oracle"
```

**Which binary is the verify binary.** The OSS-Fuzz builder builds `verify`
with `SANITIZER=address` (it must detect at least what the fuzzing binary
detects; a UBSan-only binary turns real overflows into `not_a_crash`). If your
framework already ships a better replay target, name it instead of building
one:

```json
{"build": {"verify_variant_source": "debug"}}
```

The record's `debug_binary` then becomes the verify binary and the verify
variant is not built (`spec()["provided"]`). A framework debug build still
links the fuzzer driver, so it grades `weak` (set
`build.verify_variant_link_mode: "standalone-main"` if yours does not); that is
the case an authoritative oracle exists to upgrade.

Only a confirmation upgrades; a rejection or an inconclusive answer adds
nothing, and a `strong` replay is never downgraded. `poc-realism` cannot be
declared authoritative: it checks an agent's work, it is not an oracle. The
finding marker records `evidence_source` too, so the upgrade is auditable.

**True is not the same as worth submitting.** `submittable` says the finding
is true. Whether it is worth submitting depends on your scoring oracle, so it
is a policy hook, and **`r.should_submit`** is both:

```python
cfg["submission"] = {"policy": "builtin:memory-safety",     # or python:mod:fn
                     "max_variants_per_stack_hash": 2}
r = crs.triage(record, crash, harness="parser", config=cfg, seen=already_submitted)
r.policy_verdict   # {"schema": "policy-verdict/v1", "verdict": "accept"|"reject", "reason", "policy"}
```

`builtin:any-confirmed` (default) accepts every confirmed finding;
`builtin:memory-safety` accepts only errors reported by ASan or MSan. It
rejects leaks, anything from UBSan (`sanitizer == "undefined"` or a `ubsan-*`
category), `oom`, `timeout`, `generic-crash`, `abort`, `assertion-failure`,
`signed-integer-overflow`, `integer-overflow` and `segfault`, and everything
reported by no sanitizer or by libFuzzer alone (`deadly-signal`, libFuzzer's
own timeout and OOM). A scorer that counts aborts or hangs (CRSBench counts any
non-zero exit) needs a custom policy; build it on this one as shown below. A custom policy gets the whole
result dict (including `sanitizer`, `category`, `delta_relevance`) and returns
a bool, `"accept"`/`"reject"`, a `(verdict, reason)` pair, or a dict. The core
keeps no submission state: pass `seen` ({stack_hash: count}) to enforce
`max_variants_per_stack_hash`.

A host policy that builds on a builtin composes it through the public API:
`crs.policy(name)` returns the named policy as `(result, ctx) -> (verdict,
reason)`, already normalized, and `crs.normalize(answer)` turns any of the
answer shapes above into that pair (a `PolicyError` for anything else).

```python
ms = crs.policy("builtin:memory-safety")
def decide(result, ctx):
    verdict, reason = ms(result, ctx)
    return (crs.REJECT, "vendored code") if "vendor/" in result["top_frame"] else (verdict, reason)
```

**Delta mode.** Pass the diff and triage reports whether the crash lands in
it; it never filters on it (a crash far from the diff can still be its fault
through data flow, so that call belongs to the policy):

```python
r = crs.triage(record, crash, harness="parser", config=cfg, delta_range="/work/ref.diff")
r.delta_relevance   # {"touches_diff", "frames_in_diff", "functions_in_diff",
                    #  "nearest_frame_distance", "files_changed"}
```

`delta_range` is a diff file (git or plain unified), diff text, or a git
range when you pass a campaign. An unreadable one is reported as `error`,
not raised.

**Several bugs, one target.** A delta can plant more than one bug, and every
crash in the diff passes the policy. When an inaccurate submission costs
points, submit the most specific first: `crs.rank(results)` orders them by
submittable, then a frame inside a changed hunk before one in a changed
function, then by class: a write (overflow write, wild-write, format-string),
a use-after-free, an overflow read, a read by a string scan (a missing
terminator), any other crash (`abort`, `assertion-failure`, `segfault`,
`deadly-signal`, `generic-crash` and the rest), then what is not a
memory-safety error (leak, timeout, oom, UBSan), and no crash at all last. The
stack hash breaks ties. It drops nothing; holding the tail back is your call.
`crs.rank_key(result)` gives one result's `(key, why)`.

```python
for x in crs.rank(results):          # TriageResults or triage-export/v1 dicts
    print(x.rank, x.result["pov"], x.why)
```

For a downstream consumer (a patcher in another container) the result also
carries `pov_sha256` and `original_sha256` to key records on, `sanitizer`
(which detector reported it), `frames` (top
first, up to 12) and `sanitizer_excerpt` (the report from its header through
`SUMMARY:`, bounded to 60 lines / 6000 chars), so nothing has to be re-run to
describe the bug.

Three distinctions the adapter refuses to collapse, because each leads
somewhere different:

- `flaky` ≠ `not_a_crash` — a real bug with an unreliable trigger
- `inconclusive` ≠ `rejected` — the oracle had a bad day vs the oracle said no
- `weak` ≠ `strong` evidence — triage-grade vs submission-grade

## 3. Minimization, and the trap in it

A fuzzer's reproducer is whatever buffer happened to trip the bug; 4KB where
eight bytes matter is normal. The short form is worth more than tidiness: it
makes the essential cause legible, and two long inputs that look like separate
findings often reduce to the same few bytes.

```bash
cc-fuzzer minimize run crash.bin --harness parser --json
# 4096 -> 4 bytes (99.9% smaller), same bug 530ba862… -> crash.bin.min
```

**The invariant is that it is the same bug.** Delta debugging will happily
shrink an input until it crashes *somewhere else* — smaller, still a crash, and
a different finding. Every candidate must reproduce with the same stack hash,
not merely crash:

```
crash  ≠  crash-with-the-same-cause
```

Budgets are enforced (`max_probes`, `max_rounds`), and a search that runs out
mid-step returns the **original**, never a smaller input nobody verified.

### 3.1 Which of the remaining bytes matter

The shortest input is still a mix of framing the parser needs to get anywhere
and the few bytes that decide the faulting operand. The patch author needs the
second set. `sensitivity` mutates each byte in place (`b ^ 0xFF`, `b ^ 0x01`)
and asks the minimizer's question, same bug or not:

```bash
cc-fuzzer minimize sensitivity crash.bin.min --harness parser
# bug c481acca…: 3 load-bearing, 1 constrained, 4 free, 0 unknown of 8 bytes (16 probes)
# 00000000  50 58 09 57 7a 7a 7a 7a
#            #  #  ~  #  .  .  .  .
# neighbour 558fd550… (heap-buffer-overflow) via offsets [3]
```

| Mark | Meaning |
|---|---|
| `#` load-bearing | every mutation loses the bug (a magic, a tag, an opcode) |
| `~` constrained | a big change keeps it, a one-bit change loses it: a bound. This is usually where the missing check goes |
| `.` free | filler |
| `?` unknown | probe budget ran out; nothing is guessed |

A mutation that crashes **elsewhere** is reported as a neighbouring bug with
the offsets that reach it, never counted as the same bug. Cost is two probes
per byte (default budget 1024), which is why it runs on the minimized PoV and
only once triage has confirmed it. `triage` puts it in `r.sensitivity`
(`input-sensitivity/v1`); pass `do_sensitivity=False` to skip it.

## 4. Seam two: a patch was written

```python
v = crs.check_patch(record, "fix.diff", r.pov, project_root="/src",
                    config=cfg, harness="parser", stack_hash=r.stack_hash)
if v.validated:
    submit_patch("fix.diff")
```

Five gates, in this order:

| gate | why |
|---|---|
| **before** | the PoV must crash **without** the patch |
| **apply** | it applies cleanly |
| **build** | a build failure is not a fix |
| **after** | the PoV must stop reproducing, and not crash somewhere else instead |
| **tests** | the project's own tests must still pass |

`before` is the one everyone skips, and it is why `stale_finding` is a
distinct outcome: applying a patch to a PoV that never reproduced looks
*exactly* like success. `breaks_tests` is the other one that matters — a patch
that stops the PoV by breaking the program passes every check except the test
run.

You supply apply/build/test, because a CRS already knows how to do all three
for its target:

```json
{"patch": {"apply":  "command:git apply {patch}",
           "build":  "command:./build.sh",
           "test":   "command:ctest --output-on-failure",
           "revert": "command:git checkout -- .",
           "timeout_s": 900}}
```

**Several PoVs.** Pass a list: every variant of the bug the patch is meant to
fix. All must crash before and none may crash after; `v.povs` has the per-PoV
result (`before`, `after` of `no-crash` / `same` / `moved`).

**Running the PoV somewhere else.** By default `before` and `after` replay on
the local binary. When the authoritative runner is the host's (OSS-CRS runs
PoVs through `libCRS run-pov` against a sidecar build), configure it:

```json
{"patch": {"build":     "command:/opt/crs/build.sh {patch}",
           "pov":       "command:/opt/crs/pov.sh {pov} {harness}",
           "pov_after": "command:/opt/crs/pov.sh {pov} {harness} --rebuild-id {build}",
           "test":      "command:/opt/crs/test.sh {patch} {build}"}}
```

`{build}` is the last non-empty stdout line of the build step (a rebuild id,
an image tag), empty during `before`. A pov command answers with one line:

```json
{"schema": "pov-run/v1", "crashed": true, "output": "<sanitizer report>"}
```

`output` is optional; when given, the stack hash is computed from it exactly as
local replay would, which is what lets `after` tell `same` from `moved`.
Anything that is not an answer (no JSON, a timeout) is `inconclusive`, never a
pass. Placeholders are `{patch}`, `{pov}`, `{harness}`, `{build}`; any other
is an error rather than an empty string.

**Which PoVs are one bug.** A patcher should be handed a bug, not a pile of
inputs. `crs.cluster(exports)` groups triage exports by stack hash (shortest
PoV first, as the representative). The stack hash says where a crash
surfaced, not where the bug is, so a patch settles the rest:
`crs.merge_by_patch(clusters, "fix.diff", record=..., project_root=...)`
runs the patch against every cluster's representative in one validation
(one build) and merges the clusters it stops (`pov-cluster/v1`, with
`merged_by` naming the patch).

```bash
cc-fuzzer crs cluster r1.json r2.json r3.json --patch fix.diff
```

**Steps that did not run.** "Not configured", "ran and passed" and "ran with
nothing to do" are different facts (libCRS `apply-patch-test` succeeds, by
contract, when the project has no test script). A policy per step decides
what each is worth:

```json
{"patch": {"steps": {"build": "required", "test": "preferred"}}}
```

| policy | step did not run |
|---|---|
| `required` | gate fails: `inconclusive` |
| `preferred` | gate passes; listed in `v.unverified_steps` |
| `optional` | gate passes silently (default for every step) |

A command reports which happened with a last stdout line
`{"schema": "step-result/v1", "ok": true, "ran": false, "reason": "no test script"}`
(optionally `"value"` for the build step's `{build}`). Plain exit codes keep
working.

**Extra gates.** More ordered checks after `tests`, against the patched build,
with the same command contract (and the same policies, default `required`).
A failure is its own verdict, `extra_gate_failed`:

```json
{"patch": {"extra_gates": [
  {"name": "robust", "command": "command:scripts/robust-fuzz.sh {build} {pov} 420",
   "policy": "preferred"},
  {"name": "neighbours", "neighbours": true}]}}
```

Every gate gets `{stack_hash}` besides the usual placeholders, and the
environment `CC_FUZZER_{BUILD,POV,POVS,STACK_HASH,TOUCHED_FUNCTIONS,HARNESS,PATCH}`
(touched functions come from the diff's hunk headers, `patch scope`).

- `scripts/robust-fuzz.sh` (`cc-fuzzer patch robust-fuzz`) is the reference
  gate. It fuzzes the patched libFuzzer build from the PoV and a corpus for N
  seconds, and fails on a crash that is the original bug or sits in a
  function the patch touched. Crashes elsewhere are reported and pass.
- `{"neighbours": true}` replays single-byte variants of the PoV at every
  byte the sensitivity map marked `#` or `~` and at the neighbour offsets.
  It catches a patch narrower than the bug (one that rejects the exact bad
  value but not the range around it). Pass the triage result's map:
  `crs.check_patch(..., sensitivity=r.sensitivity)`.

`cc-fuzzer patch scope fix.diff` reports what the diff touches and flags a
patch that only deletes code — the shape of "fixed" by removing the path that
reaches the bug.

## 5. The corpus seam, and what it is not

```python
crs.safe_seeds(campaign, harness)   # quarantine: reject inputs that would
                                    # damage the machine (fork bombs, dd to
                                    # a block device), not merely useless ones
crs.dictionary(campaign, harness=…) # harvest cmplog comparison operands
crs.delta_targets(campaign, range_) # what a diff touches
```

**There is no turnkey "give me better seeds" API, and it would be dishonest to
imply one.** Generating seeds, harnesses and mutators is a model's job.
cc-fuzzer supplies the *prompts* for that (§6) plus the deterministic safety
and harvesting above; you supply the model call.

### 5.1 Queries and SARIF

CodeQL runs only against a database **you** built (most frameworks build one as
a target-build step); the core never builds one:

```json
{"query": {"engines": ["codeql", "semgrep"], "codeql_db": "/out/codeql/db"}}
```

Queries come from a shipped pack of parametric templates (`rules/query-pack`):
the agent fills in function and sink names instead of writing QL, and the same
names give the same query on a rerun (`cc-fuzzer query template list|fill`).

SARIF goes both ways: `sast_scan.normalize_sarif(path_or_doc, root)` turns any
SARIF 2.1.0 into the core's finding dicts, and `sast_scan.export_sarif(findings)`
emits SARIF 2.1.0 so candidates can leave the core in the format frameworks
standardise on.

## 6. Prompts

**A CRS should usually write its own prompts, not render these.** Every
cc-fuzzer agent prompt is written for a cc-fuzzer campaign: it reads and
writes the `fuzz/` layout (`fuzz/state/`, `fuzz/corpus-quarantine/`,
`fuzz/harnesses/<name>/`), calls the campaign's scripts, and hands off to
the other agents by name. A framework with its own layout (OSS-CRS's `/out`,
`/work`, `/artifacts`) gets instructions that point at directories that do
not exist. The `oss-fuzz` profile changes the toolchain vocabulary (no nix,
no `CLAUDE_*`, no `apt-get`), not the layout.

What transfers is the judgement, and it already lives in the core, not in a
prompt: `crs.triage`, `crs.check_patch`, `crs.cluster`, the gates, the
policies. Have your agents call those, and keep the prose yours.

Rendering one is still possible when a host does adopt the `fuzz/` layout:

```python
from cc_fuzzer_core import prompts
text = prompts.render("seed-generator", profile="oss-fuzz", frontmatter=False)
```

Feature flags strip prompt sections and gate subsystems together; an
optional integration's flag (`cull_*`) is off unless turned on:

```bash
export CC_FUZZER_FEATURES="-advisory_lookup,-disclosure_reporting,-logic_oracles,-impact_tiering"
```

## 7. Build

Variants are declared as **needs** (purpose, sanitizers, instrumentation, link
mode), and a backend translates them:

```bash
cc-fuzzer variants spec --harness parser          # what must be built
cc-fuzzer build plan --harness parser --backend oss-fuzz   # how, runs nothing
```

The `oss-fuzz` backend maps purposes to the image's own controls:

| variant | `SANITIZER` | `FUZZING_ENGINE` |
|---|---|---|
| fuzzer | `address` | `libfuzzer` |
| verify | `address` | `none` (a standalone binary, no fuzzer driver) |
| coverage | `coverage` | `libfuzzer` |
| cmplog | `address` | `afl` (+ `AFL_LLVM_CMPLOG=1`) |
| symcc | — | **unsupported** |

Record the outcome so the reasons survive:

```bash
cc-fuzzer build record-args --result build-result.json
# → the write-harness-built flags, with skipped / unsupported / failed
#   each carrying its own reason
```

`unsupported` ≠ `skipped`. Skipped means the campaign turned the variant off;
unsupported means it was asked for and this image cannot. §10 (which binary
may run what) needs the difference.

## 8. Plug in your oracle

This is the integration point that matters most for a CRS: the **final
verification step** is swappable.

```json
{"verification": {"final_step": "command:/opt/crs/oracle.sh", "timeout_s": 600}}
```

Your executable receives `verify-request/v1` on stdin and answers
`verify-verdict/v1` on stdout:

```json
{"schema": "verify-verdict/v1", "status": "confirmed",
 "reason": "oracle reproduced the crash", "evidence": ["/path/to/pov.bin"]}
```

`status` is `confirmed | rejected | inconclusive`. **Use `inconclusive` for
anything that is not a decision** — a timeout, a crash in the oracle, output
you could not produce. The core already treats its own failures that way, and
folding them into `rejected` silently discards real findings.

Other forms: `python:module:callable`, or a name registered under the
`cc_fuzzer.verifiers` entry point group.

## 9. What a confirmed finding looks like

`pipeline.finalize()` is the **only** code that creates `fuzz/findings/<id>/`,
and only after a verifier confirms. It writes `<id>/.verified` last, atomically
— a `verification-marker/v1` holding the reproducer and binary with their
sha256, the variant and evidence grade, the replay verdict and the stack hash.

```bash
cc-fuzzer gate check-finding fuzz/findings/f001    # exit 1 = not verified
```

A directory without a valid marker is an interrupted or hand-made promotion and
reads as unverified. If the reproducer or the binary changed after
verification, the marker no longer describes what is on disk and the finding
reads as unverified again. **Do not create finding directories yourself** — the
API refuses it and so does the hook.

## 10. Which binary may run what

A crash reproduced on an instrumented binary is evidence about the
instrumentation. The core decides, and refuses rather than falling back:

```bash
cc-fuzzer variants select --harness parser --action replay --json
cc-fuzzer crash replay fuzz/crashes/new/parser__abc.bin --harness parser --json
```

| action | binary | fallback |
|---|---|---|
| `replay` | verify | fuzzing binary, recorded `evidence_grade: weak` |
| `verify`, `poc` | verify | **none** — refuses |
| `cmplog`, `concolic` | own variant | launcher only |

If your CRS shells out to run a crash, gate the command first:

```bash
cc-fuzzer gate classify-command --command "$CMD" --json   # exit 1 = deny
```

The exit contract is total: **0 means allowed, and any non-zero means NOT
allowed** — denied, or the gate could not decide. There is deliberately no
exit code meaning "the tool broke, carry on", so the natural idiom is the
correct one:

```bash
if ! cc-fuzzer gate classify-command --command "$CMD"; then
    refuse "$CMD"
fi
```

To tell a refusal from a failure, read `decision` from `--json` (`deny` vs
`error`) — explicitly, rather than inferring it from a status code.

The same contract guards writes into directories only the promote path may
fill. The default is `fuzz/findings/`; a CRS whose framework submits from a
watched directory protects that one too, and names the one process allowed
to write there:

```json
{"gate": {"protected_dirs": ["findings", "/artifacts/povs"],
          "allow_commands": ["crs-promote-pov"]}}
```

```bash
cc-fuzzer gate classify-write --command "cp crash-1 /artifacts/povs/" --config cfg.json  # exit 1
```

Entries are path suffixes, matched on whole components (`/artifacts/povs-old`
is not `/artifacts/povs`). An allowed command is matched as a command, not as
text: the command must be one simple command whose argv starts with the
allowed words (the program by basename, `bash`/`sh` in front of a script
allowed), with no `;`, `&&`, `||`, `&`, `|`, newline, backticks, `$(` or
redirection. `crs-promote-pov x; cp y /artifacts/povs/` is refused.

## 10.1 Export schemas

What crosses a container boundary is versioned, and its shape is pinned by
goldens (`tests/golden/exports/`). Within a version a new optional key is
additive; a removed or retyped key is a new version.

| schema | from | notable fields |
|---|---|---|
| `triage-export/v1` | `TriageResult.as_dict()` | status, should_submit, policy_verdict, stack_hash, category, sanitizer, frames, sanitizer_excerpt, pov_sha256, original_sha256, evidence_grade/source, sensitivity, delta_relevance, determinism, source_candidate_id, cause |
| `patch-export/v1` | `PatchVerdict.as_dict()` | verdict (= status), steps (with `ran`, `policy`), unverified_steps, povs (before/after), scope (with concerns, functions), build, determinism |
| `query-run/v1` | `query.run` | unchanged |

Nested documents carry their own versions: `policy-verdict/v1`,
`input-sensitivity/v1`, `delta-relevance/v1`, `determinism/v1`,
`crash-replay/v1`, `minimized-input/v1`. `crs.rank` emits
`submission-rank/v1` (rank, key, why, pov, stack_hash).

Other documents that can cross a host boundary:

| schema | from | where it matters |
|---|---|---|
| `pov-cluster/v1` | `crs.cluster`, `crs.merge_by_patch` | patch grouping (§4) |
| `pov-run/v1`, `step-result/v1` | the patch runner protocol | §4 |
| `verify-request/v1`, `verify-verdict/v1` | the `command:` oracle protocol | §8 |
| `verification-marker/v1` | `fuzz/findings/<id>/.verified` | §9 |
| `build-spec/v1`, `build-plan/v1`, `build-result/v1` | `cc-fuzzer build` | §7 |
| `delta-sweep/v1` | `cc-fuzzer sweep` (the file `CC_FUZZER_SWEEP_FILE` names) | §14 |
| `tick-result/v1` | `loop.step` | the appendix |
| `event/v1` | `fuzz/state/events.jsonl` (incl. the spend ledger) | §11 |
| `models/v1` | `cc-fuzzer models show` | §11.1 |

`hygiene call` and `governor observe` answer small unversioned JSON
(`{"decision", "reason"}` and `{"nudge"}`); §14 gives their shapes.

## 11. Budgets and accounting

```bash
cc-fuzzer ledger spend --json       # measured tokens and usd, by agent/model
cc-fuzzer query budget              # what the query lever has left
```

Every model call your runner reports lands in the ledger. If you dispatch
agents outside `loop.step`, record them yourself:

```python
from cc_fuzzer_core import ledger
ledger.append(c, agent="crash-triager",
              usage=ledger.Usage(tokens_in=..., tokens_out=..., model=...),
              source="driver", call_id=unique_id)
```

`call_id` makes it idempotent — the same call reported twice counts once.

**When the provider says the money is gone.** If a gateway owns the budget (a
LiteLLM key with `max_budget`), exhaustion arrives as an API error mid-run.
`loop.step` turns it into `errors.BudgetExhausted`, writes a
`budget_exhausted` event, and never retries it. Wrap your own model calls the
same way:

```python
from cc_fuzzer_core import errors
try:
    reply = errors.call(my_model_call, prompt, attempts=3)   # retries transient errors only
except errors.BudgetError:
    fall_through_to_deterministic_work()   # fuzz, replay, minimize, validate
```

**Catch it; do not exit.** The rest of the run still has fuzzing, replay,
minimization and patch validation to do, and none of them need a model.

**Scopes and an advisory guard.** Tag rows with a scope so one campaign holds
several caps, and check a cap with a reserve held back so the last planned
call still fits:

```python
ledger.append(c, agent=..., usage=..., source="driver", call_id=..., scope="find")
ledger.guard(c, scope="find", cap_usd=50.0, reserve=0.1)   # raises CapReached at 45.0
```

```bash
cc-fuzzer ledger guard --scope find --cap 50 --reserve 0.1   # gate contract: non-zero = not allowed
```

Local totals drift from the provider's accounting (pricing tables, cache
billing, retries you never saw), so the guard should trip **before** the
provider does, not **instead** of it.

## 11.1 Determinism

The numbers that decide a result are configuration, and every result
(`r.determinism`, `v.determinism`) echoes the values it was produced with:

```json
{"determinism": {"replay_attempts": 3, "replay_timeout_s": 30,
                 "minimize_max_probes": 400, "minimize_max_rounds": 40,
                 "sensitivity_max_probes": 1024, "fuzzer_seed": 0}}
```

These are the defaults. `fuzzer_seed: 0` is libFuzzer's "pick one"; set a
fixed seed (ParallaxCRS uses 1337) when runs must be comparable.

An explicit argument wins over config, config over the defaults. The fuzzer
seed reaches extra gates as `CC_FUZZER_FUZZER_SEED` (the reference fuzz gate
passes it to libFuzzer as `-seed`). Reproducible runs also need **pinned model
IDs**: a dated model ID, not an alias that moves. Do not edit the packaged
`data/models.json`; override it with a `models` block in fuzz-config (per
campaign) or the JSON file named by `$CC_FUZZER_MODELS` (per host), and check
the result with `cc-fuzzer models show`.

## 12. Smoke test your integration

```bash
cc-fuzzer tick state                  # none|running|stopped|stale|corrupted
cc-fuzzer tick run --prepare          # deterministic phases only
cc-fuzzer variants spec --harness X
cc-fuzzer build plan --harness X --backend oss-fuzz
cc-fuzzer schema validate             # state is well-formed
cc-fuzzer ledger spend --json
```

---

## 13. Optional: cull's candidates

`cc_fuzzer_core.integrations.cull` reads [cull](https://github.com/cloudripper/cull)'s
bug-candidate SARIF (`cull scan --format sarif-bug-candidates`). It is a
subpackage the core never imports, and every entry point is gated by a flag
that is **off by default** (`cull_intake`, `cull_feedback`, `cull_query_engine`),
so without them cc-fuzzer runs exactly as before. It hands the core only what
the core already reads:

| cull gives | the integration writes | the core consumes it through |
|---|---|---|
| ranked candidates | `fuzz/state/cull/code-review-<ts>.json` (`code-review/v1`, `tier_classified: cull`) | `findings import-cr` (high/medium only) and the promote gate |
| the same, by function | `fuzz/state/signals/cull.json` (`sast-signal/v1`, weighted by reach tier) | the prescan, which reads every file in `signals/` |
| evidence per candidate | `fuzz/state/cull/intake-<ts>.json` (`cull-intake/v1`) | `cull cards` (prompt blocks), `cull queue` |
| a crash that matches a candidate | `fuzz/state/cull/feedback.jsonl` (`cull-feedback/v1`, append-only) | cull's rerank, when it reads feedback |
| `candidate_id` | `source_candidate_id` on `triage-export/v1` | `crs.triage(candidate_matcher=feedback.matcher(intake))` |

```bash
CC_FUZZER_FEATURES=+cull_intake cc-fuzzer intake cull proj.sarif --import
cc-fuzzer cull queue          # reached tiers first; none-found held back
cc-fuzzer cull queue --delta  # and nearest the diff first within each tier
cc-fuzzer cull cards          # what a seed-generator / mutator / poc-builder sees
cc-fuzzer cull hints --dict fuzz/harnesses/parser.dict   # cull's input_hints (evidence 1.8.0)
```

`--delta` orders each tier by cull's `diff_proximity` (in-diff,
changed-function, diff-flow, near-change, changed-file, then none; position
breaks ties) without moving a candidate between tiers, and admits a held
`none-found` candidate whose label is in-diff, changed-function or diff-flow.

Tolerant reader: an invalid SARIF is an error, never an empty intake, but a
field an older cull did not ship is derived and marked `*_source: "local"`
(`candidate_id` with cull's own formula, `confidence` from
`cull.confidence_map`, `reach_tier` from cull's reachability label). With a
`cull` block in the config, `query.codeql_direct` defaults to false: the
CodeQL lever runs only through `query.codeql_engine` (`cull query`, which
`cc-fuzzer cull engine` configures when the installed cull has it), never
agent-written QL. `fuzz/state/cull/feedback.jsonl` is what `cull rerank
--feedback` reads. The line-coverage export for cull's rerank waits for cull
to define the format.

What the integration is still waiting on from cull, and what each update
switches on: [cull-upstream.md](cull-upstream.md).

## 14. Optional: agent-behaviour helpers

Four small modules help a host that runs a model agent beside the fuzzer.
None needs a campaign, none sleeps or schedules, and each answers with a
decision that the host turns into whatever its agent framework speaks. The
plugin's `hooks/*.sh` do that for Claude Code, but they are not in the wheel
(§1): a host calls the CLI or the API directly.

### 14.1 The delta sweep (`sweep`, 0.35)

A delta can plant several flaws, and an agent that chases the first suspicious
call skips the rest. The sweep turns a diff into a checklist
(`delta-sweep/v1`): one item per added line that looks like a sink, with every
class it matches, plus one per code hunk with none. Files that are not C/C++
source are closed up front (`not-code`).

- **Classes:** `format-string` (a printf-family call with no literal format,
  including the project's own `*f` wrappers the diff shows taking a literal
  elsewhere), `copy`, `alloc-size`, `alloc`, `ptr-arith`, `len-arith`,
  `index`, `index-write`, `scan`, `div`, `cast-deref`, `eq-bound`, `int-type`,
  `free`, `abort`, `loop`. From the diff's shape: `const-change` (a bound or
  size moved) and `removed-check` (a guard deleted). `macro-arg`: an ALL-CAPS
  function-like macro called with an expression argument. With
  `build(..., src_root=)` (CLI `sweep init --src`) the item's `note` carries
  the macro's expansion from its `#define`, and an argument that regroups
  in the body (`size - structsize` with `6+8+4`) makes it
  `macro-precedence`, listed first. Measured on 79 delta CPVs: an item sits
  on the vulnerable line of 64.
- **Verdicts** (`sweep mark`): `crash` and `reached` must name the input that
  was run (`--input`); `unreachable` and `safe` need a reason.
- **The gate:** `cc-fuzzer sweep gate --json [--session S] [--continuing]
  [--max-blocks N]` says whether a turn may end. It blocks at most 3 times
  **per session** (`--session`; a host with one session per round gets 3 per
  round), and again only after progress.

```bash
export CC_FUZZER_SWEEP_FILE=/work/delta-sweep.json        # no campaign needed
cc-fuzzer sweep init /work/ref.diff
cc-fuzzer sweep show --limit 20                            # for the prompt
cc-fuzzer sweep mark --input /work/pov.bin h3.s1 crash "the over-read at parse.c:88"
cc-fuzzer sweep gate --json --session "$SESSION_ID"        # in a Stop hook
```

### 14.2 The duplicate-call guard (`hygiene`, 0.36)

Some models put the same tool call into one response two or more times; the
agent CLI runs every copy and re-sends every result with each later request.
On the qualification runs that was 32% of Read and 28% of Bash calls.
`hygiene` keeps a per-session batch: a call identical to one already in the
current response is denied, the batch ends with the response, and a call
denied once runs if asked for again.

```bash
# before each tool call: the tool's input JSON on stdin, the rest as flags
echo "$TOOL_INPUT_JSON" | cc-fuzzer hygiene call --session "$S" --prompt "$PROMPT_ID" \
    --id "$TOOL_USE_ID" --tool Read          # -> {"decision": "allow"|"deny", "reason": "..."}
cc-fuzzer hygiene batch-end --session "$S"   # once every call of the response has finished
```

API: `hygiene.call(session, prompt, call_id, tool, tool_input)` returns a
reason string to deny, or `""`; `hygiene.batch_end(session)`. State
lives under `$CC_FUZZER_HOOK_STATE` (default `$TMPDIR/cc-fuzzer-hooks`), and
entries expire after `MAX_AGE_S` (300 s).

### 14.3 The behaviour governor (`governor`, 0.37)

On the qualification runs 88-89% of the agent's tool calls read or searched
the source and 1-2% ran an input. The governor watches each finished batch of
calls and, once `threshold` reading calls (default 30) have gone by since the
last input run, returns a short nudge for the host to show the model before
its next request. It repeats only after another full streak, and an input run
resets it.

```bash
echo "$POST_TOOL_BATCH_INPUT" | cc-fuzzer governor observe --session "$S" \
    --threshold 30 --run 'my-harness-name' --how 'run it with my-runner <file>'
# -> {"nudge": "..."} or {"nudge": ""}
```

The CLI reads a Claude Code PostToolBatch hook input (`session_id`,
`tool_calls`) on stdin. API: `governor.observe(session, calls, *, threshold=30,
run_patterns=DEFAULT_RUN_PATTERNS, how=...)` returns the nudge or `None`;
`governor.classify(call)` says whether one call reads, runs an input, or is
neutral. Input runs are recognised by pattern: `crc-promote-pov`,
`crs-fuzz add-seeds`, `run-pov`, `-runs=N`, gdb, plus the host's `--run`
patterns (such as the harness name). The plugin does not register it.

### 14.4 The round policy (`stoprules`, 0.38)

A host that runs model rounds beside a fuzzer has three decisions to make:
whether to continue after a round, how long a round may go without progress
(the stall), and, once the rounds have stopped, whether to idle, reopen them
or end the run. `stoprules` makes them one policy the host feeds with
outcomes; it reads no state of its own.

```python
from cc_fuzzer_core import stoprules as sr

rounds = sr.Rounds(sr.default_policy(delta=True, name="parity"))   # or "evidence"
stall_s = rounds.stall_for(open_targets=open_sweep_items)          # for the next round
d = rounds.after_round(worked=True, progressed=new_stack or new_verdict,
                       known_before=len(known_stacks), open_targets=open_sweep_items)
if d.action == sr.STOP:
    rounds.stop("dry: " + d.reason, known=len(known_stacks), corpus=corpus_files)

# while idle, every so often:
d = rounds.after_stop(now_s=time.monotonic(), run_s=elapsed, known=len(known_stacks),
                      corpus=corpus_files, budget_left=can_pay_for_a_round)
# d.action: sr.IDLE | sr.REOPEN | sr.EXIT
```

- `parity` is the rule set ParallaxCRS ran in qualification: once a bug is
  known, `dry_limit` worked rounds in a row with no new stack and no new sweep
  verdict stop the rounds (2 in delta, 3 in full); the stall is 300 s in delta
  and off in full; stopped rounds never resume.
- `evidence` keeps a round from counting dry while delta targets are open,
  doubles the stall while they are, and reopens stopped rounds on new evidence
  (a new stack, or 5% corpus growth), at most `reopen_max` times while budget
  remains. Only a stop whose reason starts with `dry` is reopened.
- `give_up_after_s` (default 0 = never) ends a run once the rounds have
  stopped and nothing has progressed for that long, after `min_run_s`.

## Things that will bite

1. **Any non-zero from `gate` means not allowed.** Never treat a non-zero
   status as "the tool failed, proceed" — that turns every refusal into a
   silent permit. The CLI has no success-but-broken exit code for exactly
   this reason.
2. **Report real token usage** or the cost cap silently does nothing.
3. **`stale` and `corrupted` are not `stopped`.** Acting on them relaunches a
   campaign whose state failed validation.
4. **`inconclusive` is not `rejected`** in a verdict, and `unsupported` is not
   `skipped` in a build result. Both distinctions carry decisions.
5. **Pin your tools.** `CC_FUZZER_TOOL_<NAME>=""` (empty) means *this image
   does not have it* and stops resolution reaching `PATH`; `CC_FUZZER_CPUS`
   pins the CPU budget so `fuzz_forks` does not vary with the host.
6. **Never hand-create `fuzz/findings/<id>/`.** It is the claim that something
   was verified.
7. **Read `should_submit`, not `status == "confirmed"`.** `submittable` is
   confirmed on strong evidence (weak evidence, a crash shown only on the
   fuzzing binary, is triage-grade); `should_submit` also asks your
   submission policy. If every binary you have is a fuzzing build, declare
   your oracle `authoritative` or nothing is ever submittable.
8. **A minimizer that only checks "still crashes" will hand you a different
   bug.** `minimize` preserves the stack hash; if you roll your own, do the
   same.
9. **Validate patches against a PoV that reproduces first.** The `before` gate
   returns `stale_finding` for a reason: patching a PoV that never crashed
   looks exactly like success.
10. **Catch `errors.BudgetError`; do not retry it.** A gateway that ran out of
    budget says so again on every retry. Fall through to the work that needs
    no model.
11. **A patch that moves the crash did not fix it.** `after` reports `moved`
    and the verdict is `does_not_fix`; one that only rejects the exact bad
    value is what the `neighbours` extra gate exists to catch.

---

## Appendix: the tick loop (you probably don't want this)

`loop.step()` advances one campaign by exactly one tick and returns a
directive. It exists for a host with **no scheduler of its own** — the Claude
Code plugin. If your CRS already schedules work, owns fuzzer lifecycle and has
a crash listener, the seams above are the right shape and this is not.

It is here because one case does suit it: driving a single target end to end
with no surrounding system, where you want cc-fuzzer to decide what to do next.

```python
from cc_fuzzer_core import loop
while True:
    r = loop.step(campaign, my_runner)   # never sleeps, never schedules
    d = r.directive
    if d.kind == loop.WAIT: sleep(d.delay_hint_s)
    elif r.halted: break
```

`my_runner.run(agent, inputs, *, model, budget)` returns a `loop.AgentResult`
carrying real token counts; the driver writes them to the ledger, which is
what makes `cost_cap` a measurement rather than a declaration.

`cc-fuzzer tick state` is worth knowing even if you skip the loop: it returns
`none | running | stopped | stale | corrupted`, and **`stale` and `corrupted`
exist to stop a caller acting** — state that failed validation, or a target
source that moved under the harness.

## Appendix: crash vocabulary

What `classify()` and `replay()` put in a result, so a policy can match on it
without parsing reports.

**`cause`** (`classify.CAUSES`), one run's label, used by `screen=`: `crash`,
`leak`, `timeout`, `oom`, `exit` (the harness called `exit()`), `none`.

**`sanitizer`** (`replay.sanitizer_of`): `address`, `memory`, `leak`,
`thread`, `undefined`, `libfuzzer` (libFuzzer reported it itself: a deadly
signal, its timeout or its OOM), or `""`.

**`category`**, in the order classify looks:

1. A sanitizer `SUMMARY:` line names it: ASan's token
   (`heap-buffer-overflow`, `stack-buffer-overflow`, `global-buffer-overflow`,
   `heap-use-after-free`, `double-free`, `stack-use-after-return`, ...), `leak`,
   or UBSan's `undefined-behavior`. An ASan SEGV is split by the fault address,
   the access kind and the frames: `null-deref` (the zero page, below 0x10000,
   or no address), `wild-read`, `wild-write`, `wild-access`, and
   `format-string` (a printf-family function in the top three frames, whose
   caller is the `top_frame`).
2. Without a summary, a UBSan `runtime error:` line: `signed-integer-overflow`,
   `integer-overflow` (unsigned), `ubsan-shift`, `ubsan-div-zero`,
   `ubsan-alignment`, `null-deref`, or `ubsan-other`.
3. Otherwise: `segfault`, `abort`, `assertion-failure`, `oom` (including
   libFuzzer's `ERROR: libFuzzer: out-of-memory`), `timeout`,
   `deadly-signal` (libFuzzer's own handler), or `generic-crash`.

`crs.rank` treats `ubsan-*` as "not a memory-safety error", but a UBSan
report categorised `undefined-behavior` (it had a summary) lands with the other
crashes. Match UBSan by `sanitizer == "undefined"` when it matters.

**`top_frame`** is the first frame in the target. Frames of the sanitizer
runtime (`__sanitizer::`, `__asan::`, ...), libFuzzer (`fuzzer::`) and the
fuzz entry point are passed over, and so are libc's `raise`, `abort` and
`__assert_fail`, so an abort is named by the target function that called it
(0.36.4).

**`stack_hash`** is the first 16 hex characters of a sha256 over the top
`HASH_FRAMES` (3) frames (the category when there are none). `frames` lists up
to 12, top first.

**The replay environment is fixed**, not inherited:
`ASAN_OPTIONS=symbolize=1:abort_on_error=1:halt_on_error=1:print_stacktrace=1:detect_leaks=1:handle_sigill=1`
and
`UBSAN_OPTIONS=halt_on_error=1:print_stacktrace=1:abort_on_error=1:silence_unsigned_overflow=1`,
the last as OSS-Fuzz and its scorers run UBSan builds (unsigned wrap-around is
defined behaviour). Add the scorer's libFuzzer flags with `replay_args` (§2).

## Appendix: environment variables the core reads

| Variable | What it does |
|---|---|
| `CC_FUZZER_ROOT` | Data root; not needed with the wheel. |
| `CC_FUZZER_FEATURES` | Feature-flag overrides on top of the profile (§6). |
| `CC_FUZZER_MODELS` | A JSON file of model overrides, above fuzz-config's `models` block (§11.1). |
| `CC_FUZZER_TOOL_<NAME>` | Path of a tool (`LLVM_COV`, `LLVM_PROFDATA`, ...) when it is not on `PATH`. |
| `CC_FUZZER_CPUS` | Cores the core may use. |
| `CC_FUZZER_SWEEP_FILE` | The sweep file when there is no campaign (§14.1). |
| `CC_FUZZER_HOOK_STATE` | State dir of `hygiene` and `governor` (default `$TMPDIR/cc-fuzzer-hooks`). |
| `CC_FUZZER_BUILD`, `_POV`, `_POVS`, `_STACK_HASH`, `_TOUCHED_FUNCTIONS`, `_HARNESS`, `_PATCH`, `_FUZZER_SEED` | Set **by** the core for an extra patch gate (§4). |
| `CCFUZZ_ALLOW_DESTRUCTIVE_SEEDS` | Lets `quarantine` pass seeds it would hold back. Leave unset. |
| `FINDINGS_SKIP_VERIFY` | **Skips verification when promoting a finding.** For tests only; never set it in a host. |
| `FINDINGS_DEDUP_THRESHOLD`, `HARNESS`, `ORACLE_TYPE`, `DIVERGENCE` | Inputs to the `findings` CLI. |
| `PROJECT_ROOT`, `FUZZ_ROOT`, `FUZZ_STATE_DIR`, `FUZZ_OUT_DIR`, `FUZZ_COV_DIR`, `FUZZ_CORPUS_DIR`, `FUZZ_CRASHES_DIR` | Where a campaign lives. A host that keeps its own state dir should set only `PROJECT_ROOT`; moving one of the others splits state. |
| `FUZZ_FORKS`, `FUZZ_FORKS_OVERRIDE`, `SNAPSHOT_COVERAGE_MAX_SAMPLES`, `STALE_THRESHOLD_SECONDS` | Campaign fuzzing and snapshot tuning. |
| `OUT` | The OSS-Fuzz builder's output dir. |

## Reference

| Need | Module | CLI |
|---|---|---|
| **triage a crash** | `crs.triage` | `crs triage` |
| **minimize a PoV** | `minimize` | `minimize run` |
| **which PoV bytes matter** | `minimize.sensitivity` | `minimize sensitivity` |
| **validate a patch** | `crs.check_patch`, `patch` | `patch validate`, `patch scope` |
| **group PoVs into bugs** | `crs.cluster`, `crs.merge_by_patch` | `crs cluster` |
| **what to submit first** | `crs.rank` | `crs rank` |
| **delta sweep checklist** | `sweep` (§14.1) | `sweep init/show/mark/gate` |
| **duplicate tool calls** | `hygiene` (§14.2) | `hygiene call`, `hygiene batch-end` |
| **reading-streak nudge** | `governor` (§14.3) | `governor observe` |
| **when rounds stop, reopen, give up** | `stoprules` (§14.4) | — (an API) |
| coverage snapshot (campaign) | `coverage.snapshot` | `coverage snapshot` |
| crash vocabulary | `crash.classify` (Appendix) | `crash classify` |
| seed safety | `crs.safe_seeds`, `quarantine` | `quarantine run` |
| cmplog dictionary | `crs.dictionary`, `cmplog` | `cmplog extract` |
| delta targets | `crs.delta_targets`, `delta` | `delta find` |
| one tick (rarely) | `loop` | `tick run` |
| campaign state | `loop` | `tick state` |
| prompts | `prompts` | `prompts render` |
| build | `variants`, `builders` | `variants spec`, `build plan` |
| binary choice | `variants` | `variants select` |
| replay | `crash.replay` | `crash replay` |
| verification | `crash.verifiers`, `crash.pipeline` | — |
| refusals | `gate` | `gate classify-command`, `gate check-finding`, `gate classify-write` |
| submission policy | `crs.judge` (`submission.policy`) | `crs triage --policy` |
| budget errors | `errors` | — |
| spend caps | `ledger.guard`, `ledger.check` | `ledger guard` |
| reproducibility knobs | `determinism` | — |
| SARIF in/out | `prescan.sast_scan.normalize_sarif`, `export_sarif` | — |
| query templates | `query.templates`, `query.fill` | `query template list\|fill` |
| cull's candidates (optional) | `integrations.cull` | `intake cull`, `cull queue\|cards\|feedback\|hints\|diff\|engine` |
| findings | `findings` | `findings` |
| spend | `ledger` | `ledger spend` |
| queries | `query` | `query run`, `query budget` |
| validation | `schema` | `schema validate` |
| flags | `features` | `feature list` |
| models | `models` | `models resolve` |
