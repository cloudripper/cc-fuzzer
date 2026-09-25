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
pip install /path/to/cc-fuzzer          # or: pip install cc-fuzzer-core
cc-fuzzer --version
```

The wheel carries its own data (prompts, rules, dictionaries, templates,
`STATE_SCHEMA.md`, `models.json`). `CC_FUZZER_ROOT` is **not** required.

## 2. Seam one: a crash arrives

```python
from cc_fuzzer_core import crs

record = {"verify_binary": "/out/parser_verify"}     # all the state it needs
cfg    = {"verification": {"final_step": "command:/opt/crs/oracle.sh"}}

r = crs.triage(record, "/crashes/x.bin", harness="parser", config=cfg)
if r.submittable:
    submit(r.pov, r.stack_hash)        # r.pov is the MINIMIZED input
```

`triage` does five things, in this order, and stops as soon as the answer is
known:

| | |
|---|---|
| **replay** | deterministically, 3×, on the binary §12 selects — never an instrumented build |
| **minimize** | smallest input reproducing **the same bug** (see §3) |
| **verify** | your oracle, via `verification.final_step` |
| **byte map** | only if confirmed: which bytes of the PoV decide the bug (see §3.1) |
| **marker** | only if confirmed, and only if you pass a campaign |

`status` is one of `confirmed`, `rejected`, `inconclusive`, `not_a_crash`,
`flaky`. Read **`r.submittable`** rather than `status == "confirmed"`: it also
requires `evidence_grade == "strong"`. A crash shown only on the fuzzing
binary — because no verify binary was built — is good enough to triage and not
good enough to submit.

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

Only a confirmation upgrades; a rejection or an inconclusive answer adds
nothing, and a `strong` replay is never downgraded. `poc-realism` cannot be
declared authoritative: it checks an agent's work, it is not an oracle. The
finding marker records `evidence_source` too, so the upgrade is auditable.

For a downstream consumer (a patcher in another container) the result also
carries `pov_sha256` and `original_sha256` to key records on, `frames` (top
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

## 6. Prompts

```python
from cc_fuzzer_core import prompts
text = prompts.render("seed-generator", profile="oss-fuzz", frontmatter=False)
```

`profile="oss-fuzz"` yields text with no nix, no `CLAUDE_*`, no `apt-get` and
no Claude Code tool vocabulary — verified across all 14 agents. The ones a CRS
is most likely to want: `seed-generator`, `mutator`, `harness-writer`,
`crash-triager`, `query-analyst`.

Feature flags strip prompt sections and gate subsystems together:

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
| verify | `undefined` | `none` |
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
unsupported means it was asked for and this image cannot. §12 needs the
difference.

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
7. **Read `submittable`, not `status == "confirmed"`.** Confirmed on weak
   evidence (no verify binary was built) is triage-grade, not
   submission-grade.
8. **A minimizer that only checks "still crashes" will hand you a different
   bug.** `minimize` preserves the stack hash; if you roll your own, do the
   same.
9. **Validate patches against a PoV that reproduces first.** The `before` gate
   returns `stale_finding` for a reason: patching a PoV that never crashed
   looks exactly like success.

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

## Reference

| Need | Module | CLI |
|---|---|---|
| **triage a crash** | `crs.triage` | `crs triage` |
| **minimize a PoV** | `minimize` | `minimize run` |
| **which PoV bytes matter** | `minimize.sensitivity` | `minimize sensitivity` |
| **validate a patch** | `crs.check_patch`, `patch` | `patch validate`, `patch scope` |
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
| refusals | `gate` | `gate classify-command`, `gate check-finding` |
| findings | `findings` | `findings` |
| spend | `ledger` | `ledger spend` |
| queries | `query` | `query run`, `query budget` |
| validation | `schema` | `schema validate` |
| flags | `features` | `feature list` |
| models | `models` | `models resolve` |
