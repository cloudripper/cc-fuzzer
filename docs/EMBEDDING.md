# Embedding cc-fuzzer in a CRS

`cc_fuzzer_core` is the deterministic driver for the whole analysis. The Claude
Code plugin is one consumer of it; a CRS entry point is another. Neither owns
the logic — both call the same code, and where they differ, the difference is
data (a profile, a config block, a runner), not a second implementation.

What you supply: an agent runner, a loop, and a build backend.
What the core supplies: everything else.

```
                     your CRS entry point
                            │
              ┌─────────────┴─────────────┐
              │                           │
      loop.step(campaign, runner)   prompts.render(agent, "oss-fuzz")
              │                           │
              ▼                           ▼
   deterministic phases            the text you send to the model
   (state, liveness, crash
    detect, coverage, derive,
    evaluate, halts)  ──────────►  a Directive you act on
```

---

## 1. Install

```bash
pip install /path/to/cc-fuzzer          # or: pip install cc-fuzzer-core
cc-fuzzer --version                     # console script lands on PATH
```

The wheel carries its own data (prompts, rules, dictionaries, templates,
`STATE_SCHEMA.md`, `models.json`), so nothing outside the package is needed.
`CC_FUZZER_ROOT` is **not** required for an installed core — set it only when
you want to override where that data is read from.

Verify the isolation contract holds in your image:

```bash
cd /tmp && env -u CLAUDE_PLUGIN_ROOT -u CC_FUZZER_ROOT \
  python -c "import cc_fuzzer_core.loop, cc_fuzzer_core.variants; print('ok')"
```

## 2. The campaign directory

Everything the core reads and writes lives under one `fuzz/` tree next to the
target. `paths.campaign()` resolves it from the cwd; `FUZZ_ROOT` and
`FUZZ_STATE_DIR` override it.

```python
from cc_fuzzer_core.paths import campaign
c = campaign()          # Campaign(project_root, fuzz_root, state_dir)
```

## 3. Drive the loop

`loop.step()` advances **exactly one tick** and returns. It never sleeps,
never schedules, and never expects to be woken — your loop owns pacing.

```python
from cc_fuzzer_core import loop

class Runner:
    """The one thing the core cannot do: call a model."""
    def run(self, agent, inputs, *, model="", budget=None):
        text, usage = my_llm(prompt_for(agent, inputs), model=model)
        return loop.AgentResult(
            text,
            tokens_in=usage.input_tokens,
            tokens_out=usage.output_tokens,
            model=model,                    # what you were actually served
        )

while True:
    r = loop.step(c, Runner())
    d = r.directive
    if d.kind == loop.DISPATCH:   run_agent(d.agent, d.args)
    elif d.kind == loop.RUN:      run_script(d.script)
    elif d.kind == loop.WAIT:     sleep(d.delay_hint_s)
    elif r.halted:                break            # halt | done | inactive
```

**Report real token counts.** The cost cap is a measurement, not a
declaration: `loop.step` writes your `AgentResult` usage to the ledger, and
`yolo_evaluate` halts on it. Returning zeros disables the cap silently.

Prefer `prepare()` when your CRS does its own dispatching and only wants the
deterministic half:

```python
pre = loop.prepare(c)        # {"state", "events", "phases", "digest"}
```

CLI equivalents: `cc-fuzzer tick run [--json]`, `cc-fuzzer tick run --prepare`,
`cc-fuzzer tick route`, `cc-fuzzer tick state`.

### Campaign states

`cc-fuzzer tick state` → one of `none | running | stopped | stale | corrupted`.
**`stale` and `corrupted` exist to stop the loop acting.** `route()` sends both
to an assessment rather than to a build or a launch; treat them the same way.

## 4. Render the prompts

```python
from cc_fuzzer_core import prompts
text = prompts.render("crash-triager", profile="oss-fuzz", frontmatter=False)
```

`profile="oss-fuzz"` yields text with no nix, no `CLAUDE_*`, no `apt-get`, and
no Claude Code tool vocabulary. `frontmatter=False` drops the Claude Code
frontmatter block. `prompts.agents()` lists what is available (14 agents;
`nix-builder` and `ops-runner` are host adapters with no portable form).

Feature flags strip prompt sections and gate subsystems together:

```bash
export CC_FUZZER_FEATURES="-advisory_lookup,-disclosure_reporting,-logic_oracles,-impact_tiering"
```

## 5. Build

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

## 6. Plug in your oracle

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

## 7. What a confirmed finding looks like

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

## 8. Which binary may run what

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

## 9. Budgets and accounting

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

## 10. Smoke test your integration

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

## Reference

| Need | Module | CLI |
|---|---|---|
| one tick | `loop` | `tick run` |
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
