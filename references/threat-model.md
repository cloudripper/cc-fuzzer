# Threat model & trust boundaries — what counts as impact

`poc-builder` reads this to decide whether a demonstrated primitive is **real impact** or a
mechanism that proves nothing. The governing rule:

> **Impact is a verified crossing of a trust boundary the attacker could not otherwise cross.**
> If the attacker could already read the data / perform the action *without* the bug, it is not
> impact — no matter what `verify.sh` prints.

This is the single test that separates an exploit from a self-fulfilling demo. A read that
returns a sentinel the exploit itself planted in adjacent memory proves the *read mechanism*
works; it does **not** prove the attacker learned anything they weren't entitled to.

## 1. Name the attacker model first

Before tiering, write (in `EXPLOIT.md` `## Threat model`):

- **Who is the attacker?** Remote unauthenticated / local unprivileged user / sandboxed renderer
  / a peer tenant / a lower-integrity process. Pick the *realistic* one for this target.
- **What can they already do / see?** The baseline. Anything the exploit "achieves" that is
  inside this baseline is not impact.
- **What is protected, and by what boundary?** The thing on the other side of the wall.

## 2. Trust-boundary taxonomy (`boundary_crossed.type`)

| Type | The wall | "Crossing it" looks like |
|---|---|---|
| `confidentiality` | data the attacker may not read | the exploit reveals a secret on the *other* side — another user's data, a key/token, `/etc/shadow`, an in-process secret (canary, a pointer that defeats ASLR) the attacker's own context never holds |
| `privilege` | uid / capability / setuid / sudo | the attacker ends up running as / influencing a higher privilege than they started with (`id -u` → 0; a `CAP_*` action they lacked) |
| `integrity` | state the attacker may not modify | a write lands in data/config/another principal's state the attacker had no write access to, and it *takes effect* |
| `authentication` | acting as a principal | the attacker is treated as a different / authenticated principal without the credential |
| `isolation` | sandbox / container / process / origin | data or control escapes the box (renderer → broker, container → host, origin A → origin B) |
| `none` | — | nothing crossed. **Not Tier A/B.** Downgrade to C or dispute. |

## 3. Per-primitive checklist — when does a primitive count?

- **Read primitive.** Counts only if the leaked bytes **live on the other side of a boundary**.
  Plant the sentinel where the attacker cannot reach it (a secret held only by the privileged
  side / another principal / the target's own protected memory), then show the attacker context
  reads it *via the bug*. A before/after is mandatory: *before* — the attacker context cannot
  obtain the value; *after* — the exploit prints it. A sentinel the exploit wrote into adjacent
  or reallocated memory is **not** cross-boundary and is at most Tier C.
  - Special case — **defeating a mitigation is confidentiality impact**: leaking a stack canary,
    a heap/text/libc pointer, or PIE base that the attacker's context cannot otherwise compute is
    a real `confidentiality` crossing (it removes a secret the defense relies on). Say which
    mitigation it defeats.
- **Write primitive.** Counts only if the controlled write reaches state **behind an integrity
  boundary** and changes a decision/outcome — a function pointer / vtable / return address /
  another principal's record / a security-relevant config. A write to your own adjacent heap with
  no consumer is not impact.
- **Exec / control-flow primitive.** Counts when control reaches attacker-chosen code/behavior
  across a `privilege` or `isolation` boundary (the classic `system("touch /tmp/pwned_$$")` is
  fine *only* when the process the attacker hijacked is more privileged or more isolated than the
  attacker — otherwise it crossed nothing).

## 4. Show it from the user's point of view

The most convincing, hardest-to-fake proof is a short **CLI** sequence a maintainer pastes and
watches: the secret prints, `id` returns 0, the protected file's content changed, the rejected
request reaches the backend. State the impact as a plain **before → after** a non-fuzzing reader
grasps. Prefer this over a C harness whenever the real binary/tool can show the same crossing.

## 5. Chainability — think outside the box (demonstrated vs projected)

Most single bugs cross only a small boundary. Ask what the primitive *unlocks*:

- **Leak → mitigation defeat → RCE**: a pointer/canary leak (confidentiality) removes ASLR/stack
  protection; combined with any write primitive → control flow.
- **Parser differential → request smuggling / filter or auth bypass**: target and a downstream
  consumer disagree on the same bytes.
- **Info leak + separate write/UAF → control**: leak gives the address the write needs.
- **DoS + state reuse / auth-state persistence → auth bypass or persistent outage.**
- **Type confusion → arbitrary read/write → privilege or isolation crossing.**

Two honesty rules:
- **Demonstrated chain**: `verify.sh` proves the *final* boundary crossing end-to-end. Only this
  sets the tier. Each upstream finding it relies on must already be confirmed in `findings.jsonl`
  (`verification.deterministic_replay == "pass"`); record them in `chained_findings`.
- **Projected chain**: a realistic escalation you did *not* mechanically prove (e.g. "this leak
  defeats ASLR; with any write primitive this is RCE"). Document it as the *potential* in
  `EXPLOIT.md` so the maintainer sees the real ceiling — but it **never** raises the tier or the
  recorded impact. Projection informs; only demonstration counts.
