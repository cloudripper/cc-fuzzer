# Logic-oracle patterns — what to hunt for that a sanitizer cannot see

The `code-reviewer` (Sonnet) and `code-reviewer-deep` (Opus) agents load this catalog on EVERY
dispatch and walk each pattern across the target. **Logic bugs do not crash.** A sanitizer-only
lens (ASan/UBSan/MSan) is a memory-discipline oracle, not a policy oracle: it sees nothing when
the code is memory-safe but the *decision* is wrong.

In a recent end-to-end campaign the highest-ROI, most build-INDEPENDENT findings were
authorization/integrity/trust-boundary bugs (e.g. a namespace-remap function whose empty-suffix
case let a hostile peer write across a tenancy boundary). The plugin should reach this lens on
tick 1, not after a manual user pivot.

Pair this with `references/threat-model.md`: that file defines what "crossing a boundary" means
(the same vocabulary `poc-builder` uses); this file is the pattern catalog reviewers walk to find
candidates that cross one.

---

## 1. Authorization / ACL bypass

**Shape.** A request reaches a privileged code path without the auth/ACL check the path's
designer intended. Three sub-shapes:
- *Missing-check on a code path*: branch A passes through the auth gate; branch B reaches the
  same privileged action without it (often a refactor leftover, a "fast path", or an internal
  caller that "knew" it was trusted).
- *Check-then-trust-different-value*: the code authorizes value X (e.g. the originally-parsed
  topic / path / uid) but then acts on value X' (the canonicalized / remapped / re-resolved
  form). The gate was real; it just guarded the wrong variable.
- *Capability confusion*: a token/handle that grants capability A is treated as also granting
  capability B because the lookup conflates them.

**Example.** An MQTT broker's `handle__publish` checks ACLs for the wire-supplied topic, then
calls into a retained-message store keyed by the *post-rewrite* topic. The ACL guarded the wrong
string.

**Trust boundary crossed.** `authentication` or `privilege` (the attacker performs an action only
a different principal / role was authorized for).

**Why a sanitizer doesn't catch it.** No memory is corrupted. The code does exactly what it was
written to do; what it was written to do is wrong policy.

**How to surface in a finding.**
- `oracle_kind`: `authorization`
- `precondition`: who the attacker is and what they had to supply (e.g. "authenticated client
  with publish rights to namespace A, no rights to namespace B")
- `trust_boundary_crossed`: e.g. `"tenant A publisher → tenant B retained-message store"`

---

## 2. Topic / namespace remap

**Shape.** Input drives a namespace lookup or rewrite; the remapped identifier crosses a
tenancy/topic/path boundary the original would have respected. The canonical type specimen: a
namespace-remap step on a peer-supplied identifier, when the configured prefix has a zero-length
effective suffix, produces a target identifier *outside* the peer's intended namespace — a
hostile peer writes into another tenant's namespace.

The general shape: `external_identifier → remap(prefix, suffix, separator) → internal_identifier`
where the remap function has a degenerate case (`len == 0`, identical prefix and suffix, empty
separator, identity transform) it doesn't reject.

**Example.** A namespace-remap function whose empty-suffix case lets a peer-supplied identifier
land outside the intended namespace. Container-name prefixing where the configured prefix is
`""`. Multi-tenant request routing where the tenant id ends up unset and falls back to a global
namespace.

**Trust boundary crossed.** `isolation` or `integrity` (cross-tenant write / cross-topic
publish).

**Why a sanitizer doesn't catch it.** The remap function returns a perfectly valid string; the
write completes successfully. The bug is that the string identifies something the source
principal had no business naming.

**How to surface in a finding.**
- `oracle_kind`: `integrity` (write across) or `authorization` (read across)
- `precondition`: which configuration shape unlocks the degenerate remap (e.g. "bridge configured
  with a zero-length input mapping suffix — a valid config the operator may produce")
- `trust_boundary_crossed`: e.g. `"bridged-peer topic namespace → broker root topic namespace"`

---

## 3. Auth-state confusion (protocol state-machine bugs)

**Shape.** A state machine accepts a message in the wrong phase — e.g. a `CONNECT`-only command
processed when already authenticated, a `SUBSCRIBE` accepted before `CONNECT` completed, a
post-`DISCONNECT` message still acted upon because the cleanup ran in the wrong order. The
state-machine has the right states; the transitions accept inputs they shouldn't.

**Example.** SMTP `AUTH` accepted after `STARTTLS` was downgraded mid-session. MQTT `WILL`
message rewritten after the connection should have been considered closed. An HTTP/2 stream
processed after `RST_STREAM`.

**Trust boundary crossed.** `authentication` (acting as a principal the state-machine should have
already required) or `integrity` (modifying state after the session that authorized it ended).

**Why a sanitizer doesn't catch it.** All memory accesses are valid; the wrong handler simply got
called.

**How to surface in a finding.**
- `oracle_kind`: `state_confusion`
- `precondition`: the protocol message sequence that drives the state-machine into the wrong
  receptive state
- `trust_boundary_crossed`: e.g. `"unauthenticated connection state → authenticated handler"`

---

## 4. Cross-session / cross-tenant data exposure

**Shape.** A read or notify path leaks data from another session/tenant due to identity confusion
at lookup time. Common shapes: a shared cache keyed by a value the attacker can collide; a
notification handler that fires for all subscribers when it should fire for one; a "last value"
slot that crosses session boundaries when the cleanup at session-end is missing or racy.

**Example.** Retained-message replay on subscribe leaks a message published by another tenant on
a topic the new subscriber wasn't entitled to. A shared response cache returns tenant B's record
to tenant A because the cache key omits the tenant id.

**Trust boundary crossed.** `confidentiality` (between principals / between tenants).

**Why a sanitizer doesn't catch it.** The read is in-bounds; the data is well-formed. The wrong
*owner* sees it.

**How to surface in a finding.**
- `oracle_kind`: `info_disclosure`
- `precondition`: the second principal's prior action that placed the leaked data (e.g. "tenant B
  previously published to topic X with retain=1")
- `trust_boundary_crossed`: e.g. `"tenant A subscriber → tenant B's retained payload"`

---

## 5. Integrity-write primitives via intended-data-only channels

**Shape.** Attacker-controlled input ends up in a write to a privileged location — config,
retained-topic store, an auth/identity DB, a logged value later trusted by an admin tool — via a
channel that was *intended* to carry only data, not control. The path is "supposed to" be a
data-only path, but the write lands on state that influences a later authorization or routing
decision.

**Example.** A retained MQTT message whose payload is later read by a config-reload subscriber
and parsed as TOML. A log line containing user-controlled bytes interpreted by `logrotate` /
`fail2ban` / an admin viewer that doesn't escape them. A username field that's also used as a
filesystem path component.

**Trust boundary crossed.** `integrity` (state-tampering across the data → control gap).

**Why a sanitizer doesn't catch it.** Every individual write is well-formed and to a legitimate
buffer. The chain of consumers is what makes it dangerous.

**How to surface in a finding.**
- `oracle_kind`: `integrity`
- `precondition`: which downstream consumer trusts the channel as control-bearing
- `trust_boundary_crossed`: e.g. `"unauth wire-client payload → broker config-reload subscriber"`

---

## 6. Trusted-input assumption on attacker-reachable paths

**Shape.** A code path assumes its input came from a trusted source (e.g. "the bridge peer is
trusted by configuration"; "this RPC is internal-cluster-only"; "this socket is a unix socket and
therefore root") — but the path is in fact reachable from a different, attacker-controllable
entry that the original author didn't anticipate. The check that would have validated the input
was elided because "the source is trusted."

**Example.** A function with a comment `/* only called from internal_admin_loop */` that
turns out to also be reachable via a refactored public API. A handler reached over a unix socket
that's been re-exposed over TCP via a forwarder. A bridge inbound path that trusts the peer's
identity claim because "bridges are peers we configured" — but the peer connection is
attacker-controllable.

**Trust boundary crossed.** Whichever boundary the elided check would have guarded — usually
`authentication` or `authorization`.

**Why a sanitizer doesn't catch it.** The "missing" check was deliberately omitted; the code
runs cleanly. The bug is that the *reachability* assumption is now wrong.

**How to surface in a finding.**
- `oracle_kind`: `authorization` (or `state_confusion` when the assumption is about protocol
  phase)
- `precondition`: how the attacker reaches the path the original author thought was internal-only
- `trust_boundary_crossed`: e.g. `"wire client → handler that assumed internal-cluster caller"`

---

## 7. Empty-prefix / empty-suffix / length-zero bypass

**Shape.** A string operation treats `len == 0` (or empty prefix / empty suffix / empty separator
/ identity transform) as "no transformation needed" and skips the check that would have flagged a
malicious input. Equivalently: a validator that early-returns on empty input as "trivially
valid." This is the empty-suffix bypass family in its most-distilled form, and it generalizes
far beyond remapping.

**Example.** A namespace-remap function's empty-suffix case → cross-namespace write. A path
normalizer that treats `""` as "current directory" and so `validate(prefix) + "" → prefix` lets a
write to the root escape a subdir jail. A capability check `if (!cap) return OK;` ("no
restriction specified" → "anything allowed").

**Trust boundary crossed.** Whatever the elided check guarded — typically `integrity`,
`isolation`, or `authorization`.

**Why a sanitizer doesn't catch it.** The empty-input branch executes without any memory error;
the bug is that it returned the wrong policy decision.

**How to surface in a finding.**
- `oracle_kind`: `authorization` / `integrity` / `state_confusion` (pick by what the elided check
  was guarding)
- `precondition`: the input that triggers the degenerate branch (e.g. "configured suffix is the
  empty string"; "validated path component is `\"\"`")
- `trust_boundary_crossed`: as above

---

## 8. Length-of-zero accept-then-trust

**Shape.** A parser/validator accepts a message whose length field is zero (or "no payload") on
the assumption that "nothing to validate" → "valid", then passes the message structure to a
downstream consumer that trusts the parser's verdict and dereferences / indexes the payload
without re-checking. The bug isn't a memory error in the parser; it's that the parser's "accept"
contract was weaker than the consumer's "trust" contract.

**Example.** A WebSocket frame with `payload_len == 0` flagged as valid; the downstream handler
reads `payload[0]` to look at the opcode-extension byte. (When this also crashes, you'll see it
as a memory bug — but the *root cause* is the contract mismatch and there are usually sibling
consumers that don't crash but do act on a garbage byte.) A protobuf message accepted with a
zero-length sub-message that a downstream serializer assumes is initialized.

**Trust boundary crossed.** Often `integrity` or `state_confusion`; sometimes `confidentiality`
when the "trusted" zero-byte payload leaks adjacent state.

**Why a sanitizer doesn't catch it.** Only the *crash-shaped* siblings of this bug fire ASan.
The logic-shaped siblings (consumer acts on uninitialized but in-bounds state, or returns the
wrong decision) are silent.

**How to surface in a finding.**
- `oracle_kind`: `state_confusion` (most common) or `integrity` / `info_disclosure` per consumer
- `precondition`: the zero-length-but-accepted message shape
- `trust_boundary_crossed`: the consumer's contract that the parser silently violated

---

## How reviewers use this

**Every** `code-reviewer` (Sonnet) and `code-reviewer-deep` (Opus) dispatch loads this file as
input and walks each of the 8 patterns across the target / diff. This is a **mandatory dimension
alongside** the CVE-memory-pattern pass — not a fallback, not "run it on plateau." Surface
candidates even when no sanitizer signal is present.

For each pattern, ask:
1. *Does this codebase have the shape?* (is there a remap function / a state machine / a "trusted
   peer" assumption / an empty-input fast-path)
2. *Is the boundary on the other side of the bug worth crossing?* (consult
   `references/threat-model.md` for what counts as impact)
3. *What is the attacker precondition?* (the realistic shape of the request that triggers the
   degenerate branch)

If yes to all three, emit a finding with `oracle_kind != memory`, populated `precondition`, and
populated `trust_boundary_crossed`. Findings tagged `oracle_kind != memory` are **first-class
promotion signals** for `poc-builder` — they tend to be build-independent, portable across libc /
heap / distro, and the framing a maintainer immediately grasps. The plugin reaches them on
tick 1 because of this lens — that is the point.
