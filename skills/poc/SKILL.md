---
name: poc
description: "Characterize the security impact of a confirmed finding for responsible disclosure. Produces a mechanically-verified impact bundle (verify.sh exits 0 only when the demonstrated impact is confirmed). Auto-dispatched after triage; available standalone for rebuilds and upgrades. — usage: <finding-id> [--rebuild] [--upgrade]"
argument-hint: "<finding-id> [--rebuild] [--upgrade]"
disable-model-invocation: true
---

Dispatches the **poc-builder** subagent (Opus, ~$3-8 per finding).

Characterizes the real-world security impact of a confirmed finding — not just a crash reproducer. The bundle's `verify.sh` exits 0 only when the demonstrated impact is confirmed (sentinel file created, `id` returns root, sentinel bytes leaked, response time > threshold, etc.). If no verifiable impact can be demonstrated, the finding is honestly marked Tier C and CVSS is adjusted down.

The agent reads `${CLAUDE_PLUGIN_ROOT}/references/` for exploitation techniques (Malloc Maleficarium, how2heap, mitigation bypass patterns) and cites the technique used in the bundle's `EXPLOIT.md`. Chaining of multiple confirmed findings is allowed when no single-finding exploit reaches a meaningful tier.

The orchestrator auto-dispatches `poc-builder` after every triage success. Use this command directly to rebuild after target source changes, upgrade a Tier-C bundle when new chain ideas emerge, or build an exploit for a legacy finding that pre-dates the agent.

## Flags

- `--rebuild` — replace an existing bundle (the agent refuses to overwrite a Tier-A/B bundle without this)
- `--upgrade` — attempt to raise the tier of an existing bundle; preserves the existing bundle if upgrade fails

The bundle layout and tier definitions are owned by the poc-builder agent and `${CLAUDE_PLUGIN_ROOT}/STATE_SCHEMA.md`; the bundle lands at `fuzz/findings/<id>/repro/`.

Finding id: $ARGUMENTS
