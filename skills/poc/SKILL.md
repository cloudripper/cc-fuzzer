---
name: poc
description: "Build or upgrade a verifiable EXPLOIT for a confirmed finding. Produces an exploit whose impact is checked mechanically by a verify.sh script. Auto-dispatched after triage; available standalone for rebuilds and upgrades. — usage: <finding-id> [--rebuild] [--upgrade]"
argument-hint: "<finding-id> [--rebuild] [--upgrade]"
disable-model-invocation: true
---

Dispatches the **poc-builder** subagent (Opus, ~$3-8 per finding).

Builds an exploit that demonstrates **real attacker impact** — not just a crash reproducer. The bundle's `verify.sh` exits 0 only when the exploit succeeded (sentinel file created, `id` returns root, sentinel bytes leaked, response time > threshold, etc.). If no verifiable impact can be built, the finding is honestly marked Tier C and CVSS is adjusted down.

The agent reads `${CLAUDE_PLUGIN_ROOT}/references/` for exploitation techniques (Malloc Maleficarium, how2heap, mitigation bypass patterns) and cites the technique used in the bundle's `EXPLOIT.md`. Chaining of multiple confirmed findings is allowed when no single-finding exploit reaches a meaningful tier.

The orchestrator auto-dispatches `poc-builder` after every triage success. Use this command directly to rebuild after target source changes, upgrade a Tier-C bundle when new chain ideas emerge, or build an exploit for a legacy finding that pre-dates the agent.

## Flags

- `--rebuild` — replace an existing bundle (the agent refuses to overwrite a Tier-A/B bundle without this)
- `--upgrade` — attempt to raise the tier of an existing bundle; preserves the existing bundle if upgrade fails

The bundle layout and tier definitions are owned by the poc-builder agent and `${CLAUDE_PLUGIN_ROOT}/STATE_SCHEMA.md`; the bundle lands at `fuzz/findings/<id>/repro/`.

Finding id: $ARGUMENTS
