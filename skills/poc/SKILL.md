---
name: poc
description: "Characterize the security impact of a confirmed finding for responsible disclosure. Produces a mechanically-verified impact bundle whose verify.sh exits 0 only when the bug is shown crossing a trust/privilege boundary the attacker couldn't otherwise cross — preferably as a pasteable CLI before/after a maintainer can grasp. Auto-dispatched after triage; available standalone for rebuilds and upgrades. — usage: <finding-id> [--rebuild] [--upgrade]"
argument-hint: "<finding-id> [--rebuild] [--upgrade]"
---

Dispatches the **poc-builder** subagent (Opus, ~$3-8 per finding).

Characterizes the real-world security impact of a confirmed finding — not just a crash reproducer. **Impact counts only as a verified trust-boundary crossing**: the bundle's `verify.sh` exits 0 only when the bug is shown moving data/control across a boundary the attacker couldn't otherwise cross — a read that returns a secret the attacker isn't entitled to (a before/after, not a self-planted adjacent-memory sentinel), `id` returning root, a write reaching protected state, a request bypassing a gate. A primitive that crosses no boundary is honestly marked Tier C (`no_boundary_crossed`) and CVSS adjusted down. CLI before/after demonstrations against the real binary are strongly preferred.

The agent reads `${CLAUDE_PLUGIN_ROOT}/references/threat-model.md` for the trust-boundary taxonomy, per-primitive checklists, and chainability prompts, and records the boundary it crossed in `verification.boundary_crossed`. Chaining of multiple confirmed findings is allowed when no single-finding exploit reaches a boundary (demonstrated chains set the tier; projected escalations are documented but never inflate it).

The orchestrator auto-dispatches `poc-builder` after every triage success. Use this command directly to rebuild after target source changes, upgrade a Tier-C bundle when new chain ideas emerge, or build an exploit for a legacy finding that pre-dates the agent.

## Flags

- `--rebuild` — replace an existing bundle (the agent refuses to overwrite a Tier-A/B bundle without this)
- `--upgrade` — attempt to raise the tier of an existing bundle; preserves the existing bundle if upgrade fails

The bundle layout and tier definitions are owned by the poc-builder agent and `${CLAUDE_PLUGIN_ROOT}/STATE_SCHEMA.md`; the bundle lands at `fuzz/findings/<id>/repro/`.

Finding id: $ARGUMENTS
