#!/usr/bin/env bash
# events.sh
#
# The writer of events.jsonl for the orchestrator. The orchestrator must call
# this rather than appending lines directly, so the schema field is always
# present and the format is consistent.
#
# Usage:
#   events.sh tick <branch> <reason> <duration_ms> [agent_called]
#   events.sh agent_call <agent> <tokens_in> <tokens_out>
#   events.sh campaign_start
#   events.sh campaign_resume
#   events.sh campaign_stop
#   events.sh corpus_quarantine <count> <details>
#   events.sh error <message>
#
# Atomic, locked append. Schema: event/v1.
#
# Shim onto the core's port, `cc-fuzzer events <cmd>` (cc_fuzzer_core.events).
# `agent_call` goes through the spend ledger (cc_fuzzer_core.ledger) and is
# recorded with source=orchestrator: advisory. The host measures each subagent
# call itself (hooks/ledger-append.sh, source=host-hook) and those rows
# supersede the orchestrator's for the same agent and tick. `tick` rows carry
# no billable tokens.

set -u

. "$(dirname "${BASH_SOURCE[0]}")/_lib/root.sh"

case "${1:-help}" in
  tick|agent_call|campaign_start|campaign_resume|campaign_stop|corpus_quarantine|error)
    exec python3 -m cc_fuzzer_core events "$@" ;;
  *)
    exec python3 -m cc_fuzzer_core events help ;;
esac
