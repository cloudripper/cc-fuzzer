#!/usr/bin/env bash
# check-campaign-state.sh
#
# Classifies the current campaign state for /cc-fuzzer:campaign dispatch.
# Prints exactly one of:
#   none        - no campaign exists; cold start needed
#   running     - campaign exists, fuzzer is alive; just print status
#   stopped     - campaign exists, fuzzer is not running; resume needed
#   stale       - target source has changed since last build; user must choose
#   corrupted   - state directory exists but fails validation; user must fix or reset
#
# Always exits 0; the classification is on stdout. Diagnostic detail on stderr.

#
# Shim onto `cc-fuzzer tick state` (cc_fuzzer_core.loop.campaign_state): same
# five words on stdout, same order of checks, same exit 0. The order IS the
# meaning -- a campaign that fails validation is `corrupted` even with a live
# fuzzer, and one whose target source moved is `stale` even when everything
# else is ready, because both route to an assessment instead of an action.

set -u

. "$(dirname "${BASH_SOURCE[0]}")/_lib/root.sh"
exec python3 -m cc_fuzzer_core tick state "$@"
