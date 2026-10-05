#!/usr/bin/env bash
# hooks/sweep-gate.sh
#
# Stop hook, OPT-IN (not in hooks/hooks.json): a turn may not end while the
# delta sweep has changed sinks with no verdict (cc_fuzzer_core.sweep). For
# autonomous use, where one turn is one work round: a CRS installs it through
# its own --settings. Interactively every assistant turn ends with Stop, so
# the plugin never registers it; add it to your settings only while working a
# sweep:
#
#   {"hooks": {"Stop": [{"hooks": [{"type": "command",
#      "command": "${CLAUDE_PLUGIN_ROOT}/hooks/sweep-gate.sh"}]}]}}
#
# Arguments are passed on (e.g. --file <sweep.json> for a host without a
# campaign). Never fails a turn on its own error: no sweep, an unreadable one,
# or a broken core all let the turn end.
set -u
. "$(dirname "${BASH_SOURCE[0]}")/../scripts/_lib/root.sh" 2>/dev/null || exit 0
exec python3 -m cc_fuzzer_core sweep gate --hook "$@"
