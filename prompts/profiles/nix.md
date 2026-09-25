# Profile: nix — the Claude Code plugin inside its reproducible Nix dev shell.
#
# This file is the plugin's ADAPTER, so it is the one place allowed to name
# Claude Code's ${CLAUDE_PLUGIN_ROOT}. A prompt source never does: it writes
# {{cc}} / {{scripts}} / {{root}} and asks for <!-- profile:environment -->.

<!-- slot:vars -->
# The core CLI. On PATH where the package is pip-installed; inside the plugin
# it is the checkout's wrapper, because an agent's Bash call inherits
# CLAUDE_PLUGIN_ROOT but not CC_FUZZER_ROOT.
cc      = ${CLAUDE_PLUGIN_ROOT}/bin/cc-fuzzer
# Scripts that have not been ported to a core verb yet. Each port turns one
# `{{scripts}}/x.sh` call site into `{{cc}} <verb>`.
scripts = ${CLAUDE_PLUGIN_ROOT}/scripts
root    = ${CLAUDE_PLUGIN_ROOT}
