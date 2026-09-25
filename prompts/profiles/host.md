# Profile: host — the Claude Code plugin against the machine's own toolchain
# (no Nix dev shell). Paths are identical to the nix profile; only the
# environment slot differs.

<!-- slot:vars -->
cc      = ${CLAUDE_PLUGIN_ROOT}/bin/cc-fuzzer
scripts = ${CLAUDE_PLUGIN_ROOT}/scripts
root    = ${CLAUDE_PLUGIN_ROOT}
