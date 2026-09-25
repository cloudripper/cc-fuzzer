# Profile: nix — the Claude Code plugin inside its reproducible Nix dev shell.
#
# This file is the plugin's ADAPTER, so it is the one place allowed to name
# Claude Code's ${CLAUDE_PLUGIN_ROOT}. A prompt source never does: it writes
# {{cc}} / {{scripts}} / {{root}} and asks for <!-- profile:environment -->.

<!-- slot:vars -->
# Who performs the directives this engine emits, named the way THIS host
# names it. The prompts say {{driver}}; only the profile knows the word.
driver        = main thread
driver_hyphen = main-thread
schedule_api  = ScheduleWakeup
dispatch_api  = `Agent`/`Task` tool
# The core CLI. On PATH where the package is pip-installed; inside the plugin
# it is the checkout's wrapper, because an agent's Bash call inherits
# CLAUDE_PLUGIN_ROOT but not CC_FUZZER_ROOT.
cc      = ${CLAUDE_PLUGIN_ROOT}/bin/cc-fuzzer
# Scripts that have not been ported to a core verb yet. Each port turns one
# `{{scripts}}/x.sh` call site into `{{cc}} <verb>`.
scripts = ${CLAUDE_PLUGIN_ROOT}/scripts
root    = ${CLAUDE_PLUGIN_ROOT}

<!-- slot:symcc_runtime -->
   `source {{scripts}}/_lib/nix-tools.sh && nix_tool symcc`. This consults
   `fuzz/state/nix-env.json` before falling back to PATH — `which symcc` alone is
   unreliable when the session inherited a stripped environment. Fix path:
   `nix develop {{root}} && claude`, or `{{scripts}}/install-symcc.sh` outside Nix.

<!-- slot:environment_gate -->
**NIX ENVIRONMENT CHECK**: read `fuzz/state/nix-environment-issues.json` (written by `nix-env-reconcile.sh` at session start); if it contains any `severity=error` issues affecting harnesses committed to `build_backend=nix`, **stop and print each issue's `remediation.human_message`**. Warnings are surfaced but don't block; skip if the file is absent.

<!-- slot:driver_bash_note -->
Under the recommended ctxctl configuration (see README), the main thread cannot run Bash directly; only you and your sibling specialists can.
