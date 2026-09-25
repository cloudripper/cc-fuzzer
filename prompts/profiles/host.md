# Profile: host — the Claude Code plugin against the machine's own toolchain
# (no Nix dev shell). Paths are identical to the nix profile; only the
# environment slot differs.

<!-- slot:vars -->
# Who performs the directives this engine emits, named the way THIS host
# names it. The prompts say {{driver}}; only the profile knows the word.
driver        = main thread
driver_hyphen = main-thread
schedule_api  = ScheduleWakeup
dispatch_api  = `Agent`/`Task` tool
cc      = ${CLAUDE_PLUGIN_ROOT}/bin/cc-fuzzer
scripts = ${CLAUDE_PLUGIN_ROOT}/scripts
root    = ${CLAUDE_PLUGIN_ROOT}

<!-- slot:symcc_runtime -->
   `{{cc}} tool which symcc`. That checks `$CC_FUZZER_TOOL_SYMCC`, then the campaign's
   recorded tool pins, then PATH. Fix path: `{{scripts}}/install-symcc.sh`, or export
   `CC_FUZZER_TOOL_SYMCC=/path/to/symcc`.

<!-- slot:environment_gate -->
**TOOLCHAIN CHECK**: the campaign builds against whatever the machine provides, so there is no pinned-environment file to reconcile. `preflight.sh` above already covered the required tools; if it passed, fall through.

<!-- slot:driver_bash_note -->
Under the recommended ctxctl configuration (see README), the main thread cannot run Bash directly; only you and your sibling specialists can.

<!-- slot:build_backend -->
### Step 0: Build backend

This campaign builds against the machine's own toolchain: there is no nix
derivation to promote to and nothing to decide here. Record the backend the
build actually used when you write the harness record (`--build-backend`
comes from the build result). Proceed to Mode A.

<!-- slot:missing_dep -->
**Missing system library / header (`fatal error: foo.h: No such file`, `cannot find -lfoo`, `Package foo was not found` from pkg-config):** the machine is missing a build dependency. **Do NOT hack include/lib paths into `build.sh`.** Report the missing package to the user and stop; installing system packages is theirs to decide, not yours.
