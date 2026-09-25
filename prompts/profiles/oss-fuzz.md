# Profile: oss-fuzz — a container entry point. The core is pip-installed, so
# `cc-fuzzer` is on PATH, and the toolchain comes from the base image.

<!-- slot:vars -->
# Who performs the directives this engine emits, named the way THIS host
# names it. The prompts say {{driver}}; only the profile knows the word.
driver        = loop driver
driver_hyphen = loop-driver
schedule_api  = its own scheduler
dispatch_api  = subagent API
cc      = cc-fuzzer
scripts = $CC_FUZZER_ROOT/scripts
root    = $CC_FUZZER_ROOT

<!-- slot:symcc_runtime -->
   `{{cc}} tool which symcc`. The image supplies the toolchain, so there is nothing to
   install from here: if it is empty, SymCC is not available in this build and the
   concolic action is unsupported — record that and exit rather than trying to install.

<!-- slot:environment_gate -->
**IMAGE CHECK**: the base image fixes the toolchain, so there is nothing to reconcile and nothing for the model to install. Treat a tool the image does not carry as an unsupported capability (record it and move on), never as something to fix from inside the campaign.

<!-- slot:driver_bash_note -->
The driver runs the deterministic steps itself and calls you only for decisions, so shell work you would otherwise delegate happens outside this prompt.

<!-- slot:build_backend -->
### Step 0: Build backend

The image fixes the toolchain, so the backend is decided before the campaign
starts: `oss-fuzz`. You do not choose it, promote to it, or fall back from it.

Ask the core for the build and record what comes back:

```bash
{{cc}} build plan --harness <name> --backend oss-fuzz   # the commands, runs nothing
{{cc}} build record-args --result <build-result.json>   # what to record
```

A variant the image cannot produce comes back `unsupported` with its reason
(SymCC, for instance). Record it and continue -- do not try to install a
toolchain from inside the campaign. Then proceed to Mode A for the harness
source itself.

<!-- slot:missing_dep -->
**Missing system library / header (`fatal error: foo.h: No such file`, `cannot find -lfoo`, `Package foo was not found` from pkg-config):** the image is missing a build dependency, and the image is fixed for the run. **Do NOT hack include/lib paths into `build.sh`, and do not install anything.** Record the missing dependency in the build result's reason and continue with the variants that do build; a dependency the image lacks is an unsupported capability, not a repair task.
