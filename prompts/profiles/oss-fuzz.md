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
