# Profile: oss-fuzz — a container entry point. The core is pip-installed, so
# `cc-fuzzer` is on PATH, and the toolchain comes from the base image.

<!-- slot:vars -->
cc      = cc-fuzzer
scripts = $CC_FUZZER_ROOT/scripts
root    = $CC_FUZZER_ROOT
