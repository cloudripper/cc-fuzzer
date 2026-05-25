# Target build dependencies for this cc-fuzzer campaign's dev shell.
#
# A function: given nixpkgs `pkgs`, return the EXTRA packages the harness build
# and fuzzer runtime need (headers, libs, tools) BEYOND cc-fuzzer's base
# toolchain. Use exact nixpkgs attrs; headers usually live in the `.dev`
# output:
#
#   pkgs: with pkgs; [ glib.dev openssl.dev libpng ]
#
# Managed by `nix run <cc-fuzzer>#init` (headless dep scan) and appended to by
# the harness-writer when a build reveals a missing library. After editing,
# re-enter the shell to apply: `nix run <cc-fuzzer>#init` (idempotent) or
# `nix develop -c claude`.
pkgs: with pkgs; [
]
