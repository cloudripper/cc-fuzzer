{
  description = "cc-fuzzer campaign environment — composes the cc-fuzzer toolchain with this target's build deps (./fuzz/nix-deps.nix).";

  # Pinned to the exact cc-fuzzer plugin source that `nix run #init` was invoked
  # from. Switch to a tracking ref (e.g. "github:cloudripper/cc-fuzzer") if
  # you'd rather follow upstream, then `nix flake update ccfuzzer`.
  inputs.ccfuzzer.url = "@CCFUZZER_SRC@";
  inputs.nixpkgs.follows = "ccfuzzer/nixpkgs";

  outputs = { self, ccfuzzer, nixpkgs }:
    let
      system = "@SYSTEM@";
      deps = import ./fuzz/nix-deps.nix;
    in {
      # The campaign dev shell: cc-fuzzer's pinned toolchain + the target build
      # deps in ./fuzz/nix-deps.nix. `nix run <cc-fuzzer>#init` populates that
      # file (headless dep scan); the harness-writer appends to it if a build
      # later reveals a missing library. Use with `nix develop`.
      devShells.${system}.default = ccfuzzer.lib.${system}.mkDevShell deps;

      # Apps to enter the composed FHS sandbox (both defined under ONE
      # `apps.${system}` — a dynamic key can't be split across two statements).
      # `nix develop -c <cmd>` does NOT work for a buildFHSEnv (the shellHook
      # execs into FHS bash before the -c command runs), so use these:
      apps.${system} = {
        # `nix run .#claude` → claude in the sandbox. Forwards args, but nix
        # needs `--` before any --flag:
        #   nix run .#claude                                  (plain)
        #   nix run .#claude -- --dangerously-skip-permissions
        claude = {
          type = "app";
          program = "${ccfuzzer.lib.${system}.mkClaudeApp deps}";
        };
        # `nix run .#default` → interactive FHS shell; or run any command:
        #   nix run .#default -- -c "<cmd>"
        default = {
          type = "app";
          program = "${ccfuzzer.lib.${system}.mkFhsEnv deps}/bin/cc-fuzzer-env";
        };
      };
    };
}
