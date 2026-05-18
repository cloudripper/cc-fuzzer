{
  description = "cc-fuzzer pinned reproducible toolchain (FHS-wrapped for AFL++/SymCC/libFuzzer compatibility)";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/release-25.11";
    llm-agents.url = "github:numtide/llm-agents.nix/7c2b15bbb92e200cb741372f050de789e7811539";
  };

  nixConfig = {
    extra-substituters = [ "https://cache.numtide.com" ];
    extra-trusted-public-keys = [ "niks3.numtide.com-1:DTx8wZduET09hRmMtKdQDxNNthLQETkc/yaX7M4qK0g=" ];
  };

  outputs = { self, nixpkgs, llm-agents }:
    let
      system = "x86_64-linux";
      pkgs = import nixpkgs { inherit system; };

      # ----------------------------------------------------------------------
      # Toolchain coupling note
      # ----------------------------------------------------------------------
      # AFL++, SymCC, and libFuzzer all need clang+compiler-rt, but they don't
      # care about the exact major version as long as everything in one shell
      # was built against the same LLVM family. We let the dev-shell carry one
      # consistent stdenv-provided clang. If you discover an ABI mismatch
      # (rare; usually surfaces as "undefined reference to __sancov_*" or
      # "PassPlugin failed to load"), pin a specific llvmPackages_NN below
      # and rebuild.
      #
      # Why no flake.lock is shipped:
      #   See README "Reproducibility tradeoffs". Users own the lock by running
      #   `nix flake update` once. The plugin doesn't impose a commit; it
      #   imposes the toolchain *shape*.
      # ----------------------------------------------------------------------

      ccFuzzerEnv = pkgs.buildFHSEnv {
        name = "cc-fuzzer-env";

        # ------------------------------------------------------------------
        # FHS-visible package set
        # ------------------------------------------------------------------
        # buildFHSEnv constructs a sandboxed FHS layout (/usr/bin, /usr/lib,
        # /lib64, ...) populated with the packages below. AFL++ and SymCC
        # were written assuming this layout; running them under pure nix
        # without FHSEnv hits hardcoded path expectations and fragile cc-
        # wrapper interactions. FHSEnv eliminates that whole class of bugs.
        targetPkgs = pkgs: with pkgs; [
          # -- Compilers / sanitizer runtimes
          # stdenv-provided clang carries a matching compiler-rt with
          # libclang_rt.fuzzer.a. That's what `-fsanitize=fuzzer` links
          # against. Don't replace this without also pinning a matching
          # llvmPackages_NN.compiler-rt.
          clang
          llvmPackages.compiler-rt
          llvmPackages.libcxx

          # -- LLVM userland tools (llvm-cov, llvm-profdata, llvm-symbolizer,
          # opt, llc). cc-fuzzer specifically calls llvm-cov + llvm-profdata
          # in snapshot-coverage.sh.
          llvmPackages.llvm

          # -- Fuzzer engines
          aflplusplus

          # -- Concolic execution
          symcc
          z3

          # -- Triage / debug
          gdb
          binutils       # gives addr2line, strings, nm, objdump, readelf
          strace

          # -- Build essentials targets typically need
          gnumake
          cmake
          ninja
          pkg-config
          gcc            # some autotools projects sniff for cc=gcc; cheap to ship
          autoconf
          automake
          libtool
          coreutils
          findutils
          gnused
          gawk
          gnugrep
          gnutar
          gzip
          bzip2
          xz
          vim
          patch
          which
          file
          glib

          # -- Common library headers/bits some targets need
          glib.dev
          zlib.dev
          openssl.dev

          # -- State-script runtime
          python3
          jq

          # -- Dev conveniences (per user request)
          ripgrep        # rg
          fd             # fd
          bat            # nicer cat for plugin debugging
          tree
        ] ++ [ llm-agents.packages.${system}.claude-code ];

        # ------------------------------------------------------------------
        # Marker env vars + project bind
        # ------------------------------------------------------------------
        # CC_FUZZER_FHS=1 is the load-bearing fingerprint; env-check.sh uses it
        # to distinguish "user is in our specific dev shell" from "user is in
        # some other random nix shell." Without this, the hook can't tell the
        # two cases apart.
        #
        # CC_FUZZER_FLAKE_REV records the flake's git rev (or "dirty" if the
        # plugin tree has uncommitted changes). The hook reports this so users
        # can correlate "campaign X was run with flake rev Y" later.
        #
        # We also re-export PWD-bind via CC_FUZZER_PROJECT_ROOT for downstream
        # scripts that want to know the user's working directory at shell-
        # entry time (since once inside the FHS sandbox, PWD can drift and
        # the user may not realize their project is bind-mounted).
        profile = ''
          export CC_FUZZER_FHS=1
          export CC_FUZZER_FLAKE_REV="${self.rev or "dirty"}"
          export CC_FUZZER_PROJECT_ROOT="$PWD"

          # Friendly banner. Quiet enough to ignore once you're used to it.
          echo "cc-fuzzer dev shell active (flake rev: ${self.rev or "dirty"})"
          echo "  toolchain: clang $(${pkgs.clang}/bin/clang --version | head -1 | awk '{print $NF}'), AFL++ $(${pkgs.aflplusplus}/bin/afl-fuzz -h 2>&1 | head -1 | awk '{print $NF}' || echo unknown)"
          echo "  project bind: $CC_FUZZER_PROJECT_ROOT"
        '';

        # ------------------------------------------------------------------
        # Auto-bind the user's $PWD into the FHS sandbox
        # ------------------------------------------------------------------
        # By default buildFHSEnv bind-mounts $HOME read-write, which covers
        # the common case (user's project lives under $HOME). For users
        # working outside $HOME (e.g. /srv/code/target/), we bind $PWD
        # explicitly via extraBwrapArgs. This makes "nix develop" work from
        # any directory.
        #
        # extraBwrapArgs only takes effect when the buildFHSEnv runs the
        # user's interactive shell (not when running `runScript` non-
        # interactively); for our dev-shell use case it's exactly what we want.
        extraBwrapArgs = [
          "--bind-try" "$PWD" "$PWD"
        ];

        runScript = "bash";
      };
    in {
      # ----------------------------------------------------------------------
      # devShells.default
      # ----------------------------------------------------------------------
      # `.env` is the trick that makes a buildFHSEnv consumable by `nix
      # develop`. Without `.env`, you'd get a wrapper script that you have
      # to run as `result/bin/cc-fuzzer-env`, which doesn't fit the
      # `nix develop <plugin-path>` workflow.
      devShells.${system}.default = ccFuzzerEnv.env;

      # Also expose the wrapper directly for users who'd rather invoke
      # `nix run .#dev` instead of `nix develop`.
      apps.${system}.dev = {
        type = "app";
        program = "${ccFuzzerEnv}/bin/cc-fuzzer-env";
      };
    };
}

