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
      # buildFHSEnv (and the bwrap it relies on) are Linux-only, so we build
      # for the Linux systems — not darwin. Add more here if needed.
      systems = [ "x86_64-linux" "aarch64-linux" ];
      forAllSystems = nixpkgs.lib.genAttrs systems;

      # Everything that depends on a concrete system/pkgs is built per-system;
      # the outputs below map it over `systems` via forAllSystems.
      perSystem = system:
        let
          pkgs = import nixpkgs { inherit system; };

          # --------------------------------------------------------------------
          # SINGLE SOURCE OF TRUTH for the LLVM toolchain (see coupling note
          # below). The dev-shell tool list AND the `lib.${system}` exports
          # (consumed by a project's own monolithic derivation — see
          # references/nix-monolithic.md) both reference these, so a target
          # library built via `lib.clangStdenv` links the SAME
          # libclang_rt.profile that this shell's llvm-cov / llvm-profdata read.
          # To pin a major, set `llvmPackages` to pkgs.llvmPackages_NN here and
          # every consumer (shell clang, exports) updates in lockstep.
          # --------------------------------------------------------------------
          llvmPackages = pkgs.llvmPackages;
          clangStdenv = llvmPackages.stdenv;

      # ----------------------------------------------------------------------
      # Toolchain coupling note
      # ----------------------------------------------------------------------
      # AFL++, SymCC, and libFuzzer all need clang+compiler-rt, but they don't
      # care about the exact major version as long as everything in one shell
      # was built against the same LLVM family. We let the dev-shell carry one
      # consistent stdenv-provided clang. If you discover an ABI mismatch
      # (rare; usually surfaces as "undefined reference to __sancov_*" or
      # "PassPlugin failed to load"), pin the `llvmPackages` binding above to a
      # specific llvmPackages_NN and rebuild.
      #
      # Why no flake.lock is shipped:
      #   See README "Reproducibility tradeoffs". Users own the lock by running
      #   `nix flake update` once. The plugin doesn't impose a commit; it
      #   imposes the toolchain *shape*.
      # ----------------------------------------------------------------------

      # mkEnv builds the FHS dev shell. `extra` is a `pkgs: [ ... ]` function
      # supplying a campaign's target-specific build deps (composed in by a
      # project flake via `lib.mkDevShell`); `projectShell` flags that composed
      # shell so env-check can tell it apart from the bare plugin shell.
      mkEnv = { extra ? (_: []), projectShell ? false }: pkgs.buildFHSEnv {
        name = "cc-fuzzer-env";

        # ------------------------------------------------------------------
        # FHS-visible package set
        # ------------------------------------------------------------------
        # buildFHSEnv constructs a sandboxed FHS layout (/usr/bin, /usr/lib,
        # /lib64, ...) populated with the packages below. AFL++ and SymCC
        # were written assuming this layout; running them under pure nix
        # without FHSEnv hits hardcoded path expectations and fragile cc-
        # wrapper interactions. FHSEnv eliminates that whole class of bugs.
        targetPkgs = pkgs: (with pkgs; [
          # === Compilers / sanitizer runtimes ===
          # clang from the single `llvmPackages` binding above; its matching
          # compiler-rt carries libclang_rt.fuzzer.a (what `-fsanitize=fuzzer`
          # links against) and libclang_rt.profile (the coverage runtime that
          # must match llvm-cov/llvm-profdata). All three come from one binding.
          llvmPackages.clang
          llvmPackages.compiler-rt
          llvmPackages.libcxx
          # LLVM userland (llvm-cov, llvm-profdata, llvm-symbolizer, opt, llc)
          llvmPackages.llvm
          llvmPackages.clang-tools  # clangd, clang-tidy, clang-format

          # === Languages (targets commonly pull these in) ===
          gcc
          python3
          perl
          rustc
          cargo
          go
          nodejs

          # === Fuzzer engines ===
          aflplusplus
          honggfuzz
          radamsa

          # === Concolic / SMT ===
          symcc
          z3

          # === Coverage / triage / debug ===
          gdb
          lldb
          rr
          valgrind
          binutils       # addr2line, strings, nm, objdump, readelf
          elfutils       # eu-* variants, often better
          strace
          ltrace
          lcov
          gcovr

          # === Build systems ===
          gnumake
          cmake
          ninja
          meson
          pkg-config
          autoconf
          automake
          libtool
          gperf
          bear           # compile_commands.json from arbitrary builds

          # === Code indexing (for agentic code understanding) ===
          universal-ctags
          cscope

          # === Core userland ===
          coreutils
          findutils
          gnused
          gawk
          gnugrep
          diffutils
          patch
          patchutils
          which
          file
          moreutils      # sponge, ts, chronic, ifne
          parallel       # GNU parallel
          time           # GNU /usr/bin/time -v
          dos2unix

          # === Process / system introspection ===
          procps         # ps, top, pkill, pgrep, vmstat, free, watch, sysctl
          psmisc         # pstree, fuser, killall, peekfd
          util-linux     # lscpu, lsblk, taskset, nsenter, flock, setsid
          lsof
          iproute2       # ip, ss
          htop
          iotop
          ncdu
          numactl
          linuxPackages.perf
          bpftrace
          bcc

          # === Networking ===
          curl
          wget
          rsync
          openssh
          tcpdump
          socat
          netcat-gnu

          # === Archive / compression ===
          gnutar
          gzip
          bzip2
          xz
          zstd
          lz4
          unzip
          p7zip
          cpio

          # === Common library headers (keep generic; target-specific goes in nix-deps.nix) ===
          glib
          glib.dev
          zlib.dev
          openssl
          openssl.dev

          # === Hex / data inspection ===
          hexyl

          # === Data formats ===
          jq
          yq
          dasel

          # === Editors / sessions ===
          vim
          tmux
          entr

          # === Nix-native dep resolution (lets agents self-resolve missing tools) ===
          nix-index

          # === VCS ===
          git

          # === Dev conveniences ===
          ripgrep
          fd
          bat
          tree
          nixfmt
        ] ++ [ llm-agents.packages.${system}.claude-code ]) ++ (extra pkgs);

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
          ${pkgs.lib.optionalString projectShell "export CC_FUZZER_PROJECT_SHELL=1"}
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

      # `nix run <cc-fuzzer>#init` — the campaign bootstrap. Runs on the host:
      # scaffolds ./flake.nix + ./fuzz/nix-deps.nix, headlessly resolves the
      # target's build deps, locks, then PRINTS the commands to launch Claude
      # (`nix run .#claude …`) and open the shell (`nix develop`). It does NOT
      # launch Claude itself. PATH carries the tools the script needs; host
      # `nix` stays on PATH (writeShellScriptBin does not reset it). CCFUZZER_SRC
      # pins the project flake's `ccfuzzer` input to exactly this plugin source.
      initApp = pkgs.writeShellScriptBin "cc-fuzzer-init" ''
        export PATH="${pkgs.lib.makeBinPath [ pkgs.git pkgs.gnused pkgs.gnugrep pkgs.coreutils llm-agents.packages.${system}.claude-code ]}:$PATH"
        export CCFUZZER_SRC="${self}"
        export CCFUZZER_SYSTEM="${system}"
        export CCFUZZER_INIT_CAP="''${CCFUZZER_INIT_CAP:-10}"
        exec ${pkgs.bash}/bin/bash ${self}/scripts/campaign-init.sh "$@"
      '';
        in { inherit pkgs mkEnv initApp llvmPackages clangStdenv; };
    in {
      # `.env` makes a buildFHSEnv consumable by `nix develop`. One per system.
      devShells = forAllSystems (system: {
        default = ((perSystem system).mkEnv {}).env;
      });

      # Extension point for per-campaign project flakes (see
      # templates/project-flake.nix). `extra` is a `pkgs: [ ... ]` of the
      # target's build deps; the result composes them onto the base toolchain
      # in one FHS env. Marked as a project shell so env-check can detect it.
      lib = forAllSystems (system: let ps = perSystem system; in {
        # ------------------------------------------------------------------
        # Toolchain-pin contract for project monolithic derivations.
        # ------------------------------------------------------------------
        # A whole-library target (e.g. systemd's libsystemd-shared.so) must be
        # built by the project's OWN derivation, not the per-harness `clang
        # src/*` flow. Build it with THESE so its instrumented .so links the
        # same libclang_rt.profile that the dev-shell's llvm-cov / llvm-profdata
        # read — otherwise the .so's __llvm_profile_runtime forces a mismatched
        # profraw version and coverage silently breaks. Usage in a project
        # flake (see templates/project-flake.nix + references/nix-monolithic.md):
        #   ccfuzzer.lib.${system}.clangStdenv.mkDerivation { ... }
        # `pkgs` is the same nixpkgs instance the plugin pins; `llvmPackages`
        # is the exact LLVM family; `clangStdenv` is its clang stdenv.
        inherit (ps) pkgs llvmPackages clangStdenv;

        # `.env` form, for `nix develop`.
        mkDevShell = extra: (ps.mkEnv { inherit extra; projectShell = true; }).env;
        # The raw FHS wrapper derivation. Its `/bin/cc-fuzzer-env` runs the FHS
        # sandbox (runScript = bash), so a command runs inside it via:
        #   <wrapper>/bin/cc-fuzzer-env -c "claude …"
        # This is how you run a command in the sandbox — `nix develop -c <cmd>`
        # does NOT work for a buildFHSEnv (its shellHook execs the wrapper
        # before the -c command runs, dropping you into FHS bash instead).
        mkFhsEnv = extra: ps.mkEnv { inherit extra; projectShell = true; };
        # A `claude` runner for the project flake: forwards its args straight to
        # `claude` inside the composed FHS sandbox, so `nix run .#claude` (plain)
        # and `nix run .#claude -- <args>` both work (nix needs `--` before any
        # `--flag`). cc-fuzzer-env's runScript is bash, so `-c '<inner>' _ "$@"`
        # runs the inner script inside the sandbox with the forwarded args.
        #
        # Campaign-local settings overlay (barebones, opt-in by presence):
        #   * If ./.claude-work/settings.json exists in the launch dir, it's
        #     layered on via `claude --settings <path>`. The system ~/.claude is
        #     left untouched — so the cc-fuzzer plugin, MCP servers, and your
        #     login all carry over; the file only *overlays* campaign settings.
        #   * ANTHROPIC_API_KEY is inherited into the sandbox (buildFHSEnv does
        #     not clear the env), so `export ANTHROPIC_API_KEY=… ; nix run .#claude`
        #     authenticates the campaign instance with that key.
        # Deliberately NO CLAUDE_CONFIG_DIR: a separate config dir is a clean
        # room — it drops MCP servers and orphans the cc-fuzzer plugin itself
        # (plugins live under ~/.claude/plugins) and forces a re-login.
        mkClaudeApp = extra:
          let
            fhs = ps.mkEnv { inherit extra; projectShell = true; };
            inner = ''
              S="$PWD/.claude-work/settings.json"
              if [ -f "$S" ]; then
                exec claude --settings "$S" "$@"
              fi
              exec claude "$@"
            '';
          in ps.pkgs.writeShellScript "ccfuzz-claude" ''
            exec ${fhs}/bin/cc-fuzzer-env -c ${ps.pkgs.lib.escapeShellArg inner} ccfuzz-claude "$@"
          '';
      });

      # `nix run .#dev` — the dev-shell wrapper; `nix run #init` — the pre-claude
      # campaign bootstrap (see initApp). Both under one per-system attrset.
      apps = forAllSystems (system:
        let ps = perSystem system; in {
          dev  = { type = "app"; program = "${ps.mkEnv {}}/bin/cc-fuzzer-env"; };
          init = { type = "app"; program = "${ps.initApp}/bin/cc-fuzzer-init"; };
        });
    };
}
