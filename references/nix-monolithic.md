# Monolithic Nix builds — whole-library targets

`/cc-fuzzer:nix-build` has two modes:

- **per-harness** (default) — the manifest lists a few source files and they're
  compiled with the FHS shell's clang (`clang src/*`). Right for a leaf target:
  a parser, a codec, one translation unit + its dependencies.
- **monolithic** — for a whole **instrumented library** (e.g. systemd's
  `libsystemd-shared.so`) that can only be produced by the project's OWN build
  system (meson/cmake/autotools), yielding many harness binaries linked against
  one shared lib. You can't express that as `clang src/*`.

If your target is a whole library and you find yourself wanting to "just run the
project's build," you want monolithic mode.

## The toolchain-pin contract (read this first)

An instrumented `.so` carries an `__llvm_profile_runtime` constructor that runs
before `main()` and **forces the profraw file-format version for every binary
that links it** — regardless of the harness binary's own clang. So if your `.so`
is built with a different LLVM than cc-fuzzer's `llvm-cov` / `llvm-profdata`,
coverage silently produces **zero lines** (the dreaded version-9-vs-10 profraw
mismatch).

The fix: build your derivation with **cc-fuzzer's exact pinned toolchain**,
exported from the plugin flake:

```nix
ccfuzzer.lib.${system}.clangStdenv     # the clang stdenv the shell uses
ccfuzzer.lib.${system}.llvmPackages     # its LLVM family (clang, compiler-rt, …)
ccfuzzer.lib.${system}.pkgs             # the same nixpkgs instance
```

Build the library + harnesses with `clangStdenv` and the instrumented `.so`
links the *same* `libclang_rt.profile` the shell's `llvm-cov` reads. No mismatch.

## Step 1 — declare the build in your project flake

`./flake.nix` already follows cc-fuzzer's nixpkgs. Add a package built with the
pinned stdenv (see `templates/project-flake.nix` for the commented stub):

```nix
packages.${system}.fuzzers =
  let
    stdenv = ccfuzzer.lib.${system}.clangStdenv;   # pinned LLVM — do not substitute
    pkgs   = ccfuzzer.lib.${system}.pkgs;
  in stdenv.mkDerivation {
    name = "my-fuzzers-cov";
    src = ./.;
    nativeBuildInputs = [ pkgs.meson pkgs.ninja pkgs.pkg-config ];
    buildInputs = (import ./fuzz/nix-deps.nix) pkgs;
    # Configure the project's build for coverage + sanitizers, build the fuzz
    # targets, and install:
    #   $out/bin/<harness binaries>
    #   $out/lib/<instrumented shared lib>
    # (exact flags are your project's — e.g. meson -Db_sanitize=address,undefined
    #  plus -fprofile-instr-generate -fcoverage-mapping on the cov build.)
  };
```

Build it once by hand to confirm it works: `nix build .#fuzzers`.

## Step 2 — write a monolithic harness manifest

For each harness, write `fuzz/harnesses/<name>/nix/manifest.json`:

```jsonc
{
  "schema": "nix-build-manifest/v1",
  "harness": "<name>",
  "build_mode": "monolithic",
  "derivation": { "flake_attr": ".#fuzzers" },   // OR { "file": "systemd-fuzz.nix", "attr": "cov" }
  "outputs": {                                    // out-subpaths within the build result
    "fuzzer":   "bin/fuzz-<name>",
    "coverage": "bin/fuzz-<name>",                // same binary if the derivation is cov-instrumented
    "verify":   "bin/fuzz-<name>"
  },
  "coverage_dso": [ "lib/libsystemd-shared-260.so" ]   // instrumented .so to register for coverage
}
```

- `derivation` — `flake_attr` (built via `nix build`) **or** `file`+`attr`
  (built via `nix-build <file> -A <attr>`, with cc-fuzzer's pinned nixpkgs on
  `-I`).
- `outputs` — which build-result subpaths back the fuzzer/coverage/verify
  variants. Omit a variant to skip it. Each is symlinked into the bundle under
  the conventional name (`<harness>_fuzzer`, `_cov`, `_verify`).
- `coverage_dso` — subpaths of instrumented `.so`s; resolved to absolute store
  paths and recorded so `snapshot-coverage.sh` feeds them to `llvm-cov` as
  `-object`. **Omit and you get zero coverage** even with a correct build.

The harness must already be **registered** in `harnesses.json` (monolithic mode
*updates* the existing record). harness-writer registers the bundle; or add it
to `fuzz-config.json:harnesses[]` + `harnesses.json` first.

## Step 3 — build

```
/cc-fuzzer:nix-build --harness <name>
```

This builds the derivation once, symlinks each `outputs` binary into the bundle,
resolves `coverage_dso`, and updates the harness record (`build_backend: "nix"`,
binary paths, `coverage_dso`, and a `nix.mode: "monolithic"` sub-object).

## Preconditions (relaxed vs per-harness)

- **`CC_FUZZER_FHS=1` is NOT required** for a monolithic build — it delegates to
  `nix build`, which only needs `nix` on PATH. (Runtime + coverage still want
  the FHS shell so the campaign's `llvm-cov`/`llvm-profdata` match the `.so`.)
- The per-harness `harness_source` / `cov_main` / `target_source` fields are
  **not** required — the derivation owns the build.

## Why not just point at the project's own derivation as-is?

Because a derivation built with a *different* LLVM than the campaign's coverage
tools breaks coverage (see the toolchain-pin contract). Pinning via
`ccfuzzer.lib.${system}.clangStdenv` is the whole point — it's what keeps the
instrumented `.so`, the harness binaries, and `llvm-cov` on one LLVM.
