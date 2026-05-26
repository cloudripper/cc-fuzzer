#!/usr/bin/env bash
# nix-build.sh
#
# Per-harness nix build runner. Reads fuzz/harnesses/<name>/nix/manifest.json,
# emits or refreshes per-variant .nix derivations, runs nix-build for each
# enabled variant, symlinks the store outputs into the harness bundle, and
# appends events to fuzz/state/nix-build-log.jsonl.
#
# Usage:
#   scripts/nix-build.sh <harness-name> [--variant <v>] [--force] [--reconstruct]
#
# Options:
#   --variant <v>     Build only the named variant (fuzzer|coverage|verify|cmplog|symcc)
#   --force           Re-generate .nix files even if they already exist
#   --reconstruct     Rebuild using the last nix-build-log.jsonl entry (e.g. after GC)
#   --no-log          Skip appending to nix-build-log.jsonl (used in validate-state.sh checks)
#
# Exit codes:
#   0 = all requested variants built or already cached
#   1 = one or more variants failed (structured failure already printed)
#   2 = usage / precondition error

set -u

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
. "$SCRIPT_DIR/_lib/path-anchor.sh"
. "$SCRIPT_DIR/_lib/nix-tools.sh"

FUZZ_ROOT="${FUZZ_ROOT:-fuzz}"
STATE_DIR="$FUZZ_ROOT/state"

usage_err() { echo "ERROR: $*" >&2; exit 2; }

HARNESS="${1:-}"; shift || true
[ -n "$HARNESS" ] || usage_err "harness name required"

ONLY_VARIANT=""
FORCE=false
RECONSTRUCT=false
DO_LOG=true

while [ $# -gt 0 ]; do
  case "$1" in
    --variant)    ONLY_VARIANT="${2:?--variant needs a name}"; shift 2 ;;
    --force)      FORCE=true; shift ;;
    --reconstruct) RECONSTRUCT=true; shift ;;
    --no-log)     DO_LOG=false; shift ;;
    *) usage_err "unknown flag '$1'" ;;
  esac
done

HARNESS_DIR="$FUZZ_ROOT/harnesses/$HARNESS"
NIX_DIR="$HARNESS_DIR/nix"
HARNESS_BIN_DIR="$HARNESS_DIR/harness"
MANIFEST="$NIX_DIR/manifest.json"
BUILD_LOG="$STATE_DIR/nix-build-log.jsonl"

[ -d "$HARNESS_DIR" ] || usage_err "harness bundle not found: $HARNESS_DIR"
[ -f "$MANIFEST" ]    || usage_err "manifest not found: $MANIFEST (run /cc-fuzzer:harness first)"

mkdir -p "$HARNESS_BIN_DIR"

# Resolve the nixpkgs path for <nixpkgs> in standalone nix-build calls.
# We want the same nixpkgs that the plugin flake is pinned to, not whatever
# the user has in channels (often nothing inside the FHS sandbox).
NIX_PATH_ARG=""
if command -v nix >/dev/null 2>&1; then
  NIXPKGS_STORE=$(nix eval --raw nixpkgs#path 2>/dev/null || true)
  if [ -n "$NIXPKGS_STORE" ]; then
    NIX_PATH_ARG="nixpkgs=$NIXPKGS_STORE"
  fi
fi

# ---------------------------------------------------------------------------
# Log helper
# ---------------------------------------------------------------------------
log_event() {
  [ "$DO_LOG" = true ] || return 0
  local harness="$1" variant="$2" event="$3" store_path="${4:-}" out_link="${5:-}"
  local drv_hash="${6:-}" duration_ms="${7:-0}" cache_hit="${8:-false}"
  local fallback_id="${9:-null}"
  [ -d "$STATE_DIR" ] || return 0
  python3 -c "
import json, os, datetime, hashlib
log = os.environ['BUILD_LOG']
harness = os.environ['LH']
variant = os.environ['LV']
event   = os.environ['LE']
store_path = os.environ.get('LSP', '')
out_link   = os.environ.get('LOL', '')
drv_hash   = os.environ.get('LDH', '')
duration_ms= int(os.environ.get('LDR', '0') or '0')
cache_hit  = os.environ.get('LCH', 'false') == 'true'
fallback_id= os.environ.get('LFI', 'null')
# ID: count existing lines + 1
n = 0
try:
    with open(log) as f:
        n = sum(1 for l in f if l.strip())
except Exception:
    pass
rec = {'schema':'nix-build/v1','id':f'nb_{n+1:04d}',
       'ts':datetime.datetime.utcnow().strftime('%Y-%m-%dT%H:%M:%SZ'),
       'harness':harness,'variant':variant,'event':event,
       'store_path':store_path or None,'out_link':out_link or None,
       'drv_hash':drv_hash or None,'duration_ms':duration_ms,
       'cache_hit':cache_hit,
       'fallback_record_id':None if fallback_id=='null' else fallback_id}
with open(log, 'a') as f:
    f.write(json.dumps(rec, separators=(',',':')) + '\n')
" BUILD_LOG="$BUILD_LOG" LH="$harness" LV="$variant" LE="$event" LSP="$store_path" \
    LOL="$out_link" LDH="$drv_hash" LDR="$duration_ms" LCH="$cache_hit" LFI="$fallback_id" 2>/dev/null || true
}

# ---------------------------------------------------------------------------
# Generate .nix files from manifest (idempotent; --force regenerates)
# ---------------------------------------------------------------------------
generate_nix_files() {
  python3 - <<'PY'
import json, os, sys

manifest_path = os.environ["MANIFEST"]
nix_dir = os.environ["NIX_DIR"]
force = os.environ.get("FORCE", "false") == "true"
fuzz_root = os.environ.get("FUZZ_ROOT", "fuzz")

try:
    m = json.load(open(manifest_path))
except Exception as e:
    print(f"ERROR: cannot read manifest: {e}", file=sys.stderr)
    sys.exit(1)

harness = m["harness"]
target_sources = [m["target_source"]] + m.get("target_extra_sources", [])
harness_source = m["harness_source"]
cov_main = m["cov_main"]
extra_cflags = m.get("extra_compile_flags", [])
extra_ldflags = m.get("extra_link_flags", [])
extra_pkgconfig = m.get("extra_pkgconfig_modules", [])
mocks = m.get("mocks", [])
variants = m.get("variants", {})

os.makedirs(nix_dir, exist_ok=True)
mocks_dir = os.path.join(nix_dir, "mocks")

def nix_str_list(lst):
    return " ".join(f'"{x}"' for x in lst)

def nix_list(lst):
    return "[ " + " ".join(f'"{x}"' for x in lst) + " ]"

# ---- common.nix ----
common_path = os.path.join(nix_dir, "common.nix")
if not os.path.exists(common_path) or force:
    deps_rel = os.path.relpath(os.path.join(fuzz_root, "nix-deps.nix"), nix_dir)
    common = f"""# common.nix — shared build helper for {harness} nix derivations.
# Generated by nix-build.sh. Safe to edit — set generated_by to "user-edit"
# in manifest.json to prevent regeneration.
{{ pkgs ? import <nixpkgs> {{}}
, targetDeps ? (import {deps_rel})
}}:
let
  lib = pkgs.lib;
  campaignDeps = targetDeps pkgs;
in rec {{
  mkCcFuzzerBinary =
    {{ name
    , sources
    , compiler
    , cflags
    , ldflags ? []
    , extraInputs ? []
    , extraEnv ? {{}}
    , extraPkgconfigModules ? []
    , installAs
    }}: pkgs.clangStdenv.mkDerivation {{
      pname = name;
      version = "campaign";
      srcs = map (s: builtins.path {{ path = s; name = builtins.baseNameOf s; }}) sources;
      dontUnpack = true;
      unpackPhase = ''
        mkdir src
        for f in $srcs; do
          cp -L "$f" src/$(echo "$f" | sed 's|.*-||')
        done
      '';
      nativeBuildInputs = [ pkgs.pkg-config ] ++
        (if compiler == "afl-clang-fast++" then [ pkgs.aflplusplus ]
         else if compiler == "sym++"         then [ pkgs.symcc ]
         else                                     [ pkgs.clang ]);
      buildInputs = campaignDeps ++ extraInputs;
      buildPhase = ''
        runHook preBuild
        ${{lib.toShellVars extraEnv}}
        {compiler} \\
          ${{lib.escapeShellArgs cflags}} \\
          $(pkg-config --cflags {' '.join(extra_pkgconfig)} 2>/dev/null || true) \\
          src/* \\
          $(pkg-config --libs {' '.join(extra_pkgconfig)} 2>/dev/null || true) \\
          ${{lib.escapeShellArgs ldflags}} \\
          -o "${{installAs}}"
        runHook postBuild
      '';
      installPhase = ''
        mkdir -p $out/bin
        cp "${{installAs}}" $out/bin/
      '';
    }};
}}
"""
    open(common_path, "w").write(common)
    print(f"  wrote {common_path}")

def write_variant(name, compiler, cflags, extra_env="{}"):
    path = os.path.join(nix_dir, f"{name}.nix")
    if os.path.exists(path) and not force:
        return
    all_sources = target_sources + [harness_source]
    # coverage and verify also need cov_main
    if name in ("coverage", "verify"):
        all_sources = all_sources + [cov_main]
    src_list = nix_list(all_sources)
    cflags_list = nix_list(cflags + extra_cflags)
    ldflags_list = nix_list(extra_ldflags)
    content = f"""# {name}.nix — {harness} {name} variant derivation.
{{ pkgs ? import <nixpkgs> {{}} }}:
let c = import ./common.nix {{ inherit pkgs; }};
    m = builtins.fromJSON (builtins.readFile ./manifest.json);
in c.mkCcFuzzerBinary {{
  name = "{harness}_{name}";
  sources = {src_list};
  compiler = "{compiler}";
  cflags = {cflags_list};
  ldflags = {ldflags_list};
  extraEnv = {extra_env};
  extraPkgconfigModules = {nix_list(extra_pkgconfig)};
  installAs = "{harness}_fuzzer{'_' + name if name != 'fuzzer' else ''}";
}}
"""
    open(path, "w").write(content)
    print(f"  wrote {path}")

# Fuzzer variant
if variants.get("fuzzer", {}).get("enabled", True):
    san = variants.get("fuzzer", {}).get("sanitizers", ["address","undefined","fuzzer"])
    cflags = ["-g", "-O1", "-fno-omit-frame-pointer"] + [f"-fsanitize={','.join(san)}"]
    write_variant("fuzzer", "clang++", cflags)

# Coverage variant
if variants.get("coverage", {}).get("enabled", True):
    cflags = ["-g", "-O0", "-fprofile-instr-generate", "-fcoverage-mapping"]
    write_variant("coverage", "clang++", cflags)

# Verify variant
if variants.get("verify", {}).get("enabled", True):
    cflags = ["-g", "-O1", "-fno-omit-frame-pointer", "-fsanitize=address,undefined"]
    write_variant("verify", "clang++", cflags)

# Cmplog variant
if variants.get("cmplog", {}).get("enabled", False):
    cflags = ["-g", "-O1", "-fno-omit-frame-pointer"]
    write_variant("cmplog", "afl-clang-fast++", cflags, '{ AFL_LLVM_CMPLOG = "1"; }')

# SymCC variant
if variants.get("symcc", {}).get("enabled", False):
    cflags = ["-g", "-O1"]
    write_variant("symcc", "sym++", cflags)

# Mock derivations
for mock in mocks:
    mname = mock.get("name", "")
    if not mname:
        continue
    os.makedirs(mocks_dir, exist_ok=True)
    mpath = os.path.join(mocks_dir, f"{mname}.nix")
    if os.path.exists(mpath) and not force:
        continue
    src_dir = mock.get("src_dir", "")
    inc_dir = mock.get("include_dir", "")
    mcflags = mock.get("compile_flags", [])
    kind = mock.get("kind", "static-library")
    lib_cmd = "ar rcs" if kind == "static-library" else "clang -shared -o"
    lib_out = f"lib{mname}.a" if kind == "static-library" else f"lib{mname}.so"
    deps_rel = os.path.relpath(os.path.join(fuzz_root, "nix-deps.nix"), mocks_dir)
    content = f"""# mocks/{mname}.nix — {mname} mock {kind} for {harness}.
{{ pkgs ? import <nixpkgs> {{}} }}:
pkgs.clangStdenv.mkDerivation {{
  pname = "{harness}-mock-{mname}";
  version = "campaign";
  srcs = pkgs.lib.filesystem.listFilesRecursive (./. + "/{src_dir}");
  dontUnpack = true;
  nativeBuildInputs = [ pkgs.clang ];
  buildInputs = (import {deps_rel}) pkgs;
  unpackPhase = ''
    mkdir src
    for f in $srcs; do cp -L "$f" src/; done
  '';
  buildPhase = ''
    clang -c -fPIC -I{inc_dir} {' '.join(mcflags)} src/*.c
    {lib_cmd} {lib_out} *.o
  '';
  installPhase = ''
    mkdir -p $out/lib $out/include
    cp {lib_out} $out/lib/
    cp -r {inc_dir}/* $out/include/ 2>/dev/null || true
  '';
}}
"""
    open(mpath, "w").write(content)
    print(f"  wrote {mpath}")

print("GENERATE_OK")
PY
}

# ---------------------------------------------------------------------------
# Build a single variant
# ---------------------------------------------------------------------------
build_variant() {
  local variant="$1"
  local nix_file="$NIX_DIR/${variant}.nix"
  [ -f "$nix_file" ] || { echo "  SKIP $variant: $nix_file not found"; return 0; }

  local out_suffix
  case "$variant" in
    fuzzer)   out_suffix="" ;;
    coverage) out_suffix="_cov" ;;
    verify)   out_suffix="_verify" ;;
    cmplog)   out_suffix="_cmplog" ;;
    symcc)    out_suffix="_symcc" ;;
    *)        out_suffix="_$variant" ;;
  esac

  local harness_name
  harness_name=$(python3 -c "import json; print(json.load(open('$MANIFEST'))['harness'])" 2>/dev/null)
  local binary_name="${harness_name}_fuzzer${out_suffix}"
  local out_link="$HARNESS_BIN_DIR/$binary_name"

  log_event "$HARNESS" "$variant" "attempt_start"

  local t0=$SECONDS
  local store_path=""
  local build_failed=false

  # nix-build to a temp result link, then resolve the store path
  local result_link="$NIX_DIR/result-${variant}"
  local nix_build_args=("$nix_file" "--out-link" "$result_link" "--print-out-paths")
  [ -n "$NIX_PATH_ARG" ] && nix_build_args=("-I" "$NIX_PATH_ARG" "${nix_build_args[@]}")

  echo "  [nix] building $variant..."
  local build_out
  if build_out=$(NIX_PATH="${NIX_PATH_ARG:+$NIX_PATH_ARG}" nix-build "${nix_build_args[@]}" 2>&1); then
    store_path=$(echo "$build_out" | tail -1)
    local was_cached=false
    # If the result link already pointed here, this was a cache hit
    [ -L "$out_link" ] && [ "$(readlink -f "$out_link")" = "$(readlink -f "$result_link/bin/$binary_name" 2>/dev/null)" ] && was_cached=true

    # Find the binary inside the store output
    local store_bin="$store_path/bin/$binary_name"
    if [ ! -x "$store_bin" ]; then
      # Fallback: first executable in store_path/bin/
      store_bin=$(find "$store_path/bin" -maxdepth 1 -type f -executable 2>/dev/null | head -1)
    fi

    if [ -n "$store_bin" ] && [ -x "$store_bin" ]; then
      ln -sfn "$store_bin" "$out_link"
      local drv_hash
      drv_hash=$(basename "$store_path" | cut -c1-8)
      local duration=$(( (SECONDS - t0) * 1000 ))
      log_event "$HARNESS" "$variant" "attempt_ok" "$store_path" "$out_link" "$drv_hash" "$duration" "$was_cached"
      echo "    OK: $out_link -> $store_bin"
    else
      build_failed=true
    fi
  else
    build_failed=true
  fi

  if [ "$build_failed" = true ]; then
    local duration=$(( (SECONDS - t0) * 1000 ))
    log_event "$HARNESS" "$variant" "attempt_fail" "" "" "" "$duration"
    echo "  FAIL: nix-build $variant failed" >&2
    echo "$build_out" >&2
    return 1
  fi
  return 0
}

# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

# Generate .nix files
echo "nix-build: generating .nix files for harness '$HARNESS'..."
RESULT=$(MANIFEST="$MANIFEST" NIX_DIR="$NIX_DIR" FORCE="$FORCE" FUZZ_ROOT="$FUZZ_ROOT" \
         generate_nix_files 2>&1)
echo "$RESULT"
if ! echo "$RESULT" | grep -q "GENERATE_OK"; then
  echo "ERROR: failed to generate .nix files" >&2
  exit 1
fi

# Determine which variants to build
MANIFEST_VARIANTS=$(python3 -c "
import json
m = json.load(open('$MANIFEST'))
enabled = [k for k,v in m.get('variants',{}).items() if isinstance(v,dict) and v.get('enabled',True)]
print(' '.join(enabled))
" 2>/dev/null)

if [ -n "$ONLY_VARIANT" ]; then
  VARIANTS_TO_BUILD="$ONLY_VARIANT"
else
  VARIANTS_TO_BUILD="$MANIFEST_VARIANTS"
fi

FAILED=0
echo "nix-build: building variants: $VARIANTS_TO_BUILD"
for v in $VARIANTS_TO_BUILD; do
  build_variant "$v" || FAILED=$((FAILED + 1))
done

if [ "$FAILED" -eq 0 ]; then
  echo "nix-build: all variants OK for harness '$HARNESS'"
  exit 0
else
  echo "nix-build: $FAILED variant(s) failed for harness '$HARNESS'" >&2
  exit 1
fi
