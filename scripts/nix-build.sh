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

# build_mode: "per_harness" (default — the clang src/* flow below) or
# "monolithic" (a whole-library target built by the project's OWN derivation;
# see build_monolithic + references/nix-monolithic.md).
BUILD_MODE=$(python3 -c "import json;print(json.load(open('$MANIFEST')).get('build_mode','per_harness'))" 2>/dev/null || echo per_harness)

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
# Monolithic build mode
#
# For whole-library targets (e.g. systemd's libsystemd-shared.so) that can't be
# expressed as `clang src/*`. The project's OWN derivation builds the
# instrumented library + harness binaries with cc-fuzzer's pinned toolchain
# (see flake.nix lib exports + references/nix-monolithic.md). The manifest
# declares the derivation, the variant->output-subpath mapping, and any
# instrumented .so to register for coverage:
#
#   { "harness": "<name>", "build_mode": "monolithic",
#     "derivation": { "flake_attr": ".#fuzz-cov" }        // OR {"file":"x.nix","attr":"cov"}
#     "outputs": { "fuzzer": "bin/fuzz-x", "coverage": "bin/fuzz-x", "verify": "bin/fuzz-x" },
#     "coverage_dso": [ "lib/libsystemd-shared-260.so" ] }
#
# We build the derivation ONCE, symlink each declared output into the bundle
# under the conventional name, and UPDATE the (pre-existing) harnesses.json
# record — so the harness must already be registered.
# ---------------------------------------------------------------------------
variant_suffix() {
  case "$1" in
    fuzzer)   echo "" ;;
    coverage) echo "_cov" ;;
    verify)   echo "_verify" ;;
    cmplog)   echo "_cmplog" ;;
    symcc)    echo "_symcc" ;;
    *)        echo "_$1" ;;
  esac
}

build_monolithic() {
  local harness_name
  harness_name=$(python3 -c "import json;print(json.load(open('$MANIFEST'))['harness'])" 2>/dev/null)
  [ -n "$harness_name" ] || { echo "ERROR: manifest missing 'harness'" >&2; return 1; }

  local flake_attr drv_file drv_attr
  flake_attr=$(python3 -c "import json;print((json.load(open('$MANIFEST')).get('derivation') or {}).get('flake_attr',''))" 2>/dev/null)
  drv_file=$(python3 -c "import json;print((json.load(open('$MANIFEST')).get('derivation') or {}).get('file',''))" 2>/dev/null)
  drv_attr=$(python3 -c "import json;print((json.load(open('$MANIFEST')).get('derivation') or {}).get('attr',''))" 2>/dev/null)

  echo "  [nix] building monolithic derivation..."
  local t0=$SECONDS OUT="" build_out="" rc=0
  if [ -n "$flake_attr" ]; then
    build_out=$(nix build "$flake_attr" --no-link --print-out-paths \
                  --extra-experimental-features 'nix-command flakes' 2>&1) || rc=$?
  elif [ -n "$drv_file" ]; then
    local nb=("$drv_file"); [ -n "$drv_attr" ] && nb+=("-A" "$drv_attr"); nb+=("--no-out-link")
    [ -n "$NIX_PATH_ARG" ] && nb=("-I" "$NIX_PATH_ARG" "${nb[@]}")
    build_out=$(nix-build "${nb[@]}" 2>&1) || rc=$?
  else
    echo "ERROR: monolithic manifest needs derivation.flake_attr or derivation.file(+attr)" >&2
    return 1
  fi
  if [ "$rc" -ne 0 ]; then
    log_event "$HARNESS" "monolithic" "attempt_fail" "" "" "" "$(( (SECONDS - t0) * 1000 ))"
    echo "  FAIL: monolithic build failed (fix your project derivation)" >&2
    echo "$build_out" >&2
    return 1
  fi
  OUT=$(echo "$build_out" | tail -1)
  [ -d "$OUT" ] || { echo "ERROR: build produced no store path (got: '$OUT')" >&2; return 1; }
  echo "    built: $OUT"

  local mono_variants
  mono_variants=$(python3 -c "import json;print(' '.join((json.load(open('$MANIFEST')).get('outputs') or {}).keys()))" 2>/dev/null)
  [ -n "$ONLY_VARIANT" ] && mono_variants="$ONLY_VARIANT"

  local fuzzer_link="" coverage_link="" verify_link="" any=0 failed=0
  for v in $mono_variants; do
    local sub; sub=$(python3 -c "import json;print((json.load(open('$MANIFEST')).get('outputs') or {}).get('$v',''))" 2>/dev/null)
    [ -n "$sub" ] || { echo "  SKIP $v: no outputs.$v in manifest"; continue; }
    local store_bin="$OUT/$sub"
    if [ ! -x "$store_bin" ]; then
      echo "  FAIL $v: '$store_bin' not found/executable in build output" >&2; failed=$((failed + 1)); continue
    fi
    local link="$HARNESS_BIN_DIR/${harness_name}_fuzzer$(variant_suffix "$v")"
    ln -sfn "$store_bin" "$link"; any=1
    case "$v" in
      fuzzer)   fuzzer_link="$link" ;;
      coverage) coverage_link="$link" ;;
      verify)   verify_link="$link" ;;
    esac
    log_event "$HARNESS" "$v" "attempt_ok" "$OUT" "$link" "$(basename "$OUT" | cut -c1-8)" "$(( (SECONDS - t0) * 1000 ))" "false"
    echo "    OK: $link -> $store_bin"
  done
  [ "$any" -eq 1 ] || { echo "ERROR: no variant outputs wired (check manifest 'outputs')" >&2; return 1; }
  [ "$failed" -eq 0 ] || { echo "ERROR: $failed declared output(s) missing from build" >&2; return 1; }

  # Resolve coverage_dso subpaths to absolute store paths (skip missing).
  local dso_args=()
  while IFS= read -r dso; do
    [ -n "$dso" ] || continue
    if [ -e "$OUT/$dso" ]; then dso_args+=("$OUT/$dso")
    else echo "  WARN: coverage_dso '$dso' not present in build output — skipping" >&2; fi
  done < <(python3 -c "import json;[print(x) for x in (json.load(open('$MANIFEST')).get('coverage_dso') or [])]" 2>/dev/null)

  # Update the pre-existing harnesses.json record in place.
  HARNESS="$HARNESS" OUT="$OUT" MANIFEST="$MANIFEST" STATE_DIR="$STATE_DIR" \
  FUZZER_LINK="$fuzzer_link" COVERAGE_LINK="$coverage_link" VERIFY_LINK="$verify_link" \
  FLAKE_ATTR="$flake_attr" DRV_FILE="$drv_file" DRV_ATTR="$drv_attr" \
  DSO_LIST="$(printf '%s\n' ${dso_args[@]+"${dso_args[@]}"})" \
  python3 - <<'PY'
import json, os, hashlib, datetime, sys
state = os.environ["STATE_DIR"]; name = os.environ["HARNESS"]
hs_path = os.path.join(state, "harnesses.json")
try:
    hset = json.load(open(hs_path))
except Exception:
    print("ERROR: harnesses.json not found/readable — monolithic mode UPDATES an "
          "existing record; register the harness bundle first", file=sys.stderr); sys.exit(1)
hs = hset.get("harnesses") or []
rec = next((h for h in hs if isinstance(h, dict) and h.get("name") == name), None)
if rec is None:
    print(f"ERROR: no harness named '{name}' in harnesses.json — register the bundle first",
          file=sys.stderr); sys.exit(1)
fz = os.environ.get("FUZZER_LINK", ""); cv = os.environ.get("COVERAGE_LINK", ""); vf = os.environ.get("VERIFY_LINK", "")
if fz: rec["harness_binary"] = fz
rec["verify_binary"] = vf or rec.get("verify_binary")
if cv:
    rec["coverage_binary"] = cv; rec["coverage_tracking"] = True
    rec.pop("coverage_disabled_reason", None)
else:
    rec["coverage_binary"] = None; rec["coverage_tracking"] = False
    rec["coverage_disabled_reason"] = "monolithic build declares no coverage output"
rec["coverage_dso"] = [x for x in os.environ.get("DSO_LIST", "").splitlines() if x.strip()]
rec["build_backend"] = "nix"
man = os.environ["MANIFEST"]
deriv = ({"flake_attr": os.environ["FLAKE_ATTR"]} if os.environ.get("FLAKE_ATTR")
         else {"file": os.environ.get("DRV_FILE", ""), "attr": os.environ.get("DRV_ATTR", "")})
now = datetime.datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ")
rec["nix"] = {"mode": "monolithic", "derivation": deriv, "store_path": os.environ["OUT"],
              "manifest_path": os.path.relpath(man), "manifest_hash": hashlib.sha256(open(man, "rb").read()).hexdigest()[:16],
              "built_at": now}
rec["built_at"] = now
tmp = hs_path + ".tmp"
json.dump(hset, open(tmp, "w"), indent=2); open(tmp, "a").write("\n"); os.replace(tmp, hs_path)
if hs:  # keep the singular mirror in sync (always harnesses[0], per convention)
    hb = os.path.join(state, "harness-built.json")
    try:
        json.dump(hs[0], open(hb + ".tmp", "w"), indent=2); open(hb + ".tmp", "a").write("\n"); os.replace(hb + ".tmp", hb)
    except Exception:
        pass
print("RECORD_OK")
PY
}

# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

# Monolithic targets delegate to the project's own derivation — skip the
# per-harness .nix generation entirely.
if [ "$BUILD_MODE" = "monolithic" ]; then
  echo "nix-build: monolithic mode for harness '$HARNESS'"
  if build_monolithic; then
    echo "nix-build: monolithic OK for harness '$HARNESS'"
    exit 0
  fi
  echo "nix-build: monolithic build failed for harness '$HARNESS'" >&2
  exit 1
fi

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
