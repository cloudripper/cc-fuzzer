#!/usr/bin/env bash
# capture-nix-env.sh
#
# Snapshots the active Nix dev-shell environment into fuzz/state/nix-env.json
# (schema nix-env/v1). Lets agents/scripts resolve tools by absolute path
# without per-call /nix/store scans.
#
# Tool list is CURATED: adding a tool to flake.nix is not enough; if cc-fuzzer
# scripts will probe it, append its binary name to TOOLS_LIST below.
#
# Invocation:
#   - Auto: env-check.sh SessionStart hook fires this on every session start.
#   - Manual: bash scripts/capture-nix-env.sh
#
# Exit codes:
#   0  snapshot written (or silently skipped because no fuzz/ in any parent)
#   2  invalid PROJECT_ROOT override (when PROJECT_ROOT is set but invalid)
#
# Output (stdout): absolute path of the snapshot file written, or empty when
# no fuzz/ project is in scope.

set -u

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# Resolve project root without using path-anchor.sh — capture is invoked at
# session start, sometimes from arbitrary cwds, and we don't want to abort
# the SessionStart hook just because the user isn't inside a fuzz project.
if [ -n "${PROJECT_ROOT:-}" ]; then
  if [ ! -d "$PROJECT_ROOT/fuzz" ]; then
    echo "ERROR: PROJECT_ROOT=$PROJECT_ROOT has no fuzz/ subdirectory" >&2
    exit 2
  fi
else
  d="$PWD"
  PROJECT_ROOT=""
  while [ "$d" != "/" ]; do
    if [ -d "$d/fuzz" ] && [ "$(basename "$d")" != "fuzz" ]; then
      PROJECT_ROOT="$d"
      break
    fi
    d=$(dirname "$d")
  done
fi

if [ -z "$PROJECT_ROOT" ] || [ ! -d "$PROJECT_ROOT/fuzz" ]; then
  # No fuzz project in scope. Silent no-op so session start isn't noisy.
  exit 0
fi

STATE_DIR="${FUZZ_STATE_DIR:-$PROJECT_ROOT/fuzz/state}"
mkdir -p "$STATE_DIR"

# Curated tool list. Keep alphabetized within each group. Mirrors what
# cc-fuzzer scripts probe — extending the flake without adding here means
# the new tool won't appear in nix-env.json (but PATH fallback still works).
TOOLS_LIST=$(cat <<'EOL'
clang
clang++
gcc
g++
llvm-cov
llvm-profdata
llvm-symbolizer
opt
llc
afl-fuzz
afl-clang-fast
afl-clang-fast++
afl-clang-lto
afl-clang-lto++
afl-cmin
afl-tmin
afl-showmap
afl-whatsup
symcc
sym++
z3
gdb
addr2line
strings
nm
objdump
readelf
strace
make
cmake
ninja
pkg-config
autoconf
automake
libtool
python3
jq
rg
fd
bat
tree
EOL
)

OUT_FILE="$STATE_DIR/nix-env.json"

# Python writes the full JSON snapshot in one shot. All inputs travel via
# environment to avoid bash-quoting JSON-escape hazards.
TOOLS_LIST="$TOOLS_LIST" \
STATE_DIR="$STATE_DIR" \
OUT_FILE="$OUT_FILE" \
python3 - <<'PY'
import json, os, shutil, time

out_file = os.environ["OUT_FILE"]

tools = {}
for name in os.environ["TOOLS_LIST"].splitlines():
    name = name.strip()
    if not name:
        continue
    tools[name] = shutil.which(name) or ""

env_keys = [
    "PKG_CONFIG_PATH",
    "LD_LIBRARY_PATH",
    "CMAKE_PREFIX_PATH",
    "C_INCLUDE_PATH",
    "CPLUS_INCLUDE_PATH",
    "NIX_LDFLAGS",
    "NIX_CFLAGS_COMPILE",
]
env = {k: os.environ.get(k, "") for k in env_keys}

snapshot = {
    "schema": "nix-env/v1",
    "captured_at": int(time.time()),
    "in_nix_shell": bool(os.environ.get("IN_NIX_SHELL", "")),
    "cc_fuzzer_fhs": os.environ.get("CC_FUZZER_FHS", "") == "1",
    "flake_rev": os.environ.get("CC_FUZZER_FLAKE_REV", "unknown"),
    "path": os.environ.get("PATH", ""),
    "tools": tools,
    "env": env,
}

with open(out_file, "w") as f:
    json.dump(snapshot, f, indent=2)
    f.write("\n")

print(out_file)
PY
