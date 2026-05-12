#!/usr/bin/env bash
# install-symcc.sh
#
# Installs SymCC from source. Handles LLVM version detection across
# Ubuntu/Debian/Kali/Fedora/Arch. SymCC supports LLVM 8 through 18; this script
# picks the highest installed compatible version, or installs LLVM 18 from
# apt.llvm.org if none is present.
#
# Total time: ~15-30 minutes depending on machine.

set -euo pipefail

#------------------------------------------------------------------------------
# v0.14: nix is the recommended path
#------------------------------------------------------------------------------
# This script is the host-tools fallback. It still works, but for
# reproducibility you almost certainly want the pinned SymCC from the plugin's
# flake.nix instead of one we built from source against your host's libstdc++.
#
# We can't auto-redirect because the user may not have nix installed and may
# not want to install it. So we print the recommendation, give them a moment
# to bail, and proceed if they don't.
if [ "${CC_FUZZER_FHS:-}" = "1" ]; then
  cat <<'EOF'
==============================================================================
 install-symcc.sh: you are inside the cc-fuzzer dev shell already
==============================================================================
 SymCC is already provided by the flake. You should not run this script
 from inside the dev shell - it's wasted work and may fight the pinned
 toolchain.

 Verify SymCC is on PATH:
   which symcc sym++

 If something looks wrong, exit Claude, exit the dev shell, and re-enter
 with `nix develop ${CLAUDE_PLUGIN_ROOT}` to refresh the env.
==============================================================================
EOF
  exit 0
fi

# Already on PATH? Skip everything (including the 5-second nix recommendation
# banner below — no point urging nix at a user who already has symcc).
if command -v symcc >/dev/null 2>&1 && command -v sym++ >/dev/null 2>&1; then
  echo "SymCC already installed: $(command -v symcc)"
  exit 0
fi

#------------------------------------------------------------------------------
# /nix/store fallback. Same pattern as run-concolic.sh and build-symcc-target.sh.
# Catches the case where the user previously entered `nix develop` (so nix
# built SymCC into /nix/store), then exited the dev shell — they have a
# Nix-built SymCC available, just not on PATH. Better than a 15-30 minute
# host rebuild.
#
# The downstream scripts (build-symcc-target.sh, run-concolic.sh) do their
# own /nix/store resolution, so we do NOT need to export PATH or touch
# ~/.bashrc to make this work for the campaign. Reporting the find is enough.
#------------------------------------------------------------------------------
_find_nix_tool() {
  find /nix/store -maxdepth 4 -type f -executable -name "$1" 2>/dev/null | head -1
}
NIX_SYMCC=$(_find_nix_tool symcc)
NIX_SYMPP=$(_find_nix_tool "sym++")
if [ -n "$NIX_SYMCC" ] && [ -n "$NIX_SYMPP" ]; then
  cat <<EOF
==============================================================================
 install-symcc.sh: found Nix-built SymCC in /nix/store — skipping host build
==============================================================================
 symcc: $NIX_SYMCC
 sym++: $NIX_SYMPP

 The downstream scripts (build-symcc-target.sh, run-concolic.sh) have their
 own /nix/store fallback and will find these automatically — no PATH setup
 needed. The 15-30 minute host build is skipped.

 If you want symcc on PATH in your interactive shell too, re-enter the
 cc-fuzzer dev shell:

   nix develop \$CLAUDE_PLUGIN_ROOT

 Not writing to ~/.bashrc — Nix garbage-collection would eventually remove
 these store paths and silently break PATH. The dev shell resolves them
 fresh each invocation and is the correct durable answer.
==============================================================================
EOF
  exit 0
fi

cat <<'EOF'
==============================================================================
 install-symcc.sh: building SymCC from source on your host
==============================================================================
 RECOMMENDED ALTERNATIVE: use the cc-fuzzer dev shell instead. It ships a
 pinned, pre-built SymCC plus a matching clang and compiler-rt, with no
 build time and full reproducibility:

   nix develop $CLAUDE_PLUGIN_ROOT
   claude

 This script is the host-tools fallback. It will:
   - take 15-30 minutes
   - require sudo for LLVM dev packages
   - produce a SymCC linked against YOUR host's libstdc++, which means
     SymCC binaries built today may break after a libstdc++ upgrade
   - leave a SymCC install at $HOME/.local/symcc that you'll need to
     uninstall manually if you ever switch to the nix path

 Continuing in 5 seconds. Press Ctrl-C to abort and switch to nix.
==============================================================================
EOF
sleep 5
echo ""

INSTALL_DIR="${SYMCC_INSTALL_DIR:-$HOME/.local/symcc}"
BUILD_DIR="$INSTALL_DIR/build"
SRC_DIR="$INSTALL_DIR/src"
SYMCC_MAX_LLVM=18  # Highest LLVM major version SymCC supports

echo "Installing SymCC to $INSTALL_DIR"
echo ""

#------------------------------------------------------------------------------
# Step 1: Detect or install a compatible LLVM (versions 11-18 work cleanly)
#------------------------------------------------------------------------------

find_compatible_llvm() {
  # Returns "VERSION:CMAKE_DIR" of the highest installed compatible LLVM, or empty.
  for v in 18 17 16 15 14 13 12 11; do
    for candidate in \
      "/usr/lib/llvm-$v/lib/cmake/llvm" \
      "/usr/lib/llvm-$v/cmake" \
      "/usr/lib/cmake/llvm-$v" \
      "/usr/local/lib/llvm-$v/lib/cmake/llvm"; do
      if [ -d "$candidate" ]; then
        if command -v "clang-$v" >/dev/null 2>&1 || [ -x "/usr/lib/llvm-$v/bin/clang" ]; then
          echo "$v:$candidate"
          return 0
        fi
      fi
    done
  done
  return 1
}

LLVM_INFO=$(find_compatible_llvm || true)

if [ -z "$LLVM_INFO" ]; then
  echo "[1/5] No compatible LLVM (11-${SYMCC_MAX_LLVM}) found. Installing LLVM ${SYMCC_MAX_LLVM} from apt.llvm.org..."

  if ! command -v apt-get >/dev/null 2>&1; then
    echo "ERROR: this auto-install path needs apt. Manual install required:" >&2
    echo "  Install any of clang-11 through clang-${SYMCC_MAX_LLVM}, with libz3-dev" >&2
    echo "  Then re-run this script." >&2
    exit 1
  fi

  echo "  Fetching LLVM apt-installer script..."
  TMP_INSTALLER=$(mktemp)
  if ! curl -fsSL https://apt.llvm.org/llvm.sh -o "$TMP_INSTALLER"; then
    echo "ERROR: could not download https://apt.llvm.org/llvm.sh" >&2
    rm -f "$TMP_INSTALLER"
    exit 1
  fi
  chmod +x "$TMP_INSTALLER"
  echo "  Running LLVM installer (will prompt for sudo)..."
  sudo "$TMP_INSTALLER" "$SYMCC_MAX_LLVM"
  rm -f "$TMP_INSTALLER"

  echo "  Installing llvm-${SYMCC_MAX_LLVM}-dev and llvm-${SYMCC_MAX_LLVM}-tools..."
  sudo apt-get install -y "llvm-${SYMCC_MAX_LLVM}-dev" "llvm-${SYMCC_MAX_LLVM}-tools"

  LLVM_INFO=$(find_compatible_llvm || true)
  if [ -z "$LLVM_INFO" ]; then
    echo "ERROR: LLVM install reported success but cmake dir not found." >&2
    exit 1
  fi
fi

LLVM_VERSION="${LLVM_INFO%%:*}"
LLVM_DIR="${LLVM_INFO#*:}"
echo "  Using LLVM $LLVM_VERSION at $LLVM_DIR"

#------------------------------------------------------------------------------
# Step 2: Build dependencies
#------------------------------------------------------------------------------
echo "[2/5] Installing build dependencies..."
if command -v apt-get >/dev/null 2>&1; then
  sudo apt-get install -y \
    build-essential cmake git ninja-build \
    libz3-dev z3 \
    python3 python3-pip \
    zlib1g-dev
elif command -v dnf >/dev/null 2>&1; then
  sudo dnf install -y \
    gcc gcc-c++ cmake git ninja-build \
    z3-devel z3 \
    python3 python3-pip \
    zlib-devel
elif command -v pacman >/dev/null 2>&1; then
  sudo pacman -S --needed --noconfirm \
    base-devel cmake git ninja \
    z3 \
    python python-pip \
    zlib
else
  echo "WARN: unrecognized package manager. Ensure these are installed:"
  echo "  build-essential cmake git ninja-build libz3-dev"
fi

#------------------------------------------------------------------------------
# Step 3: Clone SymCC
#------------------------------------------------------------------------------
echo "[3/5] Cloning SymCC..."
mkdir -p "$INSTALL_DIR"
if [ ! -d "$SRC_DIR" ]; then
  git clone --depth 1 --recurse-submodules \
    https://github.com/eurecom-s3/symcc.git "$SRC_DIR"
else
  echo "  source dir exists, pulling latest"
  (cd "$SRC_DIR" && git pull --recurse-submodules) || true
fi

#------------------------------------------------------------------------------
# Step 4: Build SymCC with the detected LLVM
#------------------------------------------------------------------------------
echo "[4/5] Building SymCC against LLVM $LLVM_VERSION..."
mkdir -p "$BUILD_DIR"
cd "$BUILD_DIR"

cmake -G Ninja \
  -DQSYM_BACKEND=OFF \
  -DCMAKE_BUILD_TYPE=Release \
  -DZ3_TRUST_SYSTEM_VERSION=on \
  -DLLVM_DIR="$LLVM_DIR" \
  "$SRC_DIR"

ninja -j"$(nproc)"

#------------------------------------------------------------------------------
# Step 5: Smoke test + PATH setup
#------------------------------------------------------------------------------
echo "[5/5] Smoke test and PATH setup..."

cat > /tmp/symcc-test.c <<'EOF'
#include <stdio.h>
#include <stdint.h>
int main(int argc, char* argv[]) {
  uint8_t buf[4];
  if (fread(buf, 1, 4, stdin) != 4) return 0;
  if (buf[0]=='A' && buf[1]=='B' && buf[2]=='C' && buf[3]=='D') return 1;
  return 0;
}
EOF

if "$BUILD_DIR/symcc" -O0 /tmp/symcc-test.c -o /tmp/symcc-test 2>&1 | tail -20; then
  if [ -x /tmp/symcc-test ]; then
    echo "  smoke test compiled successfully"
  else
    echo "  WARN: smoke test compiled but produced no binary; SymCC may still work"
  fi
else
  echo "  ERROR: smoke test failed to compile" >&2
  echo "  Check $BUILD_DIR/symcc and the LLVM $LLVM_VERSION install." >&2
fi
rm -f /tmp/symcc-test /tmp/symcc-test.c

PATH_LINE="export PATH=\"$BUILD_DIR:\$PATH\""
SHELL_RC=""
if [ -n "${ZSH_VERSION:-}" ] || [[ "${SHELL:-}" == */zsh ]]; then
  SHELL_RC="$HOME/.zshrc"
elif [ -f "$HOME/.bashrc" ]; then
  SHELL_RC="$HOME/.bashrc"
fi

if [ -n "$SHELL_RC" ] && ! grep -qF "$BUILD_DIR" "$SHELL_RC" 2>/dev/null; then
  {
    echo ""
    echo "# Added by cc-fuzzer install-symcc.sh"
    echo "$PATH_LINE"
  } >> "$SHELL_RC"
  echo "  added to $SHELL_RC"
fi

echo ""
echo "=========================================="
echo "SUCCESS. SymCC installed at $BUILD_DIR"
echo "Built against LLVM $LLVM_VERSION."
echo ""
echo "To use in this shell:"
echo "  export PATH=\"$BUILD_DIR:\$PATH\""
echo ""
echo "Or open a new shell."
echo "=========================================="
