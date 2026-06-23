#!/usr/bin/env bash
# preflight.sh
#
# Verifies tool availability and engine compatibility before the orchestrator
# advances the campaign. Writes results to fuzz/state/preflight.json and exits
# non-zero if anything required is broken.
#
# Called by:
#   - fuzz-orchestrator at SessionStart
#   - run-fuzzer.sh before launching the fuzzer
#   - /cc-fuzzer:validate

set -u

# Path anchor - refuses cwd inside fuzz/, refuses recursive fuzz/fuzz/
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
. "$SCRIPT_DIR/_lib/path-anchor.sh"
. "$SCRIPT_DIR/_lib/nix-tools.sh"
FUZZ_ROOT="${FUZZ_ROOT:-fuzz}"
STATE_DIR="$FUZZ_ROOT/state"
mkdir -p "$STATE_DIR"

OUT="$STATE_DIR/preflight.json"
TMP="$STATE_DIR/.preflight.json.tmp"

# Resolve tools. nix_tool consults fuzz/state/nix-env.json first (captured by
# the SessionStart hook), then falls back to PATH. Empty when neither resolves.
CLANG=$(nix_tool clang 2>/dev/null || true)
CLANGPP=$(nix_tool clang++ 2>/dev/null || true)

LLVM_COV=$(nix_tool llvm-cov 2>/dev/null || true)
LLVM_PROFDATA=$(nix_tool llvm-profdata 2>/dev/null || true)
# Host-tools fallback: Debian/Ubuntu/Kali install LLVM userland into
# /usr/lib/llvm-NN/bin/ rather than PATH. Walk highest-version down.
if [ -z "$LLVM_COV" ] || [ -z "$LLVM_PROFDATA" ]; then
  for v in 21 20 19 18 17 16 15 14 13 12 11; do
    [ -z "$LLVM_COV" ]      && [ -x "/usr/lib/llvm-$v/bin/llvm-cov" ]      && LLVM_COV="/usr/lib/llvm-$v/bin/llvm-cov"
    [ -z "$LLVM_PROFDATA" ] && [ -x "/usr/lib/llvm-$v/bin/llvm-profdata" ] && LLVM_PROFDATA="/usr/lib/llvm-$v/bin/llvm-profdata"
  done
fi

ADDR2LINE=$(nix_tool addr2line 2>/dev/null || true)
GDB=$(nix_tool gdb 2>/dev/null || true)
AFL_FUZZ=$(nix_tool afl-fuzz 2>/dev/null || true)
AFL_CC=$(nix_tool afl-clang-fast 2>/dev/null || true)

SYMCC=$(nix_tool symcc 2>/dev/null || true)
SYMPP=$(nix_tool "sym++" 2>/dev/null || true)
SEMGREP=$(nix_tool semgrep 2>/dev/null || true)
Z3=$(nix_tool z3 2>/dev/null || true)

# Probe libFuzzer
LIBFUZZER_AVAILABLE=false
if [ -n "$CLANG" ]; then
  if echo 'int LLVMFuzzerTestOneInput(const unsigned char*d,unsigned long s){return 0;}' \
     | "$CLANG" -x c -fsanitize=fuzzer,address -o /tmp/.cc-fuzzer-probe - 2>/dev/null; then
    LIBFUZZER_AVAILABLE=true
    rm -f /tmp/.cc-fuzzer-probe
  fi
fi

# Coverage instrumentation probe
COVERAGE_INSTRUMENTATION_AVAILABLE=false
if [ -n "$CLANG" ]; then
  if echo 'int main(){return 0;}' \
     | "$CLANG" -x c -fprofile-instr-generate -fcoverage-mapping -o /tmp/.cc-fuzzer-cov-probe - 2>/dev/null; then
    COVERAGE_INSTRUMENTATION_AVAILABLE=true
    rm -f /tmp/.cc-fuzzer-cov-probe
  fi
fi

#------------------------------------------------------------------------------
# Decide overall status
#------------------------------------------------------------------------------
ERRORS=()
WARNINGS=()

[ -n "$CLANG" ]   || ERRORS+=("clang not found")
[ -n "$CLANGPP" ] || ERRORS+=("clang++ not found")
[ "$LIBFUZZER_AVAILABLE" = "true" ] || ERRORS+=("libFuzzer not available - install compiler-rt")

[ -n "$LLVM_COV" ] || ERRORS+=("llvm-cov not in PATH or /usr/lib/llvm-*/bin/ - coverage tracking broken")
[ -n "$LLVM_PROFDATA" ] || ERRORS+=("llvm-profdata not in PATH or /usr/lib/llvm-*/bin/ - coverage tracking broken")
[ "$COVERAGE_INSTRUMENTATION_AVAILABLE" = "true" ] || ERRORS+=("clang doesn't support -fprofile-instr-generate -fcoverage-mapping")

[ -n "$ADDR2LINE" ] || WARNINGS+=("addr2line not found - triage stack symbolization will be limited")
[ -n "$GDB" ] || WARNINGS+=("gdb not found - triage gdb fallback unavailable")

[ -n "$SYMCC" ] || WARNINGS+=("symcc not found - concolic execution unavailable; run scripts/install-symcc.sh")

# v0.13: cmplog requires AFL++ toolchain (afl-clang-fast). Warn loudly when
# missing, since cmplog is the cheapest path to solving direct-compare branches.
[ -n "$AFL_CC" ] || WARNINGS+=("afl-clang-fast not found - cmplog (Redqueen-style I2S) unavailable; install AFL++ to enable")
[ -n "$SEMGREP" ] || WARNINGS+=("semgrep not found - code-review SAST signal (Tier-1) unavailable; prescan falls back to grep heuristics. Install semgrep to enable.")

# Status
STATUS="ok"
[ "${#WARNINGS[@]}" -gt 0 ] && STATUS="warnings"
[ "${#ERRORS[@]}" -gt 0 ] && STATUS="errors"

# Build JSON arrays
ERRORS_JSON=$(printf '%s\n' "${ERRORS[@]}" 2>/dev/null | python3 -c "
import sys, json
print(json.dumps([l.strip() for l in sys.stdin if l.strip()]))
" 2>/dev/null || echo "[]")
WARNINGS_JSON=$(printf '%s\n' "${WARNINGS[@]}" 2>/dev/null | python3 -c "
import sys, json
print(json.dumps([l.strip() for l in sys.stdin if l.strip()]))
" 2>/dev/null || echo "[]")

cat > "$TMP" <<EOF
{
  "schema": "preflight/v1",
  "timestamp": $(date +%s),
  "status": "$STATUS",
  "nix_status": "$([ "${CC_FUZZER_FHS:-}" = "1" ] && echo cc_fuzzer_fhs_active || ([ -n "${IN_NIX_SHELL:-}" ] && echo nix_shell_other || echo host_tools))",
  "tools": {
    "clang": "$CLANG",
    "clang++": "$CLANGPP",
    "llvm_cov": "$LLVM_COV",
    "llvm_profdata": "$LLVM_PROFDATA",
    "addr2line": "$ADDR2LINE",
    "gdb": "$GDB",
    "afl_fuzz": "$AFL_FUZZ",
    "afl_clang_fast": "$AFL_CC",
    "symcc": "$SYMCC",
    "sym++": "$SYMPP",
    "z3": "$Z3",
    "semgrep": "$SEMGREP"
  },
  "capabilities": {
    "libfuzzer_available": $LIBFUZZER_AVAILABLE,
    "coverage_instrumentation_available": $COVERAGE_INSTRUMENTATION_AVAILABLE,
    "afl_available": $([ -n "$AFL_FUZZ" ] && echo true || echo false),
    "cmplog_available": $([ -n "$AFL_CC" ] && [ -n "$AFL_FUZZ" ] && echo true || echo false),
    "symcc_available": $([ -n "$SYMCC" ] && echo true || echo false),
    "sast_available": $([ -n "$SEMGREP" ] && echo true || echo false)
  },
  "errors": $ERRORS_JSON,
  "warnings": $WARNINGS_JSON
}
EOF

mv "$TMP" "$OUT"
echo "$OUT"

# Print summary to stderr for visibility
if [ "$STATUS" = "errors" ]; then
  echo "" >&2
  echo "PREFLIGHT FAILED:" >&2
  for e in "${ERRORS[@]}"; do echo "  ERROR: $e" >&2; done
  for w in "${WARNINGS[@]}"; do echo "  WARN:  $w" >&2; done
  echo "" >&2
  echo "Fix these before running /cc-fuzzer:campaign. Coverage tracking specifically requires:" >&2
  echo "  sudo apt install llvm-18-dev llvm-18-tools clang-18  # or your distro equivalent" >&2
  echo "  ln -sf /usr/lib/llvm-18/bin/llvm-cov ~/.local/bin/" >&2
  echo "  ln -sf /usr/lib/llvm-18/bin/llvm-profdata ~/.local/bin/" >&2
  exit 1
fi

if [ "$STATUS" = "warnings" ]; then
  for w in "${WARNINGS[@]}"; do echo "  WARN: $w" >&2; done
fi

exit 0
