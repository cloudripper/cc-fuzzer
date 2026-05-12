#!/usr/bin/env bash
# doctor.sh
#
# Diagnoses cc-fuzzer state corruption. Detects every problem pattern we've
# documented in real campaigns:
#   - Recursive fuzz/fuzz/ directories (cwd-inside-fuzz bug)
#   - Multiple fuzzer processes (cwd-mismatch resume)
#   - Modified plugin files (the read-only rule violations)
#   - Dangerous flags in active fuzzer (-ignore_crashes, etc.)
#   - Multiple state/findings.jsonl at different paths
#   - Stale fuzzer.pid pointing at dead PIDs
#   - Stray timestamped files in state/ root (should be in snapshots/)
#   - Legacy fuzz/state/crashes/ path (predates v0.6 layout)
#
# Read-only. Never modifies state. Suggests fixes per problem.
set -u

# Don't path-anchor - we want to inspect from wherever the user is, including
# inside a corrupted tree. We do our own root detection.

# Find project root by walking up
PROJECT_ROOT=""
d="$PWD"
while [ "$d" != "/" ]; do
  if [ -d "$d/fuzz" ] && [ "$(basename "$d")" != "fuzz" ]; then
    PROJECT_ROOT="$d"
    break
  fi
  d=$(dirname "$d")
done

if [ -z "$PROJECT_ROOT" ]; then
  echo "cc-fuzzer:doctor: no fuzz/ directory found in $PWD or parents"
  echo "  not in a cc-fuzzer project"
  exit 0
fi

echo "cc-fuzzer:doctor inspecting $PROJECT_ROOT"
echo ""

PLUGIN_ROOT="${CLAUDE_PLUGIN_ROOT:-$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)}"
ISSUES=0
WARNINGS=0

issue() {
  ISSUES=$((ISSUES + 1))
  echo "❌ ISSUE: $*"
}
warn() {
  WARNINGS=$((WARNINGS + 1))
  echo "⚠️  WARN:  $*"
}
ok() {
  echo "✓  $*"
}

#------------------------------------------------------------------------------
# Check 1: Recursive fuzz/fuzz/ directories
#------------------------------------------------------------------------------
echo "[1/9] Checking for recursive fuzz/ directories..."
if [ -d "$PROJECT_ROOT/fuzz/fuzz" ]; then
  issue "recursive fuzz/fuzz/ exists at $PROJECT_ROOT/fuzz/fuzz/"
  echo "       This is the 'cwd inside fuzz/' bug - a script ran with cwd"
  echo "       inside the fuzz/ tree, creating nested copies."
  echo "       Fix:"
  echo "         1. Ensure no fuzzer is running in the rogue tree:"
  echo "            for pid in \$(pgrep -f fuzz_find_parser); do"
  echo "              cwd=\$(readlink /proc/\$pid/cwd)"
  echo "              case \"\$cwd\" in */fuzz/fuzz/*) kill -KILL \$pid;; esac"
  echo "            done"
  echo "         2. Diff corpus to find unique entries:"
  echo "            (see migration steps in v0.10 release notes)"
  echo "         3. Wipe: rm -rf $PROJECT_ROOT/fuzz/fuzz/"
else
  ok "no recursive fuzz/ trees"
fi
echo ""

#------------------------------------------------------------------------------
# Check 2: Multiple running fuzzers
#------------------------------------------------------------------------------
echo "[2/9] Checking for multiple fuzzer processes..."
PARENTS=()
for pid in $(pgrep -f fuzz_find_parser 2>/dev/null) $(pgrep -f LLVMFuzzer 2>/dev/null); do
  PARENT=$(ps -o ppid= -p "$pid" 2>/dev/null | tr -d ' ')
  [ -z "$PARENT" ] && continue
  if ! ps -p "$PARENT" 2>/dev/null | grep -qE 'fuzz_find_parser|LLVMFuzzer'; then
    PARENTS+=("$pid")
  fi
done
if [ "${#PARENTS[@]}" -le 1 ]; then
  ok "${#PARENTS[@]} top-level fuzzer process(es)"
else
  issue "${#PARENTS[@]} top-level fuzzer processes are running"
  for pid in "${PARENTS[@]}"; do
    CWD=$(readlink /proc/$pid/cwd 2>/dev/null || echo "?")
    echo "         PID $pid cwd=$CWD"
  done
  echo "       Fix: kill all but one. The legitimate fuzzer's cwd should"
  echo "       equal $PROJECT_ROOT (no /fuzz/fuzz/ in the path)."
fi
echo ""

#------------------------------------------------------------------------------
# Check 3: Plugin file integrity
#------------------------------------------------------------------------------
echo "[3/9] Checking plugin file integrity..."
if [ -f "$PLUGIN_ROOT/MANIFEST.md5" ]; then
  DRIFT=$(bash "$PLUGIN_ROOT/scripts/integrity-check.sh" 2>&1 | grep -c '^  - ' || true)
  DRIFT=${DRIFT:-0}
  if [ "$DRIFT" -eq 0 ]; then
    ok "all plugin files match MANIFEST.md5"
  else
    issue "$DRIFT plugin file(s) modified since release"
    echo "       This is the recurring 'agent patches plugin' violation."
    echo "       Run: bash $PLUGIN_ROOT/scripts/integrity-check.sh"
    echo "       Fix: /plugin marketplace update <name> && /plugin install cc-fuzzer@<name>"
  fi
else
  warn "MANIFEST.md5 not present at $PLUGIN_ROOT - cannot verify integrity"
fi
echo ""

#------------------------------------------------------------------------------
# Check 3b: Plugin file permissions (read-only enforcement)
#------------------------------------------------------------------------------
echo "[4/9] Checking plugin file permissions..."
if [ -f "$PLUGIN_ROOT/MANIFEST.md5" ]; then
  if [ -w "$PLUGIN_ROOT/MANIFEST.md5" ]; then
    if [ "${CC_FUZZER_DISABLE_READONLY_LOCK:-0}" = "1" ]; then
      warn "plugin tree is writable (CC_FUZZER_DISABLE_READONLY_LOCK=1 set)"
      echo "       This is intentional for plugin development but allows agents to patch files."
    else
      issue "plugin tree is writable but read-only lock should be enforced"
      echo "       Fix: bash $PLUGIN_ROOT/scripts/enforce-readonly.sh"
    fi
  else
    ok "plugin files are read-only (filesystem-level enforcement active)"
  fi
fi
echo ""

#------------------------------------------------------------------------------
# Check 4: Dangerous flags in active fuzzer command line
#------------------------------------------------------------------------------
echo "[5/9] Checking active fuzzer flags..."
DANGER_FOUND=0
for pid in $(pgrep -f fuzz_find_parser 2>/dev/null); do
  CMDLINE=$(tr '\0' ' ' < /proc/$pid/cmdline 2>/dev/null)
  for flag in '-ignore_crashes=1' '-detect_leaks=0' '-detect_odr_violation=0' '-halt_on_error=0' '-abort_on_error=0'; do
    if echo "$CMDLINE" | grep -q -- "$flag"; then
      issue "PID $pid running with $flag"
      echo "         this suppresses safety checks - kill and restart with canonical run-fuzzer.sh"
      DANGER_FOUND=1
      break
    fi
  done
done
[ "$DANGER_FOUND" -eq 0 ] && ok "no dangerous flags detected in active fuzzer(s)"
echo ""

#------------------------------------------------------------------------------
# Check 5: Multiple state/findings.jsonl
#------------------------------------------------------------------------------
echo "[6/9] Checking for duplicate findings.jsonl..."
COUNT=$(find "$PROJECT_ROOT/fuzz" -maxdepth 5 -name 'findings.jsonl' 2>/dev/null | wc -l)
if [ "$COUNT" -le 1 ]; then
  ok "single findings.jsonl"
else
  issue "$COUNT findings.jsonl files exist"
  find "$PROJECT_ROOT/fuzz" -maxdepth 5 -name 'findings.jsonl' 2>/dev/null \
    | while read f; do
      echo "         $f ($(wc -l < "$f") lines)"
    done
  echo "       Likely caused by recursive fuzz/fuzz/. Pick the canonical one"
  echo "       (usually $PROJECT_ROOT/fuzz/state/findings.jsonl)"
fi
echo ""

#------------------------------------------------------------------------------
# Check 6: Stale fuzzer.pid
#------------------------------------------------------------------------------
echo "[7/9] Checking for stale fuzzer.pid..."
if [ -f "$PROJECT_ROOT/fuzz/state/fuzzer.pid" ]; then
  PID=$(cat "$PROJECT_ROOT/fuzz/state/fuzzer.pid" 2>/dev/null)
  if [ -n "$PID" ] && ! kill -0 "$PID" 2>/dev/null; then
    warn "fuzzer.pid says $PID but that process is dead"
    echo "       Fix: rm $PROJECT_ROOT/fuzz/state/fuzzer.pid"
  else
    ok "fuzzer.pid is valid (PID $PID alive)"
  fi
else
  ok "no fuzzer.pid (no campaign running)"
fi
echo ""

#------------------------------------------------------------------------------
# Check 7: Stray timestamped files in state/ root
#------------------------------------------------------------------------------
echo "[8/9] Checking for stray snapshot files..."
STRAY=$(find "$PROJECT_ROOT/fuzz/state" -maxdepth 1 -type f \( -name 'coverage-*.json' -o -name 'gaps-*.json' -o -name 'concolic-*.json' \) 2>/dev/null | wc -l)
if [ "$STRAY" -eq 0 ]; then
  ok "no stray snapshot files in state/ root"
else
  issue "$STRAY snapshot file(s) in fuzz/state/ root (should be in fuzz/state/snapshots/)"
  echo "       Fix: mv fuzz/state/coverage-*.json fuzz/state/gaps-*.json fuzz/state/concolic-*.json fuzz/state/snapshots/ 2>/dev/null"
fi
echo ""

#------------------------------------------------------------------------------
# Check 8: Legacy fuzz/state/crashes/ path
#------------------------------------------------------------------------------
echo "[9/9] Checking for legacy crash paths..."
if [ -d "$PROJECT_ROOT/fuzz/state/crashes" ]; then
  warn "legacy fuzz/state/crashes/ directory exists"
  COUNT=$(ls "$PROJECT_ROOT/fuzz/state/crashes/" 2>/dev/null | wc -l)
  echo "       $COUNT files in there"
  echo "       Fix: triage/move to fuzz/crashes/{new,known,flaky}/, then rmdir"
else
  ok "no legacy crash paths"
fi
echo ""

#------------------------------------------------------------------------------
# Summary
#------------------------------------------------------------------------------
echo "================================================================"
if [ "$ISSUES" -eq 0 ] && [ "$WARNINGS" -eq 0 ]; then
  echo "  HEALTHY: no issues detected"
elif [ "$ISSUES" -eq 0 ]; then
  echo "  OK with $WARNINGS warning(s)"
else
  echo "  $ISSUES issue(s) and $WARNINGS warning(s) detected"
fi
echo "================================================================"

exit 0
