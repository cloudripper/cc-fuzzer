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

# Resolve the fuzz tree and state dir the SAME way the rest of the toolchain
# does (_lib/path-anchor.sh sets FUZZ_ROOT=$PROJECT_ROOT/fuzz; scripts then use
# STATE_DIR="${FUZZ_STATE_DIR:-$FUZZ_ROOT/state}"). doctor can't source
# path-anchor — it must inspect corrupted/recursive trees that path-anchor
# refuses to enter — so we mirror that resolution locally. A relative
# FUZZ_STATE_DIR resolves against PROJECT_ROOT (path-anchor achieves this by
# cd'ing to PROJECT_ROOT; doctor doesn't cd, so resolve it explicitly).
FUZZ_ROOT="$PROJECT_ROOT/fuzz"
if [ -n "${FUZZ_STATE_DIR:-}" ]; then
  case "$FUZZ_STATE_DIR" in
    /*) STATE_DIR="$FUZZ_STATE_DIR" ;;
    *)  STATE_DIR="$PROJECT_ROOT/$FUZZ_STATE_DIR" ;;
  esac
else
  STATE_DIR="$FUZZ_ROOT/state"
fi

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
echo "[1/12] Checking for recursive fuzz/ directories..."
if [ -d "$FUZZ_ROOT/fuzz" ]; then
  issue "recursive fuzz/fuzz/ exists at $FUZZ_ROOT/fuzz/"
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
  echo "         3. Wipe: rm -rf $FUZZ_ROOT/fuzz/"
else
  ok "no recursive fuzz/ trees"
fi
echo ""

#------------------------------------------------------------------------------
# Check 2: Multiple running fuzzers
#------------------------------------------------------------------------------
echo "[2/12] Checking for multiple fuzzer processes..."
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
echo "[3/12] Checking plugin file integrity..."
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
# Check 3a: STATE_SCHEMA.md <-> enums.py drift (human doc vs machine SSOT)
#------------------------------------------------------------------------------
echo "Checking STATE_SCHEMA.md enum lists against enums.py (SSOT)..."
if [ -f "$PLUGIN_ROOT/scripts/_lib/enums.py" ] && [ -f "$PLUGIN_ROOT/STATE_SCHEMA.md" ]; then
  DRIFT_OUT=$(python3 "$PLUGIN_ROOT/scripts/_lib/enums.py" doc-drift "$PLUGIN_ROOT/STATE_SCHEMA.md" 2>&1)
  if [ $? -eq 0 ]; then
    ok "documented enum lists match enums.py"
  else
    issue "STATE_SCHEMA.md enum list(s) disagree with enums.py (the machine SSOT)"
    while IFS= read -r line; do [ -n "$line" ] && echo "       $line"; done <<< "$DRIFT_OUT"
    echo "       Fix: edit the enum in scripts/_lib/enums.py AND its mirror list in STATE_SCHEMA.md."
  fi
else
  warn "enums.py or STATE_SCHEMA.md missing - cannot check enum drift"
fi
echo ""

#------------------------------------------------------------------------------
# Check 3b: Plugin file permissions (read-only enforcement)
#------------------------------------------------------------------------------
echo "[4/12] Checking plugin file permissions..."
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
echo "[5/12] Checking active fuzzer flags..."
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
echo "[6/12] Checking for duplicate findings.jsonl..."
COUNT=$(find "$FUZZ_ROOT" -maxdepth 5 -name 'findings.jsonl' 2>/dev/null | wc -l)
if [ "$COUNT" -le 1 ]; then
  ok "single findings.jsonl"
else
  issue "$COUNT findings.jsonl files exist"
  find "$FUZZ_ROOT" -maxdepth 5 -name 'findings.jsonl' 2>/dev/null \
    | while read f; do
      echo "         $f ($(wc -l < "$f") lines)"
    done
  echo "       Likely caused by recursive fuzz/fuzz/. Pick the canonical one"
  echo "       (usually $STATE_DIR/findings.jsonl)"
fi
echo ""

#------------------------------------------------------------------------------
# Check 6: Stale fuzzer.pid
#------------------------------------------------------------------------------
echo "[7/12] Checking for stale fuzzer.pid..."
if [ -f "$STATE_DIR/fuzzer.pid" ]; then
  PID=$(cat "$STATE_DIR/fuzzer.pid" 2>/dev/null)
  if [ -n "$PID" ] && ! kill -0 "$PID" 2>/dev/null; then
    warn "fuzzer.pid says $PID but that process is dead"
    echo "       Fix: rm $STATE_DIR/fuzzer.pid"
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
echo "[8/12] Checking for stray snapshot files..."
STRAY=$(find "$STATE_DIR" -maxdepth 1 -type f \( -name 'coverage-*.json' -o -name 'gaps-*.json' -o -name 'concolic-*.json' \) 2>/dev/null | wc -l)
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
echo "[9/12] Checking for legacy crash paths..."
if [ -d "$STATE_DIR/crashes" ]; then
  warn "legacy fuzz/state/crashes/ directory exists"
  COUNT=$(ls "$STATE_DIR/crashes/" 2>/dev/null | wc -l)
  echo "       $COUNT files in there"
  echo "       Fix: triage/move to fuzz/crashes/{new,known,flaky}/, then rmdir"
else
  ok "no legacy crash paths"
fi
echo ""

#------------------------------------------------------------------------------
# Check 9: Nix tool inventory (v0.18)
#------------------------------------------------------------------------------
echo "[10/12] Checking Nix tool inventory..."
NIX_ENV_FILE="$STATE_DIR/nix-env.json"
if [ -f "$NIX_ENV_FILE" ]; then
  NIX_ENV_AGE=$(python3 -c "
import json, time
try:
    d = json.load(open('$NIX_ENV_FILE'))
    age = int(time.time()) - int(d.get('captured_at', 0))
    fhs = d.get('cc_fuzzer_fhs', False)
    rev = d.get('flake_rev', 'unknown')
    tools = d.get('tools', {})
    present = sum(1 for v in tools.values() if v)
    missing = sum(1 for v in tools.values() if not v)
    crit = ['clang', 'symcc', 'afl-fuzz', 'llvm-cov', 'llvm-profdata']
    crit_missing = [k for k in crit if not tools.get(k)]
    print(f'{age}|{fhs}|{rev}|{present}|{missing}|{\",\".join(crit_missing)}')
except Exception as e:
    print(f'ERR|||||{e}')
" 2>/dev/null)
  IFS='|' read -r AGE FHS REV PRESENT MISSING CRIT_MISSING <<< "$NIX_ENV_AGE"
  if [ "$AGE" = "ERR" ]; then
    issue "nix-env.json present but unreadable"
  else
    if [ "$FHS" = "True" ]; then
      ok "cc-fuzzer Nix dev shell active (flake rev: $REV)"
    else
      warn "not inside cc-fuzzer Nix dev shell"
      echo "       Fix: exit Claude and run: nix develop \$CLAUDE_PLUGIN_ROOT && claude"
    fi
    echo "       captured ${AGE}s ago — $PRESENT tool(s) resolved, $MISSING missing"
    if [ -n "$CRIT_MISSING" ]; then
      issue "critical tools missing from environment: $CRIT_MISSING"
      echo "       These block harness builds / coverage / concolic. Run 'nix develop' before claude."
    fi
  fi
else
  warn "no nix-env.json (will be captured on next session start)"
  echo "       Fix: bash $PLUGIN_ROOT/scripts/capture-nix-env.sh"
fi
echo ""

#------------------------------------------------------------------------------
# Check 11: Nix build backend consistency (v0.22)
# Verifies that every nix-committed harness has its store paths intact and that
# the declared variant symlinks actually point into /nix/store.
#------------------------------------------------------------------------------
echo "[11/12] Checking nix build backend consistency..."
HS_FILE="$STATE_DIR/harnesses.json"
if [ -f "$HS_FILE" ]; then
  _NIX_CHECK=$(HS_FILE="$HS_FILE" python3 - <<'PY'
import json, os, sys
hs_file = os.environ.get("HS_FILE","")
ok = True
try:
    doc = json.load(open(hs_file))
except Exception:
    sys.exit(0)
for h in doc.get("harnesses",[]):
    if isinstance(h,dict) and h.get("build_backend")=="nix":
        ok=False; break
if ok:
    print("no_nix_harnesses")
PY
)
  if [ "$_NIX_CHECK" = "no_nix_harnesses" ]; then
    ok "no nix-committed harnesses in this campaign"
  else
    HS_FILE="$HS_FILE" python3 - <<'PY'
import json, os, sys

hs_file = os.environ.get("HS_FILE","")
issues=0; warnings=0
try:
    doc = json.load(open(hs_file))
except Exception as e:
    print(f"  WARN: cannot read harnesses.json: {e}"); sys.exit(0)
for h in doc.get("harnesses",[]):
    if not isinstance(h,dict): continue
    name=h.get("name","?"); backend=h.get("build_backend","legacy")
    if backend!="nix": continue
    nix_sub=h.get("nix") or {}
    for variant,vinfo in (nix_sub.get("variants") or {}).items():
        if not isinstance(vinfo,dict): continue
        sp=vinfo.get("store_path",""); ol=vinfo.get("out_link","")
        if sp and not os.path.exists(sp):
            print(f"  ISSUE: harness '{name}' variant '{variant}' store path GC'd: {sp}")
            print(f"         Fix: /cc-fuzzer:nix-build --harness {name} --variant {variant} --force")
            issues+=1
        elif ol and not os.path.exists(ol):
            print(f"  WARN:  harness '{name}' variant '{variant}' symlink missing: {ol}")
            print(f"         Fix: /cc-fuzzer:nix-build --harness {name}")
            warnings+=1
    mp=nix_sub.get("manifest_path","")
    if mp and not os.path.isfile(mp):
        print(f"  ISSUE: harness '{name}' manifest.json missing at {mp}")
        print(f"         Fix: /cc-fuzzer:harness --harness {name} to regenerate")
        issues+=1
if issues==0 and warnings==0:
    print("  ok: all nix store paths intact")
    print("  tip: run /cc-fuzzer:nix-cleanup after campaign to free store space")
PY
  fi
fi
echo ""

#------------------------------------------------------------------------------
# Check 12: Nix environment issues (v0.22)
# Surfaces severity=error issues from nix-environment-issues.json.
#------------------------------------------------------------------------------
echo "[12/12] Checking nix environment issues..."
NIX_ISSUES_FILE="$STATE_DIR/nix-environment-issues.json"
if [ -f "$NIX_ISSUES_FILE" ]; then
  python3 - <<'PY'
import json, os, sys

path = os.environ.get("NIX_ISSUES_FILE","")
try:
    doc = json.load(open(path))
except Exception:
    sys.exit(0)
issues = doc.get("issues") or []
err_count = sum(1 for i in issues if isinstance(i,dict) and i.get("severity")=="error")
warn_count = sum(1 for i in issues if isinstance(i,dict) and i.get("severity")=="warning")
if not issues:
    print("  ok: no nix environment issues")
    sys.exit(0)
for iss in issues:
    if not isinstance(iss,dict): continue
    sev = iss.get("severity","warning")
    code = iss.get("code","?")
    summary = iss.get("summary","")
    hint = (iss.get("remediation") or {}).get("human_message","")
    tag = "ISSUE" if sev=="error" else "WARN"
    print(f"  {tag}: ({code}) {summary}")
    if hint:
        print(f"         Fix: {hint}")
PY
  NIX_ISSUES_FILE="$NIX_ISSUES_FILE" python3 -c "
import json,sys,os
doc=json.load(open(os.environ['NIX_ISSUES_FILE']))
errs=[i for i in doc.get('issues',[]) if isinstance(i,dict) and i.get('severity')=='error']
warns=[i for i in doc.get('issues',[]) if isinstance(i,dict) and i.get('severity')=='warning']
sys.exit(1 if errs else (2 if warns else 0))
" 2>/dev/null
  _EC=$?
  if [ "$_EC" -eq 1 ]; then
    ISSUES=$((ISSUES + 1))
  elif [ "$_EC" -eq 2 ]; then
    WARNINGS=$((WARNINGS + 1))
  fi
else
  ok "no nix-environment-issues.json (no nix-committed harnesses or reconcile not yet run)"
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
