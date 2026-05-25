#!/usr/bin/env bash
# SessionStart hook for cc-fuzzer.
#
# Runs at every Claude Code session start, regardless of whether a fuzz/
# project exists. Performs:
#   1. Plugin file integrity check (MANIFEST.md5 verification)
#   2. Preflight tool check (clang, llvm-cov, etc) IF a fuzz/ project exists
#
# Outputs a hookSpecificOutput JSON block telling the orchestrator what state
# the environment is in.
#
# IMPORTANT: this script does NOT path-anchor because it runs before any
# specific project context is established. It looks for a fuzz/ directory in
# the user's cwd as a heuristic.
set -u

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

#------------------------------------------------------------------------------
# 0. Filesystem read-only enforcement
#------------------------------------------------------------------------------
# Lock the plugin tree to a-w so agents can't Edit/Write plugin files.
# Set CC_FUZZER_DISABLE_READONLY_LOCK=1 to disable (for plugin development).
if [ -x "$SCRIPT_DIR/enforce-readonly.sh" ]; then
  bash "$SCRIPT_DIR/enforce-readonly.sh" 2>/dev/null || true
fi

#------------------------------------------------------------------------------
# 1. Integrity check
#------------------------------------------------------------------------------
INTEGRITY_OUT=""
INTEGRITY_DRIFT=0
if [ -x "$SCRIPT_DIR/integrity-check.sh" ]; then
  INTEGRITY_OUT=$(bash "$SCRIPT_DIR/integrity-check.sh" 2>&1)
  if echo "$INTEGRITY_OUT" | grep -q "INTEGRITY WARNING"; then
    INTEGRITY_DRIFT=1
  fi
fi

#------------------------------------------------------------------------------
# 2. Nix dev-shell status (v0.14)
#------------------------------------------------------------------------------
# Three states matter:
#   cc_fuzzer_fhs_active : we're inside the cc-fuzzer FHSEnv. Toolchain is
#                          the pinned set from flake.nix. Reproducible.
#   nix_shell_other      : IN_NIX_SHELL is set but CC_FUZZER_FHS is not.
#                          User is in some other nix shell. Toolchain may
#                          differ from what cc-fuzzer was tested against.
#   host_tools           : neither IN_NIX_SHELL nor CC_FUZZER_FHS. User is
#                          using whatever's on host PATH. Builds are not
#                          reproducible across machines.
#
# CC_FUZZER_FHS=1 is exported by the flake's `profile` block; it's the
# load-bearing fingerprint. IN_NIX_SHELL alone is insufficient because
# users frequently have unrelated devShells active.
NIX_STATUS="host_tools"
if [ "${CC_FUZZER_FHS:-}" = "1" ]; then
  NIX_STATUS="cc_fuzzer_fhs_active"
elif [ -n "${IN_NIX_SHELL:-}" ]; then
  NIX_STATUS="nix_shell_other"
fi

#------------------------------------------------------------------------------
# 3. Capture Nix dev-shell environment (v0.18)
#------------------------------------------------------------------------------
# Snapshots PATH-resolved absolute paths for every tool cc-fuzzer scripts care
# about into fuzz/state/nix-env.json. Downstream scripts source
# scripts/_lib/nix-tools.sh and call `nix_tool <name>` instead of grepping
# /nix/store. Capture runs before preflight so preflight diagnostics can read
# the fresh snapshot.
if [ -d "fuzz" ] && [ -x "$SCRIPT_DIR/capture-nix-env.sh" ]; then
  bash "$SCRIPT_DIR/capture-nix-env.sh" >/dev/null 2>&1 || true
fi

#------------------------------------------------------------------------------
# 4. Preflight (only if fuzz/ exists in cwd)
#------------------------------------------------------------------------------
STATUS="not-in-project"
if [ -d "fuzz" ] && [ -x "$SCRIPT_DIR/preflight.sh" ]; then
  bash "$SCRIPT_DIR/preflight.sh" >/dev/null 2>&1 || true
  STATUS=$(python3 -c "
import json
try:
    d = json.load(open('fuzz/state/preflight.json'))
    print(d.get('status', 'unknown'))
except: print('unknown')
" 2>/dev/null || echo unknown)
fi

#------------------------------------------------------------------------------
# 4. Build context message
#------------------------------------------------------------------------------
CTX_PARTS=()

if [ "$INTEGRITY_DRIFT" -eq 1 ]; then
  CTX_PARTS+=("cc-fuzzer plugin integrity: DRIFT DETECTED. One or more plugin scripts have been modified since release. See SessionStart output above. Reinstall plugin to restore canonical state.")
fi

# Nix status only matters when the user is actually engaging with cc-fuzzer.
# The hook fires on EVERY Claude Code session (regardless of project), so we
# don't want to spam toolchain warnings into every session a user has. Gate
# the warning on "fuzz/ exists in cwd" which is the cc-fuzzer-in-use signal.
IN_FUZZ_PROJECT=0
[ -d "fuzz" ] && IN_FUZZ_PROJECT=1

if [ "$IN_FUZZ_PROJECT" -eq 1 ]; then
  case "$NIX_STATUS" in
    cc_fuzzer_fhs_active)
      REV="${CC_FUZZER_FLAKE_REV:-unknown}"
      CTX_PARTS+=("cc-fuzzer environment: pinned toolchain ACTIVE (flake rev: $REV). Builds will be reproducible.")
      # If this project has a campaign flake (per-target deps) but we're in the
      # BARE plugin shell (no project-shell marker), the target's build deps are
      # missing — the harness build will likely fail. Point at the composed shell.
      if [ "${CC_FUZZER_PROJECT_SHELL:-}" != "1" ] && [ -f "flake.nix" ] && [ -f "fuzz/nix-deps.nix" ]; then
        CTX_PARTS+=("cc-fuzzer environment: WARNING - this project has a campaign flake (fuzz/nix-deps.nix) but you are in the BARE plugin shell, so the target's build deps are NOT loaded. Re-enter the composed shell: exit, then 'nix run \${CLAUDE_PLUGIN_ROOT}#init' (or 'nix develop -c claude' from this dir).")
        {
          echo ""
          echo "=============================================================="
          echo " cc-fuzzer: campaign flake present, but deps NOT loaded"
          echo "=============================================================="
          echo " You're in the bare cc-fuzzer shell, not this campaign's"
          echo " composed shell — so the target build deps in fuzz/nix-deps.nix"
          echo " are missing and the harness build will likely fail."
          echo ""
          echo " Re-enter the campaign shell:"
          echo "   exit"
          echo "   nix run \$CLAUDE_PLUGIN_ROOT#init      # (idempotent)"
          echo "   # or, from this dir:  nix develop -c claude"
          echo "=============================================================="
          echo ""
        } >&2
      fi
      ;;
    nix_shell_other)
      CTX_PARTS+=("cc-fuzzer environment: WARNING - you are in a nix shell, but not the cc-fuzzer dev shell. Toolchain may differ from what cc-fuzzer expects. For reproducible builds, exit and re-enter with: nix develop \${CLAUDE_PLUGIN_ROOT}")
      {
        echo ""
        echo "=============================================================="
        echo " cc-fuzzer: NOT in pinned dev shell"
        echo "=============================================================="
        echo " You are inside a nix shell, but not the cc-fuzzer one."
        echo " The toolchain (clang/AFL++/SymCC) you're using may not match"
        echo " what cc-fuzzer was tested against."
        echo ""
        echo " For reproducible builds:"
        echo "   exit"
        echo "   nix develop \$CLAUDE_PLUGIN_ROOT"
        echo "   claude"
        echo "=============================================================="
        echo ""
      } >&2
      ;;
    host_tools)
      CTX_PARTS+=("cc-fuzzer environment: WARNING - using host tools. Builds will not be reproducible across machines and may fail if AFL++/SymCC/clang+compiler-rt aren't installed. For pinned toolchain, exit and re-enter via: nix develop \${CLAUDE_PLUGIN_ROOT}")
      {
        echo ""
        echo "=============================================================="
        echo " cc-fuzzer: HOST TOOLCHAIN (not reproducible)"
        echo "=============================================================="
        echo " You are running cc-fuzzer with whatever clang/AFL++/SymCC are"
        echo " on your host PATH. This works but is not reproducible: another"
        echo " user with the same campaign state may get different binaries."
        echo ""
        echo " For reproducible builds, exit Claude and run:"
        echo "   nix develop \$CLAUDE_PLUGIN_ROOT"
        echo "   claude"
        echo ""
        echo " Continuing anyway. Preflight will tell you which tools are"
        echo " missing on your host."
        echo "=============================================================="
        echo ""
      } >&2
      ;;
  esac
fi

case "$STATUS" in
  errors)
    CTX_PARTS+=("cc-fuzzer preflight: ERRORS detected. See fuzz/state/preflight.json. Coverage tracking and/or fuzzing capability is broken. Do NOT start a campaign until preflight passes.")
    ;;
  warnings)
    CTX_PARTS+=("cc-fuzzer preflight: warnings present. See fuzz/state/preflight.json. Fuzzing and coverage will work; some optional features may not.")
    ;;
  ok)
    CTX_PARTS+=("cc-fuzzer preflight: ok. All required tools present.")
    ;;
  not-in-project)
    # Don't surface anything; user isn't in a fuzz project
    ;;
  *)
    CTX_PARTS+=("cc-fuzzer preflight: status unknown.")
    ;;
esac

if [ "${#CTX_PARTS[@]}" -gt 0 ]; then
  # Print integrity warning to stderr so it shows in the session output
  if [ "$INTEGRITY_DRIFT" -eq 1 ]; then
    echo "$INTEGRITY_OUT" >&2
  fi

  # Join context parts with " | "
  CTX=$(printf '%s | ' "${CTX_PARTS[@]}" | sed 's/ | $//')

  cat <<EOF
{
  "hookSpecificOutput": {
    "hookEventName": "SessionStart",
    "additionalContext": "$CTX"
  }
}
EOF
fi

exit 0
