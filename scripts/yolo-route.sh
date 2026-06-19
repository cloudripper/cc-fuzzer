#!/usr/bin/env bash
# yolo-route.sh — deterministic main-thread router for the cc-fuzzer loop.
#
# Why this exists: under the ctxctl companion plugin the top-level thread can only
# call Agent/Skill/TodoWrite/AskUserQuestion/ExitPlanMode/ScheduleWakeup — no Bash
# and (since no cc-fuzzer agent carries Agent/Task) no subagent can spawn another
# subagent. So the MAIN THREAD is the only context that can dispatch the Opus
# specialists. The orchestrator therefore cannot delegate; it can only DECIDE and
# return a directive. This router turns deterministic, fully-state-determined moves
# (the COLD/RESUME setup chain, and the WARM no-judgment-needed cases) into that
# same directive vocabulary, so the main thread can act on them without paying for
# an orchestrator dispatch — and so a truncated free-text return can never strand
# the loop on a move that was never a judgment call to begin with.
#
# Directive vocabulary (one directive == one line; emitted on stdout here, and the
# identical shape is what the orchestrator emits as the last line of its return):
#
#   YOLO_NEXT: dispatch agent=<agent-type> args="<args>" reason="<why>"
#       Main thread dispatches the named specialist subagent via Agent(). The COLD
#       setup chain (campaign-planner -> harness-writer -> seed-generator) is a
#       sequence of these, one per loop step.
#   YOLO_NEXT: run script="<script + args>" reason="<why>"
#       Main thread dispatches ops-runner to run the named bash lever (e.g.
#       run-fuzzer.sh / snapshot-coverage.sh). ops-runner returns its output;
#       the loop then re-enters.
#   YOLO_NEXT: schedule delay=<n> prompt=<p> reason="<why>"
#       Main thread calls ScheduleWakeup(delay, prompt). Chains the YOLO tick loop.
#   YOLO_NEXT: orchestrator reason="<why>"
#       The next move needs genuine judgment — main thread dispatches the
#       fuzz-orchestrator subagent to decide (WARM ticks; unclassifiable state).
#   YOLO_NEXT: halt reason="<why>"        — a hard halt fired; stop, do not chain.
#   YOLO_NEXT: done reason="<why>"         — setup step complete, nothing to chain
#                                            (COLD/RESUME finished a one-shot step).
#   YOLO_NEXT: inactive                    — YOLO off; stop the chain.
#
# Usage:
#   yolo-route.sh                 # compute the deterministic next directive
#   yolo-route.sh read-directive  # echo the orchestrator's last persisted directive (fallback)
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
FUZZ_ROOT="${FUZZ_ROOT:-fuzz}"
FUZZ_STATE_DIR="${FUZZ_STATE_DIR:-$FUZZ_ROOT/state}"
DIRECTIVE_FILE="$FUZZ_STATE_DIR/next-directive.txt"

# read-directive: the fallback. If the orchestrator persisted its directive to
# disk before returning, surface it here so the main thread never depends on the
# tail of the free-text return surviving the channel.
if [ "${1:-}" = "read-directive" ]; then
  if [ -s "$DIRECTIVE_FILE" ]; then
    # Last non-blank line is the directive, by the same contract as the return.
    grep -vE '^[[:space:]]*$' "$DIRECTIVE_FILE" | tail -n 1
  fi
  exit 0
fi

# Default: compute the deterministic directive from campaign state.
# check-campaign-state.sh prints exactly one bare word: none|running|stopped|stale|corrupted.
MODE="$(bash "$SCRIPT_DIR/check-campaign-state.sh" 2>/dev/null || true)"
MODE="$(printf '%s' "$MODE" | tr -d '[:space:]')"

# Filesystem-derived artifact presence (no JSON producer needed). A plan exists
# once campaign-planner has written it; a harness once harness-built.json exists;
# a corpus once any per-harness corpus dir holds at least one seed.
has_plan() { [ -s "$FUZZ_STATE_DIR/plan.md" ]; }
has_harness() { [ -f "$FUZZ_STATE_DIR/harness-built.json" ]; }
has_corpus() {
  local d
  for d in "$FUZZ_ROOT"/harnesses/*/corpus; do
    [ -d "$d" ] || continue
    if find "$d" -type f -print -quit 2>/dev/null | grep -q .; then return 0; fi
  done
  return 1
}

case "$MODE" in
  running)
    # A fuzzer is live; the next move (coverage vs concolic vs triage vs escalate)
    # is a judgment call. Dispatch the orchestrator subagent for it.
    echo 'YOLO_NEXT: orchestrator reason="warm tick — coverage/triage/escalation judgment"'
    ;;
  none|stopped)
    # Fully determined by what artifacts exist. This is the COLD/RESUME setup
    # chain, made deterministic so it cannot be lost to a truncated return: each
    # call returns the single next setup step as a dispatch/run directive, and the
    # main thread re-enters the router for the step after.
    if ! has_plan; then
      echo 'YOLO_NEXT: dispatch agent=campaign-planner args="--mode fresh" reason="no plan yet — cold start"'
    elif ! has_harness; then
      echo 'YOLO_NEXT: dispatch agent=harness-writer args="" reason="plan ready, need harness"'
    elif ! has_corpus; then
      echo 'YOLO_NEXT: dispatch agent=seed-generator args="" reason="harness ready, need seed corpus"'
    else
      echo 'YOLO_NEXT: run script="run-fuzzer.sh" reason="harness + corpus ready, (re)launch fuzzing"'
    fi
    ;;
  stale|corrupted)
    # State is unsafe to act on automatically — defer to the orchestrator, which
    # prints the right refusal + next step (reset / fix) for the user.
    echo "YOLO_NEXT: orchestrator reason=\"state ${MODE} — needs assessment\""
    ;;
  *)
    echo "YOLO_NEXT: orchestrator reason=\"mode unresolved (${MODE:-empty}) — needs assessment\""
    ;;
esac
