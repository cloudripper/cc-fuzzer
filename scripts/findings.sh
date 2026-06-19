#!/usr/bin/env bash
# findings.sh
#
# The ONLY writer of findings.jsonl. Subagents must call this rather than
# editing the file directly, because the in-place dedup edit must be atomic
# and the schema must be enforced.
#
# Usage:
#   findings.sh add <stack_hash> <category> <location> <exploitability> <root_cause> <reproducer> [sanitizer_excerpt]
#   findings.sh dedup <stack_hash>
#   findings.sh count
#   findings.sh list
#   findings.sh find-by-hash <stack_hash>
#   findings.sh import-cr [snapshot-path]    # bridge code-review candidates in
#
# Behavior per STATE_SCHEMA.md:
#   - APPEND-ONLY for new findings
#   - In-place edit ONLY for dedup_count and last_seen
#   - Strict schema (finding/v2; every finding carries harnesses[])
#   - Atomic write via .tmp + mv

set -u

# Path anchor - refuses cwd inside fuzz/, refuses recursive fuzz/fuzz/
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
. "$SCRIPT_DIR/_lib/path-anchor.sh"
. "$SCRIPT_DIR/_lib/harness-path.sh"
FUZZ_ROOT="${FUZZ_ROOT:-fuzz}"
STATE_DIR="$FUZZ_ROOT/state"
FINDINGS="$STATE_DIR/findings.jsonl"
OPS="$SCRIPT_DIR/_lib/findings_ops.py"        # jsonl transforms
CHECKS="$SCRIPT_DIR/_lib/state_checks.py"     # `field` reader for harness-built.json
ENUMS="$SCRIPT_DIR/_lib/enums.py"             # SSOT enum CLI (print/check)
HB_JSON="$STATE_DIR/harness-built.json"

mkdir -p "$STATE_DIR"
[ -f "$FINDINGS" ] || touch "$FINDINGS"

# Read a key from fuzz/state/fuzz-config.json. Dot-paths are walked.
# Returns empty string if file missing or key absent.
_config_get() {
  local key="$1"
  local cfg="$STATE_DIR/fuzz-config.json"
  [ -f "$cfg" ] || { echo ""; return; }
  K="$key" CFG="$cfg" python3 -c "
import json, os, sys
cfg = os.environ['CFG']
key = os.environ['K']
try:
    d = json.load(open(cfg))
    for part in key.split('.'):
        if isinstance(d, dict) and part in d:
            d = d[part]
        else:
            d = ''
            break
    sys.stdout.write('' if d in (None, '') else str(d))
except Exception:
    pass
" 2>/dev/null
}

# Multi-harness context (multi is the only mode since v0.30): `add`/`dedup`
# callers may set $HARNESS to attribute the finding to a source harness;
# `add-harness` takes the harness as a positional arg. finding/v2 requires a
# non-empty harnesses[], so when $HARNESS is unset we fall back to the first
# declared harness (default_harness).
HARNESS_CTX="${HARNESS:-}"
if [ -z "$HARNESS_CTX" ]; then
  HARNESS_CTX="$(default_harness 2>/dev/null | head -1)"
fi

# Helper: rewrite fuzz/crashes/known/<id>/harnesses.txt with the current
# finding.harnesses[] (one harness per line, sorted-and-uniqued).
_write_harnesses_txt() {
  local id="$1"
  local harnesses_dir="$FUZZ_ROOT/crashes/known/$id"
  [ -d "$harnesses_dir" ] || return 0   # finding's repro dir not created yet
  local list
  list=$(FINDINGS="$FINDINGS" ID="$id" python3 "$OPS" harnesses-txt 2>/dev/null)
  if [ -n "$list" ]; then
    echo "$list" > "$harnesses_dir/harnesses.txt.tmp"
    mv "$harnesses_dir/harnesses.txt.tmp" "$harnesses_dir/harnesses.txt"
  fi
}

# Did a harness run ($1=exit code, $2=combined stdout+stderr) crash? Any of:
#   - killed by a deadly signal directly: rc >= 128 (= 128 + signal)
#   - a sanitizer printed a report: "SUMMARY: <Sanitizer>" or a UBSan
#     "runtime error:" line (the integer/implicit-conversion suite)
#   - libFuzzer caught the fault itself. libFuzzer installs its own signal
#     handlers, so a SIGABRT/SIGSEGV (assert, abort(), or any non-sanitizer
#     fault) is reported as "ERROR: libFuzzer: deadly signal" (also out-of-memory
#     / timeout) and the process exits **1, not 128+N**, with no sanitizer
#     SUMMARY. The rc>=128 + sanitizer gate alone misses this and routes a real
#     crash to crashes/flaky/.
#   - an ORACLE harness trapped on a logic violation. A __builtin_trap() raises
#     SIGILL (rc>=128) AND prints the CCFUZZ_ORACLE_VIOLATION marker, but it has
#     NO sanitizer SUMMARY — so the marker is matched explicitly here. Without
#     it, every logic (oracle-driven) finding fails Stage-1/2 verification.
_crashed() {
  local rc="$1" out="$2"
  [ "$rc" -ge 128 ] 2>/dev/null && return 0
  printf '%s\n' "$out" | grep -qE \
    'SUMMARY: (AddressSanitizer|UndefinedBehaviorSanitizer|LeakSanitizer|ThreadSanitizer|MemorySanitizer|libFuzzer:)|ERROR: libFuzzer:|CCFUZZ_ORACLE_VIOLATION|runtime error:'
}

cmd="${1:-help}"
shift || true

case "$cmd" in
  count)
    grep -cE '"schema"[[:space:]]*:[[:space:]]*"finding/v2"' "$FINDINGS" 2>/dev/null || echo 0
    ;;

  list)
    cat "$FINDINGS"
    ;;

  find-by-hash)
    HASH="${1:?stack_hash required}"
    # Whitespace-tolerant: on-disk findings.jsonl may carry spaces after the
    # colon if a line was rewritten by a writer using json.dumps default
    # separators (e.g. the triager's in-place annotation edit). A compact-only
    # grep silently misses those. Mirror the tolerant idiom used by `count`/`add`.
    grep -E "\"stack_hash\"[[:space:]]*:[[:space:]]*\"$HASH\"" "$FINDINGS" || true
    ;;

  add)
    if [ "$#" -lt 6 ]; then
      cat >&2 <<EOF
usage: findings.sh add <stack_hash> <category> <location> <exploitability> <root_cause> <reproducer> [sanitizer_excerpt]

This is a POSITIONAL-ARGS interface, NOT a flag-style interface.
WRONG: findings.sh add --id f001 --category null-deref --location ...
RIGHT: findings.sh add "abc123def456" "null-deref" "func\@file.c:42" "medium" "off-by-one" "fuzz/crashes/known/f001/repro.bin" ""

The id is allocated by this script - do NOT pass --id. The argument order is:
  1. stack_hash         (16-hex-char sha256-prefix of the crash stack)
  2. category           (crash: heap-buffer-overflow heap-use-after-free stack-buffer-overflow
                                  global-buffer-overflow stack-overflow null-deref assertion-failure
                                  oom timeout harness-artifact, or ubsan-<kind>;
                          logic: invariant-violation roundtrip-mismatch differential-divergence
                                  parser-differential auth-bypass access-control incorrect-validation
                                  canonicalization state-confusion integer-truncation logic-error)
  3. location           (function@file:line of the actual bug, not the libc frame)
  4. exploitability     (one of: likely medium unlikely harness-artifact)
  5. root_cause         (one or two sentences)
  6. reproducer         (path to fuzz/crashes/known/<id>/repro.bin - placeholder until you mkdir+mv)
  7. sanitizer_excerpt  (optional - first ~10 lines of the sanitizer report)

For a LOGIC finding (oracle-driven), additionally set in the ENVIRONMENT (not flags):
  ORACLE_TYPE=invariant|roundtrip|differential   and
  DIVERGENCE='{"property_id":"...","comparison":"...","observed":"...","expected":"..."}'
The stack_hash for a logic finding is the property-divergence hash (sha256 prefix of
oracle_type|property_id|divergence_class) — the dedup machinery is unchanged.
EOF
      exit 2
    fi

    # Refuse --flag-style args. This is the calling-convention bug we hit before.
    for arg in "$@"; do
      case "$arg" in
        --*) echo "ERROR: findings.sh uses POSITIONAL args, not flags. Got '$arg'. See 'findings.sh help'." >&2; exit 2;;
      esac
    done

    STACK_HASH="$1"; CATEGORY="$2"; LOCATION="$3"; EXPLOITABILITY="$4"
    ROOT_CAUSE="$5"; REPRODUCER="$6"; EXCERPT="${7:-}"

    # Validate stack_hash format - hex 12-64 chars
    if ! [[ "$STACK_HASH" =~ ^[0-9a-fA-F]{12,64}$ ]]; then
      echo "ERROR: stack_hash '$STACK_HASH' must be hex (12-64 chars). Did you mix up arg order?" >&2
      exit 2
    fi

    # Validate category enum against the SSOT (full set: crash classes + logic
    # classes used by oracle-driven findings — see STATE_SCHEMA "Oracle-Driven
    # Fuzzing"). ubsan-<kind> is validated by prefix, not membership. Single
    # enums.py call (the `add` path has no per-finding loop).
    case "$CATEGORY" in
      ubsan-*) ;;
      *) if ! python3 "$ENUMS" check categories "$CATEGORY"; then
           echo "ERROR: invalid category '$CATEGORY'. See 'findings.sh help'." >&2; exit 2
         fi ;;
    esac

    # Validate exploitability enum against the SSOT.
    if ! python3 "$ENUMS" check exploitability "$EXPLOITABILITY"; then
      echo "ERROR: invalid exploitability '$EXPLOITABILITY' (must be likely|medium|unlikely|harness-artifact)." >&2; exit 2
    fi

    # Refuse if a finding with this stack_hash already exists - caller should dedup.
    # Whitespace-tolerant grep (on-disk lines may have spaces after the colon).
    if grep -qE "\"stack_hash\"[[:space:]]*:[[:space:]]*\"$STACK_HASH\"" "$FINDINGS" 2>/dev/null; then
      echo "ERROR: stack_hash $STACK_HASH already exists - use 'dedup' instead" >&2
      exit 1
    fi

    # ------------------------------------------------------------------
    # Reproducer verification (v0.12+)
    # ------------------------------------------------------------------
    # Findings without a verified reproducer have caused real damage in
    # past campaigns. The triager produced confident root-cause narratives
    # for inputs that didn't actually reproduce against the current
    # harness binary. We refuse those at finding-creation time.
    #
    # To skip (e.g. for harness-leak findings where reproduction is
    # post-process), set FINDINGS_SKIP_VERIFY=1.
    if [ "${FINDINGS_SKIP_VERIFY:-0}" != "1" ]; then
      if [ ! -f "$REPRODUCER" ]; then
        echo "ERROR: reproducer file missing: $REPRODUCER" >&2
        echo "       create the file first, then call findings.sh add" >&2
        exit 2
      fi

      # Find the harness binary from the source harness's per-harness record.
      # Fall back to the harness-built.json mirror if the name didn't resolve.
      HARNESS_BIN=$(harness_binary "$HARNESS_CTX")
      [ "$HARNESS_BIN" = "None" ] && HARNESS_BIN=""
      if [ -z "$HARNESS_BIN" ]; then
        HARNESS_BIN=$(python3 "$CHECKS" field "$HB_JSON" harness_binary 2>/dev/null)
      fi

      if [ -z "$HARNESS_BIN" ] || [ ! -x "$HARNESS_BIN" ]; then
        echo "ERROR: cannot find harness_binary in $STATE_DIR/harness-built.json" >&2
        echo "       set FINDINGS_SKIP_VERIFY=1 to skip verification (not recommended)" >&2
        exit 2
      fi

      # ---- Stage 1: Fuzzer harness ----------------------------------------
      # Run 3x under strict sanitizer settings. A finding requires 2/3 crashes
      # to be deterministic, not flaky.
      ATTEMPTS=3
      CRASHES=0
      VERIFY_LOG="$STATE_DIR/verify-${STACK_HASH:0:12}.log"
      : > "$VERIFY_LOG"
      for i in $(seq 1 $ATTEMPTS); do
        OUT=$(ASAN_OPTIONS=symbolize=1:abort_on_error=1:halt_on_error=1:print_stacktrace=1:detect_leaks=1 \
              UBSAN_OPTIONS=halt_on_error=1:print_stacktrace=1:abort_on_error=1 \
              timeout 30 "$HARNESS_BIN" "$REPRODUCER" 2>&1)
        RC=$?   # NO `|| true`: it would make $? capture true's 0 and hide a
                # SIGILL/SIGABRT (the only signal a trap-based oracle gives). The
                # script has no `set -e`, so a non-zero rc here is safe.
        echo "=== stage1 attempt $i rc=$RC ===" >> "$VERIFY_LOG"
        echo "$OUT" >> "$VERIFY_LOG"
        if _crashed "$RC" "$OUT"; then
          CRASHES=$((CRASHES + 1))
        fi
      done

      if [ "$CRASHES" -lt 2 ]; then
        echo "ERROR: Stage 1 (harness) verification failed: $CRASHES/$ATTEMPTS attempts crashed" >&2
        echo "       reproducer is non-deterministic or no longer triggers the bug" >&2
        echo "       full log: $VERIFY_LOG" >&2
        echo "       routing input to fuzz/crashes/flaky/" >&2
        FLAKY_DIR="$FUZZ_ROOT/crashes/flaky"
        mkdir -p "$FLAKY_DIR"
        cp "$REPRODUCER" "$FLAKY_DIR/$(basename "$REPRODUCER" | sed "s/\\.bin$//")-flaky-${STACK_HASH:0:8}.bin"
        echo "       to override (not recommended): set FINDINGS_SKIP_VERIFY=1" >&2
        exit 3
      fi
      echo "stage1 ok: $CRASHES/$ATTEMPTS harness crashes" >&2

      # ---- Stage 2: Standalone ASan binary (verify_binary) -----------------
      # This is the harness-artifact filter. The verify_binary is compiled with
      # -fsanitize=address,undefined but NO -fsanitize=fuzzer and uses cov_main.c
      # as a plain main() shim. If the crash does not reproduce here, it only
      # exists inside libFuzzer's infrastructure — it is a harness artifact, not
      # a real target bug.
      VERIFY_BIN=$(harness_field "$HARNESS_CTX" verify_binary)
      [ "$VERIFY_BIN" = "None" ] && VERIFY_BIN=""
      if [ -z "$VERIFY_BIN" ]; then
        VERIFY_BIN=$(python3 "$CHECKS" field "$HB_JSON" verify_binary 2>/dev/null)
      fi

      if [ -n "$VERIFY_BIN" ] && [ -x "$VERIFY_BIN" ]; then
        S2_CRASHES=0
        for i in $(seq 1 $ATTEMPTS); do
          OUT2=$(ASAN_OPTIONS=symbolize=1:abort_on_error=1:halt_on_error=1:print_stacktrace=1:detect_leaks=1 \
                 UBSAN_OPTIONS=halt_on_error=1:print_stacktrace=1:abort_on_error=1 \
                 timeout 30 "$VERIFY_BIN" "$REPRODUCER" 2>&1)
          RC2=$?   # NO `|| true` — see Stage-1 note above (preserve the real rc).
          echo "=== stage2 attempt $i rc=$RC2 ===" >> "$VERIFY_LOG"
          echo "$OUT2" >> "$VERIFY_LOG"
          if _crashed "$RC2" "$OUT2"; then
            S2_CRASHES=$((S2_CRASHES + 1))
          fi
        done

        if [ "$S2_CRASHES" -lt 2 ]; then
          echo "ERROR: Stage 2 (standalone ASan) verification failed: $S2_CRASHES/$ATTEMPTS attempts crashed" >&2
          echo "       crash only reproduces in the fuzzer harness, not in the standalone ASan binary." >&2
          echo "       This is a harness artifact — the bug is in the libFuzzer wrapper, not in target code." >&2
          echo "       full log: $VERIFY_LOG" >&2
          echo "       routing input to fuzz/crashes/flaky/ (harness-artifact)" >&2
          FLAKY_DIR="$FUZZ_ROOT/crashes/flaky"
          mkdir -p "$FLAKY_DIR"
          cp "$REPRODUCER" "$FLAKY_DIR/$(basename "$REPRODUCER" | sed "s/\\.bin$//")-harness-artifact-${STACK_HASH:0:8}.bin"
          echo "       to override: set FINDINGS_SKIP_VERIFY=1 (only if you have strong reason to believe" >&2
          echo "       this is a real bug despite not reproducing in the standalone binary)" >&2
          exit 3
        fi
        echo "stage2 ok: $S2_CRASHES/$ATTEMPTS standalone ASan crashes — confirmed real target bug" >&2
      else
        if [ -z "$VERIFY_BIN" ]; then
          echo "WARN: verify_binary not set in harness-built.json — cannot cross-verify against standalone binary." >&2
          echo "      This finding may be a harness artifact. Rebuild harness with /cc-fuzzer:harness to enable" >&2
          echo "      Stage 2 verification." >&2
        else
          echo "WARN: verify_binary set but not executable: $VERIFY_BIN" >&2
          echo "      Rebuild harness to regenerate it." >&2
        fi
        echo "      Proceeding without Stage 2 verification. If exploitability is uncertain, use harness-artifact." >&2
      fi

      echo "verify ok: stage1=$CRASHES/$ATTEMPTS stage2=${S2_CRASHES:-skipped}/$ATTEMPTS" >&2
    fi

    # Capture the build hash from harness-built.json so we know what build
    # this finding was verified against. After a rebuild, the orchestrator
    # re-verifies and moves stale findings to crashes/stale/.
    BUILD_HASH=$(python3 "$CHECKS" field "$HB_JSON" build_command_hash 2>/dev/null)

    # Snapshot the harness binary alongside the reproducer.
    # When the harness is rebuilt later, the original binary is preserved
    # so the finding can still be reproduced for disclosure work.
    if [ -n "${HARNESS_BIN:-}" ] && [ -x "$HARNESS_BIN" ] && [ -f "$REPRODUCER" ]; then
      REPRO_DIR=$(dirname "$REPRODUCER")
      mkdir -p "$REPRO_DIR"
      if [ ! -f "$REPRO_DIR/repro.binary" ]; then
        cp "$HARNESS_BIN" "$REPRO_DIR/repro.binary" 2>/dev/null || true
      fi
    fi

    # Allocate next ID
    # Pattern matches both compact ("id":"f019") and spaced ("id": "f019") JSON.
    # Use 10# prefix to force base-10 arithmetic — leading zeros (e.g. "020")
    # would otherwise be interpreted as octal, causing 020+1=17 instead of 21.
    LAST_NUM=$(grep -oE '"id"[[:space:]]*:[[:space:]]*"f[0-9]+"' "$FINDINGS" 2>/dev/null \
                 | grep -oE 'f[0-9]+' \
                 | grep -oE '[0-9]+' \
                 | sort -n | tail -1)
    NEXT_NUM=$(( 10#${LAST_NUM:-0} + 1 ))
    NEW_ID=$(printf "f%03d" "$NEXT_NUM")

    NOW=$(date -u +"%Y-%m-%dT%H:%M:%SZ")

    # Build the finding/v2 JSON line atomically with python so escaping is
    # correct (every finding carries harnesses:[<HARNESS>]).
    # ORACLE_TYPE / DIVERGENCE flow through from the caller's environment
    # (set by crash-triager for logic findings; unset/"crash" for crash findings).
    NEW_LINE=$(HARNESS="$HARNESS_CTX" \
               NEW_ID="$NEW_ID" STACK_HASH="$STACK_HASH" CATEGORY="$CATEGORY" \
               EXPLOITABILITY="$EXPLOITABILITY" BUILD_HASH="$BUILD_HASH" NOW="$NOW" \
               ORACLE_TYPE="${ORACLE_TYPE:-}" DIVERGENCE="${DIVERGENCE:-}" \
               python3 "$OPS" build-finding "$LOCATION" "$ROOT_CAUSE" "$REPRODUCER" "$EXCERPT")

    # Append atomically
    echo "$NEW_LINE" >> "$FINDINGS"

    # Write the harnesses.txt sidecar so analysts see provenance without
    # parsing JSON. (The triager calls this after mv'ing the repro file into
    # fuzz/crashes/known/<id>/; we write the file then.)
    _write_harnesses_txt "$NEW_ID"

    echo "$NEW_ID"
    ;;

  dedup)
    STACK_HASH="${1:?stack_hash required}"
    # Whitespace-tolerant grep (on-disk lines may have spaces after the colon).
    if ! grep -qE "\"stack_hash\"[[:space:]]*:[[:space:]]*\"$STACK_HASH\"" "$FINDINGS" 2>/dev/null; then
      echo "ERROR: no finding with stack_hash $STACK_HASH" >&2
      exit 1
    fi

    NOW=$(date -u +"%Y-%m-%dT%H:%M:%SZ")
    TMP="$FINDINGS.tmp"

    # Read each line, update the matching one in-place, write atomically.
    # Append the source harness to the finding's harnesses[] if not already
    # present (HARNESS_CTX is the caller's $HARNESS, else the default harness).
    HARNESS_TO_APPEND="$HARNESS_CTX"
    FINDINGS="$FINDINGS" STACK_HASH="$STACK_HASH" NOW="$NOW" \
      HARNESS_APPEND="$HARNESS_TO_APPEND" \
      python3 "$OPS" dedup > "$TMP" 2>/dev/null

    if [ -s "$TMP" ]; then
      mv "$TMP" "$FINDINGS"
      # Print the matching id for the caller AND warn when dedup_count crosses
      # the high-dup threshold (v0.18). The triager re-runs the four-principle
      # artifact filter on high-dup findings before recording another duplicate.
      DEDUP_THRESHOLD="${FINDINGS_DEDUP_THRESHOLD:-5}"
      OUT=$(grep -E "\"stack_hash\"[[:space:]]*:[[:space:]]*\"$STACK_HASH\"" "$FINDINGS" | python3 "$OPS" dedup-info)
      MATCH_ID=$(echo "$OUT" | awk '{print $1}')
      MATCH_COUNT=$(echo "$OUT" | awk '{print $2}')
      echo "$MATCH_ID"
      if [ -n "$MATCH_COUNT" ] && [ "$MATCH_COUNT" -ge "$DEDUP_THRESHOLD" ] 2>/dev/null; then
        echo "WARN: dedup_count crossed $DEDUP_THRESHOLD for $MATCH_ID (now $MATCH_COUNT). Triager should re-run the four-principle artifact filter on this stack hash before next dedup — high-frequency repeats often turn out to be harness artifacts." >&2
      fi
      # In multi mode, refresh the harnesses.txt sidecar so it stays in sync.
      if [ -n "$HARNESS_TO_APPEND" ] && [ -n "$MATCH_ID" ]; then
        _write_harnesses_txt "$MATCH_ID"
      fi
    else
      rm -f "$TMP"
      echo "ERROR: dedup produced empty file - aborted" >&2
      exit 1
    fi
    ;;

  add-harness)
    # Append a harness to an existing finding's harnesses[] (idempotent).
    # Used by the triager when a known stack-hash crash arrives from a
    # different harness than the finding was originally attributed to.
    ID="${1:?finding id required (e.g. f005)}"
    HARNESS_NAME="${2:?harness name required}"

    # Whitespace-tolerant grep (on-disk lines may have spaces after the colon).
    if ! grep -qE "\"id\"[[:space:]]*:[[:space:]]*\"$ID\"" "$FINDINGS" 2>/dev/null; then
      echo "ERROR: no finding with id $ID" >&2
      exit 1
    fi

    TMP="$FINDINGS.tmp"
    FINDINGS="$FINDINGS" APPEND_ID="$ID" APPEND_HARNESS="$HARNESS_NAME" \
      python3 "$OPS" add-harness > "$TMP" 2>/dev/null
    RC=$?

    if [ -s "$TMP" ]; then
      mv "$TMP" "$FINDINGS"
      _write_harnesses_txt "$ID"
      echo "$ID"
    else
      rm -f "$TMP"
      echo "ERROR: add-harness produced empty file - aborted" >&2
      exit 1
    fi
    ;;

  verify)
    # Re-verify one or all findings against the current harness binary.
    # Used after a harness rebuild to detect stale findings.
    #
    # findings.sh verify             - verify all findings
    # findings.sh verify <id>        - verify one finding by id
    #
    # Outputs a table: id <tab> status (ok|stale|missing)
    # Findings whose reproducer no longer crashes are marked stale.
    # Findings are NOT modified - run findings.sh stale-mark to act on results.
    HARNESS_BIN=$(python3 "$CHECKS" field "$HB_JSON" harness_binary 2>/dev/null)
    if [ -z "$HARNESS_BIN" ] || [ ! -x "$HARNESS_BIN" ]; then
      echo "ERROR: harness binary not found in harness-built.json" >&2
      exit 2
    fi
    VERIFY_BIN=$(python3 "$CHECKS" field "$HB_JSON" verify_binary 2>/dev/null)

    TARGET_ID="${1:-}"
    while IFS= read -r line; do
      [ -z "$line" ] && continue
      ID=$(echo "$line" | python3 "$OPS" field-stdin id 2>/dev/null)
      REPRO=$(echo "$line" | python3 "$OPS" field-stdin reproducer 2>/dev/null)
      [ -z "$ID" ] && continue
      [ -n "$TARGET_ID" ] && [ "$TARGET_ID" != "$ID" ] && continue

      if [ ! -f "$REPRO" ]; then
        printf '%s\tmissing\n' "$ID"
        continue
      fi

      CRASHED=0
      for i in 1 2 3; do
        OUT=$(ASAN_OPTIONS=symbolize=1:abort_on_error=1:halt_on_error=1:print_stacktrace=1:detect_leaks=1 \
              UBSAN_OPTIONS=halt_on_error=1:print_stacktrace=1:abort_on_error=1 \
              timeout 30 "$HARNESS_BIN" "$REPRO" 2>&1)
        RC=$?   # NO `|| true` — preserve the real rc (trap-based oracle = SIGILL).
        if _crashed "$RC" "$OUT"; then
          CRASHED=$((CRASHED + 1))
        fi
      done

      if [ "$CRASHED" -ge 2 ]; then
        # Stage 1 ok — now check Stage 2 if verify_binary exists
        S2_CRASHED=0
        if [ -n "${VERIFY_BIN:-}" ] && [ -x "$VERIFY_BIN" ]; then
          for i in 1 2 3; do
            OUT2=$(ASAN_OPTIONS=symbolize=1:abort_on_error=1:halt_on_error=1:print_stacktrace=1 \
                   UBSAN_OPTIONS=halt_on_error=1:print_stacktrace=1:abort_on_error=1 \
                   timeout 30 "$VERIFY_BIN" "$REPRO" 2>&1)
            RC2=$?   # NO `|| true` — preserve the real rc.
            if _crashed "$RC2" "$OUT2"; then
              S2_CRASHED=$((S2_CRASHED + 1))
            fi
          done
          if [ "$S2_CRASHED" -ge 2 ]; then
            printf '%s\tok\n' "$ID"
          else
            printf '%s\tharness-artifact\n' "$ID"
          fi
        else
          printf '%s\tok-no-stage2\n' "$ID"
        fi
      else
        printf '%s\tstale\n' "$ID"
      fi
    done < "$FINDINGS"
    ;;

  stale-mark)
    # Mark a finding as stale: move crashes/known/<id>/ to crashes/stale/<id>/
    # and update findings.jsonl to add status=stale and stale_against_build.
    #
    # v0.30 backup safety (PLUGIN_ISSUES.md friction item 4): `stale` is a
    # rename, not a delete — the directory still lives under fuzz/. But if the
    # destination already exists (re-run; reset; collision) we MUST NOT clobber
    # it; stage the old destination to fuzz/.trash/<ts>/crashes/stale/<id>/
    # first. GC sweep (7-day, planned followup) reaps .trash.
    ID="${1:?finding id required}"
    KNOWN="$FUZZ_ROOT/crashes/known/$ID"
    STALE="$FUZZ_ROOT/crashes/stale/$ID"
    if [ ! -d "$KNOWN" ]; then
      echo "ERROR: $KNOWN does not exist" >&2
      exit 1
    fi

    CURRENT_BUILD=$(python3 "$CHECKS" field "$HB_JSON" build_command_hash 2>/dev/null)

    mkdir -p "$FUZZ_ROOT/crashes/stale"
    if [ -e "$STALE" ]; then
      TRASH_TS=$(date -u +"%Y%m%dT%H%M%SZ")
      TRASH_DST="$FUZZ_ROOT/.trash/$TRASH_TS/crashes/stale/$ID"
      mkdir -p "$(dirname "$TRASH_DST")"
      mv "$STALE" "$TRASH_DST"
      echo "stale-mark: prior $STALE staged to $TRASH_DST (not hard-deleted)" >&2
    fi
    mv "$KNOWN" "$STALE"
    # Update findings.jsonl
    FINDINGS="$FINDINGS" ID="$ID" CURRENT_BUILD="$CURRENT_BUILD" \
      python3 "$OPS" stale-mark > "$FINDINGS.tmp"
    mv "$FINDINGS.tmp" "$FINDINGS"
    echo "$ID marked stale (was $KNOWN, now $STALE)"
    ;;

  list-candidates)
    # Enumerate findings.jsonl entries still in `status: candidate` — i.e.
    # NOT yet promoted by the realism gate. Output: <id>\t<category>\t
    # <location>\t<first_seen>. Used by the orchestrator and poc-builder to
    # pick the next candidate to characterise; used by the reporter to know
    # what is unconfirmed.
    FINDINGS="$FINDINGS" python3 "$OPS" list-candidates
    ;;

  promote)
    # findings.sh promote <id> --driver <path> --verifier <path> \
    #     --boundary <str> --precondition <str> --projected <str>
    #
    # The realism-gate promotion. Flip `status: candidate` -> `status: finding`
    # and attach the realism_attestation block. The agent must supply all
    # three gate items (PLUGIN_ISSUES.md recommendation B):
    #   1. driver       — mechanical reproducer (fuzzer driver input + replay)
    #   2. verifier     — CLI-style verify-*.sh against the REAL target binary
    #                     (non-ASan / non-coverage build); exit 0 ONLY when
    #                     the trust/privilege boundary is crossed
    #   3. boundary/precondition/projected_vs_demonstrated strings
    #
    # Soft complexity check on the verifier (friction item 5 / lean PoC): if
    # the verifier exceeds the soft line count or shells out to more distinct
    # binaries than the threshold, WARN but don't reject. Thresholds are
    # configurable via fuzz-config.json:
    #   poc.verifier_complexity_soft_max_lines   (default 200)
    #   poc.verifier_complexity_soft_max_tools   (default 6)
    #
    # No --promote == no finding-status entry. This is the ONLY way the
    # findings.jsonl file gains a `status: finding` entry; schema v12 makes
    # the attestation REQUIRED.
    ID="${1:?usage: findings.sh promote <id> --driver P --verifier P --boundary S --precondition S --projected S}"
    shift
    P_DRIVER=""; P_VERIFIER=""; P_BOUNDARY=""; P_PRECOND=""; P_PROJECTED=""
    while [ "$#" -gt 0 ]; do
      case "$1" in
        --driver)       P_DRIVER="${2:-}"; shift 2 ;;
        --verifier)     P_VERIFIER="${2:-}"; shift 2 ;;
        --boundary)     P_BOUNDARY="${2:-}"; shift 2 ;;
        --precondition) P_PRECOND="${2:-}"; shift 2 ;;
        --projected)    P_PROJECTED="${2:-}"; shift 2 ;;
        *) echo "ERROR: promote: unknown flag '$1'" >&2; exit 2 ;;
      esac
    done

    # Hard gate: all three realism-gate items required. Refusal is the point.
    MISSING=""
    [ -z "$P_DRIVER" ]    && MISSING="$MISSING --driver"
    [ -z "$P_VERIFIER" ]  && MISSING="$MISSING --verifier"
    [ -z "$P_BOUNDARY" ]  && MISSING="$MISSING --boundary"
    [ -z "$P_PRECOND" ]   && MISSING="$MISSING --precondition"
    [ -z "$P_PROJECTED" ] && MISSING="$MISSING --projected"
    if [ -n "$MISSING" ]; then
      echo "ERROR: promote: missing required attestation fields:$MISSING" >&2
      echo "       schema v12 REQUIRES the 3-point realism gate — see" >&2
      echo "       references/verifier-template.sh and poc-builder.md." >&2
      exit 2
    fi

    # Files must exist (the verifier is what we point a maintainer at).
    if [ ! -f "$P_DRIVER" ]; then
      echo "ERROR: promote: --driver path does not exist: $P_DRIVER" >&2
      exit 2
    fi
    if [ ! -f "$P_VERIFIER" ]; then
      echo "ERROR: promote: --verifier path does not exist: $P_VERIFIER" >&2
      exit 2
    fi

    # Entry must already be a candidate.
    EXISTING=$(grep -E "\"id\"[[:space:]]*:[[:space:]]*\"$ID\"" "$FINDINGS" 2>/dev/null || true)
    if [ -z "$EXISTING" ]; then
      echo "ERROR: promote: no finding with id $ID" >&2
      exit 1
    fi
    CUR_STATUS=$(printf '%s' "$EXISTING" | python3 "$OPS" field-stdin status 2>/dev/null)
    if [ "$CUR_STATUS" = "finding" ]; then
      echo "WARN: promote: $ID is already status=finding; re-attesting (overwriting realism_attestation)" >&2
    elif [ -n "$CUR_STATUS" ] && [ "$CUR_STATUS" != "candidate" ]; then
      echo "ERROR: promote: $ID has status=$CUR_STATUS — promotion refused" >&2
      exit 1
    fi

    # Soft complexity check on the verifier (warn-only).
    SOFT_MAX_LINES=$(_config_get poc.verifier_complexity_soft_max_lines 2>/dev/null)
    SOFT_MAX_TOOLS=$(_config_get poc.verifier_complexity_soft_max_tools 2>/dev/null)
    [ -z "$SOFT_MAX_LINES" ] && SOFT_MAX_LINES=200
    [ -z "$SOFT_MAX_TOOLS" ] && SOFT_MAX_TOOLS=6
    V_LINES=$(wc -l < "$P_VERIFIER" 2>/dev/null | tr -d ' ')
    # Distinct command-like tokens — line start or after `|`/`;`/`&&`/`||`/`$(`.
    # Best-effort heuristic; the threshold is soft, so false positives are fine.
    V_TOOLS=$(grep -oE '(^|[|;&]|\$\()[[:space:]]*[A-Za-z_][A-Za-z0-9_.-]*' "$P_VERIFIER" 2>/dev/null \
              | sed -E 's/^[^A-Za-z_]*//' \
              | grep -vE '^(if|then|else|elif|fi|for|while|do|done|case|esac|in|set|local|export|function|return|true|false|exit|echo|test|cd|trap|read|shift|break|continue)$' \
              | sort -u | wc -l)
    if [ "${V_LINES:-0}" -gt "$SOFT_MAX_LINES" ] 2>/dev/null; then
      echo "WARN: promote: verifier is $V_LINES lines (> soft cap $SOFT_MAX_LINES). The disclosure PoC should be lean (PLUGIN_ISSUES friction 5); split research tooling out under poc-bundle/research/." >&2
    fi
    if [ "${V_TOOLS:-0}" -gt "$SOFT_MAX_TOOLS" ] 2>/dev/null; then
      echo "WARN: promote: verifier shells out to ~$V_TOOLS distinct binaries (> soft cap $SOFT_MAX_TOOLS). Consider trimming non-essential tools from the reference verifier." >&2
    fi

    NOW=$(date -u +"%Y-%m-%dT%H:%M:%SZ")
    TMP="$FINDINGS.tmp"
    FINDINGS="$FINDINGS" PROMOTE_ID="$ID" NOW="$NOW" \
      ATTEST_DRIVER="$P_DRIVER" ATTEST_VERIFIER="$P_VERIFIER" \
      ATTEST_BOUNDARY="$P_BOUNDARY" ATTEST_PRECONDITION="$P_PRECOND" \
      ATTEST_PROJECTED="$P_PROJECTED" \
      ATTEST_VERIFIER_LINES="${V_LINES:-0}" ATTEST_VERIFIER_TOOLS="${V_TOOLS:-0}" \
      python3 "$OPS" promote > "$TMP" 2>/dev/null

    if [ -s "$TMP" ]; then
      mv "$TMP" "$FINDINGS"
      echo "$ID promoted to status=finding (verifier=$P_VERIFIER, lines=$V_LINES, tools=$V_TOOLS)"
    else
      rm -f "$TMP"
      echo "ERROR: promote produced empty file - aborted" >&2
      exit 1
    fi
    ;;

  remove)
    # findings.sh remove <id>
    #
    # Backup-safe removal (PLUGIN_ISSUES friction item 4). Instead of
    # rm -rf fuzz/findings/<id>/ + sed -i out of findings.jsonl, this stages
    # both the directory and the JSONL line to fuzz/.trash/<ts>/. A 7-day GC
    # sweep policy (planned followup) reaps .trash.
    ID="${1:?usage: findings.sh remove <id>}"
    EXISTING=$(grep -E "\"id\"[[:space:]]*:[[:space:]]*\"$ID\"" "$FINDINGS" 2>/dev/null || true)
    if [ -z "$EXISTING" ]; then
      echo "ERROR: remove: no finding with id $ID" >&2
      exit 1
    fi
    TRASH_TS=$(date -u +"%Y%m%dT%H%M%SZ")
    TRASH_BASE="$FUZZ_ROOT/.trash/$TRASH_TS"
    mkdir -p "$TRASH_BASE/state"
    # Stage the JSONL line.
    printf '%s\n' "$EXISTING" >> "$TRASH_BASE/state/findings.jsonl"
    # Stage the bundle dirs if present.
    for sub in findings/$ID crashes/known/$ID; do
      SRC="$FUZZ_ROOT/$sub"
      if [ -d "$SRC" ]; then
        DST="$TRASH_BASE/$sub"
        mkdir -p "$(dirname "$DST")"
        mv "$SRC" "$DST"
        echo "remove: staged $SRC -> $DST" >&2
      fi
    done
    # Rewrite findings.jsonl without the removed line.
    grep -vE "\"id\"[[:space:]]*:[[:space:]]*\"$ID\"" "$FINDINGS" > "$FINDINGS.tmp" 2>/dev/null || true
    mv "$FINDINGS.tmp" "$FINDINGS"
    echo "$ID removed (staged to $TRASH_BASE, NOT hard-deleted)"
    ;;

  drop)
    # findings.sh drop <crash_file> <stage> <reason> [--principle <name>] [--evidence <text>]
    #
    # Appends a record to fuzz/state/dropped_crashes.jsonl (schema dropped-crash/v1).
    # The triager calls this for every crash candidate it filters out before that
    # candidate becomes a finding — transparency log per STATE_SCHEMA.md.
    if [ "$#" -lt 3 ]; then
      echo "Usage: findings.sh drop <crash_file> <stage> <reason> [--principle <name>] [--evidence <text>]" >&2
      echo "  stage in: artifact_filter | deterministic_replay | target_realistic_reproducer" >&2
      echo "  principle (required only when stage=artifact_filter):" >&2
      echo "    harness_correctness | api_contract | public_api_reachability | entry_point_currency" >&2
      exit 2
    fi
    DROP_CRASH_FILE="$1"
    DROP_STAGE="$2"
    DROP_REASON="$3"
    shift 3
    DROP_PRINCIPLE=""
    DROP_EVIDENCE=""
    while [ "$#" -gt 0 ]; do
      case "$1" in
        --principle) DROP_PRINCIPLE="${2:-}"; shift 2 ;;
        --evidence)  DROP_EVIDENCE="${2:-}";  shift 2 ;;
        *) echo "ERROR: drop: unknown flag '$1'" >&2; exit 2 ;;
      esac
    done

    case "$DROP_STAGE" in
      artifact_filter|deterministic_replay|target_realistic_reproducer) ;;
      *)
        echo "ERROR: drop: invalid stage '$DROP_STAGE'" >&2
        echo "       valid: artifact_filter | deterministic_replay | target_realistic_reproducer" >&2
        exit 2
        ;;
    esac

    if [ "$DROP_STAGE" = "artifact_filter" ]; then
      case "$DROP_PRINCIPLE" in
        harness_correctness|api_contract|public_api_reachability|entry_point_currency) ;;
        *)
          echo "ERROR: drop: --principle is required when stage=artifact_filter" >&2
          echo "       valid: harness_correctness | api_contract | public_api_reachability | entry_point_currency" >&2
          exit 2
          ;;
      esac
    fi

    DROPS_LOG="$STATE_DIR/dropped_crashes.jsonl"
    touch "$DROPS_LOG"

    # Compute a short hash if the crash file exists (helps maintainer correlate
    # without exposing full sha256). If the file is gone, leave the field null.
    DROP_HASH=""
    if [ -r "$DROP_CRASH_FILE" ]; then
      DROP_HASH=$(sha256sum "$DROP_CRASH_FILE" 2>/dev/null | awk '{print substr($1,1,8)}')
    fi

    NOW_ISO=$(date -u +"%Y-%m-%dT%H:%M:%SZ")
    CRASH="$DROP_CRASH_FILE" STAGE="$DROP_STAGE" REASON="$DROP_REASON" \
      PRINCIPLE="$DROP_PRINCIPLE" EVIDENCE="$DROP_EVIDENCE" \
      HASH="$DROP_HASH" TS="$NOW_ISO" \
      python3 "$OPS" drop-record >> "$DROPS_LOG"
    echo "dropped: $DROP_CRASH_FILE (stage=$DROP_STAGE${DROP_PRINCIPLE:+, principle=$DROP_PRINCIPLE})"
    ;;

  import-cr)
    # findings.sh import-cr [snapshot-path]
    #
    # Bridge code-review findings into the single candidate ledger. Ingests the
    # high/medium-confidence findings from a code-review/v1 snapshot into
    # findings.jsonl as status:candidate, source:code_review, cr_ref:<cr_hash>.
    # Dedups on cr_ref so re-imports don't duplicate. A code_review candidate
    # then flows through the same list-candidates -> promote realism gate as a
    # crash candidate — giving a logic bug a real discovery->triage->PoC
    # lifecycle instead of dying in the immutable per-run snapshot.
    #
    # Default snapshot: the latest fuzz/state/snapshots/code-review-*.json.
    SNAPSHOT="${1:-}"
    if [ -z "$SNAPSHOT" ]; then
      SNAPSHOT=$(ls -1t "$STATE_DIR"/snapshots/code-review-*.json 2>/dev/null | head -1)
      if [ -z "$SNAPSHOT" ]; then
        echo "ERROR: import-cr: no code-review snapshot found in $STATE_DIR/snapshots/" >&2
        echo "       run /cc-fuzzer:fuzz-review first, or pass a snapshot path." >&2
        exit 2
      fi
    fi
    if [ ! -f "$SNAPSHOT" ]; then
      echo "ERROR: import-cr: snapshot not found: $SNAPSHOT" >&2
      exit 2
    fi

    # Allocate the starting f<NNN> number (same convention as `add`). The python
    # helper increments from here per imported finding. 10# forces base-10.
    LAST_NUM=$(grep -oE '"id"[[:space:]]*:[[:space:]]*"f[0-9]+"' "$FINDINGS" 2>/dev/null \
                 | grep -oE 'f[0-9]+' \
                 | grep -oE '[0-9]+' \
                 | sort -n | tail -1)
    NEXT_NUM=$(( 10#${LAST_NUM:-0} + 1 ))

    # A code-review candidate is harness-independent (it has no reproducer
    # yet), but finding/v2 requires a non-empty harnesses[]. Attribute to the
    # caller's $HARNESS when set, else the first declared harness (HARNESS_CTX
    # already encodes that fallback).
    HARNESS_FOR_IMPORT="$HARNESS_CTX"

    NOW=$(date -u +"%Y-%m-%dT%H:%M:%SZ")
    TMP="$FINDINGS.tmp"
    cp "$FINDINGS" "$TMP" 2>/dev/null || : > "$TMP"
    FINDINGS="$FINDINGS" SNAPSHOT="$SNAPSHOT" NOW="$NOW" NEXT_NUM="$NEXT_NUM" \
      HARNESS="$HARNESS_FOR_IMPORT" \
      python3 "$OPS" import-cr >> "$TMP"
    RC=$?
    if [ "$RC" -ne 0 ]; then
      rm -f "$TMP"
      echo "ERROR: import-cr: helper failed (rc=$RC)" >&2
      exit 1
    fi
    mv "$TMP" "$FINDINGS"
    ;;

  help|*)
    cat <<EOF
findings.sh - the canonical writer for $FINDINGS

Commands:
  count              Print number of unique findings
  list               Print all findings (jsonl)
  find-by-hash H     Print finding line matching stack_hash H, if any
  add H CAT LOC EXPL ROOTCAUSE REPRODUCER [EXCERPT]
                     Append a new finding with stack_hash H. Allocates next id (f001, f002...).
                     TWO-STAGE VERIFICATION before committing:
                       Stage 1: reproducer crashes harness binary 2/3 times (ASan+fuzzer)
                       Stage 2: reproducer crashes verify_binary 2/3 times (ASan-only, no fuzzer)
                     Stage 2 failure = harness artifact, routed to crashes/flaky/, rejected.
                     Stage 1 failure = non-deterministic, routed to crashes/flaky/, rejected.
                     Set FINDINGS_SKIP_VERIFY=1 to bypass both checks (not recommended).
  verify [id]        Re-verify one or all findings against harness + verify_binary.
                     Output: id<TAB>status, status in {ok, ok-no-stage2, stale, harness-artifact, missing}.
                     ok             = stage1 + stage2 both pass
                     ok-no-stage2   = stage1 passes, verify_binary not available
                     harness-artifact = stage1 passes but stage2 fails (finding reclassifiable)
                     stale          = stage1 fails (no longer reproduces at all)
                     missing        = reproducer file missing
  stale-mark <id>    Move a finding's crashes/known/<id>/ tree to crashes/stale/<id>/
                     and add status=stale + stale_against_build to findings.jsonl.
                     If the destination already exists, it is STAGED to
                     fuzz/.trash/<ts>/ rather than hard-deleted (backup safety).
  import-cr [SNAP]   Bridge code-review findings into the candidate ledger.
                     Ingests high/medium-confidence findings from a code-review
                     snapshot (default: latest fuzz/state/snapshots/code-review-*.json)
                     into findings.jsonl as status=candidate, source=code_review,
                     cr_ref=<cr_hash>. Dedups on cr_ref. The imported candidates
                     flow through the same list-candidates -> promote realism gate.
  list-candidates    Print one line per status=candidate entry. Output:
                     <id><TAB><category><TAB><location><TAB><first_seen>
  promote <id> --driver P --verifier P --boundary S --precondition S --projected S
                     Flip status=candidate -> status=finding, attaching the
                     realism_attestation block. REQUIRED on every promotion
                     (schema v12 / PLUGIN_ISSUES.md recommendation B):
                       --driver       mechanical reproducer path
                       --verifier     CLI-style verify-*.sh against the REAL
                                      target binary (non-ASan, non-coverage);
                                      exit 0 ONLY when the boundary is crossed
                       --boundary     trust/privilege boundary crossed (string)
                       --precondition attacker precondition (string)
                       --projected    projected_vs_demonstrated narrative (string)
                     Soft complexity check on the verifier (WARN not reject):
                       poc.verifier_complexity_soft_max_lines (default 200)
                       poc.verifier_complexity_soft_max_tools (default 6)
                     in fuzz/state/fuzz-config.json.
  remove <id>        Backup-safe finding removal. Stages fuzz/findings/<id>/,
                     fuzz/crashes/known/<id>/, and the JSONL line to
                     fuzz/.trash/<ts>/ instead of hard-deleting.
  dedup H            Increment dedup_count and update last_seen for finding with stack_hash H.
                     Prints the matching finding's id.
  drop CRASH_FILE STAGE REASON [--principle P] [--evidence E]
                     Append a record to fuzz/state/dropped_crashes.jsonl explaining why
                     a crash candidate was filtered out by the triager (transparency log).
                     STAGE in: artifact_filter | deterministic_replay | target_realistic_reproducer.
                     PRINCIPLE required when STAGE=artifact_filter:
                       harness_correctness | api_contract | public_api_reachability | entry_point_currency

Per STATE_SCHEMA.md, this is the ONLY tool that should write to findings.jsonl.
EOF
    ;;
esac
