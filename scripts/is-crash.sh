#!/usr/bin/env bash
# is-crash.sh — classify sanitizer output as a crash or not.
#
# Reads captured output (stdin or first positional arg = file path) and emits a
# single-line JSON object describing whether the output represents a crash and,
# if so, what kind. Used by:
#   - reporting-agent's Step 3 classification
#   - crash-triager's Step 2 deterministic-replay check
#
# Output schema (always valid JSON, single line):
#   {
#     "is_crash":     <bool>,
#     "category":     "<heap-buffer-overflow|stack-buffer-overflow|global-buffer-overflow|"
#                     "heap-use-after-free|use-of-uninitialized-value|null-deref|"
#                     "stack-overflow|integer-overflow|signed-integer-overflow|"
#                     "assertion-failure|oom|timeout|segfault|abort|generic-crash|none>",
#     "summary_line": "<the sanitizer SUMMARY line if present, else first matching line, else "">",
#     "top_frame":    "<function @ file:line if extractable, else "">",
#     "exit_code":    <int or null — only set if --exit-code passed>
#   }
#
# Exit status:
#   0 — crash detected (is_crash == true)
#   1 — no crash (is_crash == false)
#   2 — usage error
#
# Usage:
#   bash is-crash.sh < captured_output.log
#   bash is-crash.sh captured_output.log
#   bash is-crash.sh --exit-code 134 < captured_output.log
#   bash is-crash.sh --exit-code 134 captured_output.log
#
# The --exit-code flag lets the caller pass the process's actual exit code so
# the classifier can detect crashes that produced no sanitizer output (e.g.,
# a raw SIGSEGV with no debug symbols).

set -euo pipefail

EXIT_CODE=""
INPUT_PATH=""

while [[ $# -gt 0 ]]; do
    case "$1" in
        --exit-code)
            EXIT_CODE="$2"
            shift 2
            ;;
        --help|-h)
            sed -n '2,/^$/p' "$0" | sed 's/^# \?//'
            exit 0
            ;;
        -*)
            echo "is-crash.sh: unknown flag: $1" >&2
            exit 2
            ;;
        *)
            if [[ -n "$INPUT_PATH" ]]; then
                echo "is-crash.sh: only one input path allowed" >&2
                exit 2
            fi
            INPUT_PATH="$1"
            shift
            ;;
    esac
done

# Read output into a variable so we can grep it multiple times.
if [[ -n "$INPUT_PATH" ]]; then
    if [[ ! -r "$INPUT_PATH" ]]; then
        echo "is-crash.sh: cannot read $INPUT_PATH" >&2
        exit 2
    fi
    OUTPUT=$(cat "$INPUT_PATH")
else
    OUTPUT=$(cat)
fi

# --- Detection -------------------------------------------------------------

IS_CRASH="false"
CATEGORY="none"
SUMMARY_LINE=""
TOP_FRAME=""

# 1. Sanitizer SUMMARY lines are the most reliable signal.
#    ASan: "SUMMARY: AddressSanitizer: heap-buffer-overflow ..."
#    UBSan: "SUMMARY: UndefinedBehaviorSanitizer: ..."
#    MSan: "SUMMARY: MemorySanitizer: use-of-uninitialized-value ..."
#    LSan: "SUMMARY: LeakSanitizer: ..."
SUMMARY=$(echo "$OUTPUT" | grep -E '^SUMMARY: (Address|UndefinedBehavior|Memory|Leak|Thread)Sanitizer:' | head -n 1 || true)

if [[ -n "$SUMMARY" ]]; then
    IS_CRASH="true"
    SUMMARY_LINE="$SUMMARY"
    # Extract category from the SUMMARY line.
    # Pattern: "SUMMARY: <Tool>Sanitizer: <category> [...]"
    CATEGORY=$(echo "$SUMMARY" | sed -E 's/^SUMMARY: [A-Za-z]+Sanitizer: ([a-zA-Z-]+).*/\1/')
    # Normalize known variants.
    case "$CATEGORY" in
        heap-buffer-overflow|stack-buffer-overflow|global-buffer-overflow) ;;
        heap-use-after-free|use-of-uninitialized-value) ;;
        stack-overflow|null-deref) ;;
        *)
            # Some ASan reports phrase null-deref as "SEGV on unknown address ... (pc 0x... bp ... sp ... T0)"
            # but the SUMMARY would say something like "AddressSanitizer: SEGV ..."
            if echo "$SUMMARY" | grep -qE 'SEGV|null'; then
                CATEGORY="null-deref"
            fi
            ;;
    esac
fi

# 2. ASan ERROR header (sometimes SUMMARY isn't emitted, e.g. on stack overflow).
if [[ "$IS_CRASH" == "false" ]]; then
    ASAN_ERR=$(echo "$OUTPUT" | grep -E '^==[0-9]+==ERROR: AddressSanitizer:' | head -n 1 || true)
    if [[ -n "$ASAN_ERR" ]]; then
        IS_CRASH="true"
        SUMMARY_LINE="$ASAN_ERR"
        # Extract category from the ERROR line.
        CATEGORY=$(echo "$ASAN_ERR" | sed -E 's/^==[0-9]+==ERROR: AddressSanitizer: ([a-zA-Z-]+).*/\1/')
        case "$CATEGORY" in
            stack-overflow) ;;
            SEGV) CATEGORY="null-deref" ;;
            *) ;;
        esac
    fi
fi

# 3. UBSan runtime errors. Format: "<file>:<line>:<col>: runtime error: <description>"
if [[ "$IS_CRASH" == "false" ]]; then
    UBSAN=$(echo "$OUTPUT" | grep -E ': runtime error: ' | head -n 1 || true)
    if [[ -n "$UBSAN" ]]; then
        IS_CRASH="true"
        SUMMARY_LINE="$UBSAN"
        # Map common UBSan messages to categories.
        case "$UBSAN" in
            *"signed integer overflow"*) CATEGORY="signed-integer-overflow" ;;
            *"unsigned integer overflow"*) CATEGORY="integer-overflow" ;;
            *"shift exponent"*) CATEGORY="ubsan-shift" ;;
            *"division by zero"*) CATEGORY="ubsan-div-zero" ;;
            *"load of misaligned"*) CATEGORY="ubsan-alignment" ;;
            *"null pointer"*) CATEGORY="null-deref" ;;
            *) CATEGORY="ubsan-other" ;;
        esac
    fi
fi

# 4. Plain-text crash indicators (binaries without sanitizers, or stripped output).
if [[ "$IS_CRASH" == "false" ]]; then
    if echo "$OUTPUT" | grep -qE '^(Segmentation fault|Abort trap|Aborted|Bus error)'; then
        IS_CRASH="true"
        SUMMARY_LINE=$(echo "$OUTPUT" | grep -E '^(Segmentation fault|Abort trap|Aborted|Bus error)' | head -n 1)
        case "$SUMMARY_LINE" in
            "Segmentation fault"*) CATEGORY="segfault" ;;
            "Abort trap"*|"Aborted"*) CATEGORY="abort" ;;
            "Bus error"*) CATEGORY="generic-crash" ;;
        esac
    fi
fi

# 5. Assertion failures (libc, glib, target asserts).
if [[ "$IS_CRASH" == "false" ]]; then
    ASSERT=$(echo "$OUTPUT" | grep -E 'Assertion .* failed|g_assertion_message|__assert_fail' | head -n 1 || true)
    if [[ -n "$ASSERT" ]]; then
        IS_CRASH="true"
        SUMMARY_LINE="$ASSERT"
        CATEGORY="assertion-failure"
    fi
fi

# 6. OOM signatures.
if [[ "$IS_CRASH" == "false" ]]; then
    if echo "$OUTPUT" | grep -qE 'out of memory|MemoryError|allocator_may_return_null|requested allocation size .* exceeds'; then
        IS_CRASH="true"
        SUMMARY_LINE=$(echo "$OUTPUT" | grep -E 'out of memory|MemoryError|allocator_may_return_null|requested allocation size .* exceeds' | head -n 1)
        CATEGORY="oom"
    fi
fi

# 7. libFuzzer timeout signature.
if [[ "$IS_CRASH" == "false" ]]; then
    if echo "$OUTPUT" | grep -qE 'ERROR: libFuzzer: timeout|DEADLYSIGNAL'; then
        IS_CRASH="true"
        SUMMARY_LINE=$(echo "$OUTPUT" | grep -E 'ERROR: libFuzzer: timeout|DEADLYSIGNAL' | head -n 1)
        # DEADLYSIGNAL is libFuzzer's catch-all for non-sanitizer crashes.
        if echo "$SUMMARY_LINE" | grep -q 'timeout'; then
            CATEGORY="timeout"
        else
            CATEGORY="generic-crash"
        fi
    fi
fi

# 8. Exit-code fallback (only when --exit-code was passed and nothing above matched).
if [[ "$IS_CRASH" == "false" && -n "$EXIT_CODE" ]]; then
    case "$EXIT_CODE" in
        134) IS_CRASH="true"; CATEGORY="abort";    SUMMARY_LINE="exit=134 (SIGABRT)" ;;
        139) IS_CRASH="true"; CATEGORY="segfault"; SUMMARY_LINE="exit=139 (SIGSEGV)" ;;
        137) IS_CRASH="true"; CATEGORY="oom";      SUMMARY_LINE="exit=137 (SIGKILL — OOM or external)" ;;
        135) IS_CRASH="true"; CATEGORY="generic-crash"; SUMMARY_LINE="exit=135 (SIGBUS)" ;;
        132) IS_CRASH="true"; CATEGORY="generic-crash"; SUMMARY_LINE="exit=132 (SIGILL)" ;;
        # Anything < 128 is a normal exit; ignore.
    esac
fi

# --- Top-frame extraction --------------------------------------------------
#
# Look for the FIRST non-infrastructure frame in the captured output.
# Frame patterns we care about:
#   "    #0 0x... in foo /path/to/file.c:123:4"      (ASan)
#   "    #0 0x... in foo /path/to/file.c:123"        (ASan)
#   "    #0 foo /path/to/file.c:123:4"               (ASan no-pc)
#   "    in foo /path/to/file.c:123"                 (UBSan)
#
# Infrastructure to skip (case-sensitive function-name prefixes):
INFRA_RE='__sanitizer_|__asan_|__ubsan_|__msan_|__lsan_|compiler-rt|asan_|ubsan_|msan_|fuzzer::|LLVMFuzzerTestOneInput'

if [[ "$IS_CRASH" == "true" ]]; then
    # Strategy: find lines that look like ASan/UBSan frames, extract function +
    # file:line, skip infrastructure, take the first survivor.
    TOP_FRAME=$(echo "$OUTPUT" \
        | grep -E '^\s*(#[0-9]+\s+(0x[0-9a-f]+\s+)?in\s+|in\s+)' \
        | awk '{
            # Find the "in <funcname>" anchor and the next token (path:line).
            for (i = 1; i <= NF; i++) {
                if ($i == "in") {
                    func = $(i+1);
                    loc  = $(i+2);
                    # Strip column suffix from "file.c:123:4" -> "file.c:123".
                    sub(/:[0-9]+$/, "", loc);
                    print func " @ " loc;
                    next;
                }
            }
        }' \
        | grep -vE "$INFRA_RE" \
        | head -n 1 \
        || true)
fi

# --- JSON emission ---------------------------------------------------------

json_escape() {
    # Minimal JSON string escaping: backslash, double-quote, newline, tab, CR.
    local s="$1"
    s="${s//\\/\\\\}"
    s="${s//\"/\\\"}"
    s="${s//$'\n'/\\n}"
    s="${s//$'\t'/\\t}"
    s="${s//$'\r'/\\r}"
    printf '%s' "$s"
}

EXIT_CODE_FIELD="null"
if [[ -n "$EXIT_CODE" ]]; then
    EXIT_CODE_FIELD="$EXIT_CODE"
fi

printf '{"is_crash":%s,"category":"%s","summary_line":"%s","top_frame":"%s","exit_code":%s}\n' \
    "$IS_CRASH" \
    "$(json_escape "$CATEGORY")" \
    "$(json_escape "$SUMMARY_LINE")" \
    "$(json_escape "$TOP_FRAME")" \
    "$EXIT_CODE_FIELD"

[[ "$IS_CRASH" == "true" ]] && exit 0 || exit 1
