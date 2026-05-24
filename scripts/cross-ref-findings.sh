#!/usr/bin/env bash
# cross-ref-findings.sh — match a finding's location against code-review and
# CVE intelligence snapshots, emit a single-line JSON object the reporting-agent
# can render directly.
#
# Reads:
#   fuzz/state/snapshots/code-review-*.json   (latest by mtime)
#   fuzz/state/snapshots/cve-context-*.json   (latest by mtime)
# Either may be absent — the helper returns empty arrays in that case.
#
# Output schema (always valid JSON, single line):
#   {
#     "location": "<function>@<file>:<line>",
#     "function": "<function>",
#     "file":     "<file>",
#     "code_review": [
#       {
#         "id":                     "<cr id, e.g. cr012>",
#         "pattern":                "<pattern name>",
#         "confidence":             "<low|medium|high>",
#         "evidence":               "<evidence string>",
#         "fuzzing_recommendation": "<reviewer recommendation>"
#       }, ...
#     ],
#     "cve_history": [
#       {
#         "cve":          "<CVE-YYYY-NNNNN>",
#         "category":     "<category from the cve record>",
#         "function":     "<function from the matched patch>",
#         "patched_date": "<YYYY-MM-DD>",
#         "patch_idiom":  "<one-line description of the patch shape>"
#       }, ...
#     ],
#     "snapshots": {
#       "code_review_file": "<path or null>",
#       "cve_context_file": "<path or null>"
#     }
#   }
#
# Exit status:
#   0 — success (matches may be empty)
#   2 — usage error (bad location format)
#
# Usage:
#   bash cross-ref-findings.sh '<function>@<file>:<line>'
#   bash cross-ref-findings.sh --location '<function>@<file>:<line>'
#
# Examples:
#   bash cross-ref-findings.sh 'xmlParseAttValue@parser.c:9842'
#   bash cross-ref-findings.sh 'get_wchar@charset.c:661'

set -euo pipefail

LOCATION=""

while [[ $# -gt 0 ]]; do
    case "$1" in
        --location)
            LOCATION="$2"
            shift 2
            ;;
        --help|-h)
            sed -n '2,/^$/p' "$0" | sed 's/^# \?//'
            exit 0
            ;;
        -*)
            echo "cross-ref-findings.sh: unknown flag: $1" >&2
            exit 2
            ;;
        *)
            if [[ -n "$LOCATION" ]]; then
                echo "cross-ref-findings.sh: only one location allowed" >&2
                exit 2
            fi
            LOCATION="$1"
            shift
            ;;
    esac
done

if [[ -z "$LOCATION" ]]; then
    echo "cross-ref-findings.sh: missing location (usage: bash $0 '<fn>@<file>:<line>')" >&2
    exit 2
fi

# --- Parse location -------------------------------------------------------
#
# Canonical form: "<function>@<file>:<line>"
# - <function> may contain [A-Za-z0-9_:~<>] (covers C++ qualified names + dtors + templates)
# - <file> may contain / . _ - alphanumerics
# - <line> is digits

if ! [[ "$LOCATION" =~ ^([^@]+)@([^:]+):([0-9]+)$ ]]; then
    echo "cross-ref-findings.sh: bad location format '$LOCATION' (expected '<function>@<file>:<line>')" >&2
    exit 2
fi

FUNCTION="${BASH_REMATCH[1]}"
FILE="${BASH_REMATCH[2]}"
LINE="${BASH_REMATCH[3]}"

# Use the basename of the file for matching (snapshots may carry full project-
# relative paths while findings carry only the basename, or vice versa).
FILE_BASENAME="$(basename "$FILE")"

# --- Locate the latest snapshots ------------------------------------------

SNAPSHOTS_DIR="fuzz/state/snapshots"
CODE_REVIEW_FILE=""
CVE_CONTEXT_FILE=""

if [[ -d "$SNAPSHOTS_DIR" ]]; then
    # ls -t sorts by mtime descending; head -1 picks the newest.
    CODE_REVIEW_FILE=$(ls -1t "$SNAPSHOTS_DIR"/code-review-*.json 2>/dev/null | head -1 || true)
    CVE_CONTEXT_FILE=$(ls -1t "$SNAPSHOTS_DIR"/cve-context-*.json 2>/dev/null | head -1 || true)
fi

# --- Helpers ---------------------------------------------------------------

require_jq() {
    if ! command -v jq >/dev/null 2>&1; then
        echo "cross-ref-findings.sh: jq is required but not found in PATH" >&2
        exit 2
    fi
}

json_null_or_string() {
    # Emit either `null` (no quotes) or a JSON-escaped quoted string.
    local v="$1"
    if [[ -z "$v" ]]; then
        printf 'null'
    else
        # jq is the safest way to emit a properly-escaped JSON string.
        printf '%s' "$v" | jq -Rs .
    fi
}

# --- Match against code-review --------------------------------------------
#
# Code-review snapshot is expected to follow schema (per STATE_SCHEMA):
#   {
#     "schema": "code-review/v1",
#     "findings": [
#       {
#         "id": "cr012",
#         "function": "xmlParseAttValue",
#         "file": "parser.c"  OR  "src/parser/parser.c",
#         "pattern": "missing-bounds-check",
#         "confidence": "high",
#         "evidence": "...",
#         "fuzzing_recommendation": "..."
#       }, ...
#     ],
#     ...
#   }
#
# Matching rule (per the agent prompt):
#   findings[i].function == <function>  AND  findings[i].file ends with <file_basename>

CODE_REVIEW_MATCHES="[]"

if [[ -n "$CODE_REVIEW_FILE" && -r "$CODE_REVIEW_FILE" ]]; then
    require_jq
    CODE_REVIEW_MATCHES=$(jq --arg fn "$FUNCTION" --arg fb "$FILE_BASENAME" '
        (.findings // [])
        | map(select(
            (.function // "") == $fn
            and ((.file // "") | endswith($fb))
          ))
        | map({
            id:                     (.id // null),
            pattern:                (.pattern // null),
            confidence:             (.confidence // null),
            evidence:               (.evidence // null),
            fuzzing_recommendation: (.fuzzing_recommendation // null)
          })
    ' "$CODE_REVIEW_FILE" 2>/dev/null || echo "[]")
fi

# --- Match against CVE context --------------------------------------------
#
# CVE-context snapshot is expected to follow schema (per STATE_SCHEMA):
#   {
#     "schema": "cve-context/v1",
#     "cves": [
#       {
#         "cve": "CVE-2022-29824",
#         "category": "int_overflow",
#         "patches": [
#           {
#             "files_changed":     ["parser.c"]  or ["src/parser/parser.c", ...],
#             "functions_changed": ["xmlBufferAdd"],
#             "patched_date":      "2022-06-27",
#             "patch_idiom":       "added a SIZE_MAX guard around the length arithmetic"
#           }
#         ]
#       }, ...
#     ],
#     ...
#   }
#
# Matching rule (per the agent prompt):
#   For each cve, for each patch:
#     patches[].files_changed     contains an entry that ends with <file_basename>
#     patches[].functions_changed contains <function>
#   Emit one match per (cve, patch) that satisfies both. If the same CVE has
#   multiple matching patches, emit each (the reporter may dedup by cve id if
#   it wants).

CVE_MATCHES="[]"

if [[ -n "$CVE_CONTEXT_FILE" && -r "$CVE_CONTEXT_FILE" ]]; then
    require_jq
    CVE_MATCHES=$(jq --arg fn "$FUNCTION" --arg fb "$FILE_BASENAME" '
        (.cves // [])
        | map(
            . as $cve
            | (.patches // [])
            | map(select(
                ((.functions_changed // []) | index($fn))
                and ((.files_changed // []) | map(endswith($fb)) | any)
              ))
            | map({
                cve:          ($cve.cve // null),
                category:     ($cve.category // null),
                function:     $fn,
                patched_date: (.patched_date // null),
                patch_idiom:  (.patch_idiom // null)
              })
          )
        | flatten
    ' "$CVE_CONTEXT_FILE" 2>/dev/null || echo "[]")
fi

# --- Emit combined JSON ---------------------------------------------------

# Fast path: no snapshots present → emit hand-rolled JSON with empty arrays.
# This avoids requiring jq for the common case of no intel data.
if [[ -z "$CODE_REVIEW_FILE" && -z "$CVE_CONTEXT_FILE" ]]; then
    # Escape function/file using printf %q? No — we need JSON escaping, not shell.
    # Use a tiny inline Python shim, which is more universally available than jq.
    if command -v python3 >/dev/null 2>&1; then
        python3 -c '
import json, sys
print(json.dumps({
    "location": sys.argv[1],
    "function": sys.argv[2],
    "file":     sys.argv[3],
    "code_review": [],
    "cve_history": [],
    "snapshots": {
        "code_review_file": None,
        "cve_context_file": None
    }
}, separators=(",", ":")))
' "$LOCATION" "$FUNCTION" "$FILE"
        exit 0
    fi
    # Fall through to jq if python3 is also unavailable.
fi

# Assemble the output with jq (this guarantees valid JSON regardless of how
# weird the input strings might be).
require_jq

LOCATION_JSON=$(printf '%s' "$LOCATION" | jq -Rs .)
FUNCTION_JSON=$(printf '%s' "$FUNCTION" | jq -Rs .)
FILE_JSON=$(printf '%s' "$FILE" | jq -Rs .)

CODE_REVIEW_FILE_JSON=$(json_null_or_string "$CODE_REVIEW_FILE")
CVE_CONTEXT_FILE_JSON=$(json_null_or_string "$CVE_CONTEXT_FILE")

# Compact single-line output.
jq -c -n \
    --argjson location     "$LOCATION_JSON" \
    --argjson function     "$FUNCTION_JSON" \
    --argjson file         "$FILE_JSON" \
    --argjson code_review  "$CODE_REVIEW_MATCHES" \
    --argjson cve_history  "$CVE_MATCHES" \
    --argjson cr_snapshot  "$CODE_REVIEW_FILE_JSON" \
    --argjson cve_snapshot "$CVE_CONTEXT_FILE_JSON" \
    '{
        location:    $location,
        function:    $function,
        file:        $file,
        code_review: $code_review,
        cve_history: $cve_history,
        snapshots: {
            code_review_file: $cr_snapshot,
            cve_context_file: $cve_snapshot
        }
    }'
