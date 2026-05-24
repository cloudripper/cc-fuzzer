#!/usr/bin/env bash
# _lib/harness-path.sh
#
# Central per-harness path resolver for cc-fuzzer (schema v9). Every
# downstream script that touches a per-harness file (corpus, coverage,
# snapshot, crash) sources this library and uses its helpers. That is how the
# singular/multi mode switch stays contained to one place — callers stop
# branching on the mode themselves and instead call functions that produce
# the correct path for whichever mode is active.
#
# Source order (callers):
#   . "$SCRIPT_DIR/_lib/path-anchor.sh"   # sets $FUZZ_ROOT, $PROJECT_ROOT
#   . "$SCRIPT_DIR/_lib/harness-path.sh"  # provides path helpers
#
# Public API (sourced):
#   is_multi                              # exit 0 if multi mode active
#   declared_harnesses                    # print declared harness names, one per line
#   is_known_harness <name>               # exit 0 if name is declared
#   default_harness                       # singular: entry_function; multi: harnesses[0]
#   harness_root <name>                   # bundle root (multi) or fuzz/ (singular)
#   harness_dir <name>                    # <root>/harness  (or fuzz/harness)
#   corpus_dir <name>                     # <root>/corpus
#   quarantine_dir <name>                 # <root>/corpus-quarantine
#   coverage_dir <name>                   # <root>/coverage
#   coverage_snapshot_name <name> <ts>    # basename for state/snapshots/coverage-*
#   gaps_snapshot_name <name> <ts>        # basename for state/snapshots/gaps-*
#   concolic_snapshot_name <name> <ts>    # basename for state/snapshots/concolic-*
#   cmplog_dict_name <name> <ts>          # basename for state/cmplog-dict-*
#   crash_filename <name> <hash>          # basename for fuzz/crashes/new/
#   parse_crash_filename <path>           # print "<harness>\t<hash>" (harness empty in singular)
#   harness_field <name> <field>          # read a per-harness record field
#   harness_binary <name>                 # convenience for harness_field <name> harness_binary
#   slot_to_harness <slot>                # read fuzzers.json; empty string in singular mode
#   afl_instances <out_dir>               # AFL++ instance dirs under out_dir (default first)
#
# In singular mode, the <name> argument is ignored by the path/filename
# helpers — they return the singular paths regardless. Callers may pass any
# name (typically "main" or the entry function name). This lets the caller
# code be mode-agnostic.
#
# CLI dispatch (when invoked directly, for testing): same names as the
# functions. Run `bash _lib/harness-path.sh help` for the full list.

# Internal cache so we don't re-read fuzz-config.json on every helper call
_HP_MODE=""
_HP_DECLARED=()

_hp_state_dir() { echo "${FUZZ_STATE_DIR:-${FUZZ_ROOT:-fuzz}/state}"; }

_hp_detect_mode() {
  [ -n "$_HP_MODE" ] && return 0
  _HP_MODE="singular"
  _HP_DECLARED=()
  local cfg
  cfg="$(_hp_state_dir)/fuzz-config.json"
  [ -f "$cfg" ] || return 0
  local names
  names=$(CFG="$cfg" python3 - <<'PY' 2>/dev/null
import json, os
try:
    d = json.load(open(os.environ['CFG']))
    hs = d.get('harnesses') or []
    if isinstance(hs, list):
        for h in hs:
            if isinstance(h, dict) and h.get('name'):
                print(h['name'])
except Exception:
    pass
PY
)
  if [ -n "$names" ]; then
    _HP_MODE="multi"
    while IFS= read -r n; do
      [ -n "$n" ] && _HP_DECLARED+=("$n")
    done <<< "$names"
  fi
}

# Invalidate the cache. Call this after modifying fuzz-config.json (e.g.
# during the singular -> multi upgrade) so subsequent helper calls re-detect.
hp_invalidate_cache() {
  _HP_MODE=""
  _HP_DECLARED=()
}

#------------------------------------------------------------------------------
# Mode + declared-harnesses queries
#------------------------------------------------------------------------------

is_multi() {
  _hp_detect_mode
  [ "$_HP_MODE" = "multi" ]
}

declared_harnesses() {
  _hp_detect_mode
  printf '%s\n' "${_HP_DECLARED[@]:-}"
}

is_known_harness() {
  _hp_detect_mode
  local n
  for n in "${_HP_DECLARED[@]:-}"; do
    [ "$n" = "$1" ] && return 0
  done
  return 1
}

# Singular: read harness-built.json:entry_function (the implicit harness name).
# Multi:    return harnesses[0] (first declared, declaration order is canonical).
# Empty if neither source is available.
default_harness() {
  _hp_detect_mode
  if is_multi; then
    printf '%s\n' "${_HP_DECLARED[0]:-}"
    return
  fi
  local hbj
  hbj="$(_hp_state_dir)/harness-built.json"
  [ -f "$hbj" ] || { echo ""; return; }
  HBJ="$hbj" python3 - <<'PY' 2>/dev/null
import json, os
try:
    print(json.load(open(os.environ['HBJ'])).get('entry_function',''))
except Exception:
    pass
PY
}

#------------------------------------------------------------------------------
# Per-harness directory paths
#
# In singular mode, the name argument is ignored. Callers may pass anything.
#------------------------------------------------------------------------------

_hp_fuzz_root() { echo "${FUZZ_ROOT:-fuzz}"; }

harness_root() {
  _hp_detect_mode
  if is_multi; then
    echo "$(_hp_fuzz_root)/harnesses/$1"
  else
    _hp_fuzz_root
  fi
}

harness_dir() {
  _hp_detect_mode
  if is_multi; then
    echo "$(_hp_fuzz_root)/harnesses/$1/harness"
  else
    echo "$(_hp_fuzz_root)/harness"
  fi
}

corpus_dir() {
  _hp_detect_mode
  if is_multi; then
    echo "$(_hp_fuzz_root)/harnesses/$1/corpus"
  else
    echo "$(_hp_fuzz_root)/corpus"
  fi
}

quarantine_dir() {
  _hp_detect_mode
  if is_multi; then
    echo "$(_hp_fuzz_root)/harnesses/$1/corpus-quarantine"
  else
    echo "$(_hp_fuzz_root)/corpus-quarantine"
  fi
}

coverage_dir() {
  _hp_detect_mode
  if is_multi; then
    echo "$(_hp_fuzz_root)/harnesses/$1/coverage"
  else
    echo "$(_hp_fuzz_root)/coverage"
  fi
}

#------------------------------------------------------------------------------
# Snapshot / dict filename helpers (just the basename, not the full path)
#------------------------------------------------------------------------------

coverage_snapshot_name() {
  _hp_detect_mode
  local name="$1" ts="$2"
  if is_multi; then
    echo "coverage-${name}-${ts}.json"
  else
    echo "coverage-${ts}.json"
  fi
}

gaps_snapshot_name() {
  _hp_detect_mode
  local name="$1" ts="$2"
  if is_multi; then
    echo "gaps-${name}-${ts}.json"
  else
    echo "gaps-${ts}.json"
  fi
}

concolic_snapshot_name() {
  _hp_detect_mode
  local name="$1" ts="$2"
  if is_multi; then
    echo "concolic-${name}-${ts}.json"
  else
    echo "concolic-${ts}.json"
  fi
}

cmplog_dict_name() {
  _hp_detect_mode
  local name="$1" ts="$2"
  if is_multi; then
    echo "cmplog-dict-${name}-${ts}.dict"
  else
    echo "cmplog-dict-${ts}.dict"
  fi
}

#------------------------------------------------------------------------------
# Crash filename helpers (basename for fuzz/crashes/new/)
#
# In multi mode: <harness>__<hash>.bin    (double-underscore separator)
# In singular:   <hash>.bin
#------------------------------------------------------------------------------

crash_filename() {
  _hp_detect_mode
  local name="$1" hash="$2"
  if is_multi; then
    echo "${name}__${hash}.bin"
  else
    echo "${hash}.bin"
  fi
}

# Parse a fuzz/crashes/new/ filename and print "<harness>\t<hash>"
# In singular mode, harness is empty.
# Returns nonzero if the filename doesn't conform.
parse_crash_filename() {
  _hp_detect_mode
  local base
  base=$(basename "$1")
  base="${base%.bin}"
  if is_multi; then
    if [[ "$base" =~ ^([a-z0-9][a-z0-9_-]{0,31})__([0-9a-f]+)$ ]]; then
      printf '%s\t%s\n' "${BASH_REMATCH[1]}" "${BASH_REMATCH[2]}"
      return 0
    fi
    return 1
  else
    printf '\t%s\n' "$base"
    return 0
  fi
}

#------------------------------------------------------------------------------
# Per-harness record access
#
# Multi mode:    reads from state/harnesses.json by name match
# Singular mode: reads from state/harness-built.json (name argument ignored)
#------------------------------------------------------------------------------

harness_field() {
  _hp_detect_mode
  local name="$1" field="$2"
  local sd
  sd="$(_hp_state_dir)"
  if is_multi; then
    HNAME="$name" FIELD="$field" HS="$sd/harnesses.json" python3 - <<'PY' 2>/dev/null
import json, os
try:
    doc = json.load(open(os.environ['HS']))
    for h in doc.get('harnesses', []):
        if h.get('name') == os.environ['HNAME']:
            v = h.get(os.environ['FIELD'])
            if v is None: pass
            elif isinstance(v, (list, dict)): print(json.dumps(v))
            else: print(v)
            break
except Exception:
    pass
PY
  else
    FIELD="$field" HBJ="$sd/harness-built.json" python3 - <<'PY' 2>/dev/null
import json, os
try:
    d = json.load(open(os.environ['HBJ']))
    v = d.get(os.environ['FIELD'])
    if v is None: pass
    elif isinstance(v, (list, dict)): print(json.dumps(v))
    else: print(v)
except Exception:
    pass
PY
  fi
}

harness_binary() { harness_field "$1" harness_binary; }

#------------------------------------------------------------------------------
# Slot -> harness lookup
#
# Multi:    reads fuzzers.json:slots[<slot>].harness
# Singular: returns empty string (single implicit harness; caller should fall
#           back to default_harness if it needs a name)
#------------------------------------------------------------------------------

slot_to_harness() {
  _hp_detect_mode
  local slot="$1"
  if ! is_multi; then
    echo ""
    return
  fi
  SLOT="$slot" MF="$(_hp_state_dir)/fuzzers.json" python3 - <<'PY' 2>/dev/null
import json, os
try:
    doc = json.load(open(os.environ['MF']))
    for s in doc.get('slots', []):
        if s.get('slot') == os.environ['SLOT']:
            print(s.get('harness',''))
            break
except Exception:
    pass
PY
}

#------------------------------------------------------------------------------
# AFL++ instance directories
#
# AFL++ writes each fuzzer instance into <out_dir>/<instance>/. The instance
# name is the slot when launched with -M/-S (parallel campaigns), or "default"
# for a roleless single instance. Scripts that read fuzzer_stats or harvest
# cmplog data must not assume "default" — a -M main slot lands in <out>/main/.
#
# afl_instances <out_dir>: print existing instance dir paths (those with a
# fuzzer_stats file or a queue/ dir), "default" first when present so the
# common single-slot case keeps reading the same dir. Empty if none.
#------------------------------------------------------------------------------

afl_instances() {
  local out_dir="$1"
  [ -d "$out_dir" ] || return 0
  if [ -d "$out_dir/default" ] && { [ -f "$out_dir/default/fuzzer_stats" ] || [ -d "$out_dir/default/queue" ]; }; then
    echo "$out_dir/default"
  fi
  local d base
  for d in "$out_dir"/*/; do
    [ -d "$d" ] || continue
    base=$(basename "$d")
    [ "$base" = default ] && continue
    if [ -f "${d}fuzzer_stats" ] || [ -d "${d}queue" ]; then
      echo "${d%/}"
    fi
  done
}

#------------------------------------------------------------------------------
# CLI dispatch (only when invoked directly, not when sourced)
#------------------------------------------------------------------------------

if [ "${BASH_SOURCE[0]}" = "$0" ]; then
  cmd="${1:-help}"
  shift || true
  case "$cmd" in
    is_multi)
      is_multi && echo "multi" || echo "singular"
      ;;
    declared_harnesses)
      declared_harnesses
      ;;
    is_known_harness)
      is_known_harness "${1:-}" && echo "yes" || { echo "no"; exit 1; }
      ;;
    default_harness)
      default_harness
      ;;
    harness_root|harness_dir|corpus_dir|quarantine_dir|coverage_dir)
      "$cmd" "${1:-}"
      ;;
    coverage_snapshot_name|gaps_snapshot_name|concolic_snapshot_name|cmplog_dict_name|crash_filename)
      "$cmd" "${1:-}" "${2:-}"
      ;;
    parse_crash_filename|harness_binary|slot_to_harness|afl_instances)
      "$cmd" "${1:-}"
      ;;
    harness_field)
      harness_field "${1:-}" "${2:-}"
      ;;
    help|--help|-h|*)
      cat <<EOF
_lib/harness-path.sh - per-harness path resolver (schema v9)

Mode + declared-harnesses queries:
  is_multi                              # prints "multi" or "singular"
  declared_harnesses                    # prints declared harness names (one per line)
  is_known_harness <name>               # exit 0 if name is declared
  default_harness                       # singular: entry_function; multi: harnesses[0]

Directory paths (in singular mode, <name> is ignored):
  harness_root <name>                   # bundle root
  harness_dir <name>                    # <root>/harness
  corpus_dir <name>                     # <root>/corpus
  quarantine_dir <name>                 # <root>/corpus-quarantine
  coverage_dir <name>                   # <root>/coverage

Filename helpers (basenames):
  coverage_snapshot_name <name> <ts>    # state/snapshots/coverage-*
  gaps_snapshot_name <name> <ts>        # state/snapshots/gaps-*
  concolic_snapshot_name <name> <ts>    # state/snapshots/concolic-*
  cmplog_dict_name <name> <ts>          # state/cmplog-dict-*
  crash_filename <name> <hash>          # crashes/new/<harness>__<hash>.bin
  parse_crash_filename <path>           # prints "<harness>\t<hash>"

Per-harness record access:
  harness_field <name> <field>          # arbitrary field from per-harness record
  harness_binary <name>                 # shorthand for harness_field <name> harness_binary
  slot_to_harness <slot>                # from fuzzers.json
EOF
      ;;
  esac
fi
