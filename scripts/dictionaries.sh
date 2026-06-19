#!/usr/bin/env bash
# dictionaries.sh
#
# Manages the active dictionary list for the campaign. Updates
# fuzz/state/harness-built.json's dict_files array.
#
# Usage:
#   dictionaries.sh list              # list all available + which are active
#   dictionaries.sh available         # list only what's available (bundled + project-local)
#   dictionaries.sh active            # list only what's currently active in harness-built.json
#   dictionaries.sh add <name|path>   # add a dictionary to active set
#   dictionaries.sh remove <name>     # remove from active set
#   dictionaries.sh show <name>       # print contents of a dictionary
#
# Bundled dictionaries are looked up by short name (e.g. "utf-edge-cases").
# Custom dictionaries can be passed by full path (e.g. "fuzz/dictionaries/my.dict").

set -u

# Path anchor - refuses cwd inside fuzz/, refuses recursive fuzz/fuzz/
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
. "$SCRIPT_DIR/_lib/path-anchor.sh"

FUZZ_ROOT="${FUZZ_ROOT:-fuzz}"
STATE_DIR="$FUZZ_ROOT/state"
HARNESS_INFO="$STATE_DIR/harness-built.json"
PLUGIN_DICTS="${CLAUDE_PLUGIN_ROOT:-$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)}/dictionaries"
PROJECT_DICTS="$FUZZ_ROOT/dictionaries"

resolve_dict() {
  # Resolve a name or path to an absolute dictionary path. Returns empty if not found.
  local arg="$1"
  if [ -f "$arg" ]; then
    realpath "$arg" 2>/dev/null || echo "$arg"
    return 0
  fi
  if [ -f "$PROJECT_DICTS/$arg" ]; then
    realpath "$PROJECT_DICTS/$arg"; return 0
  fi
  if [ -f "$PROJECT_DICTS/$arg.dict" ]; then
    realpath "$PROJECT_DICTS/$arg.dict"; return 0
  fi
  if [ -f "$PLUGIN_DICTS/$arg" ]; then
    realpath "$PLUGIN_DICTS/$arg"; return 0
  fi
  if [ -f "$PLUGIN_DICTS/$arg.dict" ]; then
    realpath "$PLUGIN_DICTS/$arg.dict"; return 0
  fi
  echo ""
  return 1
}

cmd="${1:-list}"
shift || true

case "$cmd" in
  available)
    echo "Bundled (in plugin):"
    for f in "$PLUGIN_DICTS"/*.dict; do
      [ -f "$f" ] || continue
      base=$(basename "$f" .dict)
      printf "  %-40s %s\n" "$base" "$f"
    done
    if [ -d "$PROJECT_DICTS" ]; then
      echo ""
      echo "Project-local (in $PROJECT_DICTS):"
      for f in "$PROJECT_DICTS"/*.dict; do
        [ -f "$f" ] || continue
        base=$(basename "$f" .dict)
        printf "  %-40s %s\n" "$base" "$f"
      done
    fi
    ;;

  active)
    if [ ! -f "$HARNESS_INFO" ]; then
      echo "No campaign found ($HARNESS_INFO missing)."
      exit 0
    fi
    python3 -c "
import json
d = json.load(open('$HARNESS_INFO'))
files = d.get('dict_files') or ([d['dict_file']] if d.get('dict_file') else [])
if files:
    for f in files: print(f)
else:
    print('(none)')
"
    ;;

  list)
    bash "$0" available
    echo ""
    echo "Active in current campaign:"
    bash "$0" active 2>/dev/null | sed 's/^/  /'
    ;;

  add)
    NAME="${1:?dictionary name or path required}"
    PATH_RESOLVED=$(resolve_dict "$NAME")
    if [ -z "$PATH_RESOLVED" ]; then
      echo "ERROR: dictionary '$NAME' not found." >&2
      echo "  searched: $PROJECT_DICTS/$NAME(.dict), $PLUGIN_DICTS/$NAME(.dict)" >&2
      echo "  use 'dictionaries.sh available' to see what's bundled" >&2
      exit 1
    fi

    if [ ! -f "$HARNESS_INFO" ]; then
      echo "ERROR: $HARNESS_INFO not found - run /cc-fuzzer:campaign first" >&2
      exit 1
    fi

    # Atomically update harness-built.json's dict_files array
    TMP="$HARNESS_INFO.tmp"
    python3 -c "
import json
d = json.load(open('$HARNESS_INFO'))
files = d.get('dict_files')
if files is None:
    files = [d['dict_file']] if d.get('dict_file') else []
if '$PATH_RESOLVED' in files:
    print('already-active')
else:
    files.append('$PATH_RESOLVED')
    print('added')
d['dict_files'] = files
# Drop the legacy single-string field if present
d.pop('dict_file', None)
json.dump(d, open('$TMP', 'w'), indent=2)
" || { rm -f "$TMP"; exit 1; }
    mv "$TMP" "$HARNESS_INFO"
    echo "  $PATH_RESOLVED"
    echo ""
    echo "NOTE: the running fuzzer must be restarted to pick up the new dictionary."
    echo "      run /fuzz-stop then /cc-fuzzer:resume-campaign"
    ;;

  remove)
    NAME="${1:?dictionary name or path required}"
    PATH_RESOLVED=$(resolve_dict "$NAME")
    [ -z "$PATH_RESOLVED" ] && PATH_RESOLVED="$NAME"  # might be an exact path that doesn't exist anymore

    if [ ! -f "$HARNESS_INFO" ]; then
      echo "ERROR: $HARNESS_INFO not found" >&2
      exit 1
    fi

    TMP="$HARNESS_INFO.tmp"
    python3 -c "
import json, os
d = json.load(open('$HARNESS_INFO'))
files = d.get('dict_files') or ([d['dict_file']] if d.get('dict_file') else [])
target = '$PATH_RESOLVED'
target_basename = os.path.basename(target)
new = [f for f in files if f != target and os.path.basename(f) != target_basename]
removed = len(files) - len(new)
d['dict_files'] = new
d.pop('dict_file', None)
json.dump(d, open('$TMP', 'w'), indent=2)
print(f'removed {removed} entries')
"
    mv "$TMP" "$HARNESS_INFO"
    ;;

  show)
    NAME="${1:?dictionary name required}"
    PATH_RESOLVED=$(resolve_dict "$NAME")
    if [ -z "$PATH_RESOLVED" ]; then
      echo "ERROR: dictionary '$NAME' not found." >&2
      exit 1
    fi
    cat "$PATH_RESOLVED"
    ;;

  help|*)
    cat <<EOF
dictionaries.sh - manage cc-fuzzer dictionaries

Commands:
  list                List all available + which are active
  available           List bundled and project-local dictionaries
  active              List dictionaries active in current campaign
  add <name|path>     Add a dictionary to the active set
  remove <name>       Remove from active set
  show <name>         Print the dictionary contents

Bundled dictionaries (plugin tree, read-only):
  $PLUGIN_DICTS

Project-local dictionaries (yours, edit freely):
  $PROJECT_DICTS

Active dictionaries are recorded in:
  $HARNESS_INFO  (dict_files array)

The fuzzer must be restarted (/fuzz-stop then /cc-fuzzer:resume-campaign) for
dictionary changes to take effect.
EOF
    ;;
esac
