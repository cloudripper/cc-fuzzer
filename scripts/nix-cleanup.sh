#!/usr/bin/env bash
# nix-cleanup.sh — Remove nix GC roots left by this campaign's harness builds.
#
# nix-build.sh pins each build output via an --out-link symlink under
# fuzz/harnesses/<name>/harness/result-<variant>. These symlinks are the only
# thing keeping the store paths alive; removing them lets nix reclaim the
# space on the next garbage-collection run.
#
# Usage: nix-cleanup.sh [--gc] [--dry-run]
#   --gc       Run nix-store --gc immediately after removing roots
#   --dry-run  Print what would be removed; make no changes

set -u
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
. "$SCRIPT_DIR/_lib/path-anchor.sh"

DO_GC=0
DRY_RUN=0
for arg in "$@"; do
  case "$arg" in
    --gc)      DO_GC=1 ;;
    --dry-run) DRY_RUN=1 ;;
  esac
done

HARNESSES_DIR="${PROJECT_ROOT:-$PWD}/fuzz/harnesses"

if [ ! -d "$HARNESSES_DIR" ]; then
  echo "No fuzz/harnesses/ directory found — nothing to clean up."
  exit 0
fi

# Collect all result-* and result symlinks (GC roots created by nix-build.sh)
ROOTS=()
while IFS= read -r -d '' link; do
  ROOTS+=("$link")
done < <(find "$HARNESSES_DIR" -maxdepth 4 \( -name 'result-*' -o -name 'result' \) -type l -print0 2>/dev/null)

if [ "${#ROOTS[@]}" -eq 0 ]; then
  echo "No nix GC roots found under fuzz/harnesses/ — nothing to clean up."
  exit 0
fi

echo "Found ${#ROOTS[@]} nix GC root(s):"
echo ""
LIVE=0
BROKEN=0
for link in "${ROOTS[@]}"; do
  TARGET=$(readlink "$link" 2>/dev/null || echo "")
  if [ -z "$TARGET" ]; then
    echo "  [broken]  $link"
    BROKEN=$((BROKEN + 1))
  elif [[ "$TARGET" == /nix/store/* ]]; then
    if [ -e "$TARGET" ]; then
      echo "  [live]    $link"
      echo "            -> $TARGET"
      LIVE=$((LIVE + 1))
    else
      echo "  [gc'd]    $link"
      echo "            -> $TARGET  (store path already gone)"
      BROKEN=$((BROKEN + 1))
    fi
  else
    echo "  [other]   $link -> $TARGET"
  fi
done

echo ""
echo "Summary: $LIVE live store path(s), $BROKEN stale/broken root(s)"

if [ "$DRY_RUN" -eq 1 ]; then
  echo ""
  echo "[dry-run] No changes made."
  exit 0
fi

echo ""
echo "Removing GC roots..."
REMOVED=0
for link in "${ROOTS[@]}"; do
  if rm -f "$link"; then
    echo "  removed: $link"
    REMOVED=$((REMOVED + 1))
  else
    echo "  WARN: could not remove: $link" >&2
  fi
done

echo ""
echo "$REMOVED GC root(s) removed."

if [ "$DO_GC" -eq 1 ]; then
  if ! command -v nix-store >/dev/null 2>&1; then
    echo "WARNING: nix-store not found — skipping GC." >&2
    echo "Run 'nix-store --gc' or 'nix-collect-garbage' manually to reclaim store space."
    exit 0
  fi
  echo ""
  echo "Running nix-store --gc ..."
  nix-store --gc
else
  echo "Store paths are now eligible for collection."
  echo "Run 'nix-store --gc' (collect unreferenced paths) or 'nix-collect-garbage -d' (also delete old profiles) to reclaim space."
fi
