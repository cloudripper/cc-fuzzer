#!/usr/bin/env bash
# campaign-init.sh — set up a campaign's nix dev shell. Run via
# `nix run <cc-fuzzer>#init`. It does NOT launch Claude; when done it PRINTS the
# commands to launch Claude (inside the composed FHS shell) and to open the
# shell alone.
#
# Why a separate shell: each Claude Code Bash tool call inherits the env Claude
# was LAUNCHED in; a skill can't switch the session's shell mid-campaign (and
# can't background the fuzzer inside a transient `nix develop -c`). So the
# campaign must run with the target's build deps already in the env — i.e.
# Claude must be launched inside the composed shell. #init builds that shell;
# YOU then launch Claude into it with the printed command.
#
# Flow:
#   1. Scaffold ./flake.nix (composes the cc-fuzzer toolchain) + ./fuzz/nix-deps.nix.
#   2. Headless agentic dep resolution: `claude -p` edits ./fuzz/nix-deps.nix
#      until the dev shell EVALUATES (`nix eval …drvPath`), pinning exact nixpkgs
#      attrs (cap CCFUZZER_INIT_CAP). Runs when the deps list is EMPTY or --force.
#   3. `nix flake lock`, then print the launch + shell commands. (No launch.)
#
# Env (set by apps.init): CCFUZZER_SRC, CCFUZZER_SYSTEM, CCFUZZER_INIT_CAP.

set -euo pipefail

usage() {
  cat <<'USAGE'
nix run <cc-fuzzer>#init — set up a campaign's nix dev shell (does NOT launch Claude).

Flags:
  --dep <attr>   seed a build dep up front (repeatable); suppresses the scan
  --no-scan      skip the headless dep scan (seed with --dep or hand-edit)
  --force        regenerate from scratch (rewrite ./fuzz/nix-deps.nix + re-scan)
  -h | --help    show this help

When finished it prints the commands to launch Claude in the campaign shell and
to open the dev shell alone.
USAGE
}

SRC="${CCFUZZER_SRC:?CCFUZZER_SRC not set (run via 'nix run <cc-fuzzer>#init')}"
SYS="${CCFUZZER_SYSTEM:-x86_64-linux}"
CAP="${CCFUZZER_INIT_CAP:-10}"
PROJECT_ROOT="$PWD"

DEPS=()
DO_SCAN=true
FORCE=false

while [ $# -gt 0 ]; do
  case "$1" in
    --dep)     DEPS+=("${2:?--dep needs an attr}"); shift 2 ;;
    --no-scan) DO_SCAN=false; shift ;;
    --force)   FORCE=true; shift ;;
    -h|--help) usage; exit 0 ;;
    *) echo "ERROR: unknown flag '$1' (see --help)" >&2; exit 2 ;;
  esac
done

FLAKE="$PROJECT_ROOT/flake.nix"
DEPS_FILE="$PROJECT_ROOT/fuzz/nix-deps.nix"

# True if ./fuzz/nix-deps.nix declares at least one package. Strips comments and
# whitespace; an empty list collapses to a body ending in "[]".
deps_nonempty() {
  local body
  body=$(sed 's/#.*//' "$DEPS_FILE" 2>/dev/null | tr -d '[:space:]')
  case "$body" in *'[]') return 1 ;; *) return 0 ;; esac
}

# ---------------------------------------------------------------------------
# 1. Scaffold
# ---------------------------------------------------------------------------
# flake.nix is a GENERATED artifact — always (re)write it so a re-run refreshes
# the pinned plugin source (CCFUZZER_SRC) and picks up app/structure changes (a
# re-run after a plugin update repairs an old project flake). Resolved deps in
# fuzz/nix-deps.nix are PRESERVED unless --force.
mkdir -p "$PROJECT_ROOT/fuzz"

sed -e "s|@CCFUZZER_SRC@|$SRC|g" -e "s|@SYSTEM@|$SYS|g" \
  "$SRC/templates/project-flake.nix" > "$FLAKE"
echo "wrote $FLAKE (ccfuzzer input: $SRC)"

if [ ! -f "$DEPS_FILE" ] || [ "$FORCE" = true ]; then
  if [ "${#DEPS[@]}" -gt 0 ]; then
    printf 'pkgs: with pkgs; [ %s ]\n' "${DEPS[*]}" > "$DEPS_FILE"
    echo "wrote $DEPS_FILE (seeded: ${DEPS[*]})"
  else
    cp "$SRC/templates/nix-deps.nix" "$DEPS_FILE"
    echo "wrote $DEPS_FILE (empty)"
  fi
else
  echo "kept existing $DEPS_FILE"
fi

# Nix flakes only see git-TRACKED files in a git repo. Stage the flake files
# (idempotent) so `nix eval`/`nix develop` can read them; later edits to tracked
# files are picked up even when uncommitted.
if git -C "$PROJECT_ROOT" rev-parse --is-inside-work-tree >/dev/null 2>&1; then
  git -C "$PROJECT_ROOT" add -f flake.nix fuzz/nix-deps.nix 2>/dev/null \
    && echo "staged flake.nix + fuzz/nix-deps.nix (so the flake can read them)"
fi

GATE="nix eval .#devShells.${SYS}.default.drvPath"

# ---------------------------------------------------------------------------
# 2. Headless agentic dep resolution
# ---------------------------------------------------------------------------
# Run the scan when the deps list is EMPTY (fresh, prior-empty, or a scan that
# earlier produced nothing) or --force — NOT merely when the file is absent.
# That makes a re-run retry a scan that came up empty. Skip when deps already
# exist (unless --force), or when --dep / --no-scan was given.
WANT_SCAN=false
if [ "$DO_SCAN" = true ] && [ "${#DEPS[@]}" -eq 0 ]; then
  if [ "$FORCE" = true ] || ! deps_nonempty; then WANT_SCAN=true; fi
fi

if [ "$WANT_SCAN" = true ] && command -v claude >/dev/null 2>&1; then
  echo ""
  echo "Resolving target build deps headlessly (cap ${CAP} attempts)…"
  PROMPT="You are configuring a Nix dev shell for fuzzing a C/C++ target in the
current directory. The shell composes cc-fuzzer's toolchain with this target's
BUILD dependencies, which you declare in ./fuzz/nix-deps.nix — a function
'pkgs: with pkgs; [ ... ]'.

GOAL: edit ./fuzz/nix-deps.nix so the dev shell evaluates. SUCCESS is this
command exiting 0:
    ${GATE}
Run it after each edit. Do NOT run a full 'nix develop' or 'nix build' — eval
is the gate (much faster; it still resolves every attr).

STEPS:
1. Inspect the project to infer the system libraries its build needs: read
   README/INSTALL, configure.ac/configure.in/configure, Makefile(s),
   CMakeLists.txt, meson.build, *.pc / pkg-config(PKG_CHECK_MODULES) usage, and
   '#include <...>' lines in the target sources/headers. List every external
   library whose headers or shared objects the build/link needs (e.g. zlib,
   openssl, libpng, glib, libuuid, ncurses).
2. Map each to its EXACT nixpkgs attribute — names drift across releases and
   headers usually live in the '.dev' output. VERIFY every attr BEFORE adding it:
       nix eval --raw nixpkgs#<attr>.outPath      (errors if the attr is wrong)
   Use 'nix search nixpkgs <keyword>' to discover the right attr when unsure.
   Prefer '<lib>.dev' for header/compile needs, the plain attr for runtime libs.
3. Write the verified attrs into ./fuzz/nix-deps.nix as 'pkgs: with pkgs; [ ... ]'.
   Keep the list MINIMAL — only what the build needs.
4. Run the gate. On 'attribute X missing' / eval error, fix that attr (re-verify
   with nix eval nixpkgs#...) and retry. At most ${CAP} edit→gate attempts;
   STOP as soon as the gate exits 0.

An EMPTY list is a valid result ONLY for a genuinely self-contained target (no
external libraries) — say so explicitly if you conclude that. Otherwise do not
finish with an empty list while real dependencies remain unresolved.

CONSTRAINTS: only edit ./fuzz/nix-deps.nix and read/inspect project files; do NOT
edit ./flake.nix. If after ${CAP} attempts the gate still fails, leave your
best-effort ./fuzz/nix-deps.nix and end with one line naming what's unresolved."

  set +e
  # Least-privilege, NOT --dangerously-skip-permissions: the scan may only read
  # the project (Read/Glob/Grep), run nix (Bash(nix *)), and write the ONE file
  # ./fuzz/nix-deps.nix — nothing else. `--permission-mode dontAsk` auto-denies
  # any other tool call and CONTINUES (no hang in headless -p), so even running
  # unattended the scan can't touch other files or run arbitrary commands.
  # (`--allowedTools` accepts comma/space-separated rules; Edit(path) also grants
  # read of that path. `dontAsk` is a real --permission-mode in Claude Code v2.1+.)
  claude -p "$PROMPT" \
    --permission-mode dontAsk \
    --allowedTools "Read,Glob,Grep,Bash(nix *),Edit(./fuzz/nix-deps.nix),Write(./fuzz/nix-deps.nix)"
  SCAN_RC=$?
  set -e
  # re-stage in case the scan rewrote the (possibly gitignored) deps file
  git -C "$PROJECT_ROOT" rev-parse --is-inside-work-tree >/dev/null 2>&1 \
    && git -C "$PROJECT_ROOT" add -f fuzz/nix-deps.nix 2>/dev/null || true

  echo ""
  if deps_nonempty; then
    echo "dep scan resolved: $(sed 's/#.*//' "$DEPS_FILE" | tr -s '[:space:]' ' ' | sed -E 's/.*\[(.*)\].*/\1/' | xargs)"
  else
    echo "dep scan found NO extra build deps."
    [ "$SCAN_RC" -eq 0 ] || echo "  (the scan exited ${SCAN_RC} — it may have errored above rather than concluding 'none needed')."
    echo "  If the base toolchain compiles the harness, that's fine. If a build later"
    echo "  fails on a missing header/lib, the harness-writer appends the attr to"
    echo "  ./fuzz/nix-deps.nix and you re-run 'nix run <cc-fuzzer>#init' to rebuild."
    echo "  To retry the scan now: re-run with --force. To add deps by hand:"
    echo "  edit ./fuzz/nix-deps.nix (e.g. 'pkgs: with pkgs; [ zlib.dev openssl.dev ]')."
  fi
elif [ "$WANT_SCAN" = true ]; then
  echo "WARN: 'claude' not on PATH — skipping the dep scan. Edit ./fuzz/nix-deps.nix by hand."
fi

# ---------------------------------------------------------------------------
# 3. Validate + lock + print next steps (NO launch)
# ---------------------------------------------------------------------------
echo ""
echo "Validating the dev shell evaluates…"
if eval "$GATE" >/dev/null 2>&1; then
  echo "  OK — dev shell evaluates."
else
  echo "  WARN — dev shell does NOT evaluate yet. Check the attrs in ./fuzz/nix-deps.nix:"
  echo "         $GATE"
  echo "         Fix them, then re-run 'nix run <cc-fuzzer>#init' (--force re-scans)."
fi

nix flake lock >/dev/null 2>&1 || true

YOLO='/cc-fuzzer:yolo on --mode self_loop --no-cap'
echo ""
echo "================================================================"
echo " Campaign flake ready in $PROJECT_ROOT"
echo " #init does NOT launch Claude — start it yourself:"
echo ""
echo "   Launch Claude in the campaign shell:"
echo "     nix run .#claude                                              # plain"
echo "     nix run .#claude -- --dangerously-skip-permissions            # unattended (no tool prompts)"
echo "     nix run .#claude -- --dangerously-skip-permissions \"$YOLO\"    # total YOLO, one shot"
echo ""
echo "   Open the dev shell only (no Claude):"
echo "     nix develop          # interactive FHS shell"
echo "     nix run .#default     # same (FHS wrapper)"
echo ""
echo " All reuse the lock + cached env (fast). Re-run '#init' only to change"
echo " deps (--force re-scans) or after a plugin update."
echo "================================================================"
