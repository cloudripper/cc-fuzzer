#!/usr/bin/env bash
# build-poc-repro.sh
#
# Scaffolds a self-contained, target-realistic reproducer bundle at
#   fuzz/findings/<finding-id>/repro/
#
# The triager invokes this for every finding that passes the verification
# pipeline. The bundle includes everything a maintainer needs to verify the
# crash WITHOUT pointing back at our fuzz harness:
#
#   - poc.{c,cc,py,sh}   the reproducer source
#   - input.bin          the minimised crashing input
#   - build.sh           builds the reproducer in the cc-fuzzer Nix dev shell
#   - run.sh             executes; expects ASan to fire with the recorded top frames
#   - asan.log           ASan output from a successful run (filled in after first run)
#   - README.md          summary tying back to the finding id
#
# Hard rule: the bundle MUST NOT reference the fuzz harness binary. The whole
# point is to demonstrate the bug via the target's documented public surface.
#
# Usage:
#   scripts/build-poc-repro.sh \
#     --finding-id <fNNN> \
#     --kind <c_program | cli_invocation | python_ctypes | ipc_replay> \
#     --input <path-to-crashing-input> \
#     --target-source <file:line> \
#     [--cli-binary <path>]       (required for cli_invocation kind)
#     [--public-header <name>]    (informational; first @include in poc.c stub)
#     [--symbol <name>]           (the target function the triager believes triggers it)
#     [--route A | B]             (verification route; defaults to B for non-cli kinds)
#     [--cvss <vector>]           (informational; embedded in README)
#     [--cwe <id>]                (informational; embedded in README)
#     [--summary <one-line>]      (informational; embedded in README)
#
# Outputs (stdout): the bundle directory absolute path.
# Exit codes:
#   0  bundle scaffolded
#   1  invalid arguments
#   2  inputs missing or unreadable

set -u

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
. "$SCRIPT_DIR/_lib/path-anchor.sh"

FINDING_ID=""
KIND=""
INPUT=""
TARGET_SOURCE=""
CLI_BIN=""
PUBLIC_HEADER=""
SYMBOL=""
ROUTE=""
CVSS=""
CWE=""
SUMMARY=""

while [ $# -gt 0 ]; do
  case "$1" in
    --finding-id)     FINDING_ID="${2:-}"; shift 2 ;;
    --kind)           KIND="${2:-}"; shift 2 ;;
    --input)          INPUT="${2:-}"; shift 2 ;;
    --target-source)  TARGET_SOURCE="${2:-}"; shift 2 ;;
    --cli-binary)     CLI_BIN="${2:-}"; shift 2 ;;
    --public-header)  PUBLIC_HEADER="${2:-}"; shift 2 ;;
    --symbol)         SYMBOL="${2:-}"; shift 2 ;;
    --route)          ROUTE="${2:-}"; shift 2 ;;
    --cvss)           CVSS="${2:-}"; shift 2 ;;
    --cwe)            CWE="${2:-}"; shift 2 ;;
    --summary)        SUMMARY="${2:-}"; shift 2 ;;
    --help|-h)        sed -n '2,/^$/p' "$0" | sed 's/^# \?//'; exit 0 ;;
    *) echo "ERROR: unknown arg '$1'" >&2; exit 1 ;;
  esac
done

# Validate args
case "$FINDING_ID" in
  f[0-9][0-9][0-9]|f[0-9][0-9][0-9][0-9]|f[0-9][0-9][0-9][0-9][0-9]) ;;
  *) echo "ERROR: --finding-id must match ^f[0-9]{3,5}\$ (got '$FINDING_ID')" >&2; exit 1 ;;
esac

case "$KIND" in
  c_program|cli_invocation|python_ctypes|ipc_replay) ;;
  *) echo "ERROR: --kind must be one of c_program | cli_invocation | python_ctypes | ipc_replay (got '$KIND')" >&2; exit 1 ;;
esac

[ -n "$INPUT" ] || { echo "ERROR: --input required" >&2; exit 1; }
[ -r "$INPUT" ] || { echo "ERROR: --input '$INPUT' not readable" >&2; exit 2; }

# Route inference: cli_invocation → A; everything else → B; unless explicitly overridden.
if [ -z "$ROUTE" ]; then
  case "$KIND" in
    cli_invocation) ROUTE="A" ;;
    *)              ROUTE="B" ;;
  esac
fi

if [ "$KIND" = "cli_invocation" ]; then
  [ -n "$CLI_BIN" ] || { echo "ERROR: --cli-binary required when --kind=cli_invocation" >&2; exit 1; }
fi

BUNDLE_DIR="$FUZZ_ROOT/findings/$FINDING_ID/repro"
mkdir -p "$BUNDLE_DIR"

# Copy the crashing input into the bundle (so the bundle is self-contained).
cp "$INPUT" "$BUNDLE_DIR/input.bin"

# ---------------------------------------------------------------------------
# Generate poc.* per kind
# ---------------------------------------------------------------------------
case "$KIND" in
  c_program)
    HDR="${PUBLIC_HEADER:-target_public.h}"
    SYM="${SYMBOL:-target_parse}"
    cat > "$BUNDLE_DIR/poc.c" <<EOF
/* poc.c — auto-scaffolded by build-poc-repro.sh for finding $FINDING_ID
 *
 * Target-realistic reproducer. Uses only the target's PUBLIC headers; no
 * harness shims, no internal symbols. Replace TODOs before claiming the
 * bundle is verifiable.
 *
 * Build under the cc-fuzzer Nix dev shell:
 *   nix develop \$CLAUDE_PLUGIN_ROOT
 *   ./build.sh
 *   ./run.sh   # expect ASan to fire with the stack the finding records
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <$HDR>   // TODO: replace with the actual public header(s) you need

static unsigned char *read_all(const char *path, size_t *n_out) {
    FILE *f = fopen(path, "rb");
    if (!f) { perror("fopen"); exit(2); }
    fseek(f, 0, SEEK_END);
    long n = ftell(f);
    fseek(f, 0, SEEK_SET);
    unsigned char *buf = malloc((size_t)n);
    if (!buf) { perror("malloc"); exit(2); }
    if (fread(buf, 1, (size_t)n, f) != (size_t)n) { perror("fread"); exit(2); }
    fclose(f);
    *n_out = (size_t)n;
    return buf;
}

int main(int argc, char **argv) {
    if (argc < 2) {
        fprintf(stderr, "usage: %s <input.bin>\n", argv[0]);
        return 2;
    }
    size_t n;
    unsigned char *buf = read_all(argv[1], &n);

    /* TODO: invoke the target's public API the way a real consumer would.
     * The triager wrote this stub from the crash's stack trace:
     *   crashing symbol:    $SYM
     *   target source:      $TARGET_SOURCE
     * Replace this body with the smallest public-API call sequence that
     * reaches that symbol with the bytes from buf. Resist the temptation
     * to copy from the fuzz harness — the harness may push the library
     * into states a real caller cannot, which is why we're rewriting.
     */
    (void)$SYM;
    (void)buf; (void)n;

    return 0;
}
EOF
    POC_FILE="poc.c"
    ;;

  cli_invocation)
    cat > "$BUNDLE_DIR/poc.sh" <<EOF
#!/usr/bin/env bash
# poc.sh — auto-scaffolded by build-poc-repro.sh for finding $FINDING_ID
#
# Invokes the target's documented CLI against the crashing input. The CLI
# itself was rebuilt with ASan inside the cc-fuzzer Nix dev shell so any
# memory error fires immediately.
set -u
BIN="\${1:-$CLI_BIN}"
INPUT="\${2:-input.bin}"

if [ ! -x "\$BIN" ]; then
  echo "ERROR: CLI binary '\$BIN' not executable" >&2
  echo "       rebuild it with ASan (see build.sh) or pass an absolute path." >&2
  exit 2
fi

# TODO: replace with the actual documented invocation. The triager set up
# the basics from the harness's known calling pattern, but a real CLI user
# usually passes flags. Pick flags from \`<BIN> --help\` and the docs.
exec "\$BIN" "\$INPUT"
EOF
    chmod +x "$BUNDLE_DIR/poc.sh"
    POC_FILE="poc.sh"
    ;;

  python_ctypes)
    SYM="${SYMBOL:-target_parse}"
    HDR="${PUBLIC_HEADER:-libtarget.so}"
    cat > "$BUNDLE_DIR/poc.py" <<EOF
#!/usr/bin/env python3
"""poc.py — auto-scaffolded by build-poc-repro.sh for finding $FINDING_ID

Target-realistic reproducer through the target's ABI via ctypes. No harness
shims, no internal symbols. Replace TODOs before claiming the bundle is
verifiable.

Run under the cc-fuzzer Nix dev shell so the system libraries (and the
ASan-instrumented build of the target) are on LD_LIBRARY_PATH:

    nix develop \$CLAUDE_PLUGIN_ROOT
    ./build.sh    # builds the ASan-instrumented target library
    ./run.sh      # expects ASan to fire with the recorded top frames
"""
import ctypes
import sys

# TODO: point at the actual ASan-built shared object produced by build.sh
lib = ctypes.CDLL("./$HDR")

# TODO: configure argtypes / restype to match the public ABI. The triager
# inferred the symbol from the crash stack:
#   crashing symbol:    $SYM
#   target source:      $TARGET_SOURCE
# A wrong prototype gives bogus crashes; double-check against the public header.
lib.$SYM.argtypes = [ctypes.c_void_p, ctypes.c_size_t]
lib.$SYM.restype  = ctypes.c_int

with open(sys.argv[1] if len(sys.argv) > 1 else "input.bin", "rb") as f:
    data = f.read()

buf = ctypes.create_string_buffer(data, len(data))
rc  = lib.$SYM(ctypes.cast(buf, ctypes.c_void_p), len(data))
print("rc =", rc)
EOF
    chmod +x "$BUNDLE_DIR/poc.py"
    POC_FILE="poc.py"
    ;;

  ipc_replay)
    cat > "$BUNDLE_DIR/poc.py" <<EOF
#!/usr/bin/env python3
"""poc.py — auto-scaffolded by build-poc-repro.sh for finding $FINDING_ID

IPC-replay reproducer. Speaks the documented wire format to a running target
daemon. No harness shims, no protocol fuzzing scaffolding — only what a real
client would send.

Usage:
    ./build.sh    # starts the ASan-instrumented daemon
    ./run.sh      # expects the daemon to crash via ASan on this message
"""
import socket
import sys

# TODO: replace with the daemon's documented endpoint
ENDPOINT = ("127.0.0.1", 11000)

with open(sys.argv[1] if len(sys.argv) > 1 else "input.bin", "rb") as f:
    payload = f.read()

s = socket.create_connection(ENDPOINT, timeout=5)
s.sendall(payload)
try:
    resp = s.recv(4096)
    print("response:", resp)
except Exception as e:
    # Crash usually breaks the connection before recv returns
    print("connection error (expected if crash fires):", e)
EOF
    chmod +x "$BUNDLE_DIR/poc.py"
    POC_FILE="poc.py"
    ;;
esac

# ---------------------------------------------------------------------------
# build.sh — compile the reproducer in the Nix dev shell
# ---------------------------------------------------------------------------
case "$KIND" in
  c_program)
    cat > "$BUNDLE_DIR/build.sh" <<'EOF'
#!/usr/bin/env bash
# Build the reproducer with the cc-fuzzer Nix dev shell's clang + ASan.
# Run from inside `nix develop $CLAUDE_PLUGIN_ROOT`.
set -eu
clang -O1 -g -fsanitize=address,undefined -fno-omit-frame-pointer \
    -o poc poc.c \
    # TODO: add -I<target-public-include> and -l<target-lib> here
echo "Built ./poc"
EOF
    chmod +x "$BUNDLE_DIR/build.sh"
    ;;
  cli_invocation)
    cat > "$BUNDLE_DIR/build.sh" <<EOF
#!/usr/bin/env bash
# build.sh — rebuild the target's CLI with ASan.
#
# The triager pointed this at:
#   $CLI_BIN
# Replace below with the target's documented build command, adding:
#   CFLAGS+="-fsanitize=address,undefined -fno-omit-frame-pointer -g -O1"
#   CXXFLAGS+="-fsanitize=address,undefined -fno-omit-frame-pointer -g -O1"
#   LDFLAGS+="-fsanitize=address,undefined"
# Then export the resulting binary path as the first arg to poc.sh.
set -eu
echo "TODO: implement build.sh for the target CLI" >&2
exit 2
EOF
    chmod +x "$BUNDLE_DIR/build.sh"
    ;;
  python_ctypes)
    cat > "$BUNDLE_DIR/build.sh" <<EOF
#!/usr/bin/env bash
# build.sh — build the target as an ASan-instrumented shared object.
# Run from inside \`nix develop \$CLAUDE_PLUGIN_ROOT\`.
set -eu
echo "TODO: build the target's shared library with -fsanitize=address,undefined" >&2
echo "      and write the result to ./$PUBLIC_HEADER (or update poc.py)." >&2
exit 2
EOF
    chmod +x "$BUNDLE_DIR/build.sh"
    ;;
  ipc_replay)
    cat > "$BUNDLE_DIR/build.sh" <<'EOF'
#!/usr/bin/env bash
# build.sh — start the target daemon under ASan.
# Run from inside `nix develop $CLAUDE_PLUGIN_ROOT`.
set -eu
echo "TODO: launch the ASan-instrumented daemon and wait for its listening port." >&2
echo "      ASAN_OPTIONS=abort_on_error=1:disable_coredump=0:strict_string_checks=1 \\" >&2
echo "        ./target-daemon --foreground &" >&2
exit 2
EOF
    chmod +x "$BUNDLE_DIR/build.sh"
    ;;
esac

# ---------------------------------------------------------------------------
# run.sh — execute the reproducer; ASan should fire
# ---------------------------------------------------------------------------
case "$KIND" in
  c_program)
    cat > "$BUNDLE_DIR/run.sh" <<'EOF'
#!/usr/bin/env bash
# run.sh — run the reproducer; expect ASan to fire on the recorded stack.
set -u
ASAN_OPTIONS="abort_on_error=1:disable_coredump=0:strict_string_checks=1:detect_leaks=0" \
  ./poc input.bin > asan.log 2>&1
rc=$?
echo "exit code: $rc"
echo "--- top of asan.log ---"
head -30 asan.log
echo "--- /asan.log ---"
exit "$rc"
EOF
    chmod +x "$BUNDLE_DIR/run.sh"
    ;;
  cli_invocation)
    cat > "$BUNDLE_DIR/run.sh" <<'EOF'
#!/usr/bin/env bash
# run.sh — invoke the ASan-instrumented CLI on the crashing input.
set -u
ASAN_OPTIONS="abort_on_error=1:disable_coredump=0:strict_string_checks=1:detect_leaks=0" \
  ./poc.sh > asan.log 2>&1
rc=$?
echo "exit code: $rc"
echo "--- top of asan.log ---"
head -30 asan.log
echo "--- /asan.log ---"
exit "$rc"
EOF
    chmod +x "$BUNDLE_DIR/run.sh"
    ;;
  python_ctypes)
    cat > "$BUNDLE_DIR/run.sh" <<'EOF'
#!/usr/bin/env bash
# run.sh — execute the Python reproducer.
set -u
ASAN_OPTIONS="abort_on_error=1:disable_coredump=0:strict_string_checks=1:detect_leaks=0" \
  python3 poc.py input.bin > asan.log 2>&1
rc=$?
echo "exit code: $rc"
echo "--- top of asan.log ---"
head -30 asan.log
echo "--- /asan.log ---"
exit "$rc"
EOF
    chmod +x "$BUNDLE_DIR/run.sh"
    ;;
  ipc_replay)
    cat > "$BUNDLE_DIR/run.sh" <<'EOF'
#!/usr/bin/env bash
# run.sh — replay the wire-format payload at the running daemon.
set -u
python3 poc.py input.bin > asan.log 2>&1
rc=$?
echo "client exit code: $rc"
echo "(daemon ASan output, if any, appears in the daemon's own stderr — capture it from build.sh's logs.)"
exit "$rc"
EOF
    chmod +x "$BUNDLE_DIR/run.sh"
    ;;
esac

# Empty asan.log placeholder so the bundle is complete even before the first run.
: > "$BUNDLE_DIR/asan.log"

# ---------------------------------------------------------------------------
# README.md — finder-facing summary
# ---------------------------------------------------------------------------
cat > "$BUNDLE_DIR/README.md" <<EOF
# Reproducer for finding $FINDING_ID

**Verification route**: $ROUTE — $([ "$ROUTE" = "A" ] && echo "the target's documented CLI rebuilt with ASan" || echo "a minimal program using only the target's public headers")
**Reproducer kind**: $KIND
**Crashing symbol**: ${SYMBOL:-unknown}
**Target source**: ${TARGET_SOURCE:-unknown}
**CVSSv3.1 (triager estimate)**: ${CVSS:-not estimated}
**CWE**: ${CWE:-not assigned}

## Summary
${SUMMARY:-No one-line summary provided.}

## What's in this bundle

- \`$POC_FILE\` — the reproducer source
- \`input.bin\` — the minimised crashing input
- \`build.sh\` — compiles the reproducer with ASan in the cc-fuzzer Nix dev shell
- \`run.sh\` — executes the reproducer; expects ASan to fire
- \`asan.log\` — the ASan output from a verifying run (filled in after first run)

## How to verify

\`\`\`bash
# 1. Enter the pinned toolchain (clang + ASan + the target's deps)
nix develop \$CLAUDE_PLUGIN_ROOT

# 2. Build the reproducer
./build.sh

# 3. Execute — should crash with the stack documented in the finding
./run.sh
\`\`\`

The reproducer does **not** use the fuzz harness. It exercises the target
through the public surface a real consumer would touch. The fuzzer was a
discovery instrument; this bundle is the proof of impact.
EOF

echo "$BUNDLE_DIR"
