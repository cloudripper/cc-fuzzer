#!/usr/bin/env bash
# netem-harness.sh — wrap a verifier in a loopback netem profile.
#
# Usage:
#   netem-harness.sh [--loss <pct>] [--jitter <ms>] [--rate <kbit>] \
#                    [--dev <iface>] [--no-loopback] \
#                    -- verify-poc.sh [args...]
#
# Why this exists (PLUGIN_ISSUES.md friction item 6):
#
#   "works on loopback" is not the same as "works over a real network." A
#   representative campaign turned up PoCs that leaned on timing-sensitive
#   primitives (parallel handshakes, disclosure races) that held over the
#   0-ms-RTT 0%-loss loopback path and collapsed under realistic latency +
#   jitter + occasional packet loss.
#   A verifier that only passes on loopback is a verifier that may not survive
#   a maintainer running it on a real LAN/WAN.
#
#   This wrapper attaches a tc-netem qdisc to a chosen interface (default `lo`)
#   for the lifetime of the verifier run, then tears it down on exit. The
#   verifier exit code propagates unchanged.
#
# Defaults come from fuzz/state/fuzz-config.json:
#
#   poc.realism.loopback_loss_pct      (default 1.0)
#   poc.realism.loopback_jitter_ms     (default 15)
#   poc.realism.loopback_rate_kbit     (default 10000)
#
# Target-supervision prerequisites:
#
#   The reference PoC's target binary MUST auto-restart on crash (an init
#   system's Restart=on-failure equivalent, supervisord, an explicit
#   `while :; do <bin>; done` loop in test scaffolding, etc.) AND must NOT be
#   under a tight rate-limit (no aggressive StartLimitIntervalSec; supervisord
#   autorestart=true with no startretries cap). Without that, a single induced
#   crash during a netem-degraded run will kill the target before the verifier
#   finishes its read, and the verifier will fail with a confusing
#   "marker missing" error
#   rather than the real "the timing-dependent primitive doesn't survive
#   real-world conditions" signal.
#
#   The poc-builder bundle README must call out these prerequisites under a
#   "## Target supervision" heading whenever a netem verifier is shipped.
#
# Privilege:
#
#   `tc qdisc add` requires CAP_NET_ADMIN (effectively root). If run without
#   it, this script PRINTS a clear "rerun under sudo OR skip if not network-
#   timing-sensitive" message and exits 2 — a WARN, not a fatal error. Some
#   PoCs (a logic bug in a parser; a write to disk; auth bypass with no race)
#   don't need network realism at all.

set -u

LOSS=""
JITTER=""
RATE=""
DEV="lo"
ENABLE=true

usage() {
  cat <<'USAGE'
netem-harness.sh — run a verifier under a tc-netem loopback profile.

Usage:
  netem-harness.sh [flags] -- <verifier> [verifier-args...]

Flags:
  --loss <pct>       packet loss percent (e.g. 1.0)
  --jitter <ms>      jitter (delay magnitude). Implies a small base delay.
  --rate <kbit>      rate limit (kilobits/sec)
  --dev <iface>      interface to attach qdisc to (default: lo)
  --no-loopback      skip qdisc setup, run verifier as-is (for portability)
  -h | --help        show this help

Defaults are read from fuzz/state/fuzz-config.json:
  poc.realism.loopback_loss_pct
  poc.realism.loopback_jitter_ms
  poc.realism.loopback_rate_kbit

Exit codes:
  <verifier's exit code>  — the verifier ran (under or without netem)
  2                        — root/CAP_NET_ADMIN required and not available
  3                        — flag/usage error
USAGE
}

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
. "$SCRIPT_DIR/_lib/path-anchor.sh" 2>/dev/null || true
FUZZ_ROOT="${FUZZ_ROOT:-fuzz}"
CFG="$FUZZ_ROOT/state/fuzz-config.json"

# Read a dot-key from fuzz-config.json. Returns "" if absent.
_cfg() {
  local key="$1"
  [ -f "$CFG" ] || { echo ""; return; }
  K="$key" CFG="$CFG" python3 -c "
import json, os, sys
try:
    d = json.load(open(os.environ['CFG']))
    for p in os.environ['K'].split('.'):
        if isinstance(d, dict) and p in d:
            d = d[p]
        else:
            d = ''
            break
    sys.stdout.write('' if d in (None, '') else str(d))
except Exception:
    pass
" 2>/dev/null
}

# Parse flags (must end with -- before the verifier command).
while [ "$#" -gt 0 ]; do
  case "$1" in
    --loss)         LOSS="${2:?--loss needs a value}"; shift 2 ;;
    --jitter)       JITTER="${2:?--jitter needs a value}"; shift 2 ;;
    --rate)         RATE="${2:?--rate needs a value}"; shift 2 ;;
    --dev)          DEV="${2:?--dev needs a value}"; shift 2 ;;
    --no-loopback)  ENABLE=false; shift ;;
    -h|--help)      usage; exit 0 ;;
    --) shift; break ;;
    *) echo "ERROR: netem-harness.sh: unknown flag '$1' (see --help)" >&2; exit 3 ;;
  esac
done

if [ "$#" -lt 1 ]; then
  echo "ERROR: no verifier command given. Usage: netem-harness.sh [flags] -- <verifier> [args]" >&2
  exit 3
fi

# Resolve defaults from config when flags weren't passed.
[ -z "$LOSS" ]   && LOSS=$(_cfg poc.realism.loopback_loss_pct)
[ -z "$JITTER" ] && JITTER=$(_cfg poc.realism.loopback_jitter_ms)
[ -z "$RATE" ]   && RATE=$(_cfg poc.realism.loopback_rate_kbit)
[ -z "$LOSS" ]   && LOSS=1.0
[ -z "$JITTER" ] && JITTER=15
[ -z "$RATE" ]   && RATE=10000

# Permission gate.
if [ "$ENABLE" = true ]; then
  if [ "$(id -u)" -ne 0 ]; then
    cat >&2 <<EOF
netem-harness.sh: tc qdisc on $DEV needs CAP_NET_ADMIN.

  - rerun under sudo:   sudo $0 --loss $LOSS --jitter $JITTER --rate $RATE -- $*
  - or skip the wrap:   $0 --no-loopback -- $*    (if this PoC isn't network-timing-sensitive)

Some PoCs don't need network realism (a parser logic bug, a local file write,
an auth bypass with no race window). For those, --no-loopback is the right
answer. For race / disclosure-timing / parallel-handshake PoCs, run with the
qdisc — "works on 0-ms loopback" is misleading.
EOF
    exit 2
  fi
  if ! command -v tc >/dev/null 2>&1; then
    echo "ERROR: 'tc' is not on PATH; install iproute2 or pass --no-loopback" >&2
    exit 2
  fi
fi

# Cleanup runs on every exit path (success, verifier failure, signal).
cleanup() {
  if [ "$ENABLE" = true ]; then
    tc qdisc del dev "$DEV" root 2>/dev/null || true
  fi
}
trap cleanup EXIT INT TERM

if [ "$ENABLE" = true ]; then
  # Replace (not add) — if a stale netem qdisc from a prior run is still
  # attached, `add` would fail with "RTNETLINK answers: File exists".
  # Delay base is half the jitter; netem applies jitter as +/- around the base.
  BASE_DELAY_MS=$(awk "BEGIN { printf \"%.1f\", $JITTER / 2 }")
  if ! tc qdisc replace dev "$DEV" root netem \
        delay "${BASE_DELAY_MS}ms" "${JITTER}ms" distribution normal \
        loss "${LOSS}%" \
        rate "${RATE}kbit" 2>/dev/null; then
    echo "ERROR: tc qdisc replace failed on $DEV (perms? interface name?)" >&2
    exit 2
  fi
  echo "netem-harness: dev=$DEV loss=${LOSS}% jitter=${JITTER}ms rate=${RATE}kbit base_delay=${BASE_DELAY_MS}ms" >&2
fi

# Run the verifier; propagate its exit code.
"$@"
RC=$?
exit "$RC"
