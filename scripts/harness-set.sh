#!/usr/bin/env bash
# harness-set.sh
#
# Declares the campaign's harness set in fuzz/state/fuzz-config.json. This is
# the config-patching step that activates schema-v9 multi-harness mode — every
# plugin script and agent keys "multi vs singular" off a non-empty harnesses[]
# in fuzz-config.json (see _lib/harness-path.sh:is_multi).
#
# Since v0.19.2 every NEW campaign runs in multi-harness mode from COLD, with a
# single harness as the degenerate case (bundle under fuzz/harnesses/<name>/).
# This means the on-disk schema never has to migrate when a second harness is
# added later — `add` just appends. Existing singular campaigns are left as-is
# and keep working on the legacy flat layout.
#
# Subcommands:
#   harness-set.sh init --entry <fn> [--name <name>] [--engine libfuzzer|aflpp]
#                       [--slot <slot>]
#       Create fuzz-config.json as fuzz-config/v3 with one declared harness and
#       one fuzzer slot bound to it. Preserves any existing scalar/object keys
#       (fuzz_forks, tick, cve, yolo, code_review). Idempotent: if a non-empty
#       harnesses[] is already present, prints the current set and exits 0
#       WITHOUT clobbering. Run this BEFORE harness-writer at COLD so the build
#       writes into the multi layout.
#
#   harness-set.sh add  --entry <fn> [--name <name>] [--engine libfuzzer|aflpp]
#                       [--slot <slot>]
#       Append a harness + slot to an ALREADY-multi campaign. Refuses on a
#       singular campaign (those need the documented singular->multi upgrade).
#       After this, build the harness with `harness-writer --harness <name>`.
#
# Naming:
#   <name>  defaults to the sanitised entry function. Must match
#           ^[a-z0-9][a-z0-9_-]{0,31}$ (harness id; underscores allowed).
#   <slot>  defaults to "main" (init) or the name with _->- (add). Must match
#           ^[a-z0-9-]{1,32}$ (no underscores). Pass --slot to override.
#   <engine> defaults to libfuzzer (the COLD harness is always a libFuzzer
#           harness; switch a slot to aflpp later via a slot/engine change).
#
# Output (stdout, last line): HARNESS_SET name=<name> slot=<slot> engine=<engine> mode=multi
# Exit 0 on success (or idempotent no-op). Exit 2 on misconfiguration.

set -u

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
. "$SCRIPT_DIR/_lib/path-anchor.sh"
. "$SCRIPT_DIR/_lib/harness-path.sh"

STATE_DIR="${FUZZ_STATE_DIR:-$FUZZ_ROOT/state}"
CFG_FILE="$STATE_DIR/fuzz-config.json"

usage_err() { echo "ERROR: $*" >&2; exit 2; }

ACTION="${1:-help}"
shift || true

ENTRY=""
NAME=""
ENGINE="libfuzzer"
SLOT=""

while [ $# -gt 0 ]; do
  case "$1" in
    --entry)   ENTRY="${2:-}";  shift 2 ;;
    --name)    NAME="${2:-}";   shift 2 ;;
    --engine)  ENGINE="${2:-}"; shift 2 ;;
    --slot)    SLOT="${2:-}";   shift 2 ;;
    -h|--help) ACTION="help"; break ;;
    *) usage_err "unknown flag '$1'" ;;
  esac
done

case "$ACTION" in
  init|add) ;;
  help|*)
    sed -n '2,40p' "${BASH_SOURCE[0]}" | sed 's/^# \{0,1\}//'
    exit 0
    ;;
esac

[ -n "$ENTRY" ] || usage_err "--entry <function> is required"
case "$ENGINE" in
  libfuzzer|aflpp) ;;
  *) usage_err "--engine '$ENGINE' must be libfuzzer or aflpp" ;;
esac

mkdir -p "$STATE_DIR"

# All the JSON shaping + validation lives in python for robustness. It prints
# the final HARNESS_SET line on success, or "ERR: <msg>" on failure.
RESULT=$(ACTION="$ACTION" ENTRY="$ENTRY" NAME="$NAME" ENGINE="$ENGINE" \
         SLOT="$SLOT" CFG="$CFG_FILE" python3 - <<'PY'
import json, os, re, sys

action = os.environ["ACTION"]
entry  = os.environ["ENTRY"].strip()
name   = os.environ["NAME"].strip()
engine = os.environ["ENGINE"].strip()
slot   = os.environ["SLOT"].strip()
cfg_path = os.environ["CFG"]

NAME_RE = re.compile(r"^[a-z0-9][a-z0-9_-]{0,31}$")
SLOT_RE = re.compile(r"^[a-z0-9-]{1,32}$")


def fail(msg):
    print("ERR: " + msg)
    sys.exit(0)


def sanitize_name(raw):
    s = raw.strip().lower()
    s = re.sub(r"[^a-z0-9_-]+", "-", s)   # invalid chars -> dash
    s = re.sub(r"-{2,}", "-", s)          # collapse dashes
    s = s.lstrip("-_")                    # first char must be [a-z0-9]
    return s[:32].rstrip("-_")


# Resolve the harness name.
if not name:
    name = sanitize_name(entry)
else:
    name = name.strip().lower()
if not NAME_RE.match(name):
    fail(f"could not derive a valid harness name from entry={entry!r} "
         f"(got {name!r}); pass --name with ^[a-z0-9][a-z0-9_-]{{0,31}}$")

# Load existing config (tolerate missing/garbage -> start fresh on init).
try:
    with open(cfg_path) as f:
        cfg = json.load(f)
    if not isinstance(cfg, dict):
        cfg = {}
except FileNotFoundError:
    cfg = {}
except Exception:
    if action == "add":
        fail("fuzz-config.json is unreadable; cannot add a harness")
    cfg = {}

harnesses = cfg.get("harnesses")
if not isinstance(harnesses, list):
    harnesses = []
slots = cfg.get("fuzzer_slots")
if not isinstance(slots, list):
    slots = []

existing_names = {h.get("name") for h in harnesses if isinstance(h, dict)}
existing_slots = {s.get("slot") for s in slots if isinstance(s, dict)}

if action == "init":
    if harnesses:
        # Already multi — do not clobber. Idempotent no-op.
        names = ",".join(sorted(n for n in existing_names if n))
        print(f"NOOP already multi; harnesses=[{names}]")
        sys.exit(0)

# Resolve the slot name.
if not slot:
    slot = "main" if action == "init" else re.sub(r"_", "-", name)[:32].rstrip("-")
if not SLOT_RE.match(slot):
    fail(f"slot {slot!r} invalid (^[a-z0-9-]{{1,32}}$); pass --slot")

if action == "add":
    if not harnesses:
        fail("not a multi-harness campaign (no harnesses[] in fuzz-config.json). "
             "`add` appends to an already-multi campaign; a singular campaign "
             "needs the documented singular->multi upgrade.")
    if name in existing_names:
        fail(f"harness {name!r} already declared")
    # Disambiguate a colliding slot name.
    base, n = slot, 2
    while slot in existing_slots:
        slot = f"{base}-{n}"[:32].rstrip("-")
        n += 1
        if not SLOT_RE.match(slot):
            fail(f"could not derive a unique slot from {base!r}; pass --slot")

# Apply.
cfg["schema"] = "fuzz-config/v3"
if "fuzz_forks" not in cfg:
    cfg["fuzz_forks"] = 2
harnesses.append({"name": name, "entry_function": entry})
slots.append({"slot": slot, "harness": name, "engine": engine})
cfg["harnesses"] = harnesses
cfg["fuzzer_slots"] = slots

tmp = cfg_path + ".tmp"
with open(tmp, "w") as f:
    json.dump(cfg, f, indent=2, sort_keys=True)
    f.write("\n")
os.replace(tmp, cfg_path)

print(f"HARNESS_SET name={name} slot={slot} engine={engine} mode=multi")
PY
)

# Surface python's verdict.
case "$RESULT" in
  ERR:*)
    echo "ERROR: ${RESULT#ERR: }" >&2
    exit 2
    ;;
  NOOP*)
    echo "harness-set: ${RESULT#NOOP }" >&2
    # Re-detect mode for any sourced caller, then report the existing set.
    hp_invalidate_cache
    echo "HARNESS_SET name=$(default_harness) mode=multi (pre-existing)"
    exit 0
    ;;
  HARNESS_SET*)
    hp_invalidate_cache   # so a sourcing caller sees multi mode immediately
    if [ "$ACTION" = "init" ]; then
      # Stamp the schema version so a fresh multi campaign is never later
      # misdetected as v0 — migrate_v0_to_v1 would recreate the singular
      # fuzz/harness/ + fuzz/corpus/ dirs and violate multi-mode's
      # mutual-exclusion rule. Declaring harnesses[] IS adopting schema v9.
      echo "v9" > "$STATE_DIR/schema-version"
    fi
    echo "wrote $CFG_FILE ($ACTION: $RESULT)" >&2
    echo "$RESULT"
    exit 0
    ;;
  *)
    echo "ERROR: harness-set.sh: unexpected result: $RESULT" >&2
    exit 2
    ;;
esac
