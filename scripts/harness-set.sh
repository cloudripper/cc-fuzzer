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
#   harness-set.sh fallback-backend <name> --reason <enum> --evidence <text>
#       Demote a nix-committed harness to legacy build_backend. Writes a
#       nix-fallback/v1 record to state/nix-fallback-log.jsonl. Archives the
#       nix/ bundle to nix-archived-<ts>/. The ONLY authorized path to flip
#       build_backend from "nix" to "legacy".
#       <reason> must be one of: unfree_license_blocked, no_nix_expr_for_target,
#       platform_unsupported, external_blob_dependency, host_lockfile_required,
#       manual_override
#
#   harness-set.sh promote-to-nix <name>
#       Promote a legacy harness to nix build_backend. Requires CC_FUZZER_FHS=1
#       and a successful trial build of every enabled variant via nix-build.sh.
#       Archives the existing build.sh to build.sh.pre-nix. The ONLY authorized
#       path to flip build_backend from "legacy" to "nix".
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
FALLBACK_REASON=""
FALLBACK_EVIDENCE=""

while [ $# -gt 0 ]; do
  case "$1" in
    --entry)    ENTRY="${2:-}";             shift 2 ;;
    --name)     NAME="${2:-}";              shift 2 ;;
    --engine)   ENGINE="${2:-}";            shift 2 ;;
    --slot)     SLOT="${2:-}";              shift 2 ;;
    --reason)   FALLBACK_REASON="${2:-}";   shift 2 ;;
    --evidence) FALLBACK_EVIDENCE="${2:-}"; shift 2 ;;
    -h|--help)  ACTION="help"; break ;;
    *) usage_err "unknown flag '$1'" ;;
  esac
done

case "$ACTION" in
  init|add|fallback-backend|promote-to-nix) ;;
  help|*)
    sed -n '2,55p' "${BASH_SOURCE[0]}" | sed 's/^# \{0,1\}//'
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
      echo "v10" > "$STATE_DIR/schema-version"
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

#==============================================================================
# fallback-backend: demote a nix-committed harness to legacy
#==============================================================================
if [ "$ACTION" = "fallback-backend" ]; then
  TARGET_NAME="$NAME"
  [ -n "$TARGET_NAME" ] || { TARGET_NAME="${ENTRY:-}"; }
  [ -n "$TARGET_NAME" ] || usage_err "fallback-backend requires a harness name as second arg: harness-set.sh fallback-backend <name>"
  [ -n "$FALLBACK_REASON" ] || usage_err "--reason is required for fallback-backend"
  [ -n "$FALLBACK_EVIDENCE" ] || FALLBACK_EVIDENCE="(no evidence provided)"

  VALID_REASONS="unfree_license_blocked no_nix_expr_for_target platform_unsupported external_blob_dependency host_lockfile_required manual_override"
  VALID=false
  for r in $VALID_REASONS; do
    [ "$r" = "$FALLBACK_REASON" ] && VALID=true && break
  done
  [ "$VALID" = true ] || usage_err "invalid --reason '$FALLBACK_REASON'. Must be one of: $VALID_REASONS"

  HS_FILE="$STATE_DIR/harnesses.json"
  [ -f "$HS_FILE" ] || usage_err "harnesses.json not found; not a multi-harness campaign"

  TS=$(date -u +%Y-%m-%dT%H:%M:%SZ)
  TS_COMPACT=$(date -u +%s)
  FALLBACK_LOG="$STATE_DIR/nix-fallback-log.jsonl"
  HARNESS_DIR_PATH="${FUZZ_ROOT:-fuzz}/harnesses/$TARGET_NAME"
  NIX_DIR_PATH="$HARNESS_DIR_PATH/nix"
  NIX_ARCHIVE="$HARNESS_DIR_PATH/nix-archived-$TS_COMPACT"

  FB_OUT=$(python3 - <<PY
import json, os, sys, datetime

hs_path   = os.environ["HS_FILE"]
name      = os.environ["TARGET_NAME"]
reason    = os.environ["FALLBACK_REASON"]
evidence  = os.environ["FALLBACK_EVIDENCE"]
log_path  = os.environ["FALLBACK_LOG"]
ts        = os.environ["TS"]

doc = json.load(open(hs_path))
harnesses = doc.get("harnesses", [])
target = next((h for h in harnesses if isinstance(h, dict) and h.get("name") == name), None)
if target is None:
    print(f"ERR: harness '{name}' not found in harnesses.json"); sys.exit(1)

prior_backend = target.get("build_backend", "(unset)")
if prior_backend == "legacy":
    print(f"ALREADY_LEGACY harness '{name}' is already build_backend=legacy")
    sys.exit(0)

n = 0
try:
    with open(log_path) as f:
        n = sum(1 for l in f if l.strip())
except Exception:
    pass

rec = {
    "schema": "nix-fallback/v1",
    "id": f"nf_{n+1:04d}",
    "ts": ts,
    "harness": name,
    "phase": "user_command",
    "reason": reason,
    "reason_class": "policy" if reason == "manual_override" else "blocker",
    "decided_by": "user_manual",
    "evidence": {"kind": "user_note", "summary": evidence},
    "remediation_hint": {
        "audience": "plugin_user",
        "category": "informational",
        "human_message": f"Harness '{name}' manually demoted to legacy build_backend. Reason: {reason}.",
        "machine_hints": {}
    }
}
with open(log_path, "a") as f:
    f.write(json.dumps(rec, separators=(",",":")) + "\n")

target["build_backend"] = "legacy"
target["build_backend_decided_at"] = ts
target["build_backend_decided_by"] = "harness-set-fallback"
target.pop("nix", None)

tmp = hs_path + ".tmp"
with open(tmp, "w") as f:
    json.dump(doc, f, indent=2)
os.replace(tmp, hs_path)

print(f"FALLBACK_OK name={name} from={prior_backend} reason={reason}")
PY
)

  case "$FB_OUT" in
    ERR:*) echo "ERROR: ${FB_OUT#ERR: }" >&2; exit 2 ;;
    ALREADY_LEGACY*) echo "harness-set: $FB_OUT" >&2; exit 0 ;;
    FALLBACK_OK*)
      # Archive the nix bundle so it's preserved for forensics
      if [ -d "$NIX_DIR_PATH" ]; then
        mv "$NIX_DIR_PATH" "$NIX_ARCHIVE" 2>/dev/null && \
          echo "archived nix bundle to $NIX_ARCHIVE" >&2 || true
      fi
      echo "$FB_OUT" >&2
      echo "$FB_OUT"
      exit 0 ;;
    *) echo "ERROR: unexpected output: $FB_OUT" >&2; exit 2 ;;
  esac
fi  # end fallback-backend

#==============================================================================
# promote-to-nix: upgrade a legacy harness to nix build_backend
#==============================================================================
if [ "$ACTION" = "promote-to-nix" ]; then
  TARGET_NAME="$NAME"
  [ -n "$TARGET_NAME" ] || { TARGET_NAME="${ENTRY:-}"; }
  [ -n "$TARGET_NAME" ] || usage_err "promote-to-nix requires a harness name as second arg"

  [ "${CC_FUZZER_FHS:-}" = "1" ] || usage_err "promote-to-nix requires CC_FUZZER_FHS=1 (run inside 'nix run .#claude')"

  HS_FILE="$STATE_DIR/harnesses.json"
  [ -f "$HS_FILE" ] || usage_err "harnesses.json not found; not a multi-harness campaign"

  HARNESS_DIR_PATH="${FUZZ_ROOT:-fuzz}/harnesses/$TARGET_NAME"
  MANIFEST_PATH="$HARNESS_DIR_PATH/nix/manifest.json"
  [ -f "$MANIFEST_PATH" ] || usage_err "manifest.json not found at $MANIFEST_PATH — run /cc-fuzzer:harness first to generate nix files"

  TS=$(date -u +%Y-%m-%dT%H:%M:%SZ)

  # Trial build
  echo "promote-to-nix: running trial nix build for harness '$TARGET_NAME'..." >&2
  SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
  if ! bash "$SCRIPT_DIR/nix-build.sh" "$TARGET_NAME" --no-log; then
    echo "ERROR: nix build failed; fix the nix derivations before promoting" >&2
    exit 1
  fi

  # Build succeeded — update harnesses.json
  PROMOTE_OUT=$(TARGET_NAME="$TARGET_NAME" HS_FILE="$HS_FILE" TS="$TS" \
    MANIFEST_PATH="$MANIFEST_PATH" FUZZ_ROOT="${FUZZ_ROOT:-fuzz}" \
    python3 - <<'PY'
import json, os, sys, hashlib, datetime

hs_path = os.environ["HS_FILE"]
name = os.environ["TARGET_NAME"]
ts = os.environ["TS"]
manifest_path = os.environ["MANIFEST_PATH"]
fuzz_root = os.environ["FUZZ_ROOT"]

doc = json.load(open(hs_path))
harnesses = doc.get("harnesses", [])
target = next((h for h in harnesses if isinstance(h, dict) and h.get("name") == name), None)
if target is None:
    print(f"ERR: harness '{name}' not found in harnesses.json"); sys.exit(1)

prior_backend = target.get("build_backend", "legacy")
if prior_backend == "nix":
    print(f"ALREADY_NIX harness '{name}' is already build_backend=nix")
    sys.exit(0)

manifest_hash = hashlib.sha256(open(manifest_path, "rb").read()).hexdigest()[:16]
nix_deps_path = os.path.join(fuzz_root, "nix-deps.nix")
nix_deps_hash = hashlib.sha256(open(nix_deps_path, "rb").read()).hexdigest()[:16] if os.path.isfile(nix_deps_path) else ""
flake_rev = os.environ.get("CC_FUZZER_FLAKE_REV", "unknown")

# Collect store paths from the result symlinks
nix_dir = os.path.join(fuzz_root, "harnesses", name, "nix")
harness_bin_dir = os.path.join(fuzz_root, "harnesses", name, "harness")
manifest = json.load(open(manifest_path))
variants_built = {}
for variant, info in manifest.get("variants", {}).items():
    if not (isinstance(info, dict) and info.get("enabled", True)):
        continue
    suffix = {"fuzzer":"","coverage":"_cov","verify":"_verify","cmplog":"_cmplog","symcc":"_symcc"}.get(variant, f"_{variant}")
    out_link = os.path.join(harness_bin_dir, f"{manifest['harness']}_fuzzer{suffix}")
    nix_file = os.path.join(nix_dir, f"{variant}.nix")
    store_path = ""
    drv_hash = ""
    if os.path.islink(out_link):
        real = os.path.realpath(out_link)
        # store path is the /nix/store/<hash>-<name> part
        parts = real.split("/")
        try:
            ni = parts.index("nix")
            store_path = "/" + "/".join(parts[ni:ni+3])
            drv_hash = parts[ni+2][:8] if len(parts) > ni+2 else ""
        except ValueError:
            store_path = os.path.dirname(os.path.dirname(real))
    variants_built[variant] = {
        "nix_file": os.path.relpath(nix_file) if os.path.isabs(nix_file) else nix_file,
        "store_path": store_path,
        "out_link": os.path.relpath(out_link) if os.path.isabs(out_link) else out_link,
        "drv_hash": drv_hash,
    }

target["build_backend"] = "nix"
target["build_backend_decided_at"] = ts
target["build_backend_decided_by"] = "harness-set-promote"
target["nix"] = {
    "manifest_path": os.path.relpath(manifest_path) if os.path.isabs(manifest_path) else manifest_path,
    "manifest_hash": manifest_hash,
    "variants": variants_built,
    "flake_rev_used": flake_rev,
    "nix_deps_hash": nix_deps_hash,
}

# Archive old build.sh
build_sh = os.path.join(harness_bin_dir, "build.sh")
if os.path.isfile(build_sh):
    os.rename(build_sh, build_sh + ".pre-nix")

tmp = hs_path + ".tmp"
with open(tmp, "w") as f:
    json.dump(doc, f, indent=2)
os.replace(tmp, hs_path)

print(f"PROMOTE_OK name={name} from={prior_backend}")
PY
)

  case "$PROMOTE_OUT" in
    ERR:*) echo "ERROR: ${PROMOTE_OUT#ERR: }" >&2; exit 2 ;;
    ALREADY_NIX*) echo "harness-set: $PROMOTE_OUT" >&2; exit 0 ;;
    PROMOTE_OK*)
      echo "$PROMOTE_OUT" >&2
      echo "$PROMOTE_OUT"
      exit 0 ;;
    *) echo "ERROR: unexpected output: $PROMOTE_OUT" >&2; exit 2 ;;
  esac
fi  # end promote-to-nix
