#!/usr/bin/env bash
# nix-env-reconcile.sh
#
# Cross-references fuzz/state/nix-env.json (the session's captured environment)
# against fuzz/state/harnesses.json (committed build_backend per harness) and
# writes fuzz/state/nix-environment-issues.json (nix-environment/v1).
#
# Called by env-check.sh at every session start (after capture-nix-env.sh).
# Also called by validate-state.sh when a fuzz project exists.
#
# Issues are classified by code (closed enum) and severity (error|warning).
# The orchestrator reads this file and refuses to tick on severity=error
# issues affecting nix-committed harnesses.
#
# Exit 0 always — even if issues are found. The caller decides what to do.

set -u

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
. "$SCRIPT_DIR/_lib/path-anchor.sh"
. "$SCRIPT_DIR/_lib/nix-tools.sh"

FUZZ_ROOT="${FUZZ_ROOT:-fuzz}"
STATE_DIR="$FUZZ_ROOT/state"
OUT="$STATE_DIR/nix-environment-issues.json"
export STATE_DIR FUZZ_ROOT OUT

# If no campaign state exists, write empty-issues and exit.
if [ ! -f "$STATE_DIR/harnesses.json" ]; then
  python3 -c "
import json, datetime
doc = {'schema':'nix-environment/v1',
       'checked_at': datetime.datetime.utcnow().strftime('%Y-%m-%dT%H:%M:%SZ'),
       'campaign_commitment': {'any_harness_nix': False, 'nix_harnesses': [], 'legacy_harnesses': []},
       'environment': {'cc_fuzzer_fhs': False, 'nix_binary_on_path': False, 'fuzz_nix_deps_present': False, 'flake_rev_runtime': None},
       'issues': []}
print(json.dumps(doc, indent=2))
" > "$TMP" 2>/dev/null && mv "$TMP" "$OUT" || true
  exit 0
fi

python3 - <<'PY'
import json, os, sys, datetime, hashlib, subprocess

state_dir = os.environ.get("STATE_DIR", "fuzz/state")
fuzz_root = os.environ.get("FUZZ_ROOT", "fuzz")
out = os.environ.get("OUT")

def safe_read(p, default=None):
    try:
        return json.load(open(p))
    except Exception:
        return default

harnesses_doc = safe_read(os.path.join(state_dir, "harnesses.json"), {})
harnesses = harnesses_doc.get("harnesses", [])
nix_harnesses = [h["name"] for h in harnesses if isinstance(h, dict) and h.get("build_backend") == "nix"]
legacy_harnesses = [h["name"] for h in harnesses if isinstance(h, dict) and h.get("build_backend") == "legacy"]
any_nix = bool(nix_harnesses)

nix_env = safe_read(os.path.join(state_dir, "nix-env.json"), {})
cc_fuzzer_fhs = bool(nix_env.get("cc_fuzzer_fhs", False))
flake_rev_runtime = nix_env.get("flake_rev")

nix_on_path = bool(os.system("command -v nix >/dev/null 2>&1") == 0)
nix_deps_present = os.path.isfile(os.path.join(fuzz_root, "nix-deps.nix"))

issues = []
issue_id = 0

def add_issue(severity, code, affected, summary, audience, category, human_msg, fix_locus):
    nonlocal issue_id
    issue_id += 1
    issues.append({
        "id": f"env{issue_id:03d}",
        "severity": severity,
        "code": code,
        "affected_harnesses": affected,
        "summary": summary,
        "audience": audience,
        "remediation": {
            "category": category,
            "human_message": human_msg,
            "fix_locus": fix_locus,
        }
    })

if any_nix:
    # Check FHS shell
    if not cc_fuzzer_fhs:
        add_issue("error", "fhs_shell_absent", nix_harnesses,
            "Campaign committed to build_backend=nix but $CC_FUZZER_FHS is unset.",
            "plugin_user", "reenter_dev_shell",
            "Re-enter the cc-fuzzer Nix dev shell: exit Claude, then run "
            "'nix run $CLAUDE_PLUGIN_ROOT#claude' (or 'nix develop $CLAUDE_PLUGIN_ROOT && claude').",
            "user_shell")

    # Check nix binary
    if not nix_on_path:
        add_issue("error", "nix_binary_missing", nix_harnesses,
            "nix binary not found on PATH; nix builds cannot run.",
            "plugin_user", "install_nix",
            "Install Nix: https://nixos.org/download — or use 'nix run $CLAUDE_PLUGIN_ROOT#claude' "
            "which provides Nix inside the FHS sandbox.",
            "user_shell")

    # Check nix-deps.nix
    if not nix_deps_present:
        add_issue("error", "nix_deps_missing", nix_harnesses,
            "fuzz/nix-deps.nix is absent; nix derivations cannot import campaign build deps.",
            "plugin_user", "restore_nix_deps",
            "Restore fuzz/nix-deps.nix (e.g. 'pkgs: with pkgs; []') and re-run "
            "'nix run $CLAUDE_PLUGIN_ROOT#init' to resolve deps.",
            "fuzz/nix-deps.nix")

    # Check nix-deps drift (hash mismatch)
    deps_path = os.path.join(fuzz_root, "nix-deps.nix")
    if nix_deps_present:
        try:
            deps_hash = hashlib.sha256(open(deps_path, "rb").read()).hexdigest()[:16]
            drifted = []
            for h in harnesses:
                if isinstance(h, dict) and h.get("build_backend") == "nix":
                    committed_hash = (h.get("nix") or {}).get("nix_deps_hash", "")
                    if committed_hash and committed_hash != deps_hash:
                        drifted.append(h["name"])
            if drifted:
                add_issue("warning", "nix_deps_drift", drifted,
                    "fuzz/nix-deps.nix changed since harness(es) were built; rebuild to pick up new deps.",
                    "plugin_user", "rebuild_harness",
                    "Run '/cc-fuzzer:nix-build' (or '/cc-fuzzer:harness') to rebuild the affected harness(es) "
                    "against the updated fuzz/nix-deps.nix.",
                    "fuzz/nix-deps.nix")
        except Exception:
            pass

    # Check store path GC / manifest drift per harness
    for h in harnesses:
        if not isinstance(h, dict) or h.get("build_backend") != "nix":
            continue
        name = h.get("name", "?")
        nix_sub = h.get("nix") or {}

        # Manifest hash drift
        manifest_path = nix_sub.get("manifest_path", "")
        manifest_hash_committed = nix_sub.get("manifest_hash", "")
        if manifest_path and manifest_hash_committed:
            try:
                actual_hash = hashlib.sha256(open(manifest_path, "rb").read()).hexdigest()[:16]
                if actual_hash != manifest_hash_committed:
                    add_issue("error", "manifest_drift", [name],
                        f"harness '{name}': manifest.json edited outside the rebuild pipeline "
                        f"(committed hash {manifest_hash_committed!r}, current {actual_hash!r}).",
                        "plugin_user", "rebuild_harness",
                        f"Run '/cc-fuzzer:nix-build --harness {name}' to rebuild with the updated manifest.",
                        f"fuzz/harnesses/{name}/nix/manifest.json")
            except Exception:
                pass

        # Store path GC check
        for variant, vinfo in (nix_sub.get("variants") or {}).items():
            if not isinstance(vinfo, dict):
                continue
            store_path = vinfo.get("store_path", "")
            if store_path and not os.path.exists(store_path):
                add_issue("error", "store_path_gc", [name],
                    f"harness '{name}' variant '{variant}' store path is gone (GC'd or never built): {store_path}",
                    "plugin_user", "rebuild_harness",
                    f"Run '/cc-fuzzer:nix-build --harness {name} --variant {variant} --force' to rebuild.",
                    f"fuzz/harnesses/{name}/harness/")

    # Flake rev drift
    if cc_fuzzer_fhs and flake_rev_runtime:
        for h in harnesses:
            if not isinstance(h, dict) or h.get("build_backend") != "nix":
                continue
            name = h.get("name", "?")
            nix_sub = h.get("nix") or {}
            flake_rev_used = nix_sub.get("flake_rev_used", "")
            if flake_rev_used and flake_rev_runtime not in ("dirty", "") and flake_rev_used != flake_rev_runtime:
                add_issue("warning", "flake_rev_drift", [name],
                    f"harness '{name}' was built at flake rev {flake_rev_used[:8]!r}, "
                    f"current rev is {flake_rev_runtime[:8]!r}.",
                    "plugin_dev",
                    "informational",
                    f"Run '/cc-fuzzer:nix-build --harness {name}' to rebuild against the current plugin version.",
                    f"fuzz/harnesses/{name}/harness/")

doc = {
    "schema": "nix-environment/v1",
    "checked_at": datetime.datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ"),
    "campaign_commitment": {
        "any_harness_nix": any_nix,
        "nix_harnesses": nix_harnesses,
        "legacy_harnesses": legacy_harnesses,
    },
    "environment": {
        "cc_fuzzer_fhs": cc_fuzzer_fhs,
        "nix_binary_on_path": nix_on_path,
        "fuzz_nix_deps_present": nix_deps_present,
        "flake_rev_runtime": flake_rev_runtime,
    },
    "issues": issues,
}

tmp = out + ".tmp"
with open(tmp, "w") as f:
    json.dump(doc, f, indent=2)
os.replace(tmp, out)
PY

exit 0
