#!/usr/bin/env bash
# campaign-header.sh
#
# Prints a compact (10-20 line) campaign-state digest, written to
# ${FUZZ_STATE_DIR}/header.txt by callers. Used by ops-runner as its
# "first read" anchor and by every subagent dispatch that wants a shared
# context snapshot without paying for a full current.json walk.
#
# Read-only. Reads:
#   fuzz/state/current.json            — name / mode / tick / target / coverage
#   fuzz/state/findings.jsonl          — promoted-findings recent slice
#   fuzz/state/snapshots/ceiling-probe-*.json — last-halt context (optional)
#   fuzz/state/fuzz-config.json        — yolo block (mode)
#   fuzz/state/authorization.json      — disclosure framing (optional)
#   fuzz/state/plan.md                 — schema-version surrogate
#
# Output is plain text to stdout. Callers redirect to header.txt themselves.
#
# Exits 0 even when the campaign is uninitialized — prints a minimal "no
# campaign yet" header so the digest is always safe to read.

set -u

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# path-anchor is best-effort: a header dispatched before campaign init has no
# fuzz/ to anchor on. path-anchor.sh exits 2 when nothing is found, so we run
# it in a subshell to detect the failure without dying ourselves.
if ! ( . "$SCRIPT_DIR/_lib/path-anchor.sh" 2>/dev/null ); then
  TS=$(date '+%Y-%m-%d %H:%M:%S')
  printf '=== cc-fuzzer campaign-header / v1 / %s ===\n' "$TS"
  printf 'campaign:    (none)            mode:    n/a       tick:    n/a\n'
  printf 'target:      (none)            schema:  v12       version: 0.30\n'
  printf '\nNo campaign initialized in cwd. Run /cc-fuzzer:campaign <target>.\n'
  exit 0
fi
# Re-source for real (now that we know it'll succeed) so PROJECT_ROOT/FUZZ_ROOT
# end up in our environment.
. "$SCRIPT_DIR/_lib/path-anchor.sh"

STATE_DIR="${FUZZ_STATE_DIR:-$FUZZ_ROOT/state}"
CURRENT="$STATE_DIR/current.json"
FINDINGS="$STATE_DIR/findings.jsonl"
CONFIG="$STATE_DIR/fuzz-config.json"
AUTHZ="$STATE_DIR/authorization.json"
SCHEMA_VERSION_FILE="$STATE_DIR/schema-version"

STATE_DIR="$STATE_DIR" CURRENT="$CURRENT" FINDINGS="$FINDINGS" CONFIG="$CONFIG" \
AUTHZ="$AUTHZ" SCHEMA_VERSION_FILE="$SCHEMA_VERSION_FILE" \
PLUGIN_ROOT="${CLAUDE_PLUGIN_ROOT:-}" \
python3 - <<'PY'
import glob
import json
import os
import time

def _load_json(p, default=None):
    try:
        with open(p) as f:
            return json.load(f)
    except Exception:
        return default

def _slurp(p, default=""):
    try:
        with open(p) as f:
            return f.read().strip()
    except Exception:
        return default

def _load_jsonl(p):
    rows = []
    try:
        with open(p) as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    rows.append(json.loads(line))
                except Exception:
                    pass
    except Exception:
        pass
    return rows

state_dir = os.environ["STATE_DIR"]
cur = _load_json(os.environ["CURRENT"]) or {}
cfg = _load_json(os.environ["CONFIG"]) or {}
authz = _load_json(os.environ["AUTHZ"]) or {}
schema_v = _slurp(os.environ["SCHEMA_VERSION_FILE"]) or "v12"

# --- header line --------------------------------------------------------
ts = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime())
print(f"=== cc-fuzzer campaign-header / v1 / {ts} ===")

# --- campaign meta ------------------------------------------------------
name = (cur.get("campaign_name") or cur.get("name") or "(unnamed)")
tick = cur.get("tick_number", 0) or 0
yolo = cfg.get("yolo") or {}
mode = yolo.get("mode") or "manual"
if yolo.get("enabled"):
    mode = f"yolo:{mode}"
target = (cur.get("target") or cur.get("target_source") or "(not declared)")

# Plugin version — best-effort from MANIFEST.md5 or plugin.json.
plugin_v = "0.30"
plugin_root = os.environ.get("PLUGIN_ROOT") or ""
if plugin_root:
    plugin_json = _load_json(os.path.join(plugin_root, ".claude-plugin", "plugin.json"))
    if plugin_json and "version" in plugin_json:
        plugin_v = plugin_json["version"]

print(f"campaign:    {name:<16} mode:    {mode:<8} tick:    {tick}")
print(f"target:      {target:<16} schema:  {schema_v:<8} version: {plugin_v}")

# --- harnesses + coverage -----------------------------------------------
harnesses = cur.get("harnesses") or []
n_live = sum(1 for h in harnesses if h.get("status") != "stale")
n_stale = sum(1 for h in harnesses if h.get("status") == "stale")
engines = sorted({(h.get("engine") or "libfuzzer") for h in harnesses if h.get("engine")})
if not engines:
    engines = ["libfuzzer"]

tc = cur.get("tick_coverage") or {}
overall = tc.get("overall") or {}
weighted = overall.get("weighted_pct")
lines_c = overall.get("lines_covered")
lines_t = overall.get("lines_total")
branch_pct = overall.get("branch_pct")

# last gain — best-effort from coverage history if present
last_gain_tick = None
hist = []
for p in sorted(glob.glob(os.path.join(state_dir, "snapshots", "tick-coverage-*.json"))):
    d = _load_json(p)
    if d:
        hist.append((int(d.get("timestamp") or 0),
                     (d.get("overall") or {}).get("weighted_pct") or 0.0))
if len(hist) >= 2:
    last_w = hist[-1][1]
    for i in range(len(hist) - 1, 0, -1):
        if hist[i][1] > hist[i-1][1]:
            # cheap: just count "ticks back"
            last_gain_tick = max(0, tick - (len(hist) - 1 - i))
            break

print()
if harnesses:
    print(f"harnesses:   {n_live} live, {n_stale} stale; engines: {', '.join(engines)}")
else:
    print(f"harnesses:   (none yet); engines: -")

if weighted is not None:
    cov_str = f"{weighted:.1f}% (line {lines_c}/{lines_t}"
    if branch_pct is not None:
        cov_str += f", branch {branch_pct:.1f}%"
    cov_str += ")"
    if last_gain_tick is not None:
        cov_str += f"; last-gain at tick {last_gain_tick}"
    print(f"coverage:    {cov_str}")
else:
    print("coverage:    (no roundup yet)")

last_halt = yolo.get("last_halt_reason") or "—"
print(f"last-halt:   {last_halt}")

# --- authorization ------------------------------------------------------
print()
print("authorization:")
ownership = authz.get("target_ownership") or \
    "<not declared — campaign-planner / user should populate fuzz/state/authorization.json>"
disclosure = authz.get("disclosure_intent") or "responsible-disclosure research"
framing   = authz.get("demo_framing") or "PoC demonstration for maintainer-facing reproducer bundle"
print(f"  ownership: {ownership}")
print(f"  disclosure: {disclosure}")
print(f"  framing: {framing}")

# --- open candidates ----------------------------------------------------
# A "candidate" is a gap OR a code-review finding still being chased. We
# count gaps from the most recent gaps-*.json AND the source:code_review
# candidates sitting in findings.jsonl (status:candidate) — those are logic
# bugs imported via `findings.sh import-cr` that have NOT yet been promoted
# through the realism gate.
findings_rows = _load_jsonl(os.environ["FINDINGS"])
candidates = []
for p in sorted(glob.glob(os.path.join(state_dir, "snapshots", "gaps-*.json")))[-1:]:
    d = _load_json(p) or {}
    for g in (d.get("gaps") or [])[:6]:
        if g.get("reason") == "dead":
            continue
        candidates.append({
            "id": g.get("id"),
            "kind": g.get("reason"),
            "severity": g.get("priority") or g.get("severity") or "med",
            "desc": (g.get("function") or g.get("file") or "?"),
        })
for f in findings_rows:
    if f.get("status") != "candidate" or f.get("source") != "code_review":
        continue
    candidates.append({
        "id": f.get("id"),
        "kind": "code_review",
        "severity": f.get("oracle_kind") or f.get("category") or "logic",
        "desc": f.get("location") or f.get("category") or "?",
    })

print()
print(f"open candidates: {len(candidates)}; top 1–3:")
if candidates:
    for c in candidates[:3]:
        print(f"  - {c['id']} {c['kind']} {c['severity']} — {c['desc']}")
else:
    print("  - (none — no gap report yet, or all gaps dead)")

# --- findings (promoted) ------------------------------------------------
findings = _load_jsonl(os.environ["FINDINGS"])
promoted = [f for f in findings if (f.get("verification") or {}).get("deterministic_replay") == "pass"
            or (f.get("status") == "finding")]
recent = sorted(promoted, key=lambda f: f.get("first_seen") or "", reverse=True)[:3]

print()
print(f"findings (promoted): {len(promoted)}; recent 1–3:")
if recent:
    for f in recent:
        fid = f.get("id") or "?"
        oracle = f.get("oracle_kind") or f.get("category") or "crash"
        sev = f.get("severity") or (f.get("verification") or {}).get("severity") or "med"
        desc = f.get("summary") or f.get("title") or (f.get("category") or "crash")
        print(f"  - {fid} {oracle} {sev} — {desc}")
else:
    print("  - (none promoted yet)")
PY
