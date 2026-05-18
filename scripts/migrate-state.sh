#!/usr/bin/env bash
# migrate-state.sh
#
# Migrates fuzz/state/ from one schema version to the next.
# Idempotent: safe to run multiple times.
#
# Currently supports:
#   - v0 (pre-schema, flat layout) -> v1 (current spec)
#
# Strategy:
#   1. Read state/schema-version, default "v0" if missing
#   2. Look up migration chain to current ($EXPECTED_SCHEMA_VERSION)
#   3. Tar up state/ first as a backup
#   4. Run each migration step
#   5. Update state/schema-version on success

set -u

# Path anchor - refuses cwd inside fuzz/, refuses recursive fuzz/fuzz/
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
. "$SCRIPT_DIR/_lib/path-anchor.sh"
FUZZ_ROOT="${FUZZ_ROOT:-fuzz}"
STATE_DIR="$FUZZ_ROOT/state"
EXPECTED_SCHEMA_VERSION="v9"

if [ ! -d "$STATE_DIR" ]; then
  echo "no state directory at $STATE_DIR - nothing to migrate"
  exit 0
fi

# Detect current version
if [ -f "$STATE_DIR/schema-version" ]; then
  CURRENT=$(head -1 "$STATE_DIR/schema-version" | tr -d ' \n')
else
  CURRENT="v0"
fi

if [ "$CURRENT" = "$EXPECTED_SCHEMA_VERSION" ]; then
  echo "state already at $EXPECTED_SCHEMA_VERSION - nothing to do"
  exit 0
fi

echo "Migrating state from $CURRENT to $EXPECTED_SCHEMA_VERSION"
echo ""

# Backup
# Skip the backup tarball when the only transition is v8 -> v9, because that
# transition is a no-op: it only rewrites state/schema-version. A backup would
# just duplicate the current state into a tarball with no recovery value. Any
# multi-step chain (e.g. v6 -> v9) still gets a backup.
BACKUP_FILE=""
if [ "$CURRENT" = "v8" ] && [ "$EXPECTED_SCHEMA_VERSION" = "v9" ]; then
  echo "(skipping backup tarball - v8 -> v9 transition is a no-op version bump)"
else
  BACKUP_DIR="$STATE_DIR/migrations"
  mkdir -p "$BACKUP_DIR"
  BACKUP_FILE="$BACKUP_DIR/${CURRENT}-${EXPECTED_SCHEMA_VERSION}-backup-$(date +%Y%m%d-%H%M%S).tar.gz"
  echo "Creating backup at $BACKUP_FILE"
  tar --exclude="$BACKUP_DIR" -czf "$BACKUP_FILE" -C "$FUZZ_ROOT" state/ 2>/dev/null || {
    echo "WARNING: backup creation failed - continuing anyway"
  }
fi

#------------------------------------------------------------------------------
# v0 -> v1: flat layout to schema/v1
#------------------------------------------------------------------------------
migrate_v0_to_v1() {
  echo "Running v0 -> v1 migration..."

  # 1. Create new directory structure
  mkdir -p "$STATE_DIR/snapshots"
  mkdir -p "$FUZZ_ROOT/harness"
  mkdir -p "$FUZZ_ROOT/crashes/new"
  mkdir -p "$FUZZ_ROOT/crashes/known"
  mkdir -p "$FUZZ_ROOT/crashes/flaky"
  mkdir -p "$FUZZ_ROOT/corpus"
  mkdir -p "$FUZZ_ROOT/corpus-quarantine"
  mkdir -p "$FUZZ_ROOT/coverage"

  # 2. Move timestamped state files into snapshots/
  for f in "$STATE_DIR"/coverage-*.json "$STATE_DIR"/gaps-*.json "$STATE_DIR"/concolic-*.json; do
    [ -f "$f" ] || continue
    base=$(basename "$f")
    if [ ! -f "$STATE_DIR/snapshots/$base" ]; then
      mv "$f" "$STATE_DIR/snapshots/$base"
      echo "  moved $base to snapshots/"
    fi
  done

  # 3. Add schema field to existing JSON files that lack it
  # 3a. Snapshots
  for f in "$STATE_DIR/snapshots"/coverage-*.json; do
    [ -f "$f" ] || continue
    python3 -c "
import json
try:
    d = json.load(open('$f'))
    if 'schema' not in d:
        d = {'schema': 'coverage-snapshot/v1', **d}
        json.dump(d, open('$f', 'w'), indent=2)
        print('  added schema to', '$f')
except Exception as e:
    print('  WARN: could not migrate $f:', e)
" 2>&1 | head -5
  done
  for f in "$STATE_DIR/snapshots"/gaps-*.json; do
    [ -f "$f" ] || continue
    python3 -c "
import json
try:
    d = json.load(open('$f'))
    if 'schema' not in d:
        d = {'schema': 'gaps-report/v1', **d}
        json.dump(d, open('$f', 'w'), indent=2)
        print('  added schema to', '$f')
except Exception as e:
    print('  WARN: could not migrate $f:', e)
" 2>&1 | head -5
  done
  for f in "$STATE_DIR/snapshots"/concolic-*.json; do
    [ -f "$f" ] || continue
    python3 -c "
import json
try:
    d = json.load(open('$f'))
    if 'schema' not in d:
        d = {'schema': 'concolic-result/v1', **d}
        json.dump(d, open('$f', 'w'), indent=2)
except Exception as e:
    pass
" 2>&1
  done

  # 3b. harness-built.json - add schema field if missing
  if [ -f "$STATE_DIR/harness-built.json" ]; then
    python3 -c "
import json, sys, hashlib, os
try:
    d = json.load(open('$STATE_DIR/harness-built.json'))
    changed = False
    if 'schema' not in d:
        d = {'schema': 'harness-built/v1', **d}
        changed = True
    # Older builds may lack hashes - compute if target_source is present
    if d.get('target_source') and 'target_source_hash' not in d:
        ts = d['target_source']
        if os.path.isfile(ts):
            with open(ts, 'rb') as f:
                d['target_source_hash'] = hashlib.sha256(f.read()).hexdigest()[:16]
            changed = True
    if d.get('build_command') and 'build_command_hash' not in d:
        d['build_command_hash'] = hashlib.sha256(d['build_command'].encode()).hexdigest()[:16]
        changed = True
    if 'built_at' not in d:
        from datetime import datetime
        d['built_at'] = datetime.utcnow().strftime('%Y-%m-%dT%H:%M:%SZ')
        changed = True
    if 'build_script' not in d:
        # Best guess
        d['build_script'] = 'fuzz/harness/build.sh'
        changed = True
    if changed:
        json.dump(d, open('$STATE_DIR/harness-built.json', 'w'), indent=2)
        print('  upgraded harness-built.json')
except Exception as e:
    print('  WARN: could not upgrade harness-built.json:', e)
"
  fi

  # 3c. findings.jsonl - upgrade lines to finding/v1 schema
  if [ -f "$STATE_DIR/findings.jsonl" ]; then
    TMP="$STATE_DIR/findings.jsonl.migrating"
    python3 -c "
import json
with open('$STATE_DIR/findings.jsonl') as f, open('$TMP', 'w') as out:
    for line in f:
        line = line.strip()
        if not line: continue
        try:
            d = json.loads(line)
        except Exception:
            out.write(line + '\n')  # preserve unparseable lines
            continue
        if d.get('schema') != 'finding/v1':
            d['schema'] = 'finding/v1'
        # Add required fields if missing
        if 'last_seen' not in d:
            d['last_seen'] = d.get('first_seen', '1970-01-01T00:00:00Z')
        if 'dedup_count' not in d:
            d['dedup_count'] = d.get('count', 1)
        # Drop the legacy 'count' field
        d.pop('count', None)
        out.write(json.dumps(d, separators=(',', ':')) + '\n')
"
    mv "$TMP" "$STATE_DIR/findings.jsonl"
    echo "  upgraded findings.jsonl"
  fi

  # 4. Move legacy crash directories
  if [ -d "$FUZZ_ROOT/known-crashes" ]; then
    echo "  migrating $FUZZ_ROOT/known-crashes -> $FUZZ_ROOT/crashes/known/"
    # Bucket by finding id if findings.jsonl maps reproducers
    # Simplest correct behavior: leave files in legacy dir, advise user
    # to manually correlate. Otherwise we risk moving files into wrong finding dirs.
    echo "  WARNING: $FUZZ_ROOT/known-crashes/ contains $(ls -1 "$FUZZ_ROOT/known-crashes" | wc -l) files"
    echo "  WARNING: cannot automatically map them to finding ids without re-triage"
    echo "  WARNING: leaving $FUZZ_ROOT/known-crashes/ in place; rename/move manually if desired"
  fi

  # 5. Stamp the version
  echo "$EXPECTED_SCHEMA_VERSION" > "$STATE_DIR/schema-version"
  echo "  wrote $STATE_DIR/schema-version = $EXPECTED_SCHEMA_VERSION"

  echo ""
  echo "v0 -> v1 migration complete."
}

#------------------------------------------------------------------------------
# v1 -> v2: add coverage build awareness, instrumentation field, mark legacy snapshots
#------------------------------------------------------------------------------
migrate_v1_to_v2() {
  echo "Running v1 -> v2 migration..."

  # 1. Bump harness-built.json schema and add coverage_tracking field.
  #    Existing v1 builds didn't have coverage_binary, so we mark
  #    coverage_tracking: false to preserve campaign behavior. The user
  #    can opt back in by rebuilding.
  if [ -f "$STATE_DIR/harness-built.json" ]; then
    python3 -c "
import json
try:
    d = json.load(open('$STATE_DIR/harness-built.json'))
    if d.get('schema') == 'harness-built/v1':
        d['schema'] = 'harness-built/v2'
        # Existing campaigns didn't build a coverage binary - opt them out.
        # User can rebuild to enable.
        if 'coverage_binary' not in d:
            d['coverage_binary'] = None
        if 'coverage_tracking' not in d:
            d['coverage_tracking'] = False
        json.dump(d, open('$STATE_DIR/harness-built.json', 'w'), indent=2)
        print('  upgraded harness-built.json to v2 (coverage_tracking=False; rebuild to enable)')
    elif d.get('schema') == 'harness-built/v2':
        print('  harness-built.json already at v2')
except Exception as e:
    print('  WARN: could not upgrade harness-built.json:', e)
"
  fi

  # 2. Back-populate instrumentation field on existing coverage snapshots
  #    per Q3 - mark them as pre-instrumentation so the validator stays green.
  if [ -d "$STATE_DIR/snapshots" ]; then
    for f in "$STATE_DIR/snapshots"/coverage-*.json; do
      [ -f "$f" ] || continue
      python3 -c "
import json
try:
    d = json.load(open('$f'))
    if d.get('schema') == 'coverage-snapshot/v1':
        d['schema'] = 'coverage-snapshot/v2'
        if 'instrumentation' not in d:
            d['instrumentation'] = {
                'tracking_enabled': False,
                'coverage_build_present': False,
                'llvm_cov_available': False,
                'coverage_run_ok': False,
                'parsed_engine_log': True,
                'fork_mode': False,
                'ok': True,  # legacy is treated as ok-but-no-coverage
                'errors': []
            }
        json.dump(d, open('$f', 'w'), indent=2)
except Exception as e:
    pass
"
    done
    echo "  back-populated instrumentation field on legacy snapshots"
  fi

  # 3. Stamp version
  echo "$EXPECTED_SCHEMA_VERSION" > "$STATE_DIR/schema-version"
  echo "  wrote $STATE_DIR/schema-version = $EXPECTED_SCHEMA_VERSION"
  echo ""
  echo "v1 -> v2 migration complete."
  echo ""
  echo "NOTE: existing harness was opted OUT of coverage tracking because the"
  echo "       v1 build didn't include a coverage binary. To enable coverage:"
  echo "         1. Run /cc-fuzzer:campaign --reset (preserves findings via tarball)"
  echo "         2. Or manually build a coverage binary and update harness-built.json"
}

#------------------------------------------------------------------------------
# v2 -> v3: convert dict_file (scalar) to dict_files (array)
#------------------------------------------------------------------------------
migrate_v2_to_v3() {
  echo "Running v2 -> v3 migration..."

  if [ -f "$STATE_DIR/harness-built.json" ]; then
    python3 -c "
import json
try:
    d = json.load(open('$STATE_DIR/harness-built.json'))
    if d.get('schema') == 'harness-built/v2':
        d['schema'] = 'harness-built/v3'
        # Convert scalar dict_file to dict_files array
        if 'dict_file' in d:
            old = d.pop('dict_file')
            existing = d.get('dict_files') or []
            if old:
                existing.append(old)
            d['dict_files'] = existing
        elif 'dict_files' not in d:
            d['dict_files'] = []
        json.dump(d, open('$STATE_DIR/harness-built.json', 'w'), indent=2)
        print('  upgraded harness-built.json to v3')
    elif d.get('schema') == 'harness-built/v3':
        print('  harness-built.json already at v3')
except Exception as e:
    print('  WARN: could not upgrade harness-built.json:', e)
"
  fi

  echo "$EXPECTED_SCHEMA_VERSION" > "$STATE_DIR/schema-version"
  echo "  wrote $STATE_DIR/schema-version = $EXPECTED_SCHEMA_VERSION"
  echo ""
  echo "v2 -> v3 migration complete."
  echo ""
  echo "NOTE: dict_files is now an array. Use /cc-fuzzer:dictionaries add <name>"
  echo "       to add bundled or project-local dictionaries."
}

#------------------------------------------------------------------------------
# v3 -> v4: backfill schema field on legacy events, add coverage_disabled_reason
#------------------------------------------------------------------------------
migrate_v3_to_v4() {
  echo "Running v3 -> v4 migration..."

  # 1. Backfill schema:event/v1 on existing events.jsonl entries that lack it
  if [ -f "$STATE_DIR/events.jsonl" ]; then
    python3 -c "
import json, os
fixed = 0
out = []
with open('$STATE_DIR/events.jsonl') as f:
    for line in f:
        line = line.strip()
        if not line: continue
        try:
            d = json.loads(line)
        except:
            out.append(line)
            continue
        if 'schema' not in d:
            d = {'schema': 'event/v1', **d}
            fixed += 1
        out.append(json.dumps(d, separators=(',', ':')))

with open('$STATE_DIR/events.jsonl.tmp', 'w') as f:
    for line in out:
        f.write(line + '\n')
os.replace('$STATE_DIR/events.jsonl.tmp', '$STATE_DIR/events.jsonl')
print(f'  backfilled schema field on {fixed} legacy events')
"
  fi

  # 2. Add coverage_disabled_reason to harness-built.json if coverage_tracking is false
  #    but no reason is set. This is what the validator now warns about (per Q2=c).
  if [ -f "$STATE_DIR/harness-built.json" ]; then
    python3 -c "
import json
try:
    d = json.load(open('$STATE_DIR/harness-built.json'))
    changed = False
    if d.get('coverage_tracking') is False and not d.get('coverage_disabled_reason'):
        d['coverage_disabled_reason'] = 'v3->v4 migration: existing campaign predates mandatory coverage. Run /cc-fuzzer:campaign --reset to enable.'
        changed = True
    if changed:
        json.dump(d, open('$STATE_DIR/harness-built.json', 'w'), indent=2)
        print('  added coverage_disabled_reason to harness-built.json')
    else:
        print('  harness-built.json: no migration needed')
except Exception as e:
    print('  WARN: harness-built.json migration skipped:', e)
"
  fi

  echo "v4" > "$STATE_DIR/schema-version"
  echo "  wrote $STATE_DIR/schema-version = v4"
  echo ""
  echo "v3 -> v4 migration complete."
}

#------------------------------------------------------------------------------
# v4 -> v5: findings get verified_against_build, fuzz-config.json added,
# crashes/stale/ directory created
#------------------------------------------------------------------------------
migrate_v4_to_v5() {
  echo "Running v4 -> v5 migration..."

  # 1. Backfill verified_against_build on existing findings (use the current
  #    build_command_hash from harness-built.json as a best guess - this is
  #    accurate if no rebuild happened since the findings were recorded, and
  #    benign if it didn't since we're just pre-populating the field).
  if [ -f "$STATE_DIR/findings.jsonl" ] && [ -f "$STATE_DIR/harness-built.json" ]; then
    python3 - <<PY
import json, os
try:
    h = json.load(open('$STATE_DIR/harness-built.json'))
    bhash = h.get('build_command_hash', '') or ''
except: bhash = ''
out = []
fixed = 0
with open('$STATE_DIR/findings.jsonl') as f:
    for line in f:
        line = line.strip()
        if not line: continue
        try:
            d = json.loads(line)
        except:
            out.append(line)
            continue
        if 'verified_against_build' not in d:
            d['verified_against_build'] = bhash
            fixed += 1
        out.append(json.dumps(d, separators=(',', ':')))
with open('$STATE_DIR/findings.jsonl.tmp', 'w') as f:
    for line in out:
        f.write(line + '\n')
os.replace('$STATE_DIR/findings.jsonl.tmp', '$STATE_DIR/findings.jsonl')
print(f'  backfilled verified_against_build on {fixed} findings')
PY
  fi

  # 2. Create crashes/stale/ directory
  mkdir -p "$FUZZ_ROOT/crashes/stale"
  echo "  created $FUZZ_ROOT/crashes/stale/"

  # 3. Create fuzz-config.json with the default fuzz_forks=2
  if [ ! -f "$STATE_DIR/fuzz-config.json" ]; then
    cat > "$STATE_DIR/fuzz-config.json" <<EOF
{
  "schema": "fuzz-config/v1",
  "fuzz_forks": 2
}
EOF
    echo "  created $STATE_DIR/fuzz-config.json (fuzz_forks=2)"
  fi

  echo "$EXPECTED_SCHEMA_VERSION" > "$STATE_DIR/schema-version"
  echo "  wrote $STATE_DIR/schema-version = $EXPECTED_SCHEMA_VERSION"
  echo ""
  echo "v4 -> v5 migration complete."
}

#------------------------------------------------------------------------------
# v5 -> v6: harness-built.json gains cmplog_enabled / cmplog_binary /
# cmplog_disabled_reason. Schema bumps to harness-built/v4. Backfill existing
# campaigns by setting cmplog_enabled=false with a migration reason; the user
# can opt in later by rebuilding via /cc-fuzzer:campaign --reset.
#------------------------------------------------------------------------------
migrate_v5_to_v6() {
  echo "Running v5 -> v6 migration..."

  if [ -f "$STATE_DIR/harness-built.json" ]; then
    python3 - <<PY
import json, os
path = '$STATE_DIR/harness-built.json'
try:
    d = json.load(open(path))
except Exception as e:
    print(f'  WARN: could not read harness-built.json: {e}')
    raise SystemExit(0)

changed = False

# Bump schema version
if d.get('schema') != 'harness-built/v4':
    d['schema'] = 'harness-built/v4'
    changed = True

# Backfill cmplog fields. Default: disabled with migration reason. Existing
# campaigns predate cmplog and will keep working without it. Users who want
# Redqueen-style I2S can rebuild via /cc-fuzzer:campaign --reset.
if 'cmplog_enabled' not in d:
    d['cmplog_enabled'] = False
    changed = True
if 'cmplog_binary' not in d:
    d['cmplog_binary'] = None
    changed = True
if not d.get('cmplog_enabled') and not d.get('cmplog_disabled_reason'):
    d['cmplog_disabled_reason'] = 'v5->v6 migration: existing campaign predates cmplog. Run /cc-fuzzer:campaign --reset to enable Redqueen-style input-to-state.'
    changed = True

if changed:
    with open(path + '.tmp', 'w') as f:
        json.dump(d, f, indent=2)
    os.replace(path + '.tmp', path)
    print('  backfilled cmplog fields in harness-built.json')
else:
    print('  harness-built.json: no migration needed')
PY
  fi

  echo "$EXPECTED_SCHEMA_VERSION" > "$STATE_DIR/schema-version"
  echo "  wrote $STATE_DIR/schema-version = $EXPECTED_SCHEMA_VERSION"
  echo ""
  echo "v5 -> v6 migration complete."
}

#------------------------------------------------------------------------------
# v6 -> v7: harness-built.json gains fuzzing_mode field (bumps to harness-built/v5);
# FINDINGS-REPORT.md placeholder created if absent; current.json gains optional
# last_report_at (no migration needed - it's optional).
#------------------------------------------------------------------------------
migrate_v6_to_v7() {
  echo "Running v6 -> v7 migration..."

  # 1. harness-built.json: v4 -> v5, backfill fuzzing_mode = "in_process"
  if [ -f "$STATE_DIR/harness-built.json" ]; then
    python3 - <<PY
import json, os
path = '$STATE_DIR/harness-built.json'
try:
    d = json.load(open(path))
except Exception as e:
    print(f'  WARN: cannot read harness-built.json: {e}')
    raise SystemExit(0)

changed = False
if d.get('schema') != 'harness-built/v5':
    d['schema'] = 'harness-built/v5'
    changed = True
if 'fuzzing_mode' not in d:
    d['fuzzing_mode'] = 'in_process'
    changed = True

if changed:
    with open(path + '.tmp', 'w') as f:
        json.dump(d, f, indent=2)
    os.replace(path + '.tmp', path)
    print('  upgraded harness-built.json to v5 (fuzzing_mode=in_process default)')
else:
    print('  harness-built.json already at v5')
PY
  fi

  # 2. Create FINDINGS-REPORT.md placeholder if absent
  REPORT="$STATE_DIR/FINDINGS-REPORT.md"
  if [ ! -f "$REPORT" ]; then
    cat > "$REPORT" <<'EOF'
# cc-fuzzer Findings Report

_No report has been generated yet. Run `/cc-fuzzer:report` to populate this file._
EOF
    echo "  created $REPORT placeholder"
  fi

  echo "v7" > "$STATE_DIR/schema-version"
  echo "  wrote schema-version = v7"
  echo ""
  echo "v6 -> v7 migration complete."
}

#------------------------------------------------------------------------------
# v7 -> v8:
#   1. findings.jsonl: tombstone legacy/malformed records to a sidecar so the
#      main file passes v7 strict validation. Records that fail any of these
#      checks get moved verbatim to findings-legacy.jsonl:
#        - JSON parse error
#        - schema != "finding/v1"
#        - id does not match ^f[0-9]{3,}$
#        - missing any required v7 field
#        - has any unrecognized v7 field
#   2. Multi-fuzzer file/state layout (added by task #17 — see below).
#------------------------------------------------------------------------------
migrate_v7_to_v8() {
  echo "Running v7 -> v8 migration..."

  # --- Step 1: findings.jsonl tombstone pass ---
  if [ -f "$STATE_DIR/findings.jsonl" ]; then
    python3 - <<PY
import json, os, re
ID_RE = re.compile(r'^f[0-9]{3,}$')
REQUIRED = {"schema","id","stack_hash","category","location","exploitability",
            "root_cause","reproducer","first_seen","last_seen","dedup_count"}
ALLOWED  = REQUIRED | {"subcategory","sanitizer_report_excerpt","verified_against_build"}

src = '$STATE_DIR/findings.jsonl'
legacy_path = '$STATE_DIR/findings-legacy.jsonl'
tmp = src + '.migrating'

valid_lines, legacy_lines = [], []
with open(src) as f:
    for ln, raw in enumerate(f, 1):
        raw = raw.rstrip('\n')
        if not raw.strip():
            continue
        # Try to parse
        try:
            d = json.loads(raw)
        except Exception:
            legacy_lines.append(raw)
            continue
        # Check schema string
        if d.get('schema') != 'finding/v1':
            legacy_lines.append(raw); continue
        # Check id format
        if not ID_RE.match(str(d.get('id',''))):
            legacy_lines.append(raw); continue
        # Check required + recognized fields
        keys = set(d.keys())
        missing = REQUIRED - keys
        unrecognized = keys - ALLOWED
        if missing or unrecognized:
            legacy_lines.append(raw); continue
        valid_lines.append(raw)

if legacy_lines:
    # Append (don't overwrite) — tombstones accumulate across migrations
    from datetime import datetime, timezone
    ts = datetime.now(timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ')
    mode = 'a' if os.path.exists(legacy_path) else 'w'
    with open(legacy_path, mode) as f:
        if mode == 'a':
            f.write('\n')
        f.write(f'# === tombstoned by v7->v8 migration on {ts} ===\n')
        for line in legacy_lines:
            f.write(line + '\n')
    print(f'  tombstoned {len(legacy_lines)} legacy/malformed findings record(s) to findings-legacy.jsonl')

with open(tmp, 'w') as f:
    for line in valid_lines:
        f.write(line + '\n')
os.replace(tmp, src)
print(f'  retained {len(valid_lines)} valid findings record(s) in findings.jsonl')
PY
  fi

  # --- Step 2: rename legacy fuzzer.* files to fuzzer-main.* layout ---
  # Pre-v0.17 had a single fuzzer.pid/.engine/.log; v0.17 has one set per
  # slot. The migration renames the legacy files into "main" slot and
  # leaves the original paths as symlinks for the brief transition window
  # so anything still reading fuzzer.pid keeps working.
  LEGACY_PID="$STATE_DIR/fuzzer.pid"
  LEGACY_ENG="$STATE_DIR/fuzzer.engine"
  LEGACY_LOG="$STATE_DIR/fuzzer.log"
  if [ -f "$LEGACY_PID" ] && [ ! -L "$LEGACY_PID" ]; then
    mv "$LEGACY_PID" "$STATE_DIR/fuzzer-main.pid"
    ln -sf "fuzzer-main.pid" "$LEGACY_PID"
    echo "  renamed fuzzer.pid -> fuzzer-main.pid (legacy path is now a symlink)"
  fi
  if [ -f "$LEGACY_ENG" ] && [ ! -L "$LEGACY_ENG" ]; then
    mv "$LEGACY_ENG" "$STATE_DIR/fuzzer-main.engine"
    ln -sf "fuzzer-main.engine" "$LEGACY_ENG"
    echo "  renamed fuzzer.engine -> fuzzer-main.engine (legacy path is now a symlink)"
  fi
  if [ -f "$LEGACY_LOG" ] && [ ! -L "$LEGACY_LOG" ]; then
    mv "$LEGACY_LOG" "$STATE_DIR/fuzzer-main.log"
    ln -sf "fuzzer-main.log" "$LEGACY_LOG"
    echo "  renamed fuzzer.log -> fuzzer-main.log (legacy path is now a symlink)"
  fi

  # --- Step 3: bump fuzz-config.json to v2, backfill fuzzer_slots = [main] ---
  CONFIG="$STATE_DIR/fuzz-config.json"
  if [ ! -f "$CONFIG" ]; then
    # No config — write a fresh v2 with sensible defaults
    cat > "$CONFIG" <<EOF
{
  "schema": "fuzz-config/v2",
  "fuzz_forks": 2,
  "fuzzer_slots": [
    {"slot": "main", "engine": "libfuzzer"}
  ]
}
EOF
    echo "  created $CONFIG (fuzz-config/v2, default single 'main' slot)"
  else
    # Existing config — preserve user settings, bump schema, backfill slots
    DETECTED_ENGINE="libfuzzer"
    if [ -f "$STATE_DIR/fuzzer-main.engine" ]; then
      DETECTED_ENGINE=$(cat "$STATE_DIR/fuzzer-main.engine" 2>/dev/null | tr -d ' \n')
      [ -z "$DETECTED_ENGINE" ] && DETECTED_ENGINE="libfuzzer"
    fi
    python3 - <<PY
import json, os
path = '$CONFIG'
try:
    d = json.load(open(path))
except Exception as e:
    print(f'  WARN: could not read $CONFIG: {e}')
    raise SystemExit(0)
changed = False
if d.get('schema') != 'fuzz-config/v2':
    d['schema'] = 'fuzz-config/v2'
    changed = True
if not d.get('fuzzer_slots'):
    d['fuzzer_slots'] = [{'slot': 'main', 'engine': '$DETECTED_ENGINE'}]
    changed = True
if changed:
    with open(path + '.tmp','w') as f:
        json.dump(d, f, indent=2)
    os.replace(path + '.tmp', path)
    print('  bumped fuzz-config.json to v2 and backfilled fuzzer_slots=[main]')
else:
    print('  fuzz-config.json already at v2 with slots')
PY
  fi

  # --- Step 4: create fuzzers.json manifest from the live fuzzer-main pid file ---
  MANIFEST="$STATE_DIR/fuzzers.json"
  if [ ! -f "$MANIFEST" ] && [ -f "$STATE_DIR/fuzzer-main.pid" ]; then
    HARNESS_BIN=""
    if [ -f "$STATE_DIR/harness-built.json" ]; then
      HARNESS_BIN=$(python3 -c "
import json
try: print(json.load(open('$STATE_DIR/harness-built.json')).get('harness_binary',''))
except: pass" 2>/dev/null)
    fi
    DETECTED_ENGINE="libfuzzer"
    if [ -f "$STATE_DIR/fuzzer-main.engine" ]; then
      DETECTED_ENGINE=$(cat "$STATE_DIR/fuzzer-main.engine" 2>/dev/null | tr -d ' \n')
      [ -z "$DETECTED_ENGINE" ] && DETECTED_ENGINE="libfuzzer"
    fi
    SLOT_PID=$(cat "$STATE_DIR/fuzzer-main.pid" 2>/dev/null | tr -d ' \n')
    [ -z "$SLOT_PID" ] && SLOT_PID="0"
    SLOT_PGID="$SLOT_PID"
    NOW_ISO=$(date -u +"%Y-%m-%dT%H:%M:%SZ")
    cat > "$MANIFEST" <<EOF
{
  "schema": "fuzzers/v1",
  "slots": [
    {
      "slot": "main",
      "engine": "$DETECTED_ENGINE",
      "binary": "$HARNESS_BIN",
      "pid": "$SLOT_PID",
      "pgid": "$SLOT_PGID",
      "started_at": "$NOW_ISO",
      "log_file": "$STATE_DIR/fuzzer-main.log",
      "pid_file": "$STATE_DIR/fuzzer-main.pid",
      "engine_file": "$STATE_DIR/fuzzer-main.engine",
      "role": null,
      "afl_power_schedule": null,
      "restart_count": 0,
      "last_restart_at": null
    }
  ]
}
EOF
    echo "  created $MANIFEST (backfilled from fuzzer-main.pid)"
  fi

  echo "v8" > "$STATE_DIR/schema-version"
  echo "  wrote schema-version = v8"
  echo ""
  echo "v7 -> v8 migration complete."
}

#------------------------------------------------------------------------------
# v8 -> v9: multi-harness mode (opt-in).
#
# This migration is intentionally a no-op for singular-mode campaigns: it only
# rewrites state/schema-version. Multi-mode activation is a separate, explicit
# user action (/cc-fuzzer:campaign --add-harness <name> --entry <fn>), which
# performs the file moves and schema upgrades in place at that time. Why:
# forcing every existing campaign to wrap itself as harnesses=[<one>] would be
# a destructive surprise. Keep singular as-is; let the user opt in.
#------------------------------------------------------------------------------
migrate_v8_to_v9() {
  echo "Running v8 -> v9 migration..."
  echo "  (no-op for singular-mode campaigns - schema-version bump only)"
  echo "  to enable multi-harness mode after this migration, run:"
  echo "    /cc-fuzzer:campaign --add-harness <name> --entry <fn>"

  echo "v9" > "$STATE_DIR/schema-version"
  echo "  wrote schema-version = v9"
  echo ""
  echo "v8 -> v9 migration complete."
}

case "$CURRENT" in
  v0)
    migrate_v0_to_v1; CURRENT="v1"
    migrate_v1_to_v2; CURRENT="v2"
    migrate_v2_to_v3; CURRENT="v3"
    migrate_v3_to_v4; CURRENT="v4"
    migrate_v4_to_v5; CURRENT="v5"
    migrate_v5_to_v6; CURRENT="v6"
    migrate_v6_to_v7; CURRENT="v7"
    migrate_v7_to_v8; CURRENT="v8"
    migrate_v8_to_v9
    ;;
  v1)
    migrate_v1_to_v2; CURRENT="v2"
    migrate_v2_to_v3; CURRENT="v3"
    migrate_v3_to_v4; CURRENT="v4"
    migrate_v4_to_v5; CURRENT="v5"
    migrate_v5_to_v6; CURRENT="v6"
    migrate_v6_to_v7; CURRENT="v7"
    migrate_v7_to_v8; CURRENT="v8"
    migrate_v8_to_v9
    ;;
  v2)
    migrate_v2_to_v3; CURRENT="v3"
    migrate_v3_to_v4; CURRENT="v4"
    migrate_v4_to_v5; CURRENT="v5"
    migrate_v5_to_v6; CURRENT="v6"
    migrate_v6_to_v7; CURRENT="v7"
    migrate_v7_to_v8; CURRENT="v8"
    migrate_v8_to_v9
    ;;
  v3)
    migrate_v3_to_v4; CURRENT="v4"
    migrate_v4_to_v5; CURRENT="v5"
    migrate_v5_to_v6; CURRENT="v6"
    migrate_v6_to_v7; CURRENT="v7"
    migrate_v7_to_v8; CURRENT="v8"
    migrate_v8_to_v9
    ;;
  v4)
    migrate_v4_to_v5; CURRENT="v5"
    migrate_v5_to_v6; CURRENT="v6"
    migrate_v6_to_v7; CURRENT="v7"
    migrate_v7_to_v8; CURRENT="v8"
    migrate_v8_to_v9
    ;;
  v5)
    migrate_v5_to_v6; CURRENT="v6"
    migrate_v6_to_v7; CURRENT="v7"
    migrate_v7_to_v8; CURRENT="v8"
    migrate_v8_to_v9
    ;;
  v6)
    migrate_v6_to_v7; CURRENT="v7"
    migrate_v7_to_v8; CURRENT="v8"
    migrate_v8_to_v9
    ;;
  v7)
    migrate_v7_to_v8; CURRENT="v8"
    migrate_v8_to_v9
    ;;
  v8)
    migrate_v8_to_v9
    ;;
  v9)
    echo "already at v9"
    ;;
  *)
    echo "ERROR: unknown source version '$CURRENT'" >&2
    echo "Supported migrations: v0 -> v1 -> v2 -> v3 -> v4 -> v5 -> v6 -> v7 -> v8 -> v9" >&2
    [ -n "$BACKUP_FILE" ] && echo "Backup is at $BACKUP_FILE; restore manually if needed." >&2
    exit 1
    ;;
esac

echo ""
if [ -n "$BACKUP_FILE" ]; then
  echo "Migration complete. Backup at $BACKUP_FILE"
else
  echo "Migration complete. (no backup tarball was needed for this transition)"
fi
echo "Run 'scripts/validate-state.sh' to verify."
