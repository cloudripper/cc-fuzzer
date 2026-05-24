#!/usr/bin/env python3
"""build_current_singular.py — compose current.json (cc-fuzzer-current/v1) for a
singular-mode campaign.

A faithful port of update-current.sh's singular path: it gathers fuzzer-slot
liveness, harness binaries, the latest coverage snapshot, plateau state, tick
count, gap-report counts, and instrumentation status, applies the recommended-
branch decision, then writes current/v1 atomically and prints the output path.
The derived tick_coverage/consult/yolo blocks are merged afterward by
derive-tick-state.py.

Reads from the environment: STATE_DIR SNAPSHOTS_DIR NOW (epoch) TMP OUT

One intentional fix vs. the old shell: the pre-v0.17 legacy `fuzzer.pid` path
used to emit `fuzzers: []` because an inline `python3 -c` interpolated bash
`true`/`false` into Python source and NameError'd (swallowed by 2>/dev/null).
This module emits the intended single `main` slot instead. The live typed-pid
path (every v0.17+ campaign) is byte-identical to the old output.
"""
import glob
import json
import os
import re
import sys


def _read_json(p, default=None):
    try:
        with open(p) as f:
            return json.load(f)
    except Exception:
        return default


def collect_slots(state_dir):
    """Return (slots, fuzzer_pid, fuzzer_running, engine).

    Mirrors the bash: typed fuzzer-<slot>.pid files take precedence (manifest
    order, then orphan pid files); otherwise the legacy single fuzzer.pid."""
    typed = sorted(glob.glob(os.path.join(state_dir, 'fuzzer-*.pid')))
    if typed:
        manifest = {}
        mf = os.path.join(state_dir, 'fuzzers.json')
        if os.path.isfile(mf):
            try:
                d = json.load(open(mf))
                for s in d.get('slots', []):
                    manifest[s['slot']] = s
            except Exception:
                pass
        seen = set()
        order = []
        for name in manifest.keys():
            order.append(name)
            seen.add(name)
        for pidf in typed:
            base = os.path.basename(pidf)
            m = re.match(r'fuzzer-(.+)\.pid$', base)
            if not m:
                continue
            n = m.group(1)
            if n not in seen:
                order.append(n)
                seen.add(n)

        slots = []
        for name in order:
            pid_path = os.path.join(state_dir, f'fuzzer-{name}.pid')
            eng_path = os.path.join(state_dir, f'fuzzer-{name}.engine')
            pid = ''
            if os.path.isfile(pid_path):
                try:
                    pid = open(pid_path).read().strip()
                except Exception:
                    pass
            engine = 'unknown'
            if os.path.isfile(eng_path):
                try:
                    engine = open(eng_path).read().strip()
                except Exception:
                    pass
            if not engine:
                engine = 'unknown'
            running = False
            if pid:
                try:
                    os.kill(int(pid), 0)
                    running = True
                except Exception:
                    pass
            m = manifest.get(name, {})
            slots.append({
                'slot': name,
                'engine': engine,
                'pid': pid,
                'running': running,
                'started_at': m.get('started_at') or None,
                'restart_count': int(m.get('restart_count', 0) or 0),
            })
        if slots:
            s0 = slots[0]
            return slots, s0.get('pid', ''), bool(s0.get('running', False)), s0.get('engine', 'unknown')
        return slots, '', False, 'unknown'

    # Legacy pre-v0.17 single-slot layout
    legacy_pid = os.path.join(state_dir, 'fuzzer.pid')
    if os.path.isfile(legacy_pid):
        try:
            pid = open(legacy_pid).read().strip()
        except Exception:
            pid = ''
        running = False
        if pid:
            try:
                os.kill(int(pid), 0)
                running = True
            except Exception:
                pass
        engine = 'unknown'
        eng = os.path.join(state_dir, 'fuzzer.engine')
        if os.path.isfile(eng):
            try:
                engine = open(eng).read().strip() or 'unknown'
            except Exception:
                pass
        slot = {
            'slot': 'main',
            'engine': engine or 'unknown',
            'pid': pid,
            'running': running,
            'started_at': None,
            'restart_count': 0,
        }
        return [slot], pid, running, engine or 'unknown'

    return [], '', False, 'unknown'


def latest_coverage(snaps_dir):
    """Pick the coverage snapshot with the highest content `timestamp`; return
    (path, filename_ts_str). filename_ts = basename minus 'coverage-' and '.json'."""
    best = None
    best_ts = -1
    for f in glob.glob(os.path.join(snaps_dir, 'coverage-*.json')):
        d = _read_json(f, {})
        if d is None:
            continue
        ts = d.get('timestamp', 0)
        if ts > best_ts:
            best_ts = ts
            best = f
    if not best:
        return '', '0'
    fn_ts = os.path.basename(best).replace('coverage-', '').replace('.json', '')
    return best, fn_ts


def plateau_state(snaps_dir, now):
    """3 most recent snapshots by content ts; <1% line growth = plateau.
    Returns (plateau_bool, last_progress_ts, seconds_since_progress)."""
    files = []
    for f in glob.glob(os.path.join(snaps_dir, 'coverage-*.json')):
        d = _read_json(f, None)
        if d is None:
            continue
        files.append((d.get('timestamp', 0), f, d))
    files.sort(reverse=True)
    if len(files) < 3:
        return False, 0, 0
    recent = files[0][2].get('coverage', {}).get('lines_covered', 0)
    oldest = files[2][2].get('coverage', {}).get('lines_covered', 0)
    delta_pct = ((recent - oldest) / max(oldest, 1)) * 100 if oldest else 0
    plateau = abs(delta_pct) < 1.0
    last_progress_ts = files[0][0] if recent > oldest else files[2][0]
    secs = (now - int(last_progress_ts)) if int(last_progress_ts) > 0 else 0
    return plateau, int(last_progress_ts), secs


def tick_count(state_dir):
    n = 0
    p = os.path.join(state_dir, 'events.jsonl')
    if not os.path.isfile(p):
        return 0
    try:
        with open(p) as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    if json.loads(line).get('event') == 'tick':
                        n += 1
                except Exception:
                    pass
    except Exception:
        pass
    return n


def latest_gap_file(state_dir, snaps_dir):
    """Newest gaps-*.json by MTIME (matches `ls -t`). Falls back to a stray
    report in the state root, warning to stderr."""
    def newest(pattern):
        cands = glob.glob(pattern)
        if not cands:
            return ''
        return max(cands, key=lambda p: os.path.getmtime(p))
    gf = newest(os.path.join(snaps_dir, 'gaps-*.json'))
    if not gf:
        stray = newest(os.path.join(state_dir, 'gaps-*.json'))
        if stray:
            sys.stderr.write(f"WARN: gap report at {stray} - should be in {snaps_dir}/. Move it.\n")
            return stray
    return gf


def gap_counts(gap_file):
    d = _read_json(gap_file, {}) if gap_file else {}
    gaps = d.get('gaps', []) if d else []
    total = len(gaps)
    direct = sum(1 for g in gaps if g.get('reason') == 'direct_compare')
    concolic = sum(1 for g in gaps if g.get('reason') in ('checksum_barrier', 'deep_path_condition'))
    seedgen = sum(1 for g in gaps if g.get('reason') in ('format_barrier', 'value_constraint'))
    harness = sum(1 for g in gaps if g.get('reason') in ('harness_gap', 'state_precondition'))
    mutator = sum(1 for g in gaps if g.get('recommended_agent') == 'mutator')
    return total, concolic, seedgen, harness, mutator, direct


def main():
    state_dir = os.environ['STATE_DIR']
    snaps_dir = os.environ['SNAPSHOTS_DIR']
    now = int(os.environ['NOW'])
    tmp_path = os.environ['TMP']
    out_path = os.environ['OUT']

    # 1. Fuzzer slots + legacy mirror fields
    slots, fuzzer_pid, fuzzer_running, engine = collect_slots(state_dir)

    # 2. Harness binaries
    harness_bin = ''
    symcc_bin = ''
    symcc_available = False
    hb = _read_json(os.path.join(state_dir, 'harness-built.json'), None)
    if hb is not None:
        harness_bin = hb.get('harness_binary', '') or '' if isinstance(hb, dict) else ''
        symcc_bin = hb.get('symcc_binary', '') or '' if isinstance(hb, dict) else ''
        if symcc_bin and os.path.isfile(symcc_bin) and os.access(symcc_bin, os.X_OK):
            symcc_available = True

    # 3. Latest coverage snapshot + stats
    cov_file, cov_ts = latest_coverage(snaps_dir)
    lines_cov = lines_total = line_pct = 0
    execs = execs_per_sec = paths = crashes_total = new_crashes = 0
    if cov_file:
        d = _read_json(cov_file, {}) or {}
        c = d.get('coverage', {})
        fs = d.get('fuzzer_stats', {})
        nc = d.get('new_crashes_since_previous', [])
        lines_cov = c.get('lines_covered', 0)
        lines_total = c.get('lines_total', 0)
        line_pct = c.get('line_pct', 0)
        execs = fs.get('execs', 0)
        execs_per_sec = fs.get('execs_per_sec', 0)
        paths = fs.get('paths', 0)
        crashes_total = fs.get('crashes', 0)
        new_crashes = len(nc)

    # 4. Findings (line count)
    unique_findings = 0
    fp = os.path.join(state_dir, 'findings.jsonl')
    if os.path.isfile(fp):
        with open(fp) as f:
            unique_findings = sum(1 for _ in f)

    # 5. Plateau
    plateau, _last_progress_ts, secs_since = plateau_state(snaps_dir, now)

    # 6. Tick number
    tick_n = tick_count(state_dir)

    # 7. Instrumentation status (from latest coverage snapshot)
    inst_ok = True
    inst_tracking = False
    if cov_file and os.path.isfile(cov_file):
        d = _read_json(cov_file, {}) or {}
        inst = d.get('instrumentation', {})
        inst_ok = bool(inst.get('ok', True))
        inst_tracking = bool(inst.get('tracking_enabled', False))

    # 8. Gaps
    gap_file = latest_gap_file(state_dir, snaps_dir)
    g_total, g_concolic, g_seedgen, g_harness, g_mutator, g_direct = gap_counts(gap_file)

    # 9. any-running
    any_running = any(s.get('running') for s in slots) if slots else fuzzer_running

    # 10. Recommended decision branch
    if not any_running:
        branch = 'restart_fuzzer'
        reason = 'no fuzzer slot is running'
    elif inst_tracking and not inst_ok:
        branch = 'fix_instrumentation'
        reason = 'coverage tracking enabled but instrumentation broken - cannot make decisions on bogus zeros'
    elif new_crashes > 0:
        branch = 'triage'
        reason = f'{new_crashes} new crash files since last snapshot'
    elif plateau and g_concolic > 0 and symcc_available:
        branch = 'concolic'
        reason = f'plateau, {g_concolic} concolic-eligible gaps, SymCC available'
    elif plateau and not gap_file:
        branch = 'analyze_gaps'
        reason = 'plateau detected, no gap report yet'
    elif plateau and g_seedgen > 0:
        branch = 'generate_seeds'
        reason = f'plateau, {g_seedgen} seedgen-eligible gaps pending'
    elif plateau and secs_since > 1800:
        branch = 'reanalyze_gaps'
        reason = 'plateau >30min, gap report stale, refresh'
    else:
        branch = 'sleep'
        reason = 'coverage climbing or recent progress, no action needed'

    # 11. Assemble current/v1
    doc = {
        "schema": "cc-fuzzer-current/v1",
        "now": now,
        "tick_number": tick_n,
        "fuzzer": {
            "pid": fuzzer_pid,
            "running": bool(fuzzer_running),
            "engine": engine or 'unknown',
        },
        "fuzzers": slots,
        "harness": {
            "binary": harness_bin,
            "symcc_binary": symcc_bin or '',
            "symcc_available": symcc_available,
        },
        "coverage": {
            "snapshot_file": cov_file,
            "snapshot_ts": int(cov_ts) if str(cov_ts).lstrip('-').isdigit() else 0,
            "lines_covered": lines_cov,
            "lines_total": lines_total,
            "line_pct": line_pct,
            "plateau": plateau,
            "seconds_since_progress": secs_since,
        },
        "fuzzer_stats": {
            "execs": execs,
            "execs_per_sec": execs_per_sec,
            "paths": paths,
            "crashes_total": crashes_total,
            "new_crashes_since_previous": new_crashes,
        },
        "findings": {
            "unique_count": unique_findings,
            "file": state_dir + '/findings.jsonl',
        },
        "gaps": {
            "latest_report": gap_file,
            "total_pending": g_total,
            "for_concolic": g_concolic,
            "for_seedgen": g_seedgen,
            "for_harness": g_harness,
            "for_mutator": g_mutator,
            "direct_compare": g_direct,
        },
        "recommendation": {
            "branch": branch,
            "reason": reason,
        },
    }
    doc['multi_fuzzer'] = len(slots) > 1

    with open(tmp_path, 'w') as f:
        json.dump(doc, f, indent=2)
    os.replace(tmp_path, out_path)
    print(out_path)
    return 0


if __name__ == "__main__":
    sys.exit(main())
