#!/usr/bin/env python3
"""build_current_multi.py — compose current.json (cc-fuzzer-current/v2) for a
multi-harness campaign.

In multi mode the per-harness state collection is too tangled with the singular
path's global variables to share code, so this runs entirely standalone: it
walks declared harnesses, computes per-harness coverage / fuzzer_stats / gaps /
recommendation, picks active_harness from a fixed priority table, writes
current/v2 with back-compat shims, and prints the output path.

Reads from the environment:
  STATE_DIR SNAPSHOTS_DIR DECLARED (newline-list) NOW (epoch) TMP OUT

This module was lifted verbatim from update-current.sh's inline heredoc; the
derived tick_coverage/consult/yolo blocks are merged afterward by
derive-tick-state.py, exactly as before.
"""
import json
import os
import sys
import glob
import re  # noqa: F401 (kept for parity with the original heredoc imports)


def main():
    state_dir = os.environ['STATE_DIR']
    snaps_dir = os.environ['SNAPSHOTS_DIR']
    declared = [n for n in os.environ['DECLARED'].splitlines() if n.strip()]
    now = int(os.environ['NOW'])
    tmp_path = os.environ['TMP']
    out_path = os.environ['OUT']

    # Priority table (highest first). Determines which harness becomes
    # active_harness when multiple have actionable recommendations.
    PRIORITY = ['triage', 'restart_fuzzer', 'fix_instrumentation', 'analyze_gaps',
                'reanalyze_gaps', 'concolic', 'generate_seeds', 'mutator', 'stop', 'sleep']
    PRI = {b: i for i, b in enumerate(PRIORITY)}

    def safe_read_json(p, default=None):
        try:
            with open(p) as f:
                return json.load(f)
        except Exception:
            return default

    # 1. Slot manifest (live)
    manifest = safe_read_json(os.path.join(state_dir, 'fuzzers.json'), {})
    slots = manifest.get('slots', [])

    def slot_alive(s):
        pid = s.get('pid', '')
        try:
            if pid and int(pid) > 0:
                os.kill(int(pid), 0)
                return True
        except (ValueError, OSError, ProcessLookupError):
            pass
        return False

    def slots_for_harness(h):
        return [s for s in slots if s.get('harness') == h]

    # 2. Harness binaries / symcc availability (from harnesses.json)
    hset = safe_read_json(os.path.join(state_dir, 'harnesses.json'), {})
    records = {h.get('name'): h for h in hset.get('harnesses', []) if isinstance(h, dict)}

    # 3. Findings counts by harness
    by_harness = {h: 0 for h in declared}
    total_findings = 0
    findings_path = os.path.join(state_dir, 'findings.jsonl')
    if os.path.isfile(findings_path):
        with open(findings_path) as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    d = json.loads(line)
                except Exception:
                    continue
                total_findings += 1
                for h in d.get('harnesses') or []:
                    if h in by_harness:
                        by_harness[h] += 1

    # 4. Per-harness state collection
    def collect(harness):
        # Coverage snapshot — pick the one with the highest timestamp field
        cov_files = glob.glob(os.path.join(snaps_dir, f'coverage-{harness}-*.json'))
        best_cov = None
        best_ts = -1
        for f in cov_files:
            d = safe_read_json(f, {})
            ts = d.get('timestamp', 0)
            if ts > best_ts:
                best_ts = ts
                best_cov = (f, d)
        cov_file = best_cov[0] if best_cov else ''
        cov_doc = best_cov[1] if best_cov else {}
        cov_ts = cov_doc.get('timestamp', 0)
        c = cov_doc.get('coverage', {})
        lines_cov = c.get('lines_covered', 0)
        lines_total = c.get('lines_total', 0)
        line_pct = c.get('line_pct', 0)

        # Plateau: 3 most recent snapshots, <1% growth = plateau
        cov_sorted = sorted(
            ((d.get('timestamp', 0), d) for d in (safe_read_json(f, {}) for f in cov_files)),
            reverse=True
        )
        plateau = False
        last_progress_ts = cov_ts
        if len(cov_sorted) >= 3:
            recent = cov_sorted[0][1].get('coverage', {}).get('lines_covered', 0)
            oldest = cov_sorted[2][1].get('coverage', {}).get('lines_covered', 0)
            delta_pct = ((recent - oldest) / max(oldest, 1)) * 100 if oldest else 0
            plateau = abs(delta_pct) < 1.0
            last_progress_ts = cov_sorted[0][0] if recent > oldest else cov_sorted[2][0]
        secs_since = max(0, now - int(last_progress_ts)) if last_progress_ts else 0

        # Instrumentation status
        inst = cov_doc.get('instrumentation', {})
        inst_ok = bool(inst.get('ok', True))
        inst_tracking = bool(inst.get('tracking_enabled', False))

        # Aggregated fuzzer stats across this harness's slots — simplest model:
        # take the snapshot's recorded stats (already aggregated when snapshot ran).
        fs = cov_doc.get('fuzzer_stats', {})
        execs = fs.get('execs', 0)
        execs_per_sec = fs.get('execs_per_sec', 0)
        paths = fs.get('paths', 0)
        crashes = fs.get('crashes', 0)
        new_crashes = len(cov_doc.get('new_crashes_since_previous', []))

        # Latest gap report
        gap_files = sorted(glob.glob(os.path.join(snaps_dir, f'gaps-{harness}-*.json')))
        gap_file = gap_files[-1] if gap_files else ''
        gap_doc = safe_read_json(gap_file, {}) if gap_file else {}
        gaps = gap_doc.get('gaps', []) if gap_file else []
        gap_total = len(gaps)
        gap_direct = sum(1 for g in gaps if g.get('reason') == 'direct_compare')
        gap_concolic = sum(1 for g in gaps if g.get('reason') in ('checksum_barrier', 'deep_path_condition'))
        gap_seedgen = sum(1 for g in gaps if g.get('reason') in ('format_barrier', 'value_constraint'))
        gap_harness = sum(1 for g in gaps if g.get('reason') in ('harness_gap', 'state_precondition'))
        gap_mutator = sum(1 for g in gaps if g.get('recommended_agent') == 'mutator')

        # Per-harness liveness across its slots
        my_slots = slots_for_harness(harness)
        any_alive = any(slot_alive(s) for s in my_slots)

        # SymCC availability — read per-harness record
        rec = records.get(harness, {})
        symcc_bin = rec.get('symcc_binary') or ''
        symcc_avail = bool(symcc_bin) and os.path.isfile(symcc_bin) and os.access(symcc_bin, os.X_OK)

        # Per-harness recommendation (same logic as singular)
        if my_slots and not any_alive:
            branch, reason = 'restart_fuzzer', f'no live slot for harness {harness}'
        elif inst_tracking and not inst_ok:
            branch, reason = 'fix_instrumentation', 'coverage tracking enabled but instrumentation broken'
        elif new_crashes > 0:
            branch, reason = 'triage', f'{new_crashes} new crash files for {harness} since last snapshot'
        elif plateau and gap_concolic > 0 and symcc_avail:
            branch, reason = 'concolic', f'plateau on {harness}, {gap_concolic} concolic-eligible gaps, SymCC available'
        elif plateau and not gap_file:
            branch, reason = 'analyze_gaps', f'plateau on {harness}, no gap report yet'
        elif plateau and gap_seedgen > 0:
            branch, reason = 'generate_seeds', f'plateau on {harness}, {gap_seedgen} seedgen-eligible gaps pending'
        elif plateau and secs_since > 1800:
            branch, reason = 'reanalyze_gaps', f'plateau on {harness} >30min, refresh'
        else:
            branch, reason = 'sleep', f'{harness}: coverage climbing or recent progress'

        return {
            'name': harness,
            'harness': {
                'binary': rec.get('harness_binary', ''),
                'symcc_binary': symcc_bin,
                'symcc_available': symcc_avail,
            },
            'coverage': {
                'snapshot_file': cov_file,
                'snapshot_ts': int(cov_ts),
                'lines_covered': lines_cov,
                'lines_total': lines_total,
                'line_pct': line_pct,
                'plateau': plateau,
                'seconds_since_progress': secs_since,
            },
            'fuzzer_stats': {
                'execs': execs,
                'execs_per_sec': execs_per_sec,
                'paths': paths,
                'crashes_total': crashes,
                'new_crashes_since_previous': new_crashes,
            },
            'gaps': {
                'latest_report': gap_file,
                'total_pending': gap_total,
                'for_concolic': gap_concolic,
                'for_seedgen': gap_seedgen,
                'for_harness': gap_harness,
                'for_mutator': gap_mutator,
                'direct_compare': gap_direct,
            },
            'recommendation': {'branch': branch, 'reason': reason},
            '_priority': PRI.get(branch, 99),
        }

    harness_entries = [collect(h) for h in declared]

    # Pick active harness via priority table; ties broken by declaration order.
    active_entry = min(
        harness_entries, key=lambda e: (e['_priority'], declared.index(e['name']))
    ) if harness_entries else None
    active_name = active_entry['name'] if active_entry else (declared[0] if declared else '')

    # Strip the internal _priority key before emitting
    for e in harness_entries:
        e.pop('_priority', None)

    # Build the per-slot summary array
    slot_summaries = []
    for s in slots:
        slot_summaries.append({
            'slot':          s.get('slot', ''),
            'harness':       s.get('harness', ''),
            'engine':        s.get('engine', 'unknown'),
            'pid':           s.get('pid', ''),
            'running':       slot_alive(s),
            'started_at':    s.get('started_at') or None,
            'restart_count': int(s.get('restart_count', 0) or 0),
        })

    # Tick number
    tick_n = 0
    events_path = os.path.join(state_dir, 'events.jsonl')
    if os.path.isfile(events_path):
        with open(events_path) as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    if json.loads(line).get('event') == 'tick':
                        tick_n += 1
                except Exception:
                    pass

    # Active-harness mirrors for back-compat shims
    ae = active_entry or {
        'harness': {'binary': '', 'symcc_binary': '', 'symcc_available': False},
        'coverage': {'snapshot_file': '', 'snapshot_ts': 0, 'lines_covered': 0, 'lines_total': 0,
                     'line_pct': 0, 'plateau': False, 'seconds_since_progress': 0},
        'fuzzer_stats': {'execs': 0, 'execs_per_sec': 0, 'paths': 0, 'crashes_total': 0, 'new_crashes_since_previous': 0},
        'gaps': {'latest_report': '', 'total_pending': 0, 'for_concolic': 0, 'for_seedgen': 0,
                 'for_harness': 0, 'for_mutator': 0, 'direct_compare': 0},
        'recommendation': {'branch': 'sleep', 'reason': ''},
    }

    # Single-slot mirror for legacy `fuzzer` field
    first_slot = slot_summaries[0] if slot_summaries else {
        'pid': '', 'running': False, 'engine': 'unknown'
    }

    doc = {
        'schema': 'cc-fuzzer-current/v2',
        'now': now,
        'tick_number': tick_n,
        'active_harness': active_name,
        'harnesses': harness_entries,
        'fuzzers': slot_summaries,
        'findings': {
            'unique_count': total_findings,
            'file': os.path.join(state_dir, 'findings.jsonl'),
            'by_harness': by_harness,
        },
        'recommendation': {
            'branch':  ae['recommendation']['branch'],
            'reason':  ae['recommendation']['reason'],
            'harness': active_name,
        },
        # Back-compat shims (mirror of harnesses[active]); removed in schema v10.
        'harness': {
            'binary':          ae['harness']['binary'],
            'symcc_binary':    ae['harness']['symcc_binary'],
            'symcc_available': ae['harness']['symcc_available'],
        },
        'coverage':     ae['coverage'],
        'fuzzer_stats': ae['fuzzer_stats'],
        'gaps':         ae['gaps'],
        'fuzzer': {
            'pid':     first_slot.get('pid', ''),
            'running': bool(first_slot.get('running', False)),
            'engine':  first_slot.get('engine', 'unknown') or 'unknown',
        },
        'multi_fuzzer': True,
    }

    with open(tmp_path, 'w') as f:
        json.dump(doc, f, indent=2)
    os.replace(tmp_path, out_path)
    print(out_path)
    return 0


if __name__ == "__main__":
    sys.exit(main())
