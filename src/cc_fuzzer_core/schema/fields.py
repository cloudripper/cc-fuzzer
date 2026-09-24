"""State schema constants: the schema version and every per-file field list.

Lifted from validate-state.sh (the HARNESS_BUILT_* building blocks and the
inline required/allowed lists passed to validate_json) so the validator, the
docs and any future writer share one definition. STATE_SCHEMA.md is the human
description of these; tests/test_core_schema.py checks the two agree on the
version.
"""
from __future__ import annotations

from dataclasses import dataclass

# The only supported state schema (v0.30+). Older campaigns cannot be migrated.
SCHEMA_VERSION = "v12"


def _f(s: str) -> tuple[str, ...]:
    return tuple(s.split(",")) if s else ()


# Field-set building blocks. The active schema is harness-built/v7; v5/v6 are
# just the shared base field lists v7 composes on (v6 adds `name`, v7 adds nix
# backend fields).
HARNESS_BUILT_SCHEMA = "harness-built/v7"
HARNESS_BUILT_REQUIRED_V5 = _f(
    "harness_source,harness_binary,build_script,entry_function,target_source,target_source_hash,"
    "build_command_hash,built_at,coverage_tracking,cmplog_enabled,fuzzing_mode")
HARNESS_BUILT_ALLOWED_V5 = _f(
    "harness_source,harness_binary,coverage_binary,coverage_dso,verify_binary,coverage_tracking,"
    "coverage_disabled_reason,cmplog_binary,cmplog_enabled,cmplog_disabled_reason,symcc_binary,"
    "mutator_source,build_script,dict_files,entry_function,input_encoding,sanitizers,fuzzing_mode,"
    "target_source,target_source_hash,build_command_hash,harness_attempts,built_at,build_command,oracle")
HARNESS_BUILT_REQUIRED_V6 = ("name",) + HARNESS_BUILT_REQUIRED_V5
HARNESS_BUILT_ALLOWED_V6 = ("name",) + HARNESS_BUILT_ALLOWED_V5
HARNESS_BUILT_REQUIRED_V7 = ("name", "build_backend") + HARNESS_BUILT_REQUIRED_V5
HARNESS_BUILT_ALLOWED_V7 = (("build_backend", "build_backend_decided_at", "build_backend_decided_by", "nix")
                            + HARNESS_BUILT_ALLOWED_V6)


@dataclass(frozen=True)
class FileSchema:
    """One JSON document type: its `schema` string and field sets. lenient =>
    unrecognized fields are a warning, not an error (immutable historical
    snapshots whose schema grew over time)."""
    schema: str
    required: tuple[str, ...]
    allowed: tuple[str, ...]
    lenient: bool = False


HARNESS_BUILT = FileSchema(HARNESS_BUILT_SCHEMA, HARNESS_BUILT_REQUIRED_V7, HARNESS_BUILT_ALLOWED_V7)
HARNESS_SET = FileSchema("harness-set/v1", ("harnesses",), ("harnesses",))
CURRENT = FileSchema(
    "cc-fuzzer-current/v2",
    _f("now,tick_number,active_harness,harnesses,fuzzers,findings,recommendation"),
    _f("now,tick_number,active_harness,harnesses,fuzzers,findings,recommendation,last_report_at,"
       "multi_fuzzer,coverage,fuzzer_stats,gaps,fuzzer,harness,tick_coverage,consult_state,yolo_state"))
BUDGET = FileSchema(
    "budget/v1",
    _f("campaign_started,limit_usd,spent_usd,last_updated"),
    _f("campaign_started,limit_usd,spent_usd,spent_per_model,tokens_in,tokens_out,last_updated"))
FUZZ_CONFIG = FileSchema(
    "fuzz-config/v3",
    _f("fuzz_forks,harnesses,fuzzer_slots"),
    _f("fuzz_forks,harnesses,fuzzer_slots,tick,cve,yolo,code_review,models"))
FUZZERS = FileSchema("fuzzers/v2", ("slots",), ("slots",))

# Snapshot files, in the order validate-state.sh checks them: (glob, schema).
# code-review-*.json is special-cased by the validator (prescan files are
# skipped; -w<NN> window partials use CODE_REVIEW_WINDOW).
SNAPSHOTS = (
    ("coverage-*.json", FileSchema(
        "coverage-snapshot/v2",
        _f("timestamp,engine,fuzzer_stats,coverage,instrumentation"),
        _f("timestamp,engine,fuzzer_stats,coverage,instrumentation,previous_snapshot_ts,"
           "new_crashes_since_previous,top_unreached_functions,harness"), lenient=True)),
    ("gaps-*.json", FileSchema(
        "gaps-report/v1", _f("timestamp,snapshot_file,gaps"), _f("timestamp,snapshot_file,gaps,harness"),
        lenient=True)),
    ("concolic-*.json", FileSchema(
        "concolic-result/v1",
        _f("timestamp,gaps_targeted,seeds_used,inputs_generated,inputs_validated,inputs_promoted_to_corpus"),
        _f("timestamp,gaps_targeted,seeds_used,inputs_generated,inputs_validated,inputs_promoted_to_corpus,"
           "symcc_timeouts,symcc_errors,harness"), lenient=True)),
    ("tick-coverage-*.json", FileSchema(
        "tick-coverage/v1", _f("timestamp,mode,harnesses,overall"),
        _f("timestamp,mode,harnesses,overall,stale_harnesses,stale_threshold_seconds"), lenient=True)),
    ("tick-briefing-*.json", FileSchema(
        "tick-briefing/v1", _f("ts,tick_number,trigger,coverage,active_gaps,sonnet_recommendation"),
        _f("ts,tick_number,trigger,last_consult_ts,last_consult_tick,ticks_since_last_consult,coverage,"
           "active_gaps,dispatched_since_last_consult,findings_since_last_consult,sonnet_recommendation,"
           "toolbox,ceiling"), lenient=True)),
    ("ceiling-probe-*.json", FileSchema(
        "ceiling-probe/v1", _f("ladder_stage,is_real_ceiling,structural_candidates,engine_fit,summary"),
        _f("timestamp,harness,plateau_active,ladder_stage,is_real_ceiling,ticks_since_gain,"
           "plateau_escalate_ticks,structural_candidates,untried_candidates,recommended_structural,"
           "attempted_since_plateau,harness_writer_dispatches_since_plateau,consult_since_plateau,"
           "engine_fit,dead_count,summary"), lenient=True)),
    ("planner-consult-*.json", FileSchema(
        "planner-consult/v1", _f("ts,verdict,reason"),
        _f("ts,tick_number,briefing_file,verdict,reason,tactic,rationale"), lenient=True)),
    ("cve-context-*.json", FileSchema(
        "cve-context/v1", _f("ts,target,nvd_query,fetch_stats,hotspots,pattern_frequency,cves"),
        _f("ts,target,nvd_query,fetch_stats,hotspots,pattern_frequency,patch_idioms,"
           "time_since_last_high_cve_days,cves"), lenient=True)),
    ("code-review-prescan-*.json", FileSchema(
        "code-review-prescan/v1", _f("ts,target_root,scope,top_candidates"),
        _f("ts,target_root,scope,top_candidates,full_inventory_summary"), lenient=True)),
)
CODE_REVIEW = FileSchema(
    "code-review/v1", _f("ts,target,scope,tiers_run,findings,focus_areas"),
    _f("ts,target,scope,tiers_run,findings,focus_areas,model_costs,revisit_passes"), lenient=True)
# Sweep-flow window partials (code-review-<ts>-w<NN>.json): need no focus_areas yet.
CODE_REVIEW_WINDOW = FileSchema(
    "code-review/v1", _f("ts,scope,findings"), CODE_REVIEW.allowed, lenient=True)
CODE_REVIEW_WINDOW_GLOB = "code-review-*-w[0-9]*.json"

# finding/v2 (findings.jsonl): the only finding schema since v0.30.
FINDING_SCHEMA = "finding/v2"
FINDING_CRASH_REQUIRED = frozenset(_f(
    "schema,id,stack_hash,category,location,exploitability,root_cause,reproducer,first_seen,"
    "last_seen,dedup_count,harnesses"))
# v0.18 additive fields (verification pipeline + maintainer-facing report).
FINDING_V018_OPTIONAL = frozenset(_f(
    "poc_kind,poc_path,cvss_v3_1,cwe_id,principles_audit,verification,disclosure_state,weaponization"))
# Oracle-driven (logic) finding fields. Absent => crash finding.
FINDING_ORACLE_OPTIONAL = frozenset(("oracle_type", "divergence"))
# Code-review-sourced candidates (findings.sh import-cr): provenance + cr framing.
FINDING_CR_SOURCE_FIELDS = frozenset(_f(
    "source,cr_ref,oracle_kind,trust_boundary_crossed,precondition,code_review_evidence,realism_attestation"))
FINDING_ALLOWED = (FINDING_CRASH_REQUIRED
                   | frozenset(_f("subcategory,sanitizer_report_excerpt,verified_against_build,status,"
                                  "stale_against_build"))
                   | FINDING_V018_OPTIONAL | FINDING_ORACLE_OPTIONAL | FINDING_CR_SOURCE_FIELDS)
# A code_review candidate has no stack_hash/reproducer; it requires provenance.
FINDING_CR_REQUIRED = (FINDING_CRASH_REQUIRED - {"stack_hash", "reproducer"}) | {"source", "cr_ref"}

# code-review/v1 per-finding required set.
CR_FINDING_REQUIRED = frozenset(_f(
    "id,cr_hash,status,file,function,line_range,pattern,confidence,tier_classified,evidence"))

FUZZERS_SLOT_REQUIRED = frozenset(_f(
    "slot,engine,binary,pid,pgid,started_at,log_file,pid_file,engine_file,restart_count"))

CORRECTION_SCHEMA = "harness-correction/v1"
CORRECTION_REQUIRED = frozenset(_f("schema,ts,finding_id,stack_hash,principle,suggested_fix"))
# The four artifact-filter principles (crash-triager) — shared by the
# harness-corrections and dropped-crash ledgers.
PRINCIPLES = frozenset(_f("harness_correctness,api_contract,public_api_reachability,entry_point_currency"))

DROPPED_SCHEMA = "dropped-crash/v1"
DROPPED_REQUIRED = frozenset(_f("schema,ts,crash_file,stage,reason"))
DROPPED_STAGES = frozenset(_f("artifact_filter,deterministic_replay,target_realistic_reproducer"))

EVENT_SCHEMA = "event/v1"
EVENT_REQUIRED = frozenset(_f("schema,ts,tick,event"))

SLOT_ENGINES = ("libfuzzer", "aflpp")
SLOT_ROLES = ("master", "secondary")
AFL_POWER_SCHEDULES = ("explore", "exploit", "fast", "coe", "quad", "lin", "seek", "rare")
FUZZING_MODES = ("in_process", "process_based")
