"""The surface a CRS actually needs, and nothing else.

A CRS already owns the things cc-fuzzer's plugin has to provide for itself: a
scheduler, fuzzer lifecycle, corpus sync across harnesses, and a listener that
hears about crashes as they happen. It does not need `loop.step()`, and
driving one campaign a tick at a time is the wrong shape for a system running
many harnesses under its own orchestration.

What is worth importing is the judgement that sits either side of the fuzzer,
in two request/response seams:

    triage(record, crash)      a crash arrived. Is it real, which bug is it,
                               what is the smallest input that shows it, and
                               does the oracle confirm it?
    check_patch(record, ...)   a patch was written. Does it stop the PoV
                               without breaking the program?
    cluster / merge_by_patch   which PoVs are one bug (the patcher's input)

Both exist because the expensive mistake in a scored run is submitting
something that is not true. Triage protects the finding; check_patch protects
the fix. Neither takes a tick, a current.json, or a scheduler -- `triage`
needs one dict describing where the binaries are.

    from cc_fuzzer_core import crs

    r = crs.triage({"verify_binary": "/out/parser_verify"}, "/crashes/x.bin",
                   harness="parser", config=cfg)
    if r.should_submit:                  # true, strong evidence, and the policy accepts it
        submit(r.pov, r.stack_hash)      # r.pov is the MINIMIZED input
        hand_to_patcher(r.sensitivity)   # which of its bytes decide the bug

The corpus helpers are the other half: quarantine before promoting a seed,
harvest a dictionary, find the delta targets a diff implies. They are
deliberately thin -- generating seeds and harnesses is a model's job, and the
core supplies the prompts for that (see cc_fuzzer_core.prompts), not a
service that pretends to do it deterministically.
"""
from __future__ import annotations

import json
import sys
from dataclasses import dataclass, field, replace
from pathlib import Path
from typing import Mapping

from cc_fuzzer_core import minimize as _minimize
from cc_fuzzer_core import patch as _patch
from cc_fuzzer_core import variants as _v
from cc_fuzzer_core.crash import pipeline as _pipeline
from cc_fuzzer_core.crash import replay as _replay
from cc_fuzzer_core.crash import verifiers as _verifiers

# Consumers in other containers key on these; a change to the shape of
# as_dict() is a new version (tests/golden/exports holds the v1 shape).
TRIAGE_SCHEMA = "triage-export/v1"

# outcomes
CONFIRMED, REJECTED, INCONCLUSIVE, NOT_A_CRASH, FLAKY = (
    "confirmed", "rejected", "inconclusive", "not_a_crash", "flaky")


@dataclass(frozen=True)
class TriageResult:
    status: str
    reason: str = ""
    pov: str = ""                 # the MINIMIZED reproducer, when there is one
    original_pov: str = ""
    pov_sha256: str = ""          # what a downstream record keys on
    original_sha256: str = ""
    stack_hash: str = ""
    category: str = ""
    top_frame: str = ""
    sanitizer: str = ""           # the detector that reported it (replay.sanitizer_of)
    frames: tuple = ()            # top first, up to replay.REPORT_FRAMES
    sanitizer_excerpt: str = ""   # the report, bounded (replay.excerpt)
    binary: str = ""
    variant: str = ""
    evidence_grade: str = ""      # after the oracle: see evidence_source
    evidence_source: str = ""     # "replay" or "oracle" (an authoritative one)
    replay_grade: str = ""        # what local replay alone established
    verdict_step: str = ""
    original_size: int = 0
    size: int = 0
    marker: str = ""
    directory: str = ""
    replay: dict = field(default_factory=dict)
    minimized: dict = field(default_factory=dict)
    sensitivity: dict = field(default_factory=dict)
    policy_verdict: dict = field(default_factory=dict)   # see submission policy below
    delta_relevance: dict = field(default_factory=dict)  # delta-relevance/v1, when asked
    determinism: dict = field(default_factory=dict)      # determinism/v1: the knobs used
    source_candidate_id: str = ""  # the static candidate this crash matched, if a matcher was given
    cause: str = ""               # classify.cause of the first replay: crash, leak, exit, ...

    @property
    def submittable(self) -> bool:
        """Confirmed by the configured oracle AND resting on real evidence.

        `weak` means the crash was only shown on the fuzzing binary because no
        verify binary was built -- usable for triage, not for a submission --
        unless an oracle declared `authoritative` confirmed it, which upgrades
        the grade (evidence_source="oracle").
        """
        return self.status == CONFIRMED and self.evidence_grade == _v.STRONG

    @property
    def should_submit(self) -> bool:
        """submittable AND the submission policy accepts it."""
        return self.submittable and self.policy_verdict.get("verdict") == ACCEPT

    def as_dict(self) -> dict:
        return {"schema": TRIAGE_SCHEMA, "status": self.status,
                "submittable": self.submittable, "reason": self.reason,
                "pov": self.pov, "original_pov": self.original_pov,
                "pov_sha256": self.pov_sha256,
                "original_sha256": self.original_sha256,
                "should_submit": self.should_submit,
                "policy_verdict": dict(self.policy_verdict),
                "stack_hash": self.stack_hash, "category": self.category,
                "sanitizer": self.sanitizer,
                "top_frame": self.top_frame, "frames": list(self.frames),
                "sanitizer_excerpt": self.sanitizer_excerpt,
                "binary": self.binary,
                "variant": self.variant, "evidence_grade": self.evidence_grade,
                "evidence_source": self.evidence_source,
                "replay_grade": self.replay_grade,
                "verdict_step": self.verdict_step,
                "original_size": self.original_size, "size": self.size,
                "marker": self.marker, "directory": self.directory,
                "replay": self.replay, "minimized": self.minimized,
                "sensitivity": self.sensitivity,
                "delta_relevance": self.delta_relevance,
                "determinism": self.determinism,
                "source_candidate_id": self.source_candidate_id,
                "cause": self.cause}


# ---------------------------------------------------------------------------
# the crash seam
# ---------------------------------------------------------------------------

def _triage(record: Mapping, crash: str, *, harness: str = "",
           config: Mapping | None = None, campaign=None, finding_id: str = "",
           finding: Mapping | None = None, do_minimize: bool = True,
           attempts: int = _replay.ATTEMPTS, timeout: int = _replay.TIMEOUT_S,
           minimize_probes: int = _minimize.MAX_PROBES,
           do_sensitivity: bool = True,
           sensitivity_probes: int = _minimize.SENSITIVITY_MAX_PROBES,
           minimize_rounds: int = _minimize.MAX_ROUNDS, screen=None) -> TriageResult:
    """triage() without the submission policy; see triage()."""
    record = _v.with_verify_source(record, config)
    r = _replay.replay(record, crash, harness=harness, attempts=attempts,
                       timeout=timeout, screen=screen)
    base = {"replay": r.as_dict(), "original_pov": crash,
            "stack_hash": r.stack_hash, "category": r.category,
            "top_frame": r.top_frame, "frames": tuple(r.frames),
            "sanitizer_excerpt": r.excerpt, "sanitizer": r.sanitizer,
            "original_sha256": _pipeline.sha256_file(crash),
            "binary": r.binary, "variant": r.variant,
            "evidence_grade": r.evidence_grade, "replay_grade": r.evidence_grade,
            "evidence_source": _verifiers.SOURCE_REPLAY,
            "original_size": Path(crash).stat().st_size if Path(crash).is_file() else 0,
            "cause": r.cause}

    if r.verdict == _replay.SCREENED:
        # a real crash, but of a kind the caller screened out (a leak, a timeout)
        return TriageResult(REJECTED, r.reason, pov=crash, size=base["original_size"],
                            pov_sha256=base["original_sha256"], **base)
    if r.verdict == _replay.NO_CRASH:
        return TriageResult(NOT_A_CRASH, r.reason, pov=crash, size=base["original_size"],
                            pov_sha256=base["original_sha256"], **base)
    if r.verdict == _replay.FLAKY:
        return TriageResult(FLAKY, r.reason + "; an unreliable trigger is not yet a finding",
                            pov=crash, size=base["original_size"],
                            pov_sha256=base["original_sha256"], **base)

    pov, mini = crash, {}
    if do_minimize:
        try:
            m = _minimize.minimize(record, crash, harness=harness,
                                   stack_hash=r.stack_hash, timeout=timeout,
                                   max_probes=minimize_probes, max_rounds=minimize_rounds)
            out = Path(crash).with_suffix(Path(crash).suffix + ".min")
            _minimize.write(m, out)
            pov, mini = str(out), m.as_dict()
        except _minimize.MinimizeError:
            # Minimization is an improvement, never a gate: a crash that
            # cannot be reduced is still a crash.
            mini = {}

    ctx = {"harness": harness, "reproducer": pov,
           "binaries": {f: record.get(f) for f in _v.BINARY_FIELD.values() if record.get(f)},
           "replay": r.as_dict(), "config": config,
           "project_root": str(getattr(campaign, "project_root", "") or "")}
    v = _verifiers.verify(finding or {"stack_hash": r.stack_hash}, ctx, config=config)

    size = Path(pov).stat().st_size if Path(pov).is_file() else base["original_size"]
    common = {**base, "pov": pov, "size": size, "minimized": mini,
              "verdict_step": v.step, "pov_sha256": _pipeline.sha256_file(pov)}
    if v.status != _verifiers.CONFIRMED:
        status = REJECTED if v.status == _verifiers.REJECTED else INCONCLUSIVE
        return TriageResult(status, v.reason, **common)

    common["evidence_grade"], common["evidence_source"] = _verifiers.evidence(
        r.evidence_grade, v, config)

    sens = {}
    if do_sensitivity:
        try:
            sens = _minimize.sensitivity(record, pov, harness=harness,
                                         stack_hash=r.stack_hash, timeout=timeout,
                                         max_probes=sensitivity_probes).as_dict()
        except _minimize.MinimizeError:
            # Like minimization: an improvement to the evidence, never a gate.
            sens = {}
    common["sensitivity"] = sens

    marker = directory = ""
    if campaign is not None and finding_id:
        f = _pipeline.finalize(campaign, finding_id,
                               finding or {"id": finding_id, "stack_hash": r.stack_hash},
                               record=record, reproducer=pov, config=config,
                               harness=harness, replay_result=r.as_dict(),
                               # the oracle already answered; do not ask twice
                               verify_fn=lambda _f, _c: v)
        marker, directory = f.marker, f.directory
    return TriageResult(CONFIRMED, v.reason, marker=marker, directory=directory, **common)


def triage(record: Mapping, crash: str, *, harness: str = "",
           config: Mapping | None = None, campaign=None, finding_id: str = "",
           finding: Mapping | None = None, do_minimize: bool = True,
           attempts: int | None = None, timeout: int | None = None,
           minimize_probes: int | None = None,
           do_sensitivity: bool = True,
           sensitivity_probes: int | None = None,
           policy: str = "", seen: Mapping | None = None,
           delta_range=None, minimize_rounds: int | None = None,
           candidate_matcher=None, screen=None) -> TriageResult:
    """A crash arrived. Decide what it is, in one call.

      1. replay it deterministically on the binary §12 selects
      2. reduce it to the smallest input showing THE SAME bug
      3. hand it to the configured final verifier (your oracle)
      4. if confirmed, map which of its bytes decide the bug (sensitivity)
      5. if confirmed and a campaign was given, write the finding marker
      6. ask the submission policy whether it is worth submitting

    Step 4 runs only on confirmed bugs: it costs two probes per byte and its
    reader is whoever writes the patch, so there is nobody to spend it on for
    a rejected crash.

    A flaky reproducer stops at step 1: it is a real bug with an unreliable
    trigger, which is a different thing from a finding, and minimizing it
    would be measuring noise.

    `policy` overrides `submission.policy` in config; `seen` maps stack_hash
    to how many variants of that bug were already submitted (for
    `max_variants_per_stack_hash`). The core keeps no submission state.

    `delta_range` (a diff file, diff text, or a git range with a campaign)
    adds delta_relevance: whether the crash's frames land in what the diff
    changed. Reported, never filtered on -- the policy may use it.

    `screen` is the fast path for raw fuzzer artifacts: the causes
    (classify.CAUSES) worth a full triage, e.g. ("crash",). The first replay
    labels the input; any other cause stops there, so a harness that called
    exit() costs one run (not_a_crash) and a leak one run (rejected). None,
    the default, replays every input `attempts` times, which is what tells
    a flaky trigger from no crash.

    `candidate_matcher(result_dict) -> str` links the crash to the static
    candidate that predicted it (an integration supplies it; the core knows
    no candidate format). Its answer is `source_candidate_id`, set before the
    policy runs so a policy can read it.
    """
    from cc_fuzzer_core import determinism as _det
    knobs = _det.resolve(config, replay_attempts=attempts, replay_timeout_s=timeout,
                         minimize_max_probes=minimize_probes,
                         minimize_max_rounds=minimize_rounds,
                         sensitivity_max_probes=sensitivity_probes)
    r = _triage(record, crash, harness=harness, config=config, campaign=campaign,
                finding_id=finding_id, finding=finding, do_minimize=do_minimize,
                attempts=knobs["replay_attempts"], timeout=knobs["replay_timeout_s"],
                minimize_probes=knobs["minimize_max_probes"],
                minimize_rounds=knobs["minimize_max_rounds"],
                do_sensitivity=do_sensitivity,
                sensitivity_probes=knobs["sensitivity_max_probes"], screen=screen)
    r = replace(r, determinism=_det.echo(knobs))
    if delta_range:
        r = replace(r, delta_relevance=_delta_relevance(r, delta_range, campaign))
    if candidate_matcher is not None:
        r = replace(r, source_candidate_id=str(candidate_matcher(r.as_dict()) or ""))
    return replace(r, policy_verdict=judge(r, config=config, policy=policy, seen=seen))


def _delta_relevance(r: TriageResult, delta_range, campaign) -> dict:
    from cc_fuzzer_core import delta as _delta
    try:
        targets = _delta.targets_of(delta_range,
                                    project_root=getattr(campaign, "project_root", None))
    except (_delta.DeltaError, OSError) as e:
        # Reporting, not gating: a diff we cannot read says nothing either way.
        return {"schema": _delta.RELEVANCE_SCHEMA, "error": str(e)}
    return _delta.relevance(_relevance_frames(r), targets)


#: Frames read from the sanitizer report for delta relevance.
RELEVANCE_FRAMES = 64


def _relevance_frames(r: TriageResult) -> list:
    """Every frame of the report: the access stack and, for ASan, the "freed
    by" and "previously allocated by" stacks. r.frames stops at
    replay.REPORT_FRAMES (12), which on a use-after-free is usually the end of
    the access and free stacks, and a diff that breaks a lifetime acts where
    the object is created or freed: on AIxCC's mosquitto delta the removed
    duplicate check was in dynsec_clients__config_load, frame #3 of the
    allocation stack, and the crash was judged off-diff."""
    from cc_fuzzer_core.crash import replay as _replay
    out = list(r.frames)
    for f in _replay.frames(r.sanitizer_excerpt or "", limit=RELEVANCE_FRAMES):
        if f not in out:
            out.append(f)
    return out


# ---------------------------------------------------------------------------
# the submission policy hook
# ---------------------------------------------------------------------------
#
# `submittable` answers "is this TRUE" (confirmed, strong evidence). Whether a
# true finding is WORTH submitting depends on the consumer's scoring oracle --
# a memory-safety scorer does not want a signed-overflow report -- so it is a
# hook, not a rule in classify.py:
#
#     {"submission": {"policy": "builtin:memory-safety",
#                     "max_variants_per_stack_hash": 2}}
#
#   builtin:any-confirmed   accept every confirmed finding (the default)
#   builtin:memory-safety   accept ASan/MSan memory errors; reject ubsan-*,
#                           oom, timeout, leak, generic-crash
#   python:module:callable  fn(result: dict, ctx: dict) -> verdict, where a
#                           verdict is a bool, "accept"/"reject", a
#                           (verdict, reason) pair, or {"verdict", "reason"}
#
# The policy is handed the whole result (as_dict), including sanitizer,
# category and delta_relevance, and never has to parse sanitizer_excerpt.

POLICY_SCHEMA = "policy-verdict/v1"
ACCEPT, REJECT = "accept", "reject"
DEFAULT_POLICY = "builtin:any-confirmed"

MEMORY_SANITIZERS = ("address", "memory")
NOT_MEMORY_SAFETY = ("oom", "timeout", "generic-crash", "abort", "assertion-failure",
                     "signed-integer-overflow", "integer-overflow", "segfault")


class PolicyError(ValueError):
    pass


def _any_confirmed(result: Mapping, ctx: Mapping):
    return ACCEPT, "confirmed"


def _memory_safety(result: Mapping, ctx: Mapping):
    cat, san = result.get("category") or "", result.get("sanitizer") or ""
    if san == "leak" or "leak" in cat:
        return REJECT, "a leak is not a memory-safety violation"
    if cat.startswith("ubsan") or san == "undefined":
        return REJECT, f"{cat or 'undefined behaviour'} is not a memory-safety error"
    if cat in NOT_MEMORY_SAFETY:
        return REJECT, f"{cat} is not a memory-safety error"
    if san not in MEMORY_SANITIZERS:
        return REJECT, f"reported by {san or 'no sanitizer'}, not ASan/MSan"
    return ACCEPT, f"{cat} reported by {san}"


BUILTIN_POLICIES = {"builtin:any-confirmed": _any_confirmed,
                    "builtin:memory-safety": _memory_safety}


def resolve_policy(name: str):
    name = (name or DEFAULT_POLICY).strip()
    if name in BUILTIN_POLICIES:
        return BUILTIN_POLICIES[name]
    if name.startswith("python:"):
        from cc_fuzzer_core.crash.verifiers import VerifierError, _python_verifier
        try:
            return _python_verifier(name[len("python:"):])
        except VerifierError as e:
            raise PolicyError(str(e)) from None
    raise PolicyError(f"unknown submission policy {name!r}: expected "
                      f"{', '.join(BUILTIN_POLICIES)} or python:module:callable")


def normalize(out) -> tuple:
    """A policy's answer as (verdict, reason). A policy may return a bool, a
    verdict string, a (verdict, reason) pair or {"verdict", "reason"}; any
    other shape, or a verdict other than accept/reject, is a PolicyError."""
    if isinstance(out, bool):
        return (ACCEPT if out else REJECT), ""
    if isinstance(out, str):
        v, reason = out, ""
    elif isinstance(out, (tuple, list)) and len(out) == 2:
        v, reason = out
    elif isinstance(out, Mapping):
        v, reason = out.get("verdict"), out.get("reason", "")
    else:
        raise PolicyError(f"a policy returned {type(out).__name__}, not a verdict")
    if v not in (ACCEPT, REJECT):
        raise PolicyError(f"a policy verdict must be {ACCEPT!r} or {REJECT!r}, got {v!r}")
    return v, str(reason or "")


def policy(name: str = ""):
    """The named policy (builtin:... or python:module:callable) as a callable
    (result, ctx) -> (verdict, reason), its answer already normalized. A host
    policy that composes another calls this, not the raw function."""
    fn = resolve_policy(name)

    def run(result, ctx=None) -> tuple:
        data = result.as_dict() if isinstance(result, TriageResult) else result
        return normalize(fn(data, dict(ctx or {})))
    run.__name__ = f"policy[{(name or DEFAULT_POLICY).strip()}]"
    return run


def judge(result: TriageResult, *, config: Mapping | None = None, policy: str = "",
          seen: Mapping | None = None) -> dict:
    """The policy-verdict/v1 for one triage result."""
    block = (config or {}).get("submission") or {}
    if not isinstance(block, Mapping):
        raise PolicyError("submission must be an object")
    name = policy or block.get("policy") or DEFAULT_POLICY
    fn = resolve_policy(name)

    def out(v, reason):
        return {"schema": POLICY_SCHEMA, "policy": name, "verdict": v, "reason": reason}

    if result.status != CONFIRMED:
        return out(REJECT, f"not confirmed ({result.status})")
    cap = block.get("max_variants_per_stack_hash")
    n = int((seen or {}).get(result.stack_hash, 0) or 0)
    if cap is not None and n >= int(cap):
        return out(REJECT, f"{n} variant(s) of {result.stack_hash} already submitted "
                           f"(max_variants_per_stack_hash={cap})")
    v, reason = normalize(fn(result.as_dict(), {"config": dict(block), "seen": n,
                                                 "policy": name}))
    return out(v, reason)


# ---------------------------------------------------------------------------
# the patch seam
# ---------------------------------------------------------------------------

def check_patch(record: Mapping, patch_file: str, pov, *, project_root,
                config: Mapping | None = None, harness: str = "",
                stack_hash: str = "",
                sensitivity: Mapping | None = None) -> _patch.PatchVerdict:
    """Does this patch stop the PoV without breaking the program?

    `pov` is one path or a list: every variant of the bug the patch is meant
    to fix. With `patch.pov` / `patch.pov_after` configured, the PoV runs
    through the host's runner (e.g. `libCRS run-pov --rebuild-id {build}`)
    instead of the local binary. `sensitivity` (a triage result's) feeds the
    built-in neighbours gate.

    Thin on purpose: the gates and their order live in cc_fuzzer_core.patch,
    and the order is the point (the PoV must crash BEFORE the patch, or
    everything after it measures nothing).
    """
    return _patch.validate(record, patch_file, pov, project_root=project_root,
                           config=config, harness=harness, stack_hash=stack_hash,
                           sensitivity=sensitivity)


# ---------------------------------------------------------------------------
# clusters: which PoVs are one bug
# ---------------------------------------------------------------------------
#
# The stack hash says where a crash surfaced, which is not always where the
# bug is: two inputs that crash in different frames can share one root
# cause. A patch is the test that settles it -- if one validated fix stops
# both, they are one bug, and a patcher should be handed them together with
# the shortest as the representative. So:
#
#   cluster(povs)                        group by stack hash
#   merge_by_patch(clusters, patch, ...) run the patch against every
#                                        cluster's representative in ONE
#                                        validation (one build); the ones it
#                                        stops become one cluster

CLUSTER_SCHEMA = "pov-cluster/v1"


@dataclass(frozen=True)
class Cluster:
    stack_hashes: tuple
    povs: tuple                  # paths, shortest first
    merged_by: str = ""          # the patch that showed these are one bug

    @property
    def id(self) -> str:
        return self.stack_hashes[0] if self.stack_hashes else ""

    @property
    def representative(self) -> str:
        return self.povs[0] if self.povs else ""

    def as_dict(self) -> dict:
        return {"schema": CLUSTER_SCHEMA, "id": self.id, "stack_hashes": list(self.stack_hashes),
                "povs": list(self.povs), "representative": self.representative,
                "merged_by": self.merged_by}


def _size(p) -> int:
    try:
        return Path(p).stat().st_size
    except OSError:
        return 1 << 62


def cluster(povs) -> list:
    """Group PoVs by stack hash. `povs`: dicts with `pov` and `stack_hash`
    (triage-export/v1 documents qualify). Largest group first."""
    groups: dict = {}
    for d in povs:
        h = str(d.get("stack_hash") or "")
        if not h or not d.get("pov"):
            continue
        groups.setdefault(h, []).append(str(d["pov"]))
    out = [Cluster((h,), tuple(sorted(set(ps), key=lambda p: (_size(p), p))))
           for h, ps in groups.items()]
    return sorted(out, key=lambda c: (-len(c.povs), c.id))


def merge_by_patch(clusters, patch_file: str, *, record: Mapping, project_root,
                   config: Mapping | None = None, harness: str = "", replay_fn=None) -> tuple:
    """(clusters, verdict): the clusters whose representative this patch
    stops are merged into one; the rest are returned unchanged.

    One patch.validate over every representative, so the patched build is
    made once. A representative that does not crash before the patch makes
    the verdict stale and nothing is merged: that is a finding problem, not
    a clustering one.
    """
    clusters = list(clusters)
    if len(clusters) < 2:
        return clusters, None
    reps = [c.representative for c in clusters]
    v = _patch.validate(record, patch_file, reps, project_root=project_root,
                        config=config, harness=harness, replay_fn=replay_fn)
    if v.status == _patch.STALE or not v.povs:
        return clusters, v
    fixed = {r.pov for r in v.povs if r.after == "no-crash"}
    hit = [c for c in clusters if c.representative in fixed]
    if len(hit) < 2:
        return clusters, v
    merged = Cluster(tuple(h for c in hit for h in c.stack_hashes),
                     tuple(sorted({p for c in hit for p in c.povs},
                                  key=lambda p: (_size(p), p))),
                     str(patch_file))
    rest = [c for c in clusters if c not in hit]
    return [merged] + rest, v


# ---------------------------------------------------------------------------
# the corpus seam (thin, and honest about it)
# ---------------------------------------------------------------------------

def safe_seeds(campaign, harness: str = "", inputs=None):
    """Promote quarantined inputs that are safe to keep, reject the rest.

    Worth calling before anything a model produced enters a corpus: the
    rejects are inputs that would damage the machine running them (fork bombs,
    writes to a block device), not merely useless ones.
    """
    from cc_fuzzer_core import quarantine
    return quarantine.quarantine(campaign, harness, inputs)


def dictionary(campaign, *, harness: str = "", output: str = ""):
    """Harvest comparison operands the fuzzer has already seen into a
    dictionary (AFL++ cmplog)."""
    from cc_fuzzer_core import cmplog
    return cmplog.extract(campaign, harness=harness, output=output)


def delta_targets(campaign, range_: str | None = None):
    """The functions a diff touches -- where to aim when the job is a known
    change rather than open exploration, which is the usual CRS shape."""
    from cc_fuzzer_core import delta
    return delta.find_targets(campaign, range_)


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def _cmd_triage(a):
    from cc_fuzzer_core import config as _config
    from cc_fuzzer_core.paths import campaign as _campaign
    from cc_fuzzer_core.variants import harness_record
    try:
        c = _campaign(strict=False)
    except Exception:
        c = None
    try:
        cfg = json.load(open(a.config)) if a.config else (_config.load(c) if c else {})
        record = harness_record(campaign=c, harness=a.harness) if not a.verify_binary \
            else {"verify_binary": a.verify_binary}
        r = triage(record, a.crash, harness=a.harness, config=cfg, campaign=c,
                   finding_id=a.finding_id, do_minimize=not a.no_minimize,
                   do_sensitivity=not a.no_sensitivity, policy=a.policy,
                   delta_range=a.delta or None,
                   screen=tuple(x for x in a.screen.split(",") if x) if a.screen is not None else None)
    except Exception as e:  # noqa: BLE001 - the CLI reports, it does not raise
        print(f"error: {type(e).__name__}: {e}", file=sys.stderr)
        return 2
    print(json.dumps(r.as_dict(), indent=2) if a.json else
          f"{r.status}: {r.reason}\n  pov {r.pov} ({r.original_size} -> {r.size} bytes)\n"
          f"  bug {r.stack_hash} {r.category} [{r.evidence_grade} via {r.evidence_source}]\n"
          f"  submittable: {r.submittable}; policy {r.policy_verdict.get('verdict')}"
          f" ({r.policy_verdict.get('reason')})"
          + (f"\n  bytes {r.sensitivity['mask']}  (# load-bearing, ~ constrained, . free)"
             if r.sensitivity else ""))
    return 0 if r.should_submit else 1


def _cmd_cluster(a):
    docs = []
    for p in a.exports:
        with open(p) as f:
            docs.append(json.load(f))
    cs = cluster(docs)
    verdict = None
    if a.patch:
        from cc_fuzzer_core import config as _config
        from cc_fuzzer_core.paths import campaign as _campaign
        from cc_fuzzer_core.variants import harness_record
        try:
            c = _campaign(strict=False)
            cfg = json.load(open(a.config)) if a.config else (_config.load(c) if c else {})
            record = {"verify_binary": a.verify_binary} if a.verify_binary \
                else harness_record(campaign=c, harness=a.harness)
            cs, verdict = merge_by_patch(cs, a.patch, record=record,
                                         project_root=a.project_root or
                                         (c.project_root if c else "."),
                                         config=cfg, harness=a.harness)
        except Exception as e:  # noqa: BLE001 - the CLI reports, it does not raise
            print(f"error: {type(e).__name__}: {e}", file=sys.stderr)
            return 2
    print(json.dumps({"clusters": [x.as_dict() for x in cs],
                      "patch": verdict.as_dict() if verdict else None}, indent=2))
    return 0


def register_cli(subparsers):
    from cc_fuzzer_core.cli import add_subsystem
    _p, verbs = add_subsystem(subparsers, "crs",
                              "The request/response surface for a CRS (no loop).")
    v = verbs.add_parser("triage", help="replay + minimize + verify one crash")
    v.add_argument("crash")
    v.add_argument("--harness", default="")
    v.add_argument("--verify-binary", default="", help="skip the harness record")
    v.add_argument("--finding-id", default="", help="also write the finding marker")
    v.add_argument("--no-minimize", action="store_true")
    v.add_argument("--no-sensitivity", action="store_true")
    v.add_argument("--delta", default="", help="diff file or git range: report delta relevance")
    v.add_argument("--screen", default=None, metavar="CAUSES",
                   help="comma-separated causes worth a full triage (e.g. crash); "
                        "any other stops after one run")
    v.add_argument("--policy", default="", help="submission policy (default: config, "
                                                 "then builtin:any-confirmed)")
    v.add_argument("--config")
    v.add_argument("--json", action="store_true")
    v.set_defaults(func=_cmd_triage)

    v = verbs.add_parser("cluster", help="group triage exports by stack hash; with "
                                         "--patch, merge the groups one patch fixes")
    v.add_argument("exports", nargs="+", help="triage-export/v1 JSON files")
    v.add_argument("--patch", default="")
    v.add_argument("--harness", default="")
    v.add_argument("--verify-binary", default="")
    v.add_argument("--project-root", default="")
    v.add_argument("--config")
    v.set_defaults(func=_cmd_cluster)
