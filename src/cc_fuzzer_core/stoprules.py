"""When model rounds stop, resume, and when a run gives up (docs/EMBEDDING.md §14.4).

A host that runs model rounds beside a fuzzer has to decide three things, and
until now each host hard-coded them:

    after a round      continue, or stop the model rounds
    within a round     how long without progress before the round ends (stall)
    once stopped       keep idling, reopen model rounds, or exit the run

This module makes them one policy the host feeds with what happened, so the
rules are written, tested and switchable in one place. It never sleeps,
schedules or reads state on its own: the host passes outcomes and evidence in
and acts on the decision (the same contract as loop.step()).

Policies:

    parity     the rules ParallaxCRS ran in AIxCC qualification, unchanged: once a
               bug is known, `dry_limit` worked rounds in a row with no new
               stack and no new sweep verdict stop the rounds; the in-round
               stall is `stall_s`; stopped rounds never resume.
    evidence   a round is not dry while delta targets remain open (a delta
               can plant several bugs; curl's dict stopped after a wrong find
               with $34 unspent), the stall is doubled while they do, and
               stopped rounds reopen on new evidence (a new stack, or the
               corpus grew by `reopen_corpus_frac`) at most `reopen_max` times
               while budget remains.

Independent of the policy, `min_round_s` keeps the stall from ending a round
younger than that: a round starts fresh and spends its first minutes
re-reading the diff and the code, and a 300 s stall ended every delta round
after the first before it ran a single input (6 of 6 model runs, Q37). And
`give_up_after_s` (0 = never) lets a run exit cleanly once its model rounds
have stopped, nothing has progressed (no new stack, no corpus growth) for
that long, and it has run `min_run_s`.
"""
from __future__ import annotations

from dataclasses import dataclass, field

POLICIES = ("parity", "evidence")
CONTINUE, STOP = "continue", "stop"
IDLE, REOPEN, EXIT = "idle", "reopen", "exit"


@dataclass(frozen=True)
class Policy:
    name: str = "parity"
    dry_limit: int = 3                # 0 = never stop for dry rounds
    stall_s: float = 0.0              # 0 = no in-round stall stop
    min_round_s: float = 0.0          # the stall never ends a round younger than this
    reopen_max: int = 2
    reopen_corpus_frac: float = 0.05
    give_up_after_s: float = 0.0      # 0 = never exit
    min_run_s: float = 7200.0

    def __post_init__(self):
        if self.name not in POLICIES:
            raise ValueError(f"unknown stop policy {self.name!r} (known: {', '.join(POLICIES)})")


def default_policy(*, delta: bool, name: str = "parity", dry_limit: int | None = None,
                   stall_s: float | None = None, min_round_s: float | None = None,
                   **kw) -> Policy:
    """ParallaxCRS's defaults: dry limit 2 in delta (a delta can hold several
    CPVs) and 3 in full; stall 300 s in delta, off in full; a stalled round
    still runs 900 s (the stall is off in full mode, so it matters in delta)."""
    return Policy(name=name,
                  dry_limit=(2 if delta else 3) if dry_limit is None else dry_limit,
                  stall_s=(300.0 if delta else 0.0) if stall_s is None else stall_s,
                  min_round_s=900.0 if min_round_s is None else min_round_s, **kw)


@dataclass(frozen=True)
class Decision:
    action: str
    reason: str = ""


@dataclass
class Rounds:
    """The tracker a host keeps for one run."""
    policy: Policy
    dry: int = 0
    stopped: str = ""              # why the model rounds stopped ("" while running)
    reopened: int = 0
    _stop_known: int = 0           # stacks known when the rounds stopped
    _stop_corpus: int = 0          # corpus size when the rounds stopped
    _last_known: int = -1
    _last_corpus: int = -1
    _last_progress_s: float = 0.0
    history: list = field(default_factory=list)

    # -- during the rounds
    def stall_for(self, *, open_targets: int = 0) -> float:
        """The in-round stall for the next round, s (0 = none)."""
        s = self.policy.stall_s
        if self.policy.name == "evidence" and open_targets > 0:
            return 2 * s
        return s

    def stall_due(self, *, round_s: float, idle_s: float, stall_s: float) -> bool:
        """Whether the in-round stall ends the round now: `idle_s` s without
        progress reached `stall_s` (0 = no stall) and the round has run
        `round_s` >= the policy's `min_round_s`."""
        return stall_s > 0 and idle_s >= stall_s and round_s >= self.policy.min_round_s

    def after_round(self, *, worked: bool, progressed: bool, known_before: int,
                    open_targets: int = 0) -> Decision:
        """A round ended. `worked`: the model did work (not an upstream error);
        `progressed`: a new stack or sweep verdict; `known_before`: stacks known
        when it started; `open_targets`: delta items still open."""
        if not worked:
            return Decision(CONTINUE, "no work done: the host backs off and retries")
        if progressed or not known_before:
            self.dry = 0
        elif self.policy.name == "evidence" and open_targets > 0:
            pass                        # open delta targets: not a dry round
        else:
            self.dry += 1
        self.history.append((self.dry, progressed, known_before, open_targets))
        if self.policy.dry_limit and self.dry >= self.policy.dry_limit:
            return Decision(STOP, f"{self.dry} model rounds in a row found nothing new "
                                  f"({known_before} known)")
        return Decision(CONTINUE, "")

    def stop(self, reason: str, *, known: int = 0, corpus: int = 0) -> None:
        """The host stopped the model rounds (dry, budget, refusals)."""
        self.stopped = reason
        self._stop_known, self._stop_corpus = known, corpus

    # -- once the rounds have stopped
    def after_stop(self, *, now_s: float, run_s: float, known: int, corpus: int,
                   budget_left: bool) -> Decision:
        """Called periodically while idle. `now_s` a monotonic clock, `run_s` how
        long the run has been going, `known` stacks known, `corpus` the corpus
        size, `budget_left` whether another round could be paid for."""
        if known != self._last_known or corpus > self._last_corpus:
            if self._last_known >= 0:
                self._last_progress_s = now_s
            self._last_known, self._last_corpus = known, corpus
        if not self._last_progress_s:
            self._last_progress_s = now_s

        if (self.policy.name == "evidence" and self.stopped.startswith("dry")
                and budget_left and self.reopened < self.policy.reopen_max):
            grew = (self._stop_corpus > 0 and
                    corpus >= self._stop_corpus * (1 + self.policy.reopen_corpus_frac))
            if known > self._stop_known or grew:
                self.reopened += 1
                self.dry, self.stopped = 0, ""
                why = (f"{known - self._stop_known} new stack(s)" if known > self._stop_known
                       else f"corpus {self._stop_corpus} -> {corpus}")
                return Decision(REOPEN, f"new evidence since the rounds stopped ({why}); "
                                        f"reopening ({self.reopened}/{self.policy.reopen_max})")

        g = self.policy.give_up_after_s
        if g > 0 and run_s >= self.policy.min_run_s and now_s - self._last_progress_s >= g:
            return Decision(EXIT, f"model rounds stopped ({self.stopped or 'none ran'}), no new "
                                  f"stack and no corpus growth for {now_s - self._last_progress_s:.0f}s, "
                                  f"run {run_s:.0f}s")
        return Decision(IDLE, "")
