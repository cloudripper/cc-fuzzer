"""stoprules: the round policy a host feeds with outcomes (Phase 3)."""
from __future__ import annotations

import random
import unittest

from cc_fuzzer_core import stoprules as sr


def legacy(outcomes, dry_limit):
    """ParallaxCRS's inline rule before stoprules (crs/src/crc.py, qualification
    through 1.14): the decision after each worked round."""
    dry, out = 0, []
    for worked, progressed, known in outcomes:
        if not worked:
            out.append(sr.CONTINUE)
            continue
        dry = 0 if (progressed or not known) else dry + 1
        out.append(sr.STOP if dry_limit and dry >= dry_limit else sr.CONTINUE)
        if out[-1] == sr.STOP:
            break
    return out


class ParityTest(unittest.TestCase):
    def test_parity_matches_the_old_rule_on_random_histories(self):
        rng = random.Random(1337)
        for _ in range(3000):
            delta = rng.random() < 0.5
            limit = rng.choice([0, 1, 2, 3, 5])
            hist = [(rng.random() < 0.9, rng.random() < 0.3, rng.choice([0, 0, 1, 2, 4]))
                    for _ in range(rng.randint(1, 15))]
            r = sr.Rounds(sr.default_policy(delta=delta, dry_limit=limit))
            got = []
            for worked, progressed, known in hist:
                d = r.after_round(worked=worked, progressed=progressed, known_before=known,
                                  open_targets=rng.randint(0, 3))     # parity ignores it
                got.append(d.action)
                if d.action == sr.STOP:
                    break
            self.assertEqual(got, legacy(hist, limit), hist)

    def test_parity_defaults_are_the_crs_ones(self):
        self.assertEqual((sr.default_policy(delta=True).dry_limit, sr.default_policy(delta=True).stall_s), (2, 300))
        self.assertEqual((sr.default_policy(delta=False).dry_limit, sr.default_policy(delta=False).stall_s), (3, 0))
        r = sr.Rounds(sr.default_policy(delta=True))
        self.assertEqual(r.stall_for(open_targets=5), 300)                 # parity: unchanged

    def test_parity_never_reopens_or_exits_by_default(self):
        r = sr.Rounds(sr.default_policy(delta=True))
        r.stop("dry: 2 rounds", known=1, corpus=100)
        for t in range(0, 100000, 600):
            d = r.after_stop(now_s=t, run_s=t, known=1 + t // 1000, corpus=100 + t, budget_left=True)
            self.assertEqual(d.action, sr.IDLE)

    def test_unknown_policy_is_an_error(self):
        with self.assertRaises(ValueError):
            sr.Policy(name="yolo")


class EvidenceTest(unittest.TestCase):
    def test_open_delta_targets_keep_rounds_from_counting_dry(self):
        """Q7: curl dict's rounds stopped after a wrong find with $34 unspent."""
        r = sr.Rounds(sr.default_policy(delta=True, name="evidence"))
        for _ in range(5):
            self.assertEqual(r.after_round(worked=True, progressed=False, known_before=1,
                                           open_targets=3).action, sr.CONTINUE)
        self.assertEqual(r.stall_for(open_targets=3), 600)
        r.after_round(worked=True, progressed=False, known_before=1, open_targets=0)
        self.assertEqual(r.after_round(worked=True, progressed=False, known_before=1,
                                       open_targets=0).action, sr.STOP)

    def test_stopped_rounds_reopen_on_new_evidence_at_most_twice(self):
        r = sr.Rounds(sr.default_policy(delta=True, name="evidence"))
        r.stop("dry: 2 rounds", known=1, corpus=1000)
        self.assertEqual(r.after_stop(now_s=0, run_s=0, known=1, corpus=1010, budget_left=True).action, sr.IDLE)
        d = r.after_stop(now_s=60, run_s=60, known=2, corpus=1010, budget_left=True)
        self.assertEqual(d.action, sr.REOPEN)
        self.assertIn("1 new stack", d.reason)
        r.stop("dry: 2 rounds", known=2, corpus=1010)
        d = r.after_stop(now_s=120, run_s=120, known=2, corpus=1100, budget_left=True)   # +8.9%
        self.assertEqual(d.action, sr.REOPEN)
        r.stop("dry: 2 rounds", known=2, corpus=1100)
        self.assertEqual(r.after_stop(now_s=180, run_s=180, known=9, corpus=9000,
                                      budget_left=True).action, sr.IDLE)                  # cap reached

    def test_no_reopen_without_budget_or_after_a_budget_stop(self):
        r = sr.Rounds(sr.default_policy(delta=True, name="evidence"))
        r.stop("dry: 2 rounds", known=1, corpus=100)
        self.assertEqual(r.after_stop(now_s=0, run_s=0, known=5, corpus=100, budget_left=False).action, sr.IDLE)
        r = sr.Rounds(sr.default_policy(delta=True, name="evidence"))
        r.stop("budget: cap reached", known=1, corpus=100)
        self.assertEqual(r.after_stop(now_s=0, run_s=0, known=5, corpus=100, budget_left=True).action, sr.IDLE)


class GiveUpTest(unittest.TestCase):
    def test_a_stalled_run_exits_after_the_window_and_the_minimum(self):
        """Q8: curl dict ran ~6 h after its fuzzer went flat."""
        r = sr.Rounds(sr.default_policy(delta=True, give_up_after_s=3600, min_run_s=7200))
        r.stop("dry: 2 rounds", known=1, corpus=500)
        self.assertEqual(r.after_stop(now_s=0, run_s=5000, known=1, corpus=500, budget_left=True).action, sr.IDLE)
        self.assertEqual(r.after_stop(now_s=3000, run_s=8000, known=1, corpus=520, budget_left=True).action,
                         sr.IDLE)                                        # the corpus grew: clock reset
        self.assertEqual(r.after_stop(now_s=6000, run_s=11000, known=1, corpus=520, budget_left=True).action,
                         sr.IDLE)                                        # 3000 s flat < 3600
        d = r.after_stop(now_s=6700, run_s=11700, known=1, corpus=520, budget_left=True)
        self.assertEqual(d.action, sr.EXIT)
        self.assertIn("no new stack and no corpus growth", d.reason)

    def test_no_exit_before_the_minimum_run(self):
        r = sr.Rounds(sr.default_policy(delta=False, give_up_after_s=60, min_run_s=7200))
        r.stop("no model budget")
        r.after_stop(now_s=0, run_s=0, known=0, corpus=10, budget_left=False)
        self.assertEqual(r.after_stop(now_s=6000, run_s=6000, known=0, corpus=10, budget_left=False).action,
                         sr.IDLE)
        self.assertEqual(r.after_stop(now_s=7300, run_s=7300, known=0, corpus=10, budget_left=False).action,
                         sr.EXIT)


if __name__ == "__main__":
    unittest.main()
