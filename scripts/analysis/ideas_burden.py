#!/usr/bin/env python3
"""Whole-normal alert burden of the frozen screen methods (Pulse 5.11a), next to the running rule.

Streams every bound, scored decision row of the given worker roots (same row filter and episode rule as
``confirmation_study normal``: positives of one container merge into an episode unless 15 s apart), with
campaign spans excluded, and counts episodes per replica-hour for:

- ``joint_k2of2_a10``  : the running rule (joint_p, 2 consecutive windows, alpha x10);
- ``cauchy_k2of2_a10`` : Cauchy combination of tree_p and support_p, same confirmation;
- ``cusum_b3_h6``      : CUSUM on -ln joint_p with drift 3, alarm at 6 (reset after a > 1 s gap).

Parameters were frozen on 21/10 (``ideas-screen-v1.json``) before the evaluated run existed.
"""
import argparse, json, math, sys, time
from collections import defaultdict
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
from sentinel_pulse.attack.confirmation_study import IDENTITY, EpisodeCounter, scored_rows  # noqa: E402
from sentinel_pulse.detector.confirmation import ConfirmationPolicy, ConfirmationState  # noqa: E402


def cauchy(p1, p2):
    clip = lambda p: min(max(p, 1e-15), 1 - 1e-15)
    t = (math.tan((0.5 - clip(p1)) * math.pi) + math.tan((0.5 - clip(p2)) * math.pi)) / 2
    return 0.5 - math.atan(t) / math.pi


class Gap:
    """Per-container history that restarts after a gap > 1 s or an overlap > 0.25 s (as ConfirmationState)."""
    def __init__(self):
        self.last = {}

    def restart(self, key, row):
        start, end = float(row['window_start']), float(row['window_end'])
        last = self.last.get(key)
        self.last[key] = end
        return last is None or start - last > 1.0 or start < last - 0.25


class CauchyK2:
    def __init__(self, scale=10.0):
        self.scale, self.gap, self.prev = scale, Gap(), {}

    def update(self, key, row):
        passed = cauchy(float(row['tree_p']), float(row['support_p'])) <= float(row['candidate_policy_alpha']) * self.scale
        if self.gap.restart(key, row):
            self.prev[key] = False
        fire = passed and self.prev.get(key, False)
        self.prev[key] = passed
        return fire


class Cusum:
    def __init__(self, b=3.0, h=6.0):
        self.b, self.h, self.gap, self.s = b, h, Gap(), {}

    def update(self, key, row):
        if self.gap.restart(key, row):
            self.s[key] = 0.0
        self.s[key] = max(0.0, self.s.get(key, 0.0) - math.log(max(float(row['joint_p']), 1e-12)) - self.b)
        return self.s[key] >= self.h


def span(text):
    a, b = (float(x) for x in text.split(':'))
    return a, b


def main():
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument('--worker-root', type=Path, action='append', required=True)
    p.add_argument('--model-hash', required=True); p.add_argument('--policy-hash', required=True)
    p.add_argument('--since', type=float); p.add_argument('--until', type=float)
    p.add_argument('--exclude', type=span, action='append', default=[])
    p.add_argument('--output', required=True)
    a = p.parse_args()
    joint = ConfirmationState(ConfirmationPolicy(2, 2, 10.0))
    others = {'cauchy_k2of2_a10': CauchyK2(10.0), 'cusum_b3_h6': Cusum(3.0, 6.0)}
    counters = {name: EpisodeCounter() for name in ('joint_k2of2_a10', *others)}
    seconds = defaultdict(float); stats = defaultdict(int)
    for root in a.worker_root:
        for row in scored_rows(root, a.model_hash, a.policy_hash, a.since, a.until, a.exclude, stats):
            key = tuple(str(row.get(name)) for name in IDENTITY)
            workload, end = row['workload_key'], float(row['window_end'])
            seconds[workload] += max(0.0, end - float(row['window_start']))
            if joint.update(row):
                counters['joint_k2of2_a10'].add(workload, key, end)
            for name, det in others.items():
                if det.update(key, row):
                    counters[name].add(workload, key, end)
    hours = sum(seconds.values()) / 3600
    result = dict(schema='pulse-ideas-burden-v1', worker_roots=[str(r) for r in a.worker_root], model_hash=a.model_hash,
                  policy_hash=a.policy_hash, since_unix=a.since, until_unix=a.until, excluded_spans=[list(s) for s in a.exclude],
                  scored_replica_hours=hours, stats=dict(stats),
                  methods={name: dict(total_episodes=sum(c.episodes.values()), total_positive_windows=sum(c.windows.values()),
                                      episodes_per_replica_hour=sum(c.episodes.values()) / hours if hours else None,
                                      episodes=dict(c.episodes))
                           for name, c in counters.items()},
                  computed_at_unix=time.time())
    Path(a.output).write_text(json.dumps(result, indent=2))
    print(json.dumps({n: round(v['episodes_per_replica_hour'] or -1, 3) for n, v in result['methods'].items()}), hours)


if __name__ == '__main__':
    main()
