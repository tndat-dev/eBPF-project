#!/usr/bin/env python3
"""Part C of protocol ml-final-study-v1: the threshold rule on the cluster, where there are thousands of held-out blocks.

Thresholds per workload, from the held-out 60 s block maxima of the registered cross-fit (token_branch_fit.py
--dump-maxima, which must reproduce the v5 thresholds within 1e-9):
  gumbel     the v5 rule (moment Gumbel without the top 1 %, alpha' = 0.00018)
  empirical  the empirical (1 - alpha') quantile of the maxima (numpy linear interpolation)
  matched    the empirical quantile at the level the Gumbel threshold actually leaves above it on the held-out blocks
Each is applied to the v5 run: trials (as run and attack-specific, live_attribution.py definitions) and the normal burden
on the declared segments (episodes of one container less than 15 s apart, per replica-hour, outside the campaign span).
LID-DS 2021 development under the same empirical rule: the cross-fit recording maxima of the model scores of part D.

    python3 cluster_threshold.py --maxima DIR --models MODELS.json --run-root RUN --model-scores DIR \
        --lidds-alarms a.json.gz --cbds-alarms c.json.gz --output out.json
"""
import argparse
from collections import defaultdict
import json
from pathlib import Path
import sys

import numpy as np

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
sys.path.insert(0, str(Path(__file__).resolve().parent))
from sentinel_pulse.common import open_sealed  # noqa: E402
from sentinel_pulse.detector.token_model import CountTokenLM  # noqa: E402
import live_attribution as la  # noqa: E402
import lidds_token_study as st  # noqa: E402
import token_branch_fit as fit  # noqa: E402

ALPHA = 0.0002 * 0.9
SEGMENTS = ('s00010', 's00020', 's00030', 's00040', 's00045')
QUIET = 15.0


def thresholds(maxima_dir, models):
    out, check = {}, 0.0
    for path in sorted(Path(maxima_dir).glob('*.maxima.json')):
        doc = json.loads(path.read_text())
        w = doc['workload']
        if w not in models:
            continue
        b = np.asarray([x[-1] for x in doc['blocks']], float)
        g = fit.threshold(fit.trimmed_gumbel(b), ALPHA)
        check = max(check, abs(g - models[w][1]))
        above = float((b > g).mean())
        out[w] = dict(blocks=len(b), gumbel=g, empirical=float(np.quantile(b, 1 - ALPHA)),
                      matched=float(np.quantile(b, 1 - above)) if above > 0 else float(b.max()),
                      gumbel_exceedance=above, design=ALPHA)
    return out, check


def trial_rates(trials, windows, models, lms, thr):
    """{rule: {set: [hits, n]}} for attack (as run, attack-specific), benign, admin, control."""
    by_pair = defaultdict(dict)
    for t in trials:
        by_pair[t['pair']][t['label']] = t
    rules = list(next(iter(thr.values())).keys() & {'gumbel', 'empirical', 'matched'})
    out = {r: defaultdict(lambda: [0, 0]) for r in rules}
    for t in trials:
        w = t['workload']
        if w not in thr:
            continue
        lm = lms[w]
        wins = la.interval_windows(windows, t)
        full = [la.score(lm, g) for _, g, _, _ in wins]
        spec = None
        if t['label'] == 'attack':
            ref = set()
            for label in ('benign', 'admin'):
                o = by_pair[t['pair']].get(label)
                if o is not None and o['key'] == t['key']:
                    for _, grams, _, _ in la.interval_windows(windows, o):
                        ref.update(tuple(g[:4]) for g in grams)
            spec = [la.score(lm, g, frozenset(ref)) for _, g, _, _ in wins]
        primary = t['rate'] in la.PRIMARY
        for r in rules:
            sets = [(t['label'], full)] + ([('attack-specific', spec)] if spec is not None else [])
            for name, scores in sets:
                for key in (name, f'{name}-primary') if primary else (name,):
                    out[r][key][0] += any(s > thr[w][r] for s in scores)
                    out[r][key][1] += 1
    return {r: dict(v) for r, v in out.items()}


def burden(root, trials, thr):
    """Episodes per replica-hour on the declared segments, outside the campaign span, per rule."""
    lo = min(t['start'] for t in trials)
    hi = max(t['start'] for t in trials) + la.HORIZON
    rules = ('gumbel', 'empirical', 'matched')
    alarms = {r: defaultdict(list) for r in rules}
    seconds = 0.0
    for seg in sorted(p for p in root.glob('workers/*/segments/*') if p.name in SEGMENTS):
        with open_sealed(seg / 'decisions.jsonl') as stream:
            for line in stream:
                if '"token-score"' not in line:
                    continue
                row = json.loads(line)
                end, w = row.get('window_end'), row.get('workload_key')
                if end is None or w not in thr or lo - 60 <= end <= hi + 60:
                    continue
                seconds += 0.5
                for r in rules:
                    if row['token_score'] > thr[w][r]:
                        alarms[r][(row['pod_uid'], row['container_name'])].append(end)
    out = {}
    for r in rules:
        episodes = 0
        for times in alarms[r].values():
            times.sort()
            episodes += 1 + sum(1 for a, b in zip(times, times[1:]) if b - a >= QUIET)
        out[r] = dict(episodes=episodes, replica_hours=seconds / 3600, per_replica_hour=episodes / (seconds / 3600) if seconds else None)
    return out


class Fixed(st.TokenScenario):
    """A token scenario with a per-scenario threshold given directly."""

    def __init__(self, path, column, columns, level):
        super().__init__(path, column, columns)
        self.tau = float(np.quantile(self.maxima, 1 - level))

    def firings(self, branches, alpha, name):
        a = self.a.get(name)
        if a is None or not len(a):
            return []
        return sorted(a[a[:, self.i] > self.tau, 0].tolist())


def lidds(model_scores, docs):
    cols = st.columns_of(st.base_spec())
    out = {}
    for doc, part, key in ((docs[0], 'development', 'lidds'), (docs[1], 'all', 'cbds')):
        names = [s for s in sorted(doc['scenarios']) if (Path(model_scores) / f'{s}.npz').exists()]
        for rule, make in (('gumbel', lambda s: st.TokenScenario(Path(model_scores) / f'{s}.npz', 'top10', cols)),
                           ('empirical', lambda s: Fixed(Path(model_scores) / f'{s}.npz', 'top10', cols, ALPHA))):
            pooled, _ = st.m.score({s: make(s) for s in names}, doc, ('T',), ALPHA, part)
            out.setdefault(rule, {})[key] = dict(detected=pooled['detected'], attack_recordings=pooled['attack_recordings'],
                                                 false_alarm_recordings=pooled['false_alarm_recordings'],
                                                 normal_recordings=pooled['normal_recordings'], latency_p95=pooled['latency_p95'])
    return out


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument('--maxima', type=Path, required=True)
    ap.add_argument('--models', type=Path, required=True)
    ap.add_argument('--run-root', type=Path, required=True)
    ap.add_argument('--model-scores', type=Path, required=True)
    ap.add_argument('--lidds-alarms', type=Path, required=True)
    ap.add_argument('--cbds-alarms', type=Path, required=True)
    ap.add_argument('--output', type=Path, required=True)
    ap.add_argument('--jobs', type=int, default=6)
    a = ap.parse_args()
    models = la.load_models(a.models)
    thr, check = thresholds(a.maxima, models)
    doc = dict(schema='ml-final-study-v1-cluster-threshold', protocol='sentinel_pulse/protocol/ml-final-study-v1.json',
               gumbel_reproduces_v5=dict(largest_difference=check, passed=check <= 1e-9), thresholds=thr)
    if check <= 1e-9:
        trials = la.live.load_trials(a.run_root / la.CAMPAIGN)
        windows, _ = la.collect(a.run_root, trials, a.jobs)
        lms = {w: CountTokenLM.load(Path(models[w][0])) for w in sorted({t['workload'] for t in trials} & set(thr))}
        doc['trials'] = trial_rates(trials, windows, models, lms, thr)
        doc['burden'] = burden(a.run_root, trials, thr)
        doc['lidds'] = lidds(a.model_scores, (st.m.load(a.lidds_alarms), st.m.load(a.cbds_alarms)))
    a.output.write_text(json.dumps(doc, indent=1, default=float))
    print(json.dumps({k: doc[k] for k in ('gumbel_reproduces_v5', 'burden', 'lidds') if k in doc}, default=float))


if __name__ == '__main__':
    main()
