#!/usr/bin/env python3
"""Per-scenario positive rates of attack, benign-launch and idle-control intervals, plus how
persistent positives are inside each 15 s interval (fraction of positive windows); JSON receipt.
Uses the decision rows stored in each trial's EVALUATION_INPUT.json (policy as run)."""
import argparse, collections, glob, json, time
import numpy as np

p = argparse.ArgumentParser(description=__doc__)
p.add_argument('--campaign', action='append', required=True); p.add_argument('--output', required=True)
a = p.parse_args()
by = collections.defaultdict(collections.Counter); frac = collections.defaultdict(list); first = collections.defaultdict(list)
for campaign in a.campaign:
    for path in sorted(glob.glob(campaign + '/trials/*/EVALUATION_INPUT.json')):
        d = json.load(open(path)); rows = [r for r in d['decisions'] if r.get('status') == 'candidate-raw-score-only']
        for label in ('control', 'benign', 'attack'):
            t = d.get(label)
            if not t: continue
            s = float(t['start_at']); w = [r for r in rows if s <= r['window_start'] and r['window_end'] <= s + 15]
            if len(w) < 20: continue
            pos = [r for r in w if r.get('candidate_alert_preview')]
            by[d['attack']['scenario']][label + ('_pos' if pos else '_neg')] += 1
            frac[label].append(len(pos) / len(w))
            if pos: first[label].append(min(r['window_end'] for r in pos) - s)
rate = lambda c, l: c[l + '_pos'] / max(1, c[l + '_pos'] + c[l + '_neg'])
result = dict(schema='pulse-attack-vs-benign-v1', campaigns=a.campaign,
              by_scenario={sc: {l: rate(c, l) for l in ('attack', 'benign', 'control')} | dict(counts=dict(c)) for sc, c in sorted(by.items())},
              positive_window_fraction={l: dict(n=len(v), mean=float(np.mean(v)), median=float(np.median(v)),
                                                share_at_least_0_5=float(np.mean(np.array(v) >= .5))) for l, v in frac.items()},
              first_positive_seconds={l: dict(p10=float(np.percentile(v, 10)), p50=float(np.percentile(v, 50)), p90=float(np.percentile(v, 90)))
                                      for l, v in first.items() if v},
              note='intervals with < 20 scored windows skipped; labels are expected labels (not adjudicated)',
              computed_at_unix=time.time())
json.dump(result, open(a.output, 'w'), indent=2); print(json.dumps(result)[:1500])
