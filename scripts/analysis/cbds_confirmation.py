#!/usr/bin/env python3
"""CB-DS confirmation (protocol cbds-confirmation-v1) from the lidds_evaluate_v2.py output of scenario CB-DS.

Every CB-DS recording is used (subset 'all': nothing was designed on CB-DS). Per arm: detection over the 900
attack recordings and per attack type (recording names ``<attack>_<n>``), false-alarm recordings over the
test/normal ones, Wilson 95 % CI; C1 / C2 of the protocol for step3; step3 - system with a paired bootstrap over
recordings (attack and normal resampled apart, 10,000 draws).

    python3 scripts/analysis/cbds_confirmation.py lidds-evaluation-v2-cbds.json --output cbds-confirmation.json
"""
from __future__ import annotations

import argparse
from collections import defaultdict
import json
import math
from pathlib import Path

import numpy as np

SEED = 20261031
PRIMARY = 'step3'


def wilson(k, n, z=1.96):
    if not n:
        return None
    p = k / n
    den = 1 + z * z / n
    centre = (p + z * z / (2 * n)) / den
    half = z * math.sqrt(p * (1 - p) / n + z * z / (4 * n * n)) / den
    return [centre - half, centre + half]


def rates(outcomes):
    att = [o for o in outcomes if o[0] == 'test-normal_and_attack']
    nor = [o for o in outcomes if o[0] == 'test-normal']
    det, fa = sum(bool(o[1]) for o in att), sum(o[3] > 0 for o in nor)
    return dict(attack_recordings=len(att), detected=det, detection_rate=det / len(att) if att else None,
                detection_ci95=wilson(det, len(att)), normal_recordings=len(nor), false_alarm_recordings=fa,
                false_alarm_rate=fa / len(nor) if nor else None, false_alarm_ci95=wilson(fa, len(nor)))


def by_attack(outcomes):
    groups = defaultdict(list)
    for o in outcomes:
        if o[0] == 'test-normal_and_attack':
            groups[o[6].rsplit('_', 1)[0]].append(o)
    return {a: dict(recordings=len(v), detected=sum(bool(o[1]) for o in v),
                    detection_rate=sum(bool(o[1]) for o in v) / len(v), detection_ci95=wilson(sum(bool(o[1]) for o in v), len(v)))
            for a, v in sorted(groups.items())}


def paired_difference(raw, a, b, reps=10000, seed=SEED):
    """a - b in detection and false-alarm rate; recordings matched by name, resampled with replacement."""
    def table(split, col):
        x = {o[6]: o for o in raw[a] if o[0] == split}
        y = {o[6]: o for o in raw[b] if o[0] == split}
        names = sorted(set(x) & set(y))
        f = (lambda o: bool(o[1])) if col == 'det' else (lambda o: o[3] > 0)
        return np.array([[f(x[n]), f(y[n])] for n in names], float)
    rng = np.random.default_rng(seed)
    out = {}
    for key, split, col in (('detection', 'test-normal_and_attack', 'det'), ('false_alarm', 'test-normal', 'fa')):
        t = table(split, col)
        if not len(t):
            out[key] = None; continue
        d = t[:, 0] - t[:, 1]
        boots = d[rng.integers(0, len(d), size=(reps, len(d)))].mean(1)
        out[key] = dict(diff=float(d.mean()), ci95=[float(np.percentile(boots, 2.5)), float(np.percentile(boots, 97.5))],
                        only_a=int((d > 0).sum()), only_b=int((d < 0).sum()))
    return out


def confirm(doc, scenario='CB-DS'):
    raw = doc['recordings'][scenario]
    arms = {arm: dict(**rates(v), by_attack=by_attack(v)) for arm, v in raw.items()}
    s3 = arms[PRIMARY]
    c1 = s3['detection_rate'] >= 0.90 and s3['false_alarm_rate'] <= 0.030
    c2 = s3['detection_rate'] >= 0.95 and s3['false_alarm_rate'] <= 0.030
    return dict(schema='pulse-cbds-confirmation-v1', protocol='sentinel_pulse/protocol/cbds-confirmation-v1.json',
                subset='all', arms=arms, criteria=dict(C1=c1, C2=c2),
                differences={f'{a}-{b}': paired_difference(raw, a, b) for a, b in
                             (('step3', 'system'), ('step1', 'system'), ('step2', 'step1'), ('step3', 'step2'))},
                fit=doc['scenarios'][scenario].get('fit'), limits=doc['scenarios'][scenario].get('limits'))


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument('evaluation', type=Path, help='lidds_evaluate_v2.py output with scenario CB-DS')
    ap.add_argument('--output', type=Path, required=True)
    a = ap.parse_args()
    doc = confirm(json.loads(a.evaluation.read_text()))
    a.output.write_text(json.dumps(doc, indent=1, default=float))
    print(json.dumps(dict(criteria=doc['criteria'], **{k: {m: doc['arms'][k][m] for m in ('detection_rate', 'false_alarm_rate')}
                                                       for k in ('system', 'step1', 'step2', 'step3')}), default=float))


if __name__ == '__main__':
    main()
