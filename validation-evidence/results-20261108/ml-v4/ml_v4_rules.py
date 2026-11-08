#!/usr/bin/env python3
"""Cross-fitted token branch with Gumbel fits less sensitive to a few held-out maxima, LID-DS 2021 development and CB-DS
only (official not read). A held-out recording with rare normal behaviour scores high under a model that never saw it,
but the final model has learnt it, so the largest held-out maxima overstate its tail. Rules fixed before any result:

  R1 moments (lidds-ml-v3); R2 quantiles Q25, Q50, Q75; R3 quantiles Q50, Q90; R4 moments without the top 1 % of maxima.

Tree and support keep the moment Gumbel on validation maxima. Reported per rule, alpha and branch share; nothing selected.
"""
import math
from pathlib import Path
import sys

import numpy as np

ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(ROOT / 'scripts' / 'analysis'))
import lidds_ml_v2 as m  # noqa: E402
import lidds_v3_combine as v3  # noqa: E402

E = ROOT / 'validation-evidence/results-20261101/lidds-v4'
ALPHAS = (0.001, 0.0005, 0.0002, 0.0001, 0.00005)
SHARES = {'1/3': (1 / 3, 1 / 3, 1 / 3), 'T.8': (.8, .1, .1)}
GQ = lambda p: -math.log(-math.log(p))   # standard Gumbel quantile


def r1(x):
    return m.gumbel(x)


def r2(x):
    q25, q50, q75 = np.quantile(x, [.25, .5, .75])
    beta = max((q75 - q25) / (GQ(.75) - GQ(.25)), 1e-6)
    return float(q50 - beta * GQ(.5)), float(beta)


def r3(x):
    q50, q90 = np.quantile(x, [.5, .9])
    beta = max((q90 - q50) / (GQ(.9) - GQ(.5)), 1e-6)
    return float(q50 - beta * GQ(.5)), float(beta)


def r4(x):
    keep = np.sort(x)[:max(2, int(math.ceil(len(x) * .99)) - 0)]
    keep = keep[:max(2, len(x) - max(1, int(round(len(x) * .01))))]
    return m.gumbel(keep)


RULES = dict(R1=r1, R2=r2, R3=r3, R4=r4)


def thresholds(scn, rule, levels):
    z, col, i, end, _ = scn.branch['T']
    mx = np.asarray([z[k][:, i].max() for k in z.files if k.startswith('val/') and len(z[k])], float)
    out = {'T': m.threshold(RULES[rule](mx), levels['T'])}
    for b in ('tree', 'support'):
        out[b] = m.threshold(scn.branch[b][4], levels[b])
    return out


def evaluate(scns, docs, rule, levels, part):
    pooled, per = [], {}
    for s, scn in scns.items():
        thr = thresholds(scn, rule, levels)
        recs, rows = docs['scenarios'][s]['alarms'], []
        wanted = m.part_filter(s, recs, part)
        for name, r in recs.items():
            if not wanted(name, r):
                continue
            f = []
            for b in m.CORE:
                z, col, i, end, _ = scn.branch[b]
                if name in z.files and len(z[name]):
                    a = z[name]
                    f.extend(a[m.transform(col, a[:, i]) > thr[b], end].tolist())
            f.sort()
            ex = r['exploit']
            after = [t for t in f if ex is not None and t > ex]
            rows.append((r['split'], bool(after), after[0] - ex if after else None,
                         bool(f) if ex is None else any(t <= ex for t in f), r['subset']))
        per[s] = v3.metrics(rows)
        pooled.extend(rows)
    met = v3.metrics(pooled)
    met['within3'] = sum(1 for x in pooled if x[0] == 'test-normal_and_attack' and x[2] is not None and x[2] <= 3.0)
    return met, per


def main():
    m.set_token_column('xfit')
    lidds, cbds = m.load(E / 'lidds-evaluation-v2-alarms.json.gz'), m.load(E / 'lidds-evaluation-v2-cbds-alarms.json.gz')
    dirs = dict(scores='/var/tmp/lid-ds-2021/ml-scores-allwin', tokens='/var/tmp/lid-ds-2021/ml-xfit-tokens')
    lid = {s: m.Scenario(s, dirs) for s in sorted(lidds['scenarios'])}
    cb = {'CB-DS': m.Scenario('CB-DS', dirs)}
    print('rule share alpha | dev detected/544 FA/3403 p95 within3 | CB-DS det/891 FA/1410 | dev per scenario (missed, FA) where nonzero')
    for rule in RULES:
        for sname, sh in SHARES.items():
            for alpha in ALPHAS:
                levels = dict(zip(m.CORE, (alpha * x for x in sh)))
                d, per = evaluate(lid, lidds, rule, levels, 'development')
                c, _ = evaluate(cb, cbds, rule, levels, 'all')
                detail = {s: (v['attack_recordings'] - v['detected'], v['false_alarm_recordings']) for s, v in per.items()
                          if v['attack_recordings'] != v['detected'] or v['false_alarm_recordings']}
                print(f"{rule} {sname:4s} {alpha:<7g} | {d['detected']:3d} {d['false_alarm_recordings']:3d} {d['latency_p95']:.2f} {d['within3']:3d} "
                      f"| {c['detected']:3d} {c['false_alarm_recordings']:3d} | {detail}", flush=True)


if __name__ == '__main__':
    main()
