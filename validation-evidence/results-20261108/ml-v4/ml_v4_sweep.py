#!/usr/bin/env python3
"""lidds-ml-v3 rule with other alphas and per-branch alpha shares, LID-DS 2021 development and CB-DS only (official is
not read). Same scores, same Gumbel fits; only the per-branch level changes. Reported, nothing selected here.

    python3 ml_v4_sweep.py --scores DIR --tokens DIR --lidds-alarms a.json.gz --cbds-alarms c.json.gz
"""
import argparse
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(ROOT / 'scripts' / 'analysis'))
import lidds_ml_v2 as m  # noqa: E402
import lidds_v3_combine as v3  # noqa: E402

ALPHAS = (0.0002, 0.0001, 0.00005, 0.00002, 0.00001, 0.000005, 0.000002, 0.000001)
SHARES = {'1/3 each': (1 / 3, 1 / 3, 1 / 3), 'T .6 tree .2 sup .2': (.6, .2, .2), 'T .8 tree .1 sup .1': (.8, .1, .1),
          'T .5 tree .1 sup .4': (.5, .1, .4), 'T .4 tree .2 sup .4': (.4, .2, .4)}


def fire(scn, name, levels):
    out = []
    for b, alpha in levels.items():
        z, col, i, end, fit = scn.branch[b]
        if name in z.files and len(z[name]):
            a = z[name]
            out.extend(a[m.transform(col, a[:, i]) > m.threshold(fit, alpha), end].tolist())
    return sorted(out)


def evaluate(scns, docs, levels, part):
    pooled = []
    for s, scn in scns.items():
        recs = docs['scenarios'][s]['alarms']
        wanted = m.part_filter(s, recs, part)
        for name, r in recs.items():
            if not wanted(name, r):
                continue
            f, ex = fire(scn, name, levels), r['exploit']
            after = [t for t in f if ex is not None and t > ex]
            pooled.append((r['split'], bool(after), after[0] - ex if after else None,
                           bool(f) if ex is None else any(t <= ex for t in f), r['subset']))
    met = v3.metrics(pooled)
    met['within3'] = sum(1 for x in pooled if x[0] == 'test-normal_and_attack' and x[2] is not None and x[2] <= 3.0)
    return met


def main():
    ap = argparse.ArgumentParser()
    for k in ('scores', 'tokens', 'lidds-alarms', 'cbds-alarms'):
        ap.add_argument('--' + k, required=True)
    a = ap.parse_args()
    m.set_token_column('select1f')
    lidds, cbds = m.load(a.lidds_alarms), m.load(a.cbds_alarms)
    dirs = dict(scores=a.scores, tokens=a.tokens)
    lid = {s: m.Scenario(s, dirs) for s in sorted(lidds['scenarios'])}
    cb = {'CB-DS': m.Scenario('CB-DS', dirs)}
    print('shares | alpha | dev detected/544 FA/3403 p95 within3 | CB-DS detected/891 FA/1410')
    for sname, sh in SHARES.items():
        for alpha in ALPHAS:
            levels = dict(zip(m.CORE, (alpha * x for x in sh)))
            d, c = evaluate(lid, lidds, levels, 'development'), evaluate(cb, cbds, levels, 'all')
            print(f"{sname:20s} {alpha:<9g} | {d['detected']:3d} {d['false_alarm_recordings']:3d} {d['latency_p95']:.2f} {d['within3']:3d} "
                  f"| {c['detected']:3d} {c['false_alarm_recordings']:3d}", flush=True)


if __name__ == '__main__':
    main()
