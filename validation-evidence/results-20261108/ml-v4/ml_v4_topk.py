#!/usr/bin/env python3
"""Window statistic of the token branch: mean of the top k per-event -log p, k in 1, 3, 5, 10, 20, LID-DS 2021 development
and CB-DS only (official not read; lidds_ml_token_topk.py scored no official recording). Model plain (as lidds-ml-v3, R1) or
xfit (R1, R4). Tree and support as lidds-ml-v3. Gate: plain top10 at 1/3, alpha 0.0002 must give 530/544, 17/3403.
Nothing selected here."""
import json
from pathlib import Path
import sys

import numpy as np

sys.path.insert(0, str(Path(__file__).resolve().parent))
import ml_v4_edges as ed  # noqa: E402

m, v3 = ed.m, ed.v3
TOPK = Path('/var/tmp/lid-ds-2021/ml-topk')
TOPS = (1, 3, 5, 10, 20)
SHARES = {'1/3': (1 / 3, 1 / 3, 1 / 3), 'T.9': (.9, .05, .05), 'T only': (1.0, 0.0, 0.0)}
ALPHAS = (0.001, 0.0005, 0.0002, 0.0001, 0.00005)
SETS = (('plain', 'R1'), ('xfit', 'R1'), ('xfit', 'R4'))
NO_EDGE = (0, 0)


class Scn(ed.Scn):
    def __init__(self, name, recs, keep, model, top):
        ed.TOKENS[f'{model}-{top}'] = TOPK / model
        z_t, i_t, e_t = ed.matrix(TOPK / model, name, f'top{top}')
        self.arrays, self.edges, self.keep = {b: {} for b in m.CORE}, {}, keep
        tests = [n for n, r in recs.items() if keep(n, r) and n in z_t.files]
        for k in [f for f in z_t.files if f.startswith('val/')] + tests:
            a = z_t[k]
            if len(a):
                self.arrays['T'][k] = (a[:, e_t], a[:, i_t])
        for b, col in (('tree', 'tree_plain'), ('support', 'support')):
            z, i, e = ed.matrix(ed.SCORES, name, col)
            for k in [f for f in z.files if f.startswith('val/')] + tests:
                a = z[k]
                if len(a):
                    self.arrays[b][k] = (a[:, e], m.transform(col, a[:, i]))


def thresholds(scn, rule, levels):
    fits = scn.fits(rule, NO_EDGE)
    return {b: (m.threshold(fits[b], levels[b]) if levels[b] > 0 else float('inf')) for b in m.CORE}


def evaluate(scns, docs, rule, levels):
    pooled, per = [], {}
    for s, scn in scns.items():
        thr = thresholds(scn, rule, levels)
        rows = []
        for name, r in docs['scenarios'][s]['alarms'].items():
            if not scn.keep(name, r):
                continue
            f = []
            for b in m.CORE:
                if name in scn.arrays[b]:
                    ends, sc = scn.arrays[b][name]
                    f.extend(ends[sc > thr[b]].tolist())
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
    lidds, cbds = m.load(ed.E / 'lidds-evaluation-v2-alarms.json.gz'), m.load(ed.E / 'lidds-evaluation-v2-cbds-alarms.json.gz')
    print('model rule top share alpha | dev detected/544 FA/3403 p95 within3 | CB-DS det/891 FA/1410 | dev (missed, FA) where nonzero', flush=True)
    for model, rule in SETS:
        for top in TOPS:
            lid = {}
            for s in sorted(lidds['scenarios']):
                recs = lidds['scenarios'][s]['alarms']
                lid[s] = Scn(s, recs, m.part_filter(s, recs, 'development'), model, top)
            cb = {'CB-DS': Scn('CB-DS', cbds['scenarios']['CB-DS']['alarms'], lambda n, r: True, model, top)}
            for sname, sh in SHARES.items():
                for alpha in ALPHAS:
                    levels = dict(zip(m.CORE, (alpha * x for x in sh)))
                    d, per = evaluate(lid, lidds, rule, levels)
                    c, _ = evaluate(cb, cbds, rule, levels)
                    detail = {s: (v['attack_recordings'] - v['detected'], v['false_alarm_recordings']) for s, v in per.items()
                              if v['attack_recordings'] != v['detected'] or v['false_alarm_recordings']}
                    print(f"{model:5s} {rule} top{top:<2d} {sname:6s} {alpha:<7g} | {d['detected']:3d} {d['false_alarm_recordings']:3d} {d['latency_p95']:.2f} {d['within3']:3d} "
                          f"| {c['detected']:3d} {c['false_alarm_recordings']:3d} | {detail}", flush=True)


if __name__ == '__main__':
    main()
