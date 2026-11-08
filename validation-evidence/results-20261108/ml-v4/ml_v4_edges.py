#!/usr/bin/env python3
"""Leave out the incomplete windows at the edges of a recording, LID-DS 2021 development and CB-DS only (official not read).

A recording starts and stops inside a 0.5 s window, so its first and last windows are partial and their ratios are
distorted; many development false alarms fire exactly there (fa-where.txt). Edges are taken from the token matrix (the
first and last window with events) and left out of every branch, in validation and test alike, then the thresholds are
refitted. Variants: none, first, last, both. Token column select1f (R1) and xfit (R1, R4 as ml_v4_rules.py). Nothing selected.
"""
import json
import math
from pathlib import Path
import sys

import numpy as np

ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(ROOT / 'scripts' / 'analysis'))
import lidds_ml_v2 as m  # noqa: E402
import lidds_v3_combine as v3  # noqa: E402

E = ROOT / 'validation-evidence/results-20261101/lidds-v4'
SCORES = Path('/var/tmp/lid-ds-2021/ml-scores-allwin')
TOKENS = dict(select1f=Path('/var/tmp/lid-ds-2021/ml-v3-tokens'), xfit=Path('/var/tmp/lid-ds-2021/ml-xfit-tokens'))
SHARES = {'1/3': (1 / 3, 1 / 3, 1 / 3), 'T.8': (.8, .1, .1), 'T.9': (.9, .05, .05), 'T.95': (.95, .025, .025)}
ALPHAS = (0.001, 0.0005, 0.0002, 0.0001, 0.00005)
EDGES = {'none': (0, 0), 'first': (1, 0), 'last': (0, 1), 'both': (1, 1)}
SETS = [('select1f', 'R1'), ('xfit', 'R1'), ('xfit', 'R4')]


def r4(x):
    x = np.sort(x)
    return m.gumbel(x[:max(2, len(x) - max(1, int(round(len(x) * .01))))])


FIT = dict(R1=m.gumbel, R4=r4)


def matrix(path, name, col):
    meta = json.loads((path / f'{name}.json').read_text())
    return np.load(path / f'{name}.npz'), meta['columns'].index(col), meta['columns'].index('window_end')


class Scn:
    """Arrays of the wanted recordings only: {branch: {recording: (ends, transformed scores)}}"""

    def __init__(self, name, recs, keep, column):
        z_t, i_t, e_t = matrix(TOKENS[column], name, column)
        self.arrays, self.edges = {b: {} for b in m.CORE}, {}
        names = [k for k in z_t.files if k.startswith('val/')]
        vals = set(names)
        tests = [n for n, r in recs.items() if keep(n, r) and n in z_t.files]
        for k in names + tests:
            a = z_t[k]
            if len(a):
                self.arrays['T'][k] = (a[:, e_t], a[:, i_t])
                self.edges[k] = (a[:, e_t].min(), a[:, e_t].max())
        for b, col in (('tree', 'tree_plain'), ('support', 'support')):
            z, i, e = matrix(SCORES, name, col)
            for k in [f for f in z.files if f.startswith('val/')] + tests:
                a = z[k]
                if len(a):
                    self.arrays[b][k] = (a[:, e], m.transform(col, a[:, i]))
        self.vals = vals

    def scores(self, b, k, edge):
        ends, sc = self.arrays[b][k]
        lo, hi = self.edges.get(k, (-math.inf, math.inf))
        ok = np.ones(len(ends), bool)
        if edge[0]:
            ok &= ends > lo
        if edge[1]:
            ok &= ends < hi
        return ends[ok], sc[ok]

    def fits(self, rule, edge):
        out = {}
        for b in m.CORE:
            mx = [s.max() for s in (self.scores(b, k, edge)[1] for k in self.arrays[b] if k.startswith('val/')) if len(s)]
            out[b] = (FIT[rule] if b == 'T' else m.gumbel)(np.asarray(mx, float))
        return out


def evaluate(scns, docs, rule, edge, levels):
    pooled, per = [], {}
    for s, scn in scns.items():
        fits = scn.fits(rule, edge)
        thr = {b: m.threshold(fits[b], levels[b]) for b in m.CORE}
        rows = []
        for name, r in docs['scenarios'][s]['alarms'].items():
            if not scn.keep(name, r):
                continue
            f = []
            for b in m.CORE:
                if name in scn.arrays[b]:
                    ends, sc = scn.scores(b, name, edge)
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
    lidds, cbds = m.load(E / 'lidds-evaluation-v2-alarms.json.gz'), m.load(E / 'lidds-evaluation-v2-cbds-alarms.json.gz')
    print('token rule edges share alpha | dev detected/544 FA/3403 p95 within3 | CB-DS det/891 FA/1410 | dev (missed, FA) where nonzero', flush=True)
    for column in ('select1f', 'xfit'):
        lid = {}
        for s in sorted(lidds['scenarios']):
            recs = lidds['scenarios'][s]['alarms']
            part = m.part_filter(s, recs, 'development')
            scn = Scn(s, recs, part, column)
            scn.keep = part
            lid[s] = scn
        recs = cbds['scenarios']['CB-DS']['alarms']
        cb = Scn('CB-DS', recs, lambda n, r: True, column)
        cb.keep = lambda n, r: True
        for col, rule in SETS:
            if col != column:
                continue
            for ename, edge in EDGES.items():
                for sname, sh in SHARES.items():
                    for alpha in ALPHAS:
                        levels = dict(zip(m.CORE, (alpha * x for x in sh)))
                        d, per = evaluate(lid, lidds, rule, edge, levels)
                        c, _ = evaluate({'CB-DS': cb}, cbds, rule, edge, levels)
                        detail = {s: (v['attack_recordings'] - v['detected'], v['false_alarm_recordings']) for s, v in per.items()
                                  if v['attack_recordings'] != v['detected'] or v['false_alarm_recordings']}
                        print(f"{col:8s} {rule} {ename:5s} {sname:4s} {alpha:<7g} | {d['detected']:3d} {d['false_alarm_recordings']:3d} {d['latency_p95']:.2f} {d['within3']:3d} "
                              f"| {c['detected']:3d} {c['false_alarm_recordings']:3d} | {detail}", flush=True)


if __name__ == '__main__':
    main()
