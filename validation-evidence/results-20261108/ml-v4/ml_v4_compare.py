#!/usr/bin/env python3
"""Token branch v3 (select1f, model on training, Gumbel on validation maxima) against cross-fit (xfit), development only:
per scenario the Gumbel fit, the threshold, the largest maxima, and detected / false alarms of the token branch alone at a
common per-branch level; which recordings each one alone catches."""
import json
from pathlib import Path
import sys

import numpy as np

ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(ROOT / 'scripts' / 'analysis'))
import lidds_ml_v2 as m  # noqa: E402

E = ROOT / 'validation-evidence/results-20261101/lidds-v4/lidds-evaluation-v2-alarms.json.gz'
LEVEL = 0.0002 * 0.8
docs = m.load(E)


def load(path, col):
    out = {}
    for s in sorted(docs['scenarios']):
        meta = json.loads((Path(path) / f'{s}.json').read_text())
        i = meta['columns'].index(col)
        z = np.load(Path(path) / f'{s}.npz')
        mx = np.asarray([z[k][:, i].max() for k in z.files if k.startswith('val/') and len(z[k])])
        out[s] = (z, i, meta['columns'].index('window_end'), mx)
    return out


A, B = load('/var/tmp/lid-ds-2021/ml-v3-tokens', 'select1f'), load('/var/tmp/lid-ds-2021/ml-xfit-tokens', 'xfit')
print(f"level {LEVEL:g} | scenario | v3 n mu beta thr top3 | xfit n mu beta thr top3 | v3 det fa | xfit det fa | lost by xfit | gained")
tot = [0, 0, 0, 0]
for s in sorted(docs['scenarios']):
    recs = docs['scenarios'][s]['alarms']
    wanted = m.part_filter(s, recs, 'development')
    row, res = [], []
    for (z, i, e, mx) in (A[s], B[s]):
        fit = m.gumbel(mx)
        thr = m.threshold(fit, LEVEL)
        det, fa = set(), set()
        for name, r in recs.items():
            if not wanted(name, r) or name not in z.files or not len(z[name]):
                continue
            a, ex = z[name], r['exploit']
            hit = a[a[:, i] > thr, e]
            if ex is None:
                if len(hit):
                    fa.add(name)
            elif (hit > ex).any():
                det.add(name)
        row.append(f"{len(mx):3d} {fit[0]:6.2f} {fit[1]:5.2f} {thr:6.2f} {np.round(np.sort(mx)[-3:], 1).tolist()}")
        res.append((det, fa))
    tot[0] += len(res[0][0]); tot[1] += len(res[0][1]); tot[2] += len(res[1][0]); tot[3] += len(res[1][1])
    print(f"{s:22s} | {row[0]} | {row[1]} | {len(res[0][0]):3d} {len(res[0][1]):2d} | {len(res[1][0]):3d} {len(res[1][1]):2d} | {len(res[0][0]-res[1][0])} | {len(res[1][0]-res[0][0])}")
print('token alone, totals: v3 det, fa; xfit det, fa:', tot)
