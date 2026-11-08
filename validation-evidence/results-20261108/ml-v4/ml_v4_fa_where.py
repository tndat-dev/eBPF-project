#!/usr/bin/env python3
"""Development false alarms of the three branches: which branch, margin over its threshold in Gumbel betas, where in the
recording the first firing lies and how many windows fire; tree and support at alpha 0.0002 x 0.05, token select1f at
0.0002 x 0.9. Development only."""
import json
from pathlib import Path
import sys

import numpy as np

ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(ROOT / 'scripts' / 'analysis'))
import lidds_ml_v2 as m  # noqa: E402

E = ROOT / 'validation-evidence/results-20261101/lidds-v4'
LEVELS = dict(T=.0002 * .9, tree=.0002 * .05, support=.0002 * .05)
m.set_token_column('select1f')
docs = m.load(E / 'lidds-evaluation-v2-alarms.json.gz')
dirs = dict(scores='/var/tmp/lid-ds-2021/ml-scores-allwin', tokens='/var/tmp/lid-ds-2021/ml-v3-tokens')
for s in sorted(docs['scenarios']):
    scn = m.Scenario(s, dirs)
    recs = docs['scenarios'][s]['alarms']
    wanted = m.part_filter(s, recs, 'development')
    vals = {b: np.asarray([m.transform(scn.branch[b][1], scn.branch[b][0][k][:, scn.branch[b][2]]).max()
                           for k in scn.branch[b][0].files if k.startswith('val/') and len(scn.branch[b][0][k])]) for b in m.CORE}
    for name, r in recs.items():
        if not wanted(name, r) or r['exploit'] is not None:
            continue
        for b in m.CORE:
            z, col, i, end, fit = scn.branch[b]
            if name not in z.files or not len(z[name]):
                continue
            a = z[name]
            sc = m.transform(col, a[:, i])
            thr = m.threshold(fit, LEVELS[b])
            hit = np.flatnonzero(sc > thr)
            if len(hit):
                t0, t1 = a[0, end], a[-1, end]
                print(f"{s:20s} {name:28s} {b:7s} thr {thr:7.2f} max {sc.max():8.2f} (+{(sc.max()-thr)/fit[1]:6.1f} beta; val max {vals[b].max():7.2f}) "
                      f"windows {len(hit):3d}/{len(a):4d} first at {a[hit[0], end]-t0:6.1f}s of {t1-t0:6.1f}s")
