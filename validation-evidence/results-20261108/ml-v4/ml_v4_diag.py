#!/usr/bin/env python3
"""Where lidds-ml-v3 still errs on LID-DS 2021 development (official not read): per false alarm the branches that fire,
per missed attack how close each branch came (max score after the exploit minus threshold, in branch units), and the
number of validation / training recordings per scenario. Development and CB-DS only.

    python3 ml_v4_diag.py --scores DIR --tokens DIR --lidds-alarms a.json.gz --cbds-alarms c.json.gz
"""
import argparse
from collections import Counter, defaultdict
from pathlib import Path
import sys
import zipfile

import numpy as np

ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(ROOT / 'scripts' / 'analysis'))
import lidds_ml_v2 as m  # noqa: E402

ALPHA = 0.0002


def main():
    ap = argparse.ArgumentParser()
    for k in ('scores', 'tokens', 'lidds-alarms', 'cbds-alarms'):
        ap.add_argument('--' + k, required=True)
    ap.add_argument('--archives', default='/var/tmp/lid-ds-2021')
    a = ap.parse_args()
    m.set_token_column('select1f')
    lidds = m.load(a.lidds_alarms)
    dirs = dict(scores=a.scores, tokens=a.tokens)
    fa_by, miss_rows, splits = Counter(), [], {}
    for s in sorted(lidds['scenarios']):
        scn = m.Scenario(s, dirs)
        recs = lidds['scenarios'][s]['alarms']
        wanted = m.part_filter(s, recs, 'development')
        thr = {b: m.threshold(scn.branch[b][4], ALPHA / 3) for b in m.CORE}
        z = scn.branch['T'][0]
        n_val = sum(1 for k in z.files if k.startswith('val/'))
        try:
            names = zipfile.ZipFile(Path(a.archives) / f'{s}.zip').namelist()
            n_train = len({n.split('/')[-1].split('.')[0] for n in names if '/training/' in n})
        except Exception:
            n_train = None
        splits[s] = (n_val, n_train)
        for name, r in recs.items():
            if not wanted(name, r):
                continue
            ex = r['exploit']
            per = {}
            for b in m.CORE:
                zz, col, i, end, fit = scn.branch[b]
                if name not in zz.files or not len(zz[name]):
                    per[b] = (None, None)
                    continue
                arr = zz[name]
                sc = m.transform(col, arr[:, i])
                after = sc[arr[:, end] > ex] if ex is not None else sc
                before = sc[arr[:, end] <= ex] if ex is not None else sc
                per[b] = (float(after.max()) - thr[b] if len(after) else None,
                          float(before.max()) - thr[b] if len(before) else None)
            if ex is None:
                fired = [b for b in m.CORE if per[b][0] is not None and per[b][0] > 0]
                if fired:
                    fa_by['+'.join(fired)] += 1
                    fa_by[f'scenario {s}'] += 1
            else:
                det = any(per[b][0] is not None and per[b][0] > 0 for b in m.CORE)
                if not det:
                    miss_rows.append((s, name, {b: None if per[b][0] is None else round(per[b][0], 2) for b in m.CORE},
                                      {b: round(fit[1], 2) for b, (_, _, _, _, fit) in scn.branch.items()}))
    print('validation / training recordings per scenario:', splits)
    print('false alarms by firing branches and scenario:', dict(fa_by))
    print('missed attacks: max(score after exploit) - threshold per branch (gumbel beta in second dict):')
    for row in miss_rows:
        print(' ', row)


if __name__ == '__main__':
    main()
