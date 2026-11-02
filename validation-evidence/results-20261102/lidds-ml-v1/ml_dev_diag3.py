"""lidds-ml-v1 diagnosis 3, DEVELOPMENT only: per scenario, recordings whose smallest p reaches the floor of its branch."""
import json, sys
from collections import defaultdict
import numpy as np
sys.path.insert(0, '/home/dat/eBPF-project/scripts/analysis')
import lidds_v3_combine as v3
O = '/var/tmp/lid-ds-2021/ml-v1/'
al = json.load(open('/var/tmp/lid-ds-2021/v3-window/lidds-evaluation-v2-alarms.json'))['scenarios']
COL = ['end', 'tree', 'tree_fix', 'support', 'g1', 'g1_fix', 'g3', 'g3_fix', 'g4', 'g4_fix', 'g2']
SHOW = ['tree', 'support', 'g1', 'g1_fix', 'g2', 'g3', 'g3_fix', 'g4', 'g4_fix']
print(f"{'scenario':22s} {'kind':5s} {'n':>4s} " + ' '.join(f'{b:>7s}' for b in SHOW) + '   any')
tot = defaultdict(int)
for s, res in sorted(al.items()):
    z = np.load(O + s + '.npz'); recs = res['alarms']
    dn = v3.normal_dev(s, [n for n, r in recs.items() if r['split'] == 'test-normal'])
    floor = {b: 1.0 for b in SHOW}
    for n in z.files:
        a = z[n]
        if len(a):
            for b in SHOW: floor[b] = min(floor[b], a[:, COL.index(b)].min())
    for kind in ('att', 'nor'):
        c = defaultdict(int); n_rec = 0; anyb = 0
        for n, r in recs.items():
            if kind == 'att':
                if r['split'] == 'test-normal' or r['subset'] != 'development': continue
            elif r['split'] != 'test-normal' or n not in dn: continue
            n_rec += 1
            a = z[n] if n in z.files else np.empty((0, 11))
            if kind == 'att' and len(a): a = a[a[:, 0] > r['exploit']]
            hit = False
            for b in SHOW:
                if len(a) and a[:, COL.index(b)].min() <= floor[b] * 1.0001:
                    c[b] += 1
                    if b in ('tree', 'support', 'g1', 'g2', 'g3', 'g4'): hit = True
            anyb += hit
        print(f"{s:22s} {kind:5s} {n_rec:4d} " + ' '.join(f'{c[b]:7d}' for b in SHOW) + f' {anyb:5d}')
        tot[kind, 'n'] += n_rec; tot[kind, 'any'] += anyb
print('pooled any plain branch at its floor: attacks', tot['att', 'any'], '/', tot['att', 'n'], ' normals', tot['nor', 'any'], '/', tot['nor', 'n'])
