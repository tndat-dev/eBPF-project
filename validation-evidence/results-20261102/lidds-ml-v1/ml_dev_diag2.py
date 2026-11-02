"""lidds-ml-v1 diagnosis 2, DEVELOPMENT only: conformal floor, and what the decision rule alone can buy."""
import json, sys
import numpy as np
sys.path.insert(0, '/home/dat/eBPF-project/scripts/analysis')
import lidds_v3_combine as v3
O = '/var/tmp/lid-ds-2021/ml-v1/'
al = json.load(open('/var/tmp/lid-ds-2021/v3-window/lidds-evaluation-v2-alarms.json'))['scenarios']
COL = ['end', 'tree', 'tree_fix', 'support', 'g1', 'g1_fix', 'g3', 'g3_fix', 'g4', 'g4_fix', 'g2']
ix = {c: i for i, c in enumerate(COL)}
SETS = {'g0': ['tree', 'support'], 'g0+g1+g2': ['tree', 'support', 'g1', 'g2'], 'g0+g1+g2+g3': ['tree', 'support', 'g1', 'g2', 'g3']}
att = {k: [] for k in SETS}; nor = {k: [] for k in SETS}
floor_att = {c: [0, 0] for c in COL[1:]}; floor_nor = {c: [0, 0] for c in COL[1:]}; floors = {}
for s, res in al.items():
    z = np.load(O + s + '.npz'); recs = res['alarms']
    dn = v3.normal_dev(s, [n for n, r in recs.items() if r['split'] == 'test-normal'])
    fl = None
    for n, r in recs.items():
        if r['split'] == 'test-normal':
            if n not in dn: continue
            is_att = False
        else:
            if r['subset'] != 'development': continue
            is_att = True
        a = z[n] if n in z.files else np.empty((0, 11))
        if len(a): fl = min(fl, a[:, 1:].min()) if fl is not None else a[:, 1:].min()
        if is_att and len(a): a = a[a[:, 0] > r['exploit']]
        for c in COL[1:]:
            d = floor_att if is_att else floor_nor
            if len(a):
                d[c][0] += float(a[:, ix[c]].min() <= 1.5 * 1e-9 + a[:, ix[c]].min() and a[:, ix[c]].min() < 0.0006); d[c][1] += 1
        for k, bs in SETS.items():
            if len(a):
                p = np.minimum(1, len(bs) * a[:, [ix[b] for b in bs]].min(axis=1))
                one = float(p.min()); two = float(np.maximum(p[1:], p[:-1]).min()) if len(p) > 1 else 1.0
            else:
                one = two = 1.0
            (att if is_att else nor)[k].append((one, two))
    floors[s] = fl
print('smallest p per scenario (the conformal floor is 1/(n_cal+1)):', {k: round(v, 5) for k, v in floors.items() if v is not None})
print('\nshare of dev recordings whose smallest p after the exploit is below 0.0006 (near the floor)')
for c in COL[1:]:
    print(f"  {c:9s} attacks {100*floor_att[c][0]/floor_att[c][1]:5.1f}%   normals {100*floor_nor[c][0]/floor_nor[c][1]:5.1f}%")
print('\nBonferroni of a set; recall at each normal FA, sweeping the threshold (<=)')
for k in SETS:
    A, N = np.array(att[k]), np.array(nor[k])
    for name, c in (('one window', 0), ('two windows', 1)):
        out = []
        for t in (0.0005, 0.001, 0.002, 0.004, 0.00833, 0.016, 0.03, 0.06):
            out.append(f"{t:g}:{100*np.mean(A[:,c]<=t):.0f}/{100*np.mean(N[:,c]<=t):.1f}")
        print(f"  {k:12s} {name:11s} recall/FA  " + '  '.join(out))
