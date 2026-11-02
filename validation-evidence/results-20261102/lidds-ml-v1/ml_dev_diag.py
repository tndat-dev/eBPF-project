"""lidds-ml-v1 diagnosis, DEVELOPMENT data only (attacks: v2 development; normals: v3 30 %)."""
import json, sys
from collections import defaultdict
import numpy as np
sys.path.insert(0, '/home/dat/eBPF-project/scripts/analysis')
import lidds_v3_combine as v3
O = '/var/tmp/lid-ds-2021/ml-v1/'
sel = json.load(open(O + 'lidds-ml-v1.json'))
print('== all 24 configs, development (recall, FA, precision, p95) and CB-DS (recall, FA)')
for r in sorted(sel['screening'], key=lambda r: -r['development']['detected']):
    d, c = r['development'], r['cbds']
    print(f"{r['config']:42s} {100*d['recall']:5.1f} {100*d['false_alarm_rate']:5.2f} {100*(d['precision_base_rate'] or 0):5.1f} {d['latency_p95']:5.2f} | {100*c['recall']:5.1f} {100*c['false_alarm_rate']:5.2f}")
al = json.load(open('/var/tmp/lid-ds-2021/v3-window/lidds-evaluation-v2-alarms.json'))['scenarios']
COL = ['end', 'tree', 'tree_fix', 'support', 'g1', 'g1_fix', 'g3', 'g3_fix', 'g4', 'g4_fix', 'g2']
BR = ['tree', 'tree_fix', 'support', 'g1', 'g1_fix', 'g2', 'g3', 'g3_fix', 'g4', 'g4_fix']
att, nor = [], []      # (scenario, {branch: (min p one window, min max(p_t,p_t-1) two windows)}, scored)
noscore = defaultdict(int); total = defaultdict(int)
for s, res in al.items():
    z = np.load(O + s + '.npz')
    recs = res['alarms']
    dn = v3.normal_dev(s, [n for n, r in recs.items() if r['split'] == 'test-normal'])
    for n, r in recs.items():
        if r['split'] == 'test-normal':
            if n not in dn: continue
            is_att = False
        else:
            if r['subset'] != 'development': continue
            is_att = True; total[s] += 1
        a = z[n] if n in z.files else np.empty((0, 11))
        if is_att:
            a = a[a[:, 0] > r['exploit']] if len(a) else a
            if not len(a): noscore[s] += 1
        one, two = {}, {}
        for b in BR:
            p = a[:, COL.index(b)] if len(a) else np.array([1.0])
            one[b] = float(p.min())
            two[b] = float(np.maximum(p[1:], p[:-1]).min()) if len(p) > 1 else 1.0
        (att if is_att else nor).append((s, one, two))
print('\nattack recordings', len(att), 'normal', len(nor), 'attacks with no scored window after the exploit:', sum(noscore.values()), dict(noscore))
def at_fa(key, b, fa=0.01):
    idx = 1 if key == 'one' else 2
    vals = np.sort([x[idx][b] for x in nor])
    tau = vals[int(fa * len(vals))]          # the largest threshold with about fa of normal recordings below it
    det = defaultdict(int)
    for x in att:
        if x[idx][b] < tau: det[x[0]] += 1
    return tau, sum(det.values()), det
print('\n== each learned branch alone, threshold set for about 1 % of dev normal recordings')
print(f"{'branch':10s} {'tau(1win)':>10s} {'recall 1win':>12s} {'tau(2win)':>10s} {'recall 2win':>12s}")
scen = {}
for b in BR:
    t1, d1, m1 = at_fa('one', b); t2, d2, m2 = at_fa('two', b); scen[b] = m1
    print(f"{b:10s} {t1:10.5f} {100*d1/len(att):11.1f}% {t2:10.5f} {100*d2/len(att):11.1f}%")
print('\n== per scenario, one-window rule at 1 % normal FA (detected of dev attacks)')
names = sorted(total)
print(f"{'scenario':24s} {'n':>3s} {'noWin':>5s} " + ' '.join(f'{b:>8s}' for b in ('tree','support','g1','g1_fix','g2','g3','g4')))
for s in names:
    print(f"{s:24s} {total[s]:3d} {noscore[s]:5d} " + ' '.join(f"{scen[b][s]:8d}" for b in ('tree','support','g1','g1_fix','g2','g3','g4')))
# union with per-branch 1/K FA budget, one window
print('\n== union of branches (one window), each branch at 2 %/K of dev normals; reported recall and actual normal FA')
for bs in (['tree','support'],['tree','support','g1','g2','g3'],['tree','support','g1','g2','g3','g4'],['tree_fix','support','g1_fix','g2','g3_fix','g4_fix']):
    taus = {b: np.sort([x[1][b] for x in nor])[int(0.02 / len(bs) * len(nor))] for b in bs}
    det = sum(any(x[1][b] < taus[b] for b in bs) for x in att); fa = sum(any(x[1][b] < taus[b] for b in bs) for x in nor)
    print(bs, f'recall {100*det/len(att):.1f}%  normal FA {100*fa/len(nor):.2f}%')
