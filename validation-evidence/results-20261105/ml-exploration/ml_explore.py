"""Before lidds-ml-v2, DEVELOPMENT only: recording-level Gumbel thresholds on raw branch scores, one-window decision.
Official matrices are never opened: only development attacks (v2 subset) and development normals (v3 30 %)."""
import json, math, sys, glob, os, zlib
from collections import defaultdict
import numpy as np
sys.path.insert(0, '/home/dat/eBPF-project/scripts/analysis')
import lidds_v3_combine as v3
O = '/var/tmp/lid-ds-2021/ml-scores/'
al = json.load(open('/var/tmp/lid-ds-2021/v3-window/lidds-evaluation-v2-alarms.json'))['scenarios']
COL = None
BR = ['tree_plain', 'tree_fix', 'support', 'g1_plain', 'g1_fix', 'g3_plain', 'g3_fix', 'g4_plain', 'g4_fix', 'g2_top10', 'g2_mass', 'g1d_mass', 'g4d_mass']
PROB = {'tree_plain', 'tree_fix', 'g1_plain', 'g1_fix', 'g3_plain', 'g3_fix', 'g4_plain', 'g4_fix'}
MASS = {'g2_mass', 'g1d_mass', 'g4d_mass'}
def tf(b, x):
    x = np.asarray(x, float)
    if b in PROB: return np.log(np.clip(x, 1e-4, 1 - 1e-4) / (1 - np.clip(x, 1e-4, 1 - 1e-4)))
    if b in MASS: return np.log1p(x)
    return x
data = {}                     # scenario -> dict(val={b: maxima}, att=[(first-time arrays)], nor=[...])
degenerate = defaultdict(int)
for f in sorted(glob.glob(O + '*.json')):
    s = os.path.basename(f)[:-5]
    meta = json.load(open(f))
    COL = meta['columns']; ix = {c: i for i, c in enumerate(COL)}
    z = np.load(O + s + '.npz')
    keys = set(z.files)
    val = defaultdict(list)
    for k in keys:
        if k.startswith('val/'):
            a = z[k]
            if len(a):
                for b in BR: val[b].append(tf(b, a[:, ix[b]]).max())
    if s == 'CB-DS':
        names = {n: 'all' for n, r in meta['recordings'].items()}
    else:
        recs = al[s]['alarms']
        dn = v3.normal_dev(s, [n for n, r in recs.items() if r['split'] == 'test-normal'])
        names = {n: 'att' for n, r in recs.items() if r['split'] != 'test-normal' and r['subset'] == 'development'}
        names.update({n: 'nor' for n in dn})
    att, nor = [], []
    for n, kind in names.items():
        r = meta['recordings'].get(n)
        a = z[n] if n in keys else np.empty((0, len(COL)))
        isatt = r and r['split'] != 'test-normal' if r else kind == 'att'
        if kind == 'att' or (kind == 'all' and isatt):
            ex = r['exploit'] if r else al[s]['alarms'][n]['exploit']
            a = a[a[:, 0] > ex] if len(a) else a
            att.append((a[:, 0] - ex if len(a) else np.empty(0), {b: tf(b, a[:, ix[b]]) if len(a) else np.empty(0) for b in BR}))
        else:
            nor.append((None, {b: tf(b, a[:, ix[b]]) if len(a) else np.empty(0) for b in BR}))
    fit = {}
    for b in BR:
        m = np.asarray(val[b]) if val[b] else np.zeros(1)
        sd = m.std(); beta = max(sd * math.sqrt(6) / math.pi, 1e-6); loc = m.mean() - 0.5772 * beta
        fit[b] = (loc, beta, m.max())
        if sd == 0: degenerate[b] += 1
    data[s] = dict(att=att, nor=nor, fit=fit)
print('scenarios', len(data), 'branches with constant validation maxima (scenario count):', dict(degenerate))
ALPHAS = [0.2, 0.1, 0.05, 0.02, 0.01, 0.005, 0.002, 0.001, 0.0003, 0.0001]
def thr(fit, a):
    loc, beta, mx = fit
    return loc - beta * math.log(-math.log(1 - a))
def evaluate(bs, a, scen=None):
    det = fa = na = nn = 0; lat = []
    per = {}
    for s, d in data.items():
        if s == 'CB-DS' or (scen and s != scen): continue
        t = {b: thr(d['fit'][b], a / len(bs)) for b in bs}
        dd = 0
        for times, sc in d['att']:
            na += 1
            if len(times):
                fire = np.any([sc[b] > t[b] for b in bs], axis=0)
                if fire.any():
                    det += 1; dd += 1; lat.append(times[np.argmax(fire)])
        ff = 0
        for _, sc in d['nor']:
            nn += 1
            if any(len(sc[b]) and (sc[b] > t[b]).any() for b in bs): fa += 1; ff += 1
        per[s] = (dd, len(d['att']), ff, len(d['nor']))
    return det / max(na, 1), fa / max(nn, 1), float(np.percentile(lat, 95)) if lat else None, per, det, na, fa, nn
print('\n== single branch, recording-level Gumbel threshold: recall/FA at each alpha')
for b in BR:
    print(f'{b:11s} ' + ' '.join(f"{a:g}:{100*evaluate([b],a)[0]:.0f}/{100*evaluate([b],a)[1]:.1f}" for a in ALPHAS))
print('\n== sets (Bonferroni on alpha): recall/FA/p95')
SETS = [['tree_plain','support'], ['tree_plain','support','g2_top10'], ['tree_plain','support','g2_mass'], ['support','g2_mass'], ['support','g2_mass','g3_fix'],
        ['tree_plain','support','g2_mass','g3_fix'], ['tree_plain','support','g2_mass','g3_fix','g1d_mass'], ['tree_plain','support','g2_mass','g3_fix','g4d_mass'],
        ['tree_plain','support','g2_mass','g3_fix','g1d_mass','g4d_mass'], ['tree_fix','support','g2_mass','g3_fix','g1d_mass','g4d_mass']]
for bs in SETS:
    print('+'.join(bs))
    print('   ' + ' '.join(f"{a:g}:{100*evaluate(bs,a)[0]:.1f}/{100*evaluate(bs,a)[1]:.2f}/{evaluate(bs,a)[2] or 0:.1f}s" for a in ALPHAS))
# per scenario of the fullest set at the alpha whose FA is closest to 0.8 % and 2 %
full = SETS[-2]
for target in (0.008, 0.02):
    best = min(ALPHAS, key=lambda a: abs(evaluate(full, a)[1] - target))
    r = evaluate(full, best)
    print(f'\nfull set at alpha {best} (FA {100*r[1]:.2f}%, recall {100*r[0]:.1f}%, p95 {r[2]}):')
    for s, v in sorted(r[3].items()): print(f'  {s:22s} attacks {v[0]}/{v[1]}  normals {v[2]}/{v[3]}')
# CB-DS with the same thresholds
d = data.get('CB-DS')
if d:
    for a in (0.01, 0.001):
        t = {b: thr(d['fit'][b], a / len(full)) for b in full}
        det = sum(1 for times, sc in d['att'] if len(times) and np.any([sc[b] > t[b] for b in full], axis=0).any())
        fa = sum(1 for _, sc in d['nor'] if any(len(sc[b]) and (sc[b] > t[b]).any() for b in full))
        print(f'CB-DS full set alpha {a}: attacks {det}/{len(d["att"])}, normals {fa}/{len(d["nor"])}')
