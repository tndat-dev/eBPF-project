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

FINE = [0.5,0.3,0.2,0.15,0.1,0.07,0.05,0.03,0.02,0.015,0.01,0.007,0.005,0.003,0.002,0.0015,0.001,0.0007,0.0005,0.0003,0.0002,0.0001,0.00005,0.00002,0.00001]
def best_at(bs, limit):
    best = None
    for a in FINE:
        r = evaluate(bs, a)
        if r[1] <= limit and (best is None or r[0] > best[1]):
            best = (a, r[0], r[1], r[2], r[4], r[6])
    return best
for limit in (0.008, 0.02):
    print(f'\n== greedy forward selection, recall at normal FA <= {100*limit:g} %')
    cur = []; bestr = 0
    while True:
        cand = [(best_at(cur + [b], limit), b) for b in BR if b not in cur]
        cand = [c for c in cand if c[0]]
        if not cand: break
        top = max(cand, key=lambda c: c[0][1])
        if top[0][1] <= bestr + 1e-9: break
        bestr = top[0][1]; cur = cur + [top[1]]
        a, rec, fa, p95, det, f = top[0]
        print(f"  +{top[1]:11s} alpha {a:<8g} recall {100*rec:.1f}% ({det}/544) FA {100*fa:.2f}% ({f}) p95 {p95:.2f}s")
    a, *_ = best_at(cur, limit)
    r = evaluate(cur, a)
    print('  per scenario (attacks, normals):')
    for s, v in sorted(r[3].items()): print(f'    {s:22s} {v[0]}/{v[1]}   {v[2]}/{v[3]}')
    d = data['CB-DS']; t = {b: thr(d['fit'][b], a / len(cur)) for b in cur}
    det = sum(1 for times, sc in d['att'] if len(times) and np.any([sc[b] > t[b] for b in cur], axis=0).any())
    fa = sum(1 for _, sc in d['nor'] if any(len(sc[b]) and (sc[b] > t[b]).any() for b in cur))
    print(f'  CB-DS same thresholds rule: attacks {det}/{len(d["att"])}, normals {fa}/{len(d["nor"])}')
# unseen share diagnostic on development attacks for g1d, g4d
ix = {c: i for i, c in enumerate(COL)}
for name, u in (('g1d_mass','g1d_unseen'),('g4d_mass','g4d_unseen')):
    tot = uns = 0.0
    for f in sorted(glob.glob(O + '*.json')):
        s0 = os.path.basename(f)[:-5]
        if s0 == 'CB-DS': continue
        z = np.load(O + s0 + '.npz'); recs = al[s0]['alarms']
        for n, r in recs.items():
            if r['split'] != 'test-normal' and r['subset'] == 'development' and n in z.files and len(z[n]):
                a = z[n]; a = a[a[:, 0] > r['exploit']]
                tot += a[:, ix[name]].sum(); uns += a[:, ix[u]].sum()
    print(f'{name}: share of attack-window mass from items never seen in training: {100*uns/max(tot,1e-9):.1f}%')
