"""Before lidds-ml-v2, DEVELOPMENT only: threshold methods on raw branch scores (one window; official never opened)."""
import json, math, sys, glob, os
from collections import defaultdict
import numpy as np
from scipy import stats
sys.path.insert(0, '/home/dat/eBPF-project/scripts/analysis')
import lidds_v3_combine as v3
O = '/var/tmp/lid-ds-2021/ml-scores/'
al = json.load(open('/var/tmp/lid-ds-2021/v3-window/lidds-evaluation-v2-alarms.json'))['scenarios']
BR = ['tree_plain', 'support', 'g1_fix', 'g2_top10', 'g3_fix', 'g4_fix']
PROB = {'tree_plain', 'g1_fix', 'g3_fix', 'g4_fix'}
def tf(b, x):
    x = np.asarray(x, float)
    if b in PROB:
        c = np.clip(x, 1e-4, 1 - 1e-4); return np.log(c / (1 - c))
    return x
data = {}
for f in sorted(glob.glob(O + '*.json')):
    s = os.path.basename(f)[:-5]
    meta = json.load(open(f)); ix = {c: i for i, c in enumerate(meta['columns'])}
    z = np.load(O + s + '.npz'); keys = set(z.files)
    maxima = defaultdict(list); windows = defaultdict(list); lens = []; val = []
    for k in keys:
        if k.startswith('val/') and len(z[k]):
            a = z[k]; lens.append(len(a))
            val.append(np.column_stack([tf(b, a[:, ix[b]]) for b in BR]))
    if s == 'CB-DS':
        names = {n: ('att' if r['split'] != 'test-normal' else 'nor') for n, r in meta['recordings'].items()}
    else:
        recs = al[s]['alarms']
        dn = v3.normal_dev(s, [n for n, r in recs.items() if r['split'] == 'test-normal'])
        names = {n: 'att' for n, r in recs.items() if r['split'] != 'test-normal' and r['subset'] == 'development'}
        names.update({n: 'nor' for n in dn})
    att, nor = [], []
    for n, kind in names.items():
        a = z[n] if n in keys else np.empty((0, len(ix)))
        if kind == 'att':
            ex = meta['recordings'][n]['exploit']
            a = a[a[:, 0] > ex] if len(a) else a
            att.append((a[:, 0] - ex if len(a) else np.empty(0), np.column_stack([tf(b, a[:, ix[b]]) for b in BR]) if len(a) else np.empty((0, len(BR)))))
        else:
            nor.append(np.column_stack([tf(b, a[:, ix[b]]) for b in BR]) if len(a) else np.empty((0, len(BR))))
    data[s] = dict(att=att, nor=nor, val=val)

def gumbel(m):
    beta = max(np.std(m) * math.sqrt(6) / math.pi, 1e-6); return np.mean(m) - .5772 * beta, beta
def thr(fit, a):
    return fit[0] - fit[1] * math.log(-math.log(1 - a))
def sliding(x, w):
    if w == 1 or len(x) < w: return x if w == 1 else np.full(len(x), x.sum() if len(x) else 0.0)
    c = np.convolve(x, np.ones(w), 'full')[:len(x)]
    return c
def fusers(Z, name, idx):
    Z = Z[:, idx]
    if name == 'max': return Z.max(axis=1)
    pos = np.clip(Z, 0, None)
    if name == 'sum_pos': return pos.sum(axis=1)
    if name == 'top2': return np.sort(pos, axis=1)[:, -2:].sum(axis=1)
    if name == 'l2': return np.sqrt((pos ** 2).sum(axis=1))
    raise ValueError(name)
def per_branch(d):
    """window-level normalisation from validation windows: median and upper spread, per branch."""
    V = np.concatenate(d['val'])
    med = np.median(V, axis=0); up = np.percentile(V, 99, axis=0) - med
    return med, np.maximum(up, 1e-3)
for d in data.values(): d['norm'] = per_branch(d)
ALPHAS = [0.2, 0.1, 0.05, 0.03, 0.02, 0.01, 0.007, 0.005, 0.003, 0.002, 0.001, 0.0005, 0.0002, 0.0001]
def run(idx, fuse, w):
    rows = {}
    for s, d in data.items():
        med, up = d['norm']
        sc = lambda M: sliding(fusers((M - med) / up, fuse, idx), w) if len(M) else np.empty(0)
        fit = gumbel([sc(v).max() for v in d['val']])
        rows[s] = dict(fit=fit, att=[(t, sc(M)) for t, M in d['att']], nor=[sc(M) for M in d['nor']])
    return rows
def ev(rows, a):
    det = fa = na = nn = 0; lat = []; per = {}
    for s, r in rows.items():
        if s == 'CB-DS': continue
        t = thr(r['fit'], a); dd = ff = 0
        for times, v in r['att']:
            na += 1
            if len(times) and (v > t).any(): det += 1; dd += 1; lat.append(times[np.argmax(v > t)])
        for v in r['nor']:
            nn += 1
            if len(v) and (v > t).any(): fa += 1; ff += 1
        per[s] = (dd, len(r['att']), ff, len(r['nor']))
    return det / na, fa / nn, float(np.percentile(lat, 95)) if lat else None, per, det, fa
SETS = {'3': [BR.index(b) for b in ('g2_top10', 'g3_fix', 'support')], '4': [BR.index(b) for b in ('g2_top10', 'g3_fix', 'support', 'g1_fix')],
        '5': [BR.index(b) for b in ('g2_top10', 'g3_fix', 'support', 'g1_fix', 'g4_fix')], 'all6': list(range(len(BR)))}
print('set fuse w | best recall at FA<=0.8% | at FA<=2%')
res = []
for sn, idx in SETS.items():
    for fuse in ('max', 'top2', 'sum_pos', 'l2'):
        for w in (1, 2, 4):
            rows = run(idx, fuse, w); evs = [(ev(rows, a), a) for a in ALPHAS]; line = []
            for lim in (0.008, 0.02):
                ok = [x for x in evs if x[0][1] <= lim]
                if ok:
                    r, a = max(ok, key=lambda x: x[0][0]); line.append(f"{100*r[0]:.1f}/{100*r[1]:.2f} a={a:g} p95={r[2]:.2f}")
                    if lim == 0.008: res.append((r[0], sn, fuse, w, a, r))
                else: line.append('-')
            print(f"{sn:5s}{fuse:8s}{w} | {line[0]:36s} | {line[1]}")
res.sort(key=lambda x: -x[0])
for rec, sn, fuse, w, a, r in res[:2]:
    print(f"\nbest: set {sn} {fuse} w={w} alpha {a}: recall {100*rec:.1f}% ({r[4]}), FA {100*r[1]:.2f}% ({r[5]}), p95 {r[2]:.2f}s")
    for s, v in sorted(r[3].items()): print(f"   {s:22s} {v[0]}/{v[1]}  {v[2]}/{v[3]}")
    rows = run(SETS[sn], fuse, w); cb = rows['CB-DS']; t = thr(cb['fit'], a)
    print('   CB-DS', sum(1 for tm, v in cb['att'] if len(tm) and (v > t).any()), '/', len(cb['att']), ' normals', sum(1 for v in cb['nor'] if len(v) and (v > t).any()), '/', len(cb['nor']))
