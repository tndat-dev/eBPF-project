"""DEVELOPMENT only: how close is the lidds-ml-v2 threshold rule (moment-Gumbel on per-recording validation maxima,
alpha / 3 per branch, one window fires) to the best possible threshold choice on the same scores?

1. Oracle frontiers with attack labels (upper bounds no label-free rule can beat on these scores):
   a. token branch alone, any threshold per scenario (exact);
   b. the three branches, Gumbel tail levels combined by min, any level per scenario (exact on that statistic);
   c. the same statistic with one level for all scenarios (what choosing alpha does).
2. Other label-free fits of the validation maxima at the same Bonferroni rule: Gumbel by maximum likelihood, GEV,
   normal, exponential tail above the median, the plain validation maximum.
3. Calibration: Gumbel's predicted exceedance against (i) held-out validation recordings, leave one out, and (ii) the
   development normals; GEV shape per scenario and branch.
Official recordings are never read: every recording used passes part_filter(..., 'development') or is validation."""
import math, sys
from collections import defaultdict
import numpy as np
from scipy import stats
from pathlib import Path as _P
ROOT = str(_P(__file__).resolve().parents[3]) + '/'   # repository root, on any machine
sys.path.insert(0, ROOT + 'scripts/analysis')
import lidds_ml_v2 as m
S = sys.argv[1]
doc = m.load(ROOT + 'validation-evidence/results-20261101/lidds-v4/lidds-evaluation-v2-alarms.json.gz')
names = sorted(doc['scenarios']); B = ('T', 'tree', 'support'); NEG = -1e18

data = {}
for s in names:
    sc = m.Scenario(s, dict(scores=S + '/allwin', tokens=S + '/tokens'))
    recs = doc['scenarios'][s]['alarms']; want = m.part_filter(s, recs, 'development')
    d = dict(val={}, att={}, nor={})
    for b in B:
        z, col, i, end, _ = sc.branch[b]
        d['val'][b] = np.array([m.transform(col, z[k][:, i]).max() for k in z.files if k.startswith('val/') and len(z[k])])
        a, n = [], []
        for name, r in recs.items():
            if not want(name, r): continue
            x = z[name] if name in z.files and len(z[name]) else None
            if r['exploit'] is None:
                n.append(m.transform(col, x[:, i]).max() if x is not None else NEG)
            else:
                if x is not None:
                    y = x[x[:, end] > r['exploit']]
                    a.append(m.transform(col, y[:, i]).max() if len(y) else NEG)
                else:
                    a.append(NEG)
        d['att'][b], d['nor'][b] = np.array(a), np.array(n)
    data[s] = d
NA = sum(len(data[s]['att']['T']) for s in names); NN = sum(len(data[s]['nor']['T']) for s in names)
print(f'development: {NA} attack, {NN} normal recordings, {len(names)} scenarios')

def fit(method, v):
    v = np.asarray(v, float)
    if method == 'gumbel_moments': return ('g',) + m.gumbel(v)
    if method == 'gumbel_mle': loc, sc = stats.gumbel_r.fit(v); return ('g', loc, max(sc, 1e-6))
    if method == 'gev_mle': c, loc, sc = stats.genextreme.fit(v); return ('gev', c, loc, max(sc, 1e-6))
    if method == 'normal': return ('n', v.mean(), max(v.std(), 1e-6))
    if method == 'exp_tail':
        u = np.median(v); e = v[v > u] - u; return ('e', u, max(e.mean() if len(e) else 1e-6, 1e-6), (v > u).mean())
    if method == 'val_max': return ('max', v.max())
def thr(f, a):
    k = f[0]
    if k == 'g': return f[1] - f[2] * math.log(-math.log(1 - a))
    if k == 'gev': return stats.genextreme.isf(a, f[1], f[2], f[3])
    if k == 'n': return f[1] + f[2] * stats.norm.isf(a)
    if k == 'e': return f[1] + f[2] * math.log(f[3] / a) if a < f[3] else f[1]
    if k == 'max': return f[1]
def tail(f, x):
    """Gumbel exceedance probability of x (the combined statistic of frontiers b and c)."""
    z = (x - f[1]) / f[2]
    return -np.expm1(-np.exp(-z))

def evaluate(method, alpha):
    det = fa = 0
    for s in names:
        d = data[s]; t = {b: thr(fit(method, d['val'][b]), alpha / 3) for b in B}
        det += int(np.any([d['att'][b] > t[b] for b in B], axis=0).sum())
        fa += int(np.any([d['nor'][b] > t[b] for b in B], axis=0).sum())
    return det, fa

ALPHAS = sorted(set(np.round(np.logspace(-7, -0.6, 60), 12)))
print('\n== 2. label-free fits, same rule (alpha/3 per branch, one window): best development recall at a false-alarm budget')
curves = {}
for method in ('gumbel_moments', 'gumbel_mle', 'gev_mle', 'normal', 'exp_tail', 'val_max'):
    pts = [evaluate(method, a) + (a,) for a in (ALPHAS if method != 'val_max' else [0.5])]
    curves[method] = pts
    row = []
    for budget in (0.004, 0.006, 0.008, 0.01, 0.02):
        ok = [p for p in pts if p[1] <= budget * NN]
        row.append(f'{100*budget:.1f}%: ' + (f'{100*max(ok)[0]/NA:.1f}% ({max(ok)[0]}, FA {max(ok)[1]})' if ok else 'none'))
    extra = f' | single point recall {100*pts[0][0]/NA:.1f}% FA {100*pts[0][1]/NN:.2f}%' if method == 'val_max' else ''
    print(f'  {method:15s} ' + ' | '.join(row) + extra)
d0, f0 = evaluate('gumbel_moments', 0.0005)
print(f'  registered point (gumbel_moments, alpha 0.0005): {100*d0/NA:.2f}% ({d0}), FA {100*f0/NN:.2f}% ({f0})')

def frontier(options, budget):
    """options[s] = list of (fa, det) achievable in scenario s; maximise total det with total fa <= budget (exact DP)."""
    best = np.full(budget + 1, -1); best[0] = 0
    for opts in options:
        new = np.full(budget + 1, -1)
        for f, dd in opts:
            if f > budget: continue
            shifted = np.full(budget + 1, -1); shifted[f:] = np.where(best[:budget + 1 - f] >= 0, best[:budget + 1 - f] + dd, -1)
            new = np.maximum(new, shifted)
        best = new
    return int(best.max())
def roc(att, nor):
    """(fa, det) for every useful threshold on one scenario's recording scores."""
    out = []
    for f in range(len(nor) + 1):
        t = np.sort(nor)[::-1][f] if f < len(nor) else NEG
        out.append((f, int((att > t).sum())))
    return out

print('\n== 1. oracle frontiers with attack labels (development; recall at a false-alarm budget)')
comb = {}
for s in names:
    d = data[s]; fs = {b: fit('gumbel_moments', d['val'][b]) for b in B}
    comb[s] = (np.min([tail(fs[b], d['att'][b]) for b in B], axis=0), np.min([tail(fs[b], d['nor'][b]) for b in B], axis=0))
for budget in (0.004, 0.006, 0.008, 0.01, 0.02):
    K = int(budget * NN)
    a = frontier([roc(data[s]['att']['T'], data[s]['nor']['T']) for s in names], K)
    b = frontier([roc(-comb[s][0], -comb[s][1]) for s in names], K)
    levels = sorted(set(np.concatenate([comb[s][1] for s in names]).tolist() + [0.0]))
    c = max(((sum(int((comb[s][0] < q).sum()) for s in names), sum(int((comb[s][1] < q).sum()) for s in names)) for q in levels + [1e-300]),
            key=lambda p: (p[1] <= K, p[0]))
    c = c[0] if c[1] <= K else None
    g = [p for p in curves['gumbel_moments'] if p[1] <= K]
    print(f'  FA <= {100*budget:.1f}% ({K}): a token alone, per-scenario {100*a/NA:.1f}% ({a}) | b three branches, per-scenario level {100*b/NA:.1f}% ({b}) | '
          f'c one level for all {100*c/NA:.1f}% ({c}) | label-free Gumbel rule {100*max(g)[0]/NA:.1f}% ({max(g)[0]})')

print('\n== 3a. calibration on validation itself, leave one recording out (pure normal, no test shift)')
for a in (0.05, 0.01, 0.003, 0.001):
    for b in B:
        obs = n = 0
        for s in names:
            v = data[s]['val'][b]
            for j in range(len(v)):
                rest = np.delete(v, j); obs += int(v[j] > thr(fit('gumbel_moments', rest), a)); n += 1
        print(f'  branch {b:8s} level {a:<6g}: expected {a*n:6.2f} of {n}, observed {obs}')
print('\n== 3b. calibration on the development normals (test shift included), fused rule')
for a in (0.05, 0.01, 0.005, 0.002, 0.001, 0.0005, 0.0002):
    det, fa = evaluate('gumbel_moments', a)
    print(f'  alpha {a:<7g}: designed FA <= {100*a:.3f}%, observed {100*fa/NN:.2f}% ({fa}); recall {100*det/NA:.1f}%')
print('\n== 3c. GEV shape xi of the validation maxima (xi = 0 is Gumbel; >0 heavier tail, <0 bounded)')
for b in B:
    xs = []
    for s in names:
        c, loc, sc = stats.genextreme.fit(data[s]['val'][b]); xs.append(-c)
    xs = np.array(xs)
    print(f'  {b:8s} median {np.median(xs):+.2f}, range {xs.min():+.2f} to {xs.max():+.2f}, scenarios with xi > 0.3: {int((xs > 0.3).sum())}/15, xi < -0.3: {int((xs < -0.3).sum())}/15')

print('\n== 3d. which branch raises the development false alarms and detections at the registered point (alpha 0.0005)')
cnt = defaultdict(int); dets = defaultdict(int)
for s in names:
    d = data[s]; t = {b: thr(fit('gumbel_moments', d['val'][b]), 0.0005 / 3) for b in B}
    over = {b: d['nor'][b] > t[b] for b in B}; hit = {b: d['att'][b] > t[b] for b in B}
    for j in range(len(d['nor']['T'])):
        who = tuple(b for b in B if over[b][j])
        if who: cnt[who] += 1
    for j in range(len(d['att']['T'])):
        who = tuple(b for b in B if hit[b][j])
        if who: dets[who] += 1
print('  false-alarm recordings by firing branches:', dict(cnt))
print('  detected attack recordings by firing branches:', dict(dets))
