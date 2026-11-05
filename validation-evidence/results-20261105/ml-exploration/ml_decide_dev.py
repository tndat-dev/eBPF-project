"""Before lidds-ml-v2, DEVELOPMENT only (official matrices never opened): decision methods on raw branch scores."""
import gzip, json, math, os, sys, glob
from collections import defaultdict
import numpy as np
from scipy import optimize, stats
ROOT = '/home/tndat/Downloads/eBPF-project/'
sys.path.insert(0, ROOT + 'scripts/analysis')
import lidds_v3_combine as v3
O = sys.argv[1].rstrip('/') + '/'
al = json.load(gzip.open(ROOT + 'validation-evidence/results-20261101/lidds-v4/lidds-evaluation-v2-alarms.json.gz', 'rt'))['scenarios']
BR = ['g2_top10', 'g3_fix', 'support']
PROB = {'g3_fix'}
def tf(b, x):
    x = np.asarray(x, float)
    if b in PROB:
        c = np.clip(x, 1e-4, 1 - 1e-4); return np.log(c / (1 - c))
    return x
data = {}
for f in sorted(glob.glob(O + '*.json')):
    s = os.path.basename(f)[:-5]; meta = json.load(open(f)); ix = {c: i for i, c in enumerate(meta['columns'])}
    z = np.load(O + s + '.npz'); keys = set(z.files)
    mat = lambda a: np.column_stack([tf(b, a[:, ix[b]]) for b in BR]) if len(a) else np.empty((0, len(BR)))
    val = [mat(z[k]) for k in sorted(keys) if k.startswith('val/') and len(z[k])]
    if s == 'CB-DS':
        kinds = {n: ('att' if r['split'] != 'test-normal' else 'nor') for n, r in meta['recordings'].items()}
    else:
        recs = al[s]['alarms']; dn = v3.normal_dev(s, [n for n, r in recs.items() if r['split'] == 'test-normal'])
        kinds = {n: 'att' for n, r in recs.items() if r['split'] != 'test-normal' and r['subset'] == 'development'}
        kinds.update({n: 'nor' for n in dn})
        names_all = [n for n, r in recs.items() if r['split'] != 'test-normal' and r['subset'] == 'development']
        for n in meta['recordings']:
            if n not in recs: kinds[n] = 'att' if False else None      # present only in this run: not in the v2 split list
    att, nor = [], []
    for n, kind in kinds.items():
        if kind is None: continue
        a = z[n] if n in keys else np.empty((0, len(ix)))
        if kind == 'att':
            ex = meta['recordings'][n]['exploit'] if n in meta['recordings'] else None
            if ex is None: continue
            a = a[a[:, 0] > ex] if len(a) else a
            att.append((a[:, 0] - ex if len(a) else np.empty(0), mat(a)))
        else:
            nor.append(mat(a))
    data[s] = dict(val=val, att=att, nor=nor)
LID = [s for s in data if s != 'CB-DS']
print('scenarios', len(data), 'dev attacks', sum(len(data[s]['att']) for s in LID), 'dev normals', sum(len(data[s]['nor']) for s in LID))
# ------------------------------------------------------------------ exchangeability of normal maxima
print('\n== dev normal recordings above the validation maximum, per branch (expected n/(K+1) if exchangeable)')
totexp = 0; tot = [0, 0, 0]
for s in LID:
    d = data[s]; K = len(d['val']); line = []
    for i, b in enumerate(BR):
        mv = max(v[:, i].max() for v in d['val'])
        c = sum(1 for m in d['nor'] if len(m) and m[:, i].max() > mv); tot[i] += c; line.append(c)
    e = len(d['nor']) / (K + 1); totexp += e
    print(f'  {s:22s} K={K:3d} n={len(d["nor"]):3d} expected {e:4.1f}  ' + ' '.join(f'{b}={c}' for b, c in zip(BR, line)))
print(f'  total expected per branch {totexp:.0f}: ' + ' '.join(f'{b}={c}' for b, c in zip(BR, tot)))
# ------------------------------------------------------------------ threshold fits
def gumbel_moments(m):
    beta = max(np.std(m) * math.sqrt(6) / math.pi, 1e-6); return (0.0, np.mean(m) - .5772 * beta, beta)
def isf(fit, a):
    xi, loc, sc = fit
    y = -math.log(1 - a)
    return loc - sc * math.log(y) if abs(xi) < 1e-9 else loc + sc * (y ** (-xi) - 1) / xi
def censored_fit(m, xi, cens=2):
    m = np.sort(m); keep = m[:-cens] if len(m) > cens + 5 else m; c = keep[-1]; n_c = len(m) - len(keep)
    def nll(p):
        loc, ls = p; sc = math.exp(ls)
        ll = stats.genextreme.logpdf(keep, -xi, loc, sc).sum()
        if n_c: ll += n_c * stats.genextreme.logsf(c, -xi, loc, sc)
        return -ll if np.isfinite(ll) else 1e12
    beta = max(np.std(keep) * math.sqrt(6) / math.pi, 1e-3)
    r = optimize.minimize(nll, [np.mean(keep) - .5772 * beta, math.log(beta)], method='Nelder-Mead', options=dict(maxiter=400))
    return (xi, r.x[0], math.exp(r.x[1]))
def pooled_shape(i):
    shapes = []
    for s in LID:
        m = np.array([v[:, i].max() for v in data[s]['val']])
        if np.std(m) > 0:
            try: shapes.append(-stats.genextreme.fit(m)[0])
            except Exception: pass
    return float(np.clip(np.median(shapes), -0.2, 0.3))
SHAPE = [pooled_shape(i) for i in range(len(BR))]
print('\npooled GEV shape per branch', dict(zip(BR, [round(x, 3) for x in SHAPE])))
for s, d in data.items():
    d['fit_m'] = [gumbel_moments(np.array([v[:, i].max() for v in d['val']])) for i in range(len(BR))]
    d['fit_c'] = [censored_fit(np.array([v[:, i].max() for v in d['val']]), SHAPE[i]) for i in range(len(BR))]
ALPHAS = [0.2, 0.1, 0.05, 0.03, 0.02, 0.015, 0.01, 0.007, 0.005, 0.003, 0.002, 0.0015, 0.001, 0.0007, 0.0005, 0.0003, 0.0002, 0.0001, 0.00005]
def summarize(name, stat):
    """stat(s, M, a) -> boolean firing per window of matrix M at level a."""
    res = []
    for a in ALPHAS:
        det = fa = 0; lat = []; per = {}
        for s in LID:
            d = data[s]; dd = ff = 0
            for t, M in d['att']:
                if len(M):
                    fire = stat(s, M, a)
                    if fire.any(): dd += 1; lat.append(t[np.argmax(fire)])
            for M in d['nor']:
                if len(M) and stat(s, M, a).any(): ff += 1
            det += dd; fa += ff; per[s] = (dd, len(d['att']), ff, len(d['nor']))
        res.append((a, det, fa, float(np.percentile(lat, 95)) if lat else float('nan'), per))
    na, nn = sum(len(data[s]['att']) for s in LID), sum(len(data[s]['nor']) for s in LID)
    print(f'\n== {name}: alpha recall/FA/p95')
    print('   ' + ' '.join(f"{a:g}:{100*d/na:.1f}/{100*f/nn:.2f}/{l:.1f}" for a, d, f, l, _ in res))
    for lim in (0.006, 0.008, 0.02):
        ok = [r for r in res if r[2] / nn <= lim]
        if ok:
            a, d, f, l, per = max(ok, key=lambda r: r[1])
            weak = ' '.join(f"{k[:13]}:{v[0]}/{v[1]}" for k, v in sorted(per.items()) if v[0] < v[1])
            print(f"   FA<={100*lim:g}%: alpha {a:g} recall {100*d/na:.1f}% ({d}) FA {100*f/nn:.2f}% ({f}) p95 {l:.2f}s precision {100*d/(d+f):.1f}%  | {weak}")
    return res
def bonf(key):
    def st(s, M, a):
        fit = data[s][key]
        return np.any([M[:, i] > isf(fit[i], a / len(BR)) for i in range(len(BR))], axis=0)
    return st
summarize('Bonferroni, moment Gumbel (reference)', bonf('fit_m'))
summarize('Bonferroni, pooled shape + censor top 2', bonf('fit_c'))
# joint minP: per-branch recording-level tail p of each window, one statistic for the set, calibrated on validation recordings
def gev_logsf(fit, x):
    xi, loc, sc = fit
    if abs(xi) < 1e-9:
        y = np.exp(-(x - loc) / sc)
    else:
        y = np.clip(1 + xi * (x - loc) / sc, 1e-12, None) ** (-1 / xi)
    p = -np.expm1(-np.clip(y, 0, 700))
    return np.log(np.clip(p, 1e-300, 1))
def evidence(s, M, key):
    return -np.stack([gev_logsf(data[s][key][i], M[:, i]) for i in range(len(BR))], axis=1).max(axis=1) if False else -np.min(np.stack([gev_logsf(data[s][key][i], M[:, i]) for i in range(len(BR))], axis=1), axis=1)
for key, label in (('fit_m', 'moment'), ('fit_c', 'pooled')):
    for s, d in data.items():
        d['joint_' + label] = gumbel_moments(np.array([evidence(s, v, key).max() for v in d['val']]))
    def st(s, M, a, key=key, label=label):
        return evidence(s, M, key) > isf(data[s]['joint_' + label], a)
    summarize(f'joint minP ({label} marginals), calibrated on validation recordings', st)
# combined Shewhart-CUSUM on log evidence, recording-level threshold on max S
def cusum(e, k):
    out = np.empty(len(e)); S = 0.0
    for i, x in enumerate(e):
        S = max(0.0, S + x - k); out[i] = S
    return out
for k in (1.0, 2.0, 3.0):
    for s, d in data.items():
        d[f'cu{k}'] = gumbel_moments(np.array([cusum(evidence(s, v, 'fit_m'), k).max() for v in d['val']]))
    def st(s, M, a, k=k):
        return cusum(evidence(s, M, 'fit_m'), k) > isf(data[s][f'cu{k}'], a)
    summarize(f'Shewhart-CUSUM on log evidence, k={k}', st)
# score overlap at the weak scenarios
print('\n== missed attacks of the reference at FA about 0.76 % that lie within the normal band (branch max <= dev normal p99 for every branch)')
a = 0.002
for s in LID:
    d = data[s]; fit = d['fit_m']; miss = inb = 0
    p99 = [np.percentile([M[:, i].max() for M in d['nor'] if len(M)], 99) for i in range(len(BR))]
    for t, M in d['att']:
        fired = len(M) and np.any([M[:, i] > isf(fit[i], a / len(BR)) for i in range(len(BR))], axis=0).any()
        if not fired:
            miss += 1
            if len(M) == 0 or all(M[:, i].max() <= p99[i] for i in range(len(BR))): inb += 1
    if miss: print(f'  {s:22s} missed {miss:3d}, inside the normal band {inb:3d}')
