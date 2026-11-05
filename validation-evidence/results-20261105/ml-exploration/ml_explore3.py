"""Before lidds-ml-v2, DEVELOPMENT only: threshold methods on raw branch scores (one window; official never opened)."""
import json, math, sys, glob, os
from collections import defaultdict
import numpy as np
from scipy import stats
sys.path.insert(0, '/home/dat/eBPF-project/scripts/analysis')
import lidds_v3_combine as v3
O = '/var/tmp/lid-ds-2021/ml-scores/'
al = json.load(open('/var/tmp/lid-ds-2021/v3-window/lidds-evaluation-v2-alarms.json'))['scenarios']
BR = ['g2_top10', 'g3_fix', 'support']
PROB = {'g3_fix'}
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
    maxima = defaultdict(list); windows = defaultdict(list); lens = []
    for k in keys:
        if k.startswith('val/') and len(z[k]):
            a = z[k]; lens.append(len(a))
            for b in BR:
                v = tf(b, a[:, ix[b]]); maxima[b].append(v.max()); windows[b].append(v)
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
            att.append((a[:, 0] - ex if len(a) else np.empty(0), {b: tf(b, a[:, ix[b]]) if len(a) else np.empty(0) for b in BR}))
        else:
            nor.append({b: tf(b, a[:, ix[b]]) if len(a) else np.empty(0) for b in BR})
    data[s] = dict(att=att, nor=nor, max={b: np.asarray(maxima[b]) for b in BR}, win={b: np.concatenate(windows[b]) for b in BR}, wpr=float(np.median(lens)))
def t_gumbel(s, b, a):
    m = data[s]['max'][b]; beta = max(m.std() * math.sqrt(6) / math.pi, 1e-6); return m.mean() - .5772 * beta - beta * math.log(-math.log(1 - a))
def t_robust(s, b, a):
    m = data[s]['max'][b]; q1, q2, q3 = np.percentile(m, [25, 50, 75]); beta = max((q3 - q1) / 1.5725, 1e-6); loc = q2 + beta * math.log(math.log(2)); return loc - beta * math.log(-math.log(1 - a))
def t_gev(s, b, a):
    m = data[s]['max'][b]
    try:
        c, loc, sc = stats.genextreme.fit(m); return float(stats.genextreme.isf(a, c, loc, sc))
    except Exception:
        return t_gumbel(s, b, a)
def t_gpd(s, b, a):
    d = data[s]; w = d['win'][b]; u = np.percentile(w, 95); ex = w[w > u] - u
    pw = 1 - (1 - a) ** (1 / d['wpr'])          # per-window probability for a recording-level a
    if len(ex) < 20 or ex.std() == 0: return w.max()
    c, _, sc = stats.genpareto.fit(ex, floc=0)
    return float(u + stats.genpareto.isf(pw / 0.05, c, 0, sc)) if pw < .05 else u
def t_qmax(s, b, a):
    m = np.sort(data[s]['max'][b]); return float(np.quantile(m, min(1 - a, 1.0))) if a > 1 / len(m) else float(m[-1] + (a ** -1) * 0)
METH = dict(gumbel_moments=t_gumbel, gumbel_robust=t_robust, gev_mle=t_gev, gpd_windows=t_gpd)
ALPHAS = [0.3, 0.2, 0.1, 0.05, 0.03, 0.02, 0.01, 0.007, 0.005, 0.003, 0.002, 0.001, 0.0005, 0.0002, 0.0001, 0.00001]
cache = {}
def thr(m, s, b, a):
    k = (m, s, b, a)
    if k not in cache: cache[k] = METH[m](s, b, a)
    return cache[k]
def ev(m, a, bs=BR):
    det = fa = na = nn = 0; lat = []; per = {}
    for s, d in data.items():
        if s == 'CB-DS': continue
        t = {b: thr(m, s, b, a / len(bs)) for b in bs}; dd = ff = 0
        for times, sc in d['att']:
            na += 1
            if len(times):
                fire = np.any([sc[b] > t[b] for b in bs], axis=0)
                if fire.any(): det += 1; dd += 1; lat.append(times[np.argmax(fire)])
        for sc in d['nor']:
            nn += 1
            if any(len(sc[b]) and (sc[b] > t[b]).any() for b in bs): fa += 1; ff += 1
        per[s] = (dd, len(d['att']), ff, len(d['nor']))
    return det / na, fa / nn, (float(np.percentile(lat, 95)) if lat else None), per, det, fa
print('method: alpha:recall/FA')
for m in METH:
    print(m, ' '.join(f"{a:g}:{100*ev(m,a)[0]:.1f}/{100*ev(m,a)[1]:.2f}" for a in ALPHAS))
for limit in (0.008, 0.02):
    print(f'\n== best at FA <= {100*limit:g} %')
    for m in METH:
        ok = [(ev(m, a), a) for a in ALPHAS]; ok = [x for x in ok if x[0][1] <= limit]
        if not ok: print(m, 'none'); continue
        r, a = max(ok, key=lambda x: x[0][0])
        print(f"{m:16s} alpha {a:g} recall {100*r[0]:.1f}% ({r[4]}) FA {100*r[1]:.2f}% ({r[5]}) p95 {r[2]:.2f}s  " + ' '.join(f"{s[:14]}:{v[0]}/{v[1]}" for s, v in sorted(r[3].items()) if v[0] < v[1]))
print('\n== per-scenario validation maxima of g2_top10 (min/median/p90/max) and dev attack/normal maxima medians')
for s, d in sorted(data.items()):
    m = d['max']['g2_top10']
    am = [sc['g2_top10'].max() for t, sc in d['att'] if len(t)]; nm = [sc['g2_top10'].max() for sc in d['nor'] if len(sc['g2_top10'])]
    print(f"{s:22s} val {m.min():.1f}/{np.median(m):.1f}/{np.percentile(m,90):.1f}/{m.max():.1f}  attack median {np.median(am):.1f} p10 {np.percentile(am,10):.1f}  normal median {np.median(nm):.1f} p99 {np.percentile(nm,99):.1f}")
