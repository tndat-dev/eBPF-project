"""Before lidds-ml-v2, DEVELOPMENT only: branch curves and greedy sets from raw scores (official matrices never read).
    python3 ml_branches.py DIR=PREFIX[:col,col] ... """
import gzip, json, math, os, sys, glob
from collections import defaultdict
import numpy as np
ROOT = '/home/tndat/Downloads/eBPF-project/'
sys.path.insert(0, ROOT + 'scripts/analysis')
import lidds_v3_combine as v3
al = json.load(gzip.open(ROOT + 'validation-evidence/results-20261101/lidds-v4/lidds-evaluation-v2-alarms.json.gz', 'rt'))['scenarios']
LOGIT = {'tree_plain', 'tree_fix', 'g1_plain', 'g1_fix', 'g3_plain', 'g3_fix', 'g4_plain', 'g4_fix'}
def tf(b, x):
    x = np.asarray(x, float)
    if b.split('.')[-1] in LOGIT:
        c = np.clip(x, 1e-4, 1 - 1e-4); return np.log(c / (1 - c))
    if b.split('.')[-1] in ('g2_mass', 'g1d_mass', 'g4d_mass', 'unseen_grams', 'unseen_tokens'):
        return np.log1p(x)
    return x
SRC = []
for a in sys.argv[1:]:
    d, spec = a.split('=', 1); prefix, _, cols = spec.partition(':')
    SRC.append((d.rstrip('/') + '/', prefix, cols.split(',')))
data = defaultdict(lambda: dict(val=defaultdict(list), att=defaultdict(dict), nor=defaultdict(dict), n_att=0, n_nor=0, att_names=[], nor_names=[]))
for d, prefix, cols in SRC:
    for f in sorted(glob.glob(d + '*.json')):
        s = os.path.basename(f)[:-5]; meta = json.load(open(f)); ix = {c: i for i, c in enumerate(meta['columns'])}
        z = np.load(d + s + '.npz'); keys = set(z.files); dd = data[s]
        if s == 'CB-DS':
            att = [n for n, r in meta['recordings'].items() if r['split'] != 'test-normal']; nor = [n for n, r in meta['recordings'].items() if r['split'] == 'test-normal']
            ex = {n: meta['recordings'][n]['exploit'] for n in att}
        else:
            recs = al[s]['alarms']; nor = sorted(v3.normal_dev(s, [n for n, r in recs.items() if r['split'] == 'test-normal']))
            att = [n for n, r in recs.items() if r['split'] != 'test-normal' and r['subset'] == 'development']; ex = {n: recs[n]['exploit'] for n in att}
        dd['att_names'], dd['nor_names'] = att, nor
        for c in cols:
            b = f'{prefix}.{c}'
            for k in sorted(keys):
                if k.startswith('val/') and len(z[k]):
                    dd['val'][b].append(tf(c, z[k][:, ix[c]]).max())
            for n in att:
                a = z[n] if n in keys else np.empty((0, len(ix)))
                a = a[a[:, 0] > ex[n]] if len(a) else a
                dd['att'][n][b] = (a[:, 0] - ex[n], tf(c, a[:, ix[c]])) if len(a) else (np.empty(0), np.empty(0))
            for n in nor:
                a = z[n] if n in keys else np.empty((0, len(ix)))
                dd['nor'][n][b] = tf(c, a[:, ix[c]]) if len(a) else np.empty(0)
BR = [f'{p}.{c}' for _, p, cols in SRC for c in cols]
LID = [s for s in data if s != 'CB-DS']
NA, NN = sum(len(data[s]['att_names']) for s in LID), sum(len(data[s]['nor_names']) for s in LID)
print('scenarios', len(LID), 'dev attacks', NA, 'dev normals', NN, 'branches', len(BR))
def fit(s, b):
    m = np.asarray(data[s]['val'][b]); beta = max(np.std(m) * math.sqrt(6) / math.pi, 1e-6) if len(m) else 1e-6
    return (np.mean(m) - .5772 * beta if len(m) else 0.0), beta
FITS = {(s, b): fit(s, b) for s in data for b in BR}
def thr(s, b, a):
    loc, beta = FITS[s, b]; return loc - beta * math.log(-math.log(1 - a))
ALPHAS = [0.3, 0.2, 0.15, 0.1, 0.07, 0.05, 0.03, 0.02, 0.015, 0.01, 0.007, 0.005, 0.003, 0.002, 0.0015, 0.001, 0.0007, 0.0005, 0.0003, 0.0002, 0.0001, 0.00005, 0.00002, 0.00001]
def ev(bs, a, scens=LID):
    det = fa = 0; lat = []; per = {}
    for s in scens:
        d = data[s]; t = {b: thr(s, b, a / len(bs)) for b in bs}; dd = ff = 0
        for n in d['att_names']:
            first = None
            for b in bs:
                tt, v = d['att'][n].get(b, (np.empty(0), np.empty(0)))
                if len(v):
                    w = v > t[b]
                    if w.any():
                        x = tt[np.argmax(w)]; first = x if first is None else min(first, x)
            if first is not None: dd += 1; lat.append(first)
        for n in d['nor_names']:
            if any(len(d['nor'][n].get(b, ())) and (d['nor'][n][b] > t[b]).any() for b in bs): ff += 1
        det += dd; fa += ff; per[s] = (dd, len(d['att_names']), ff, len(d['nor_names']))
    return det, fa, float(np.percentile(lat, 95)) if lat else float('nan'), per
def best(bs, lim, p95=None):
    b = None
    for a in ALPHAS:
        r = ev(bs, a)
        if r[1] / NN <= lim and (p95 is None or r[2] <= p95) and (b is None or r[0] > b[1][0]):
            b = (a, r)
    return b
print('\n== single branch: best recall at FA<=0.8% | at FA<=2%')
for b in BR:
    x, y = best([b], .008), best([b], .02)
    fmt = lambda v: f"{100*v[1][0]/NA:5.1f}%/{100*v[1][1]/NN:.2f}% p95 {v[1][2]:.2f}" if v else '  none'
    print(f'  {b:22s} {fmt(x)} | {fmt(y)}')
RULE = {b for b in BR if b.split('.')[-1].startswith('unseen')}
for lim in (0.006, 0.008, 0.02):
    print(f'\n== greedy on learned branches, FA<={100*lim:g}%, p95<=3 s')
    cur, bestr = [], -1
    while True:
        cand = [(best(cur + [b], lim, 3.0), b) for b in BR if b not in cur and b not in RULE]
        cand = [c for c in cand if c[0]]
        if not cand: break
        (a, r), b = max(cand, key=lambda c: c[0][1][0])
        if r[0] <= bestr: break
        bestr = r[0]; cur.append(b)
        print(f"  +{b:22s} alpha {a:<8g} recall {100*r[0]/NA:.1f}% ({r[0]}) FA {100*r[1]/NN:.2f}% ({r[1]}) p95 {r[2]:.2f}s precision {100*r[0]/(r[0]+r[1]):.1f}%")
    if cur:
        a, r = best(cur, lim, 3.0)
        print('  per scenario:', ' '.join(f"{s[:14]}:{v[0]}/{v[1]},{v[2]}" for s, v in sorted(r[3].items())))
        if 'CB-DS' in data:
            cb = ev(cur, a, ['CB-DS']); print(f"  CB-DS: {cb[0]}/{len(data['CB-DS']['att_names'])}, normals {cb[1]}/{len(data['CB-DS']['nor_names'])}")

print('\n== candidate sets (Bonferroni on recording-level alpha): recall/FA/p95')
for bs in (['T.top10'], ['T.top10', 'A.support'], ['T.top10', 'A.g3_fix'], ['T.top10', 'A.support', 'A.g3_fix'], ['T.top10', 'A.tree_plain', 'A.support'] if 'A.tree_plain' in BR else ['T.top10']):
    print(' ', '+'.join(bs))
    print('    ' + ' '.join(f"{a:g}:{100*ev(bs,a)[0]/NA:.1f}/{100*ev(bs,a)[1]/NN:.2f}/{ev(bs,a)[2]:.2f}" for a in (0.01, 0.005, 0.003, 0.002, 0.001, 0.0005)))
    if 'CB-DS' in data:
        print('    CB-DS at 0.002:', ev(bs, 0.002, ['CB-DS'])[:2])
