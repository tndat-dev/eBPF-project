"""After lidds-ml-v2 official, DEVELOPMENT only: how much room is left? Official matrices are never read here."""
import gzip, json, math, sys, os, glob
from collections import Counter, defaultdict
import numpy as np
ROOT = '/home/tndat/Downloads/eBPF-project/'
sys.path.insert(0, ROOT + 'scripts/analysis')
import lidds_ml_v2 as m, lidds_v3_combine as v3
S = sys.argv[1]
doc = m.load(ROOT + 'validation-evidence/results-20261101/lidds-v4/lidds-evaluation-v2-alarms.json.gz')
names = sorted(doc['scenarios'])
scn = {s: m.Scenario(s, dict(scores=S + '/allwin', tokens=S + '/tokens')) for s in names}
def evaluate(weights, alpha):
    """weights: {branch: share of alpha}."""
    det = fa = 0; lat = []; miss = Counter(); fas = Counter()
    for s in names:
        recs = doc['scenarios'][s]['alarms']; want = m.part_filter(s, recs, 'development'); sc = scn[s]
        for n, r in recs.items():
            if not want(n, r): continue
            fire = []
            for b, w in weights.items():
                z, col, i, end, fit = sc.branch[b]
                if n in z.files and len(z[n]):
                    a = z[n]; fire += a[m.transform(col, a[:, i]) > m.threshold(fit, alpha * w), end].tolist()
            fire.sort(); ex = r['exploit']
            if ex is None:
                if fire: fa += 1; fas[s] += 1
            else:
                after = [t for t in fire if t > ex]
                if after: det += 1; lat.append(after[0] - ex)
                else: miss[s] += 1
    return det, fa, float(np.percentile(lat, 95)), miss, fas
NA, NN = 544, 3403
print('== residual misses of the selected configuration and of the token model alone')
for name, w, a in (('selected T+tree+support a=0.0005', dict(T=1/3, tree=1/3, support=1/3), .0005), ('token alone a=0.002', dict(T=1.0), .002)):
    d, f, p, miss, fas = evaluate(w, a)
    print(f'  {name}: {d}/{NA} {100*d/NA:.2f}%, FA {f}/{NN} {100*f/NN:.2f}%, p95 {p:.2f}; missed {dict(miss)}; false alarms {dict(fas)}')
print('\n== alpha shares: token gets most of the budget, the frequency branches stay')
for tw in (1/3, 0.6, 0.8, 0.9, 0.95):
    o = (1 - tw) / 2
    print(f'  T share {tw:.2f}: ' + ' '.join(f"{a:g}:{100*evaluate(dict(T=tw, tree=o, support=o), a)[0]/NA:.1f}/{100*evaluate(dict(T=tw, tree=o, support=o), a)[1]/NN:.2f}" for a in (.003, .002, .001, .0005)))
# threshold variance: refit on half the validation recordings, twice, to see what K buys
print('\n== sensitivity of the token threshold to validation size (development only)')
rng = np.random.default_rng(1)
for k in (15, 30, 45, 60):
    res = []
    for rep in range(10):
        d = f = 0
        for s in names:
            z, col, i, end, _ = scn[s].branch['T']
            val = [x for x in z.files if x.startswith('val/') and len(z[x])]
            pick = rng.choice(len(val), size=min(k, len(val)), replace=False)
            fit = m.gumbel([z[val[j]][:, i].max() for j in pick]); t = m.threshold(fit, .002)
            recs = doc['scenarios'][s]['alarms']; want = m.part_filter(s, recs, 'development')
            for n, r in recs.items():
                if not want(n, r) or n not in z.files or not len(z[n]): continue
                a = z[n]
                if r['exploit'] is None: f += bool((a[:, i] > t).any())
                else:
                    c = a[a[:, end] > r['exploit']]; d += bool(len(c) and (c[:, i] > t).any())
        res.append((d, f))
    r = np.array(res); print(f'  K={k:2d}: recall {100*r[:,0].mean()/NA:.1f}% (sd {100*r[:,0].std()/NA:.2f}), FA {100*r[:,1].mean()/NN:.2f}% (sd {100*r[:,1].std()/NN:.2f})')
# LSTM versus the n-gram model on the scenarios the LSTM has finished
T = S + '/teacher/'
print('\n== LSTM reference versus token n-gram on finished scenarios (each alone, same recordings, alpha 0.002 and 0.0005)')
tot = Counter()
for f in sorted(glob.glob(T + '*.json')):
    s = os.path.basename(f)[:-5]
    if s == 'CB-DS': continue
    meta = json.load(open(f)); z = np.load(T + s + '.npz'); i = meta['columns'].index('top10'); end = meta['columns'].index('window_end')
    fit = m.gumbel([z[k][:, i].max() for k in z.files if k.startswith('val/') and len(z[k])])
    z2, col, i2, end2, fit2 = scn[s].branch['T']
    recs = doc['scenarios'][s]['alarms']; want = m.part_filter(s, recs, 'development')
    line = []
    for a_ in (.002, .0005):
        c = Counter(); t1, t2 = m.threshold(fit, a_), m.threshold(fit2, a_)
        for n, r in recs.items():
            if not want(n, r): continue
            for tag, zz, ii, ee, tt in (('L', z, i, end, t1), ('N', z2, i2, end2, t2)):
                if n in zz.files and len(zz[n]):
                    a = zz[n]
                    if r['exploit'] is None: c[tag + 'fa'] += bool((a[:, ii] > tt).any())
                    else:
                        x = a[a[:, ee] > r['exploit']]; c[tag + 'det'] += bool(len(x) and (x[:, ii] > tt).any())
        line.append(f"a={a_:g} LSTM {c['Ldet']}/{c['Lfa']} n-gram {c['Ndet']}/{c['Nfa']}")
        if a_ == .002:
            for k_ in ('Ldet', 'Lfa', 'Ndet', 'Nfa'): tot[k_] += c[k_]
    print(f"  {s:22s} train {meta['report']['train_cpu_hours']:.1f} CPU-h, pairs {meta['report']['unique_pairs']}, stopped {meta['report']['stopped_by_time']} | " + ' | '.join(line))
print('  total at 0.002:', dict(tot))
