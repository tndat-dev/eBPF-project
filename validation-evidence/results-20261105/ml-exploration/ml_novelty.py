"""Before lidds-ml-v2, DEVELOPMENT only: does the token model grade what it never saw, or is it a novelty rule?"""
import gzip, json, math, os, sys, glob
from collections import Counter, defaultdict
import numpy as np
ROOT = '/home/tndat/Downloads/eBPF-project/'
sys.path.insert(0, ROOT + 'scripts/analysis')
import lidds_v3_combine as v3
al = json.load(gzip.open(ROOT + 'validation-evidence/results-20261101/lidds-v4/lidds-evaluation-v2-alarms.json.gz', 'rt'))['scenarios']
D = sys.argv[1].rstrip('/') + '/'; A = 0.002
c = Counter(); rows = defaultdict(list); per = []
ALPHAS = [0.1, 0.05, 0.02, 0.01, 0.005, 0.003, 0.002, 0.001, 0.0005, 0.0002]
curves = defaultdict(lambda: defaultdict(lambda: [0, 0]))
def gum(m):
    b = max(np.std(m) * math.sqrt(6) / math.pi, 1e-6); return np.mean(m) - .5772 * b, b
def thr(f, a): return f[0] - f[1] * math.log(-math.log(1 - a))
oracle_det = oracle_fa = 0; ceiling = 0
for f in sorted(glob.glob(D + '*.json')):
    s = os.path.basename(f)[:-5]
    if s == 'CB-DS': continue
    meta = json.load(open(f)); ix = {k: i for i, k in enumerate(meta['columns'])}; z = np.load(D + s + '.npz'); keys = set(z.files)
    T, G, U = ix['top10'], ix['unseen_grams'], ix['unseen_tokens']
    vals = [z[k] for k in sorted(keys) if k.startswith('val/') and len(z[k])]
    fit = {n: gum([v[:, i].max() for v in vals]) for n, i in (('top10', T), ('grams', G), ('tokens', U))}
    fit['grams'] = gum([np.log1p(v[:, G]).max() for v in vals]); fit['tokens'] = gum([np.log1p(v[:, U]).max() for v in vals])
    val_with_new = sum(1 for v in vals if v[:, U].max() > 0); val_with_gram = sum(1 for v in vals if v[:, G].max() > 0)
    t = thr(fit['top10'], A)
    recs = al[s]['alarms']; dn = v3.normal_dev(s, [n for n, r in recs.items() if r['split'] == 'test-normal'])
    n_new = n_gram = fired_new = fired_gram = 0; w_gram = w_gram_fire = 0
    nmax, amax = [], []
    for n in dn:
        a = z[n] if n in keys else np.empty((0, len(ix)))
        if not len(a): continue
        g = a[:, G] > 0; u = a[:, U] > 0; fire = a[:, T] > t
        n_gram += g.any(); n_new += u.any(); fired_gram += bool(g.any() and fire.any()); fired_new += bool(u.any() and fire.any())
        w_gram += g.sum(); w_gram_fire += (g & fire).sum()
        nmax.append((a[:, T].max(), np.log1p(a[:, G]).max(), np.log1p(a[:, U]).max()))
    aw_gram = aw_fire = 0; miss = 0; nosig = 0
    for n, r in recs.items():
        if r['split'] == 'test-normal' or r['subset'] != 'development': continue
        a = z[n] if n in keys else np.empty((0, len(ix)))
        a = a[a[:, 0] > r['exploit']] if len(a) else a
        if not len(a): amax.append((-1e9, 0, 0)); continue
        g = a[:, G] > 0; fire = a[:, T] > t
        aw_gram += g.sum(); aw_fire += (g & fire).sum()
        amax.append((a[:, T].max(), np.log1p(a[:, G]).max(), np.log1p(a[:, U]).max()))
    nm, am = np.array(nmax), np.array(amax)
    k = int(0.008 * len(nm))                         # oracle: the threshold is chosen knowing the dev normals, k of them may exceed it
    ot = np.sort(nm[:, 0])[-k - 1] if len(nm) else 0
    oracle_det += int((am[:, 0] > ot).sum()); oracle_fa += int((nm[:, 0] > ot).sum())
    print(f"{s:22s} val recordings with unseen token {val_with_new:2d}/{len(vals)}, gram {val_with_gram:2d}/{len(vals)} | dev normals with unseen token {n_new:3d}, gram {n_gram:3d} of {len(dn)}; of these fired {fired_new:3d}, {fired_gram:3d} | normal windows with unseen gram: {int(w_gram):5d}, fired {int(w_gram_fire):3d}; attack: {int(aw_gram):5d}, fired {int(aw_fire):4d}")
    c['nn'] += len(dn); c['new'] += n_new; c['gram'] += n_gram; c['fnew'] += fired_new; c['fgram'] += fired_gram; c['wg'] += int(w_gram); c['wgf'] += int(w_gram_fire); c['awg'] += int(aw_gram); c['awf'] += int(aw_fire)
    c['degenerate'] += val_with_gram == 0
    rows['n'].append(nm); rows['a'].append(am)
    for name, col, fname in (('top10', 0, 'top10'), ('unseen grams', 1, 'grams'), ('unseen tokens', 2, 'tokens')):
        for al_ in ALPHAS:
            th = thr(fit[fname], al_)
            curves[name][al_][0] += int((am[:, col] > th).sum()); curves[name][al_][1] += int((nm[:, col] > th).sum())
    for al_ in ALPHAS:
        tg, tu = thr(fit['grams'], al_ / 2), thr(fit['tokens'], al_ / 2)
        curves['grams OR tokens (rules)'][al_][0] += int(((am[:, 1] > tg) | (am[:, 2] > tu)).sum()); curves['grams OR tokens (rules)'][al_][1] += int(((nm[:, 1] > tg) | (nm[:, 2] > tu)).sum())
print('\npooled', dict(c))
print(f"dev normal recordings holding an unseen token {100*c['new']/c['nn']:.1f}%, an unseen gram {100*c['gram']/c['nn']:.1f}%; of those the model fired on {100*c['fnew']/max(c['new'],1):.1f}%, {100*c['fgram']/max(c['gram'],1):.1f}%")
print(f"windows with an unseen gram: normal {c['wg']} fired {100*c['wgf']/max(c['wg'],1):.2f}%; attack after exploit {c['awg']} fired {100*c['awf']/max(c['awg'],1):.2f}%")
N, Am = np.concatenate(rows['n']), np.concatenate(rows['a'])
print(f'\noracle (per-scenario threshold set with attack-free dev normals, FA about 0.8 % each): recall {100*oracle_det/len(Am):.1f}% ({oracle_det}/{len(Am)}), FA {100*oracle_fa/len(N):.2f}%  ; information ceiling on development 533/544')
print('\nrecall / FA at each alpha:')
for name, d in curves.items():
    print(f'  {name:26s} ' + ' '.join(f"{a:g}:{100*d[a][0]/len(Am):.1f}/{100*d[a][1]/len(N):.2f}" for a in ALPHAS))
