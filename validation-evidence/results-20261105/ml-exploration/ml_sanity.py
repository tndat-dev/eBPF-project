"""Before lidds-ml-v2, DEVELOPMENT only: is the token model's development result an artefact?"""
import gzip, json, math, os, sys, glob
from collections import defaultdict, Counter
import numpy as np
ROOT = '/home/tndat/Downloads/eBPF-project/'
sys.path.insert(0, ROOT + 'scripts/analysis')
import lidds_v3_combine as v3
al = json.load(gzip.open(ROOT + 'validation-evidence/results-20261101/lidds-v4/lidds-evaluation-v2-alarms.json.gz', 'rt'))['scenarios']
D = sys.argv[1].rstrip('/') + '/'; A = float(sys.argv[2])
print(f'token model top10, alpha {A}')
print(f"{'scenario':22s} {'K':>3s} {'thr':>6s} | normal FA | attack: fired before exploit, fired after, detected but pre-fired too | median s to first post-exploit firing | firing windows after exploit with no unseen gram / no unseen token (of detected recordings: all their firing windows)")
TOT = Counter(); margins = defaultdict(list); first_kind = Counter(); pre_all = []
for f in sorted(glob.glob(D + '*.json')):
    s = os.path.basename(f)[:-5]
    if s == 'CB-DS': continue
    meta = json.load(open(f)); ix = {c: i for i, c in enumerate(meta['columns'])}; z = np.load(D + s + '.npz'); keys = set(z.files)
    m = np.array([z[k][:, ix['top10']].max() for k in sorted(keys) if k.startswith('val/') and len(z[k])])
    beta = max(m.std() * math.sqrt(6) / math.pi, 1e-6); t = m.mean() - .5772 * beta - beta * math.log(-math.log(1 - A))
    recs = al[s]['alarms']; dn = v3.normal_dev(s, [n for n, r in recs.items() if r['split'] == 'test-normal'])
    fa = sum(1 for n in dn if n in keys and len(z[n]) and (z[n][:, ix['top10']] > t).any())
    natt = pre = post = both = 0; delays = []; nog = noT = 0
    for n, r in recs.items():
        if r['split'] == 'test-normal' or r['subset'] != 'development': continue
        natt += 1
        if n not in keys or not len(z[n]): continue
        a = z[n]; ex = r['exploit']; b, c = a[a[:, 0] <= ex], a[a[:, 0] > ex]
        f_pre = len(b) and (b[:, ix['top10']] > t).any(); fire = c[:, ix['top10']] > t if len(c) else np.zeros(0, bool)
        pre += bool(f_pre)
        if fire.any():
            post += 1; both += bool(f_pre); delays.append(c[np.argmax(fire), 0] - ex)
            w = c[fire]
            ng = (w[:, ix['unseen_grams']] == 0).any(); nt = (w[:, ix['unseen_tokens']] == 0).any()
            nog += bool(ng); noT += bool(nt)
            first = c[np.argmax(fire)]
            first_kind['first firing window has an unseen token' if first[ix['unseen_tokens']] > 0 else ('first firing window has an unseen gram only' if first[ix['unseen_grams']] > 0 else 'first firing window has neither')] += 1
    print(f"{s:22s} {len(m):3d} {t:6.1f} | {fa:3d}/{len(dn):3d} {100*fa/len(dn):5.2f}% | pre {pre:3d}/{natt:3d} {100*pre/natt:5.1f}%  post {post:3d}  both {both:3d} | {np.median(delays) if delays else 0:5.2f}s | any non-novel firing window: no unseen gram {nog:3d}, no unseen token {noT:3d}")
    TOT['fa'] += fa; TOT['n'] += len(dn); TOT['natt'] += natt; TOT['pre'] += pre; TOT['post'] += post; TOT['both'] += both; TOT['nog'] += nog; TOT['noT'] += noT
print('\npooled', dict(TOT), f"normal FA {100*TOT['fa']/TOT['n']:.2f}%  pre-exploit firing in attack recordings {100*TOT['pre']/TOT['natt']:.2f}%")
print('first firing window of detected recordings:', dict(first_kind))
