"""Before lidds-ml-v2, DEVELOPMENT only: why the best one-window configuration misses (official never opened)."""
import json, math, sys, gzip, glob, os
from collections import Counter, defaultdict
import numpy as np
sys.path.insert(0, '/home/dat/eBPF-project/scripts/analysis')
O = '/var/tmp/lid-ds-2021/ml-scores/'
al = json.load(open('/var/tmp/lid-ds-2021/v3-window/lidds-evaluation-v2-alarms.json'))['scenarios']
BR = ['g2_top10', 'g3_fix', 'support']; A = 0.002 / 3
def tf(b, x):
    x = np.asarray(x, float)
    if b == 'g3_fix':
        c = np.clip(x, 1e-4, 1 - 1e-4); return np.log(c / (1 - c))
    return x
print('scenario | dev attacks | missed | missed with a rule-branch alarm after the exploit (information exists) | of those: every such alarm outside G0-scored windows | missed with no scored window after exploit | windows after exploit per missed: all/scored (median) | seconds exploit->first scored (median)')
tot = Counter()
for s in sorted(al):
    meta = json.load(open(O + s + '.json')); ix = {c: i for i, c in enumerate(meta['columns'])}
    z = np.load(O + s + '.npz'); keys = set(z.files); t = {}
    for b in BR:
        m = [tf(b, z[k][:, ix[b]]).max() for k in keys if k.startswith('val/') and len(z[k])]
        beta = max(np.std(m) * math.sqrt(6) / math.pi, 1e-6); t[b] = np.mean(m) - .5772 * beta - beta * math.log(-math.log(1 - A))
    rows = defaultdict(list)
    with gzip.open(f'/var/tmp/lid-ds-2021/converted-v2/{s}/test-normal_and_attack.jsonl.gz', 'rt') as f:
        for line in f:
            r = json.loads(line); rows[r['lidds']['recording']].append((r['window_end'], bool(r.get('eligible_for_normal_review'))))
    n = miss = info = outside = noscore = 0; wall = []; wsc = []; delay = []
    for name, r in al[s]['alarms'].items():
        if r['split'] == 'test-normal' or r['subset'] != 'development': continue
        n += 1; ex = r['exploit']
        a = z[name] if name in keys else np.empty((0, len(ix)))
        a = a[a[:, 0] > ex] if len(a) else a
        if len(a) and any((tf(b, a[:, ix[b]]) > t[b]).any() for b in BR): continue
        miss += 1
        scored = {round(float(x) * 2) for x in a[:, 0]} if len(a) else set()
        rule = [w for b in ('path', 'bytes', 'ngram', 'errno', 'tripwire') for w in r['arms'].get(b, []) if w > ex]
        if rule:
            info += 1
            if not any(round(w * 2) in scored for w in rule): outside += 1
        if not len(a): noscore += 1
        after = [w for w, e in rows.get(name, []) if w > ex]
        wall.append(len(after)); wsc.append(len(a))
        if len(a): delay.append(a[0, 0] - ex)
    print(f"{s:22s} {n:3d} {miss:3d} {info:3d} {outside:3d} {noscore:3d}  {np.median(wall) if wall else 0:5.0f}/{np.median(wsc) if wsc else 0:<5.0f} {np.median(delay) if delay else 0:6.1f}")
    for k, v in (('n', n), ('miss', miss), ('info', info), ('outside', outside), ('noscore', noscore)): tot[k] += v
print('total', dict(tot))
