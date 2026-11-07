"""DEVELOPMENT only: lidds-ml-v2 with the token branch rebuilt on each alphabet of lidds_ml_token_alphabets.py.
Reports each alphabet alone (alpha 0.002) and with tree + support at the selected alpha 0.0005, the registered rule.
Gate: the alphabet ``full`` must reproduce the development result of lidds-ml-v2 (95.96 %, 522/544; 0.56 %, 19/3,403)."""
import glob, json, os, sys
from collections import Counter
import numpy as np
from pathlib import Path as _P
ROOT = str(_P(__file__).resolve().parents[3]) + '/'   # repository root, on any machine
sys.path.insert(0, ROOT + 'scripts/analysis')
import lidds_ml_v2 as m
S, A = sys.argv[1], sys.argv[2]
doc = m.load(ROOT + 'validation-evidence/results-20261101/lidds-v4/lidds-evaluation-v2-alarms.json.gz')
cb = m.load(ROOT + 'validation-evidence/results-20261101/lidds-v4/lidds-evaluation-v2-cbds-alarms.json.gz')
done = sorted(os.path.basename(f)[:-5] for f in glob.glob(A + '/*.json'))
print('scenarios done', len(done), done)
meta0 = json.load(open(f'{A}/{done[0]}.json')); names = meta0['columns'][1:]
def fit_of(z, j):
    return m.gumbel([z[k][:, j].max() for k in z.files if k.startswith('val/') and len(z[k])])
def run(alphabet, alpha, others, source, scenarios):
    det = fa = att = nor = 0; lat = []; per = {}
    for s in scenarios:
        z = np.load(f'{A}/{s}.npz'); j = names.index(alphabet) + 1
        sc = m.Scenario(s, dict(scores=S + '/allwin', tokens=S + '/tokens')); parts = len(others) + 1
        thr = m.threshold(fit_of(z, j), alpha / parts)
        recs = source['scenarios'][s]['alarms']; want = m.part_filter(s, recs, 'development') if source is doc else (lambda n, r: True)
        d0 = f0 = a0 = n0 = 0
        for n, r in recs.items():
            if not want(n, r): continue
            fire = z[n][z[n][:, j] > thr, 0].tolist() if n in z.files and len(z[n]) else []
            fire += sc.firings(others, alpha * len(others) / parts, n) if others else []
            ex = r['exploit']
            if ex is None:
                n0 += 1; f0 += bool(fire)
            else:
                a0 += 1; after = [t for t in fire if t > ex]
                if after: d0 += 1; lat.append(min(after) - ex)
        det += d0; fa += f0; att += a0; nor += n0; per[s] = (d0, a0, f0, n0)
    return det, att, fa, nor, float(np.percentile(lat, 95)) if lat else float('nan'), per
ds = [s for s in done if s != 'CB-DS']
# gate (when the run has it): the column `full` (or `base` of the variants) must equal the registered token branch on every development and validation recording
gate_col = 'full' if 'full' in names else 'base' if 'base' in names else None
for s in (ds if gate_col else []):
    z = np.load(f'{A}/{s}.npz'); j = names.index(gate_col) + 1
    zt, col, it, et, _ = m.Scenario(s, dict(scores=S + '/allwin', tokens=S + '/tokens')).branch['T']
    worst = 0.0; n = 0
    for k in z.files:
        if k not in zt.files or not len(zt[k]): continue
        ref = {float(w): float(x) for w, x in zip(zt[k][:, et], zt[k][:, it])}
        for w, x in zip(z[k][:, 0], z[k][:, j]):
            if float(w) in ref: worst = max(worst, abs(ref[float(w)] - float(x))); n += 1
    print(f'gate {s}: {n} windows compared, largest difference {worst:.2e}')
print('alphabet | alone a=.002: recall, FA, p95 | with tree+support a=.0005: recall, FA, p95 | CB-DS with tree+support det/att FA/n')
for a in names:
    x = run(a, .002, (), doc, ds); y = run(a, .0005, ('tree', 'support'), doc, ds)
    c = run(a, .0005, ('tree', 'support'), cb, ['CB-DS']) if 'CB-DS' in done else None
    print(f"{a:13s} | {x[0]}/{x[1]} {100*x[0]/x[1]:.2f}% {100*x[2]/x[3]:.2f}% {x[4]:.2f}s | {y[0]}/{y[1]} {100*y[0]/y[1]:.2f}% {y[2]}/{y[3]} {100*y[2]/y[3]:.2f}% {y[4]:.2f}s | " + (f"{c[0]}/{c[1]} {c[2]}/{c[3]}" if c else '-'))
    print('   per scenario with tree+support:', {s: f'{v[0]}/{v[1]},{v[2]}' for s, v in y[5].items() if v[0] < v[1] or v[2] > 2})
