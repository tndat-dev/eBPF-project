"""DEVELOPMENT only: small LSTM versus the token n-gram (same tokens, windows, top-10 score), each alone.
Gumbel thresholds as the protocol, then threshold-free: AUC of the recording score and recall at a per-scenario
oracle threshold with normal false alarms at most 1 %. Official matrices are never read here."""
import glob, json, os, sys
from collections import Counter
import numpy as np
ROOT = '/home/tndat/Downloads/eBPF-project/'
sys.path.insert(0, ROOT + 'scripts/analysis')
import lidds_ml_v2 as m
S = sys.argv[1]
doc = m.load(ROOT + 'validation-evidence/results-20261101/lidds-v4/lidds-evaluation-v2-alarms.json.gz')
T = S + '/teacher/'
def auc(a, n):
    a, n = np.asarray(a), np.asarray(n)
    return float(((a[:, None] > n[None]).sum() + .5 * (a[:, None] == n[None]).sum()) / (len(a) * len(n)))
tot = Counter(); print('scenario | train s, epochs, vocabulary, unique pairs | a=.0005 det/FA LSTM, n-gram | AUC LSTM, n-gram | oracle recall at FA<=1% LSTM, n-gram | attacks, normals')
for f in sorted(glob.glob(T + '*.json')):
    s = os.path.basename(f)[:-5]
    if s == 'CB-DS': continue
    meta = json.load(open(f)); z = np.load(T + s + '.npz'); i = meta['columns'].index('top10'); end = meta['columns'].index('window_end')
    fit = m.gumbel([z[k][:, i].max() for k in z.files if k.startswith('val/') and len(z[k])])
    sc = m.Scenario(s, dict(scores=S + '/allwin', tokens=S + '/tokens')); z2, col, i2, end2, fit2 = sc.branch['T']
    recs = doc['scenarios'][s]['alarms']; want = m.part_filter(s, recs, 'development')
    sc_a = dict(L=[], N=[]); sc_n = dict(L=[], N=[]); c = Counter()
    for n, r in recs.items():
        if not want(n, r): continue
        for tag, zz, ii, ee, tt in (('L', z, i, end, m.threshold(fit, .0005)), ('N', z2, i2, end2, m.threshold(fit2, .0005))):
            a = zz[n] if n in zz.files and len(zz[n]) else np.zeros((0, 8))
            if r['exploit'] is None:
                x = float(a[:, ii].max()) if len(a) else -1e9; sc_n[tag].append(x); c[tag + 'fa'] += x > tt
            else:
                b = a[a[:, ee] > r['exploit']] if len(a) else a
                x = float(b[:, ii].max()) if len(b) else -1e9; sc_a[tag].append(x); c[tag + 'det'] += x > tt
    o = {}
    for t in 'LN':
        thr = np.quantile(sc_n[t], .99); o[t] = int((np.asarray(sc_a[t]) > thr).sum())
    for k in ('Ldet', 'Lfa', 'Ndet', 'Nfa'): tot[k] += int(c[k])
    tot['Lo'] += o['L']; tot['No'] += o['N']; tot['att'] += len(sc_a['L']); tot['nor'] += len(sc_n['L'])
    rp = meta['report']
    print(f"{s:21s} | {rp['seconds']:4.0f} {rp['epochs']} {rp['vocabulary']:4d} {rp['unique_pairs']:7d} | {c['Ldet']:3d}/{c['Lfa']:2d} {c['Ndet']:3d}/{c['Nfa']:2d} | {auc(sc_a['L'], sc_n['L']):.3f} {auc(sc_a['N'], sc_n['N']):.3f} | {o['L']:3d} {o['N']:3d} | {len(sc_a['L'])} {len(sc_n['L'])}")
print('total', dict(tot))
