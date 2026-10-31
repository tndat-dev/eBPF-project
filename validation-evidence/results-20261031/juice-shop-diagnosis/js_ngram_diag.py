"""Diagnostic (development data only): Juice-Shop per-window scores of the v2 signals."""
import json, sys, zipfile, io, collections
import numpy as np
sys.path.insert(0, '/home/dat/eBPF-project'); sys.path.insert(0, '/home/dat/eBPF-project/scripts/analysis')
from sentinel_pulse.lidds import convert, signals
dev = json.load(open(sys.argv[1])); out_path = sys.argv[2]
outer = zipfile.ZipFile('/var/tmp/lid-ds-2021/Juice-Shop.zip')
def members(split):
    for m in sorted(outer.namelist()):
        if m.endswith('.zip') and not m.startswith('__MACOSX') and '/'.join(m.split('/')[1:-1]).replace('/', '-') == split:
            yield m.rsplit('/', 1)[-1][:-4], m
def windows(m):
    blob = outer.read(m); _, lines = convert.recording(blob)
    z = zipfile.ZipFile(io.BytesIO(blob)); meta = json.loads(z.read(next(n for n in z.namelist() if n.endswith('.json'))))
    return signals.recording_signals(lines), meta
ref = signals.Reference()
for _, m in members('training'):
    ref.learn(windows(m)[0])
val = []
for _, m in members('validation'):
    val.extend(windows(m)[0].values())
for s in val: ref.widen(s)
limits = signals.thresholds(ref, val)
vs = np.array([signals.scores(ref, s)['ngram_new'] for s in val])
res = dict(limits=dict(limits), validation_ngram_new=dict(n=len(vs), q=[float(np.quantile(vs, q)) for q in (0.5, 0.9, 0.99, 0.999, 1)]),
           validation_top=sorted(vs.tolist())[-15:], attack=[], normal=[])
for name, m in members('test-normal_and_attack'):
    if name not in dev['attack']: continue
    w, meta = windows(m); ex = meta['time']['exploit'][0]['absolute']
    post = {e: signals.scores(ref, s) for e, s in w.items() if e >= ex}
    pre = {e: signals.scores(ref, s) for e, s in w.items() if e < ex}
    res['attack'].append(dict(name=name, exploit=meta.get('exploit_name'), post_max={k: max(v[k] for v in post.values()) for k in limits},
                              pre_max={k: max(v[k] for v in pre.values()) if pre else 0 for k in limits},
                              post_ngram_top=sorted((v['ngram_new'] for v in post.values()), reverse=True)[:5]))
for name, m in members('test-normal'):
    if name not in dev['normal']: continue
    w, _ = windows(m)
    sc = [signals.scores(ref, s) for s in w.values()]
    res['normal'].append(dict(name=name, max={k: max(v[k] for v in sc) for k in limits}))
json.dump(res, open(out_path, 'w'), indent=1)
print('done')
