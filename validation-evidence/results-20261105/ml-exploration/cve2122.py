"""CVE-2012-2122, development attacks only: when does the token model fire, relative to the exploit and the recording?"""
import json, math, sys, io, zipfile
import numpy as np
sys.path.insert(0, '/home/dat/eBPF-project/scripts/analysis')
import lidds_ml_tokens as tk
import gzip
doc = json.load(gzip.open('/home/dat/eBPF-project/validation-evidence/results-20261101/lidds-v4/lidds-evaluation-v2-alarms.json.gz', 'rt'))
recs = doc['scenarios']['CVE-2012-2122']['alarms']
z = np.load('/var/tmp/lid-ds-2021/ml-tokens/CVE-2012-2122.npz'); meta = json.load(open('/var/tmp/lid-ds-2021/ml-tokens/CVE-2012-2122.json')); ix = {c: i for i, c in enumerate(meta['columns'])}
mx = [z[k][:, ix['top10']].max() for k in z.files if k.startswith('val/') and len(z[k])]
beta = max(np.std(mx) * math.sqrt(6) / math.pi, 1e-6); t = np.mean(mx) - .5772 * beta - beta * math.log(-math.log(1 - .0005 / 3))
print('threshold', round(t, 2), 'validation max', round(max(mx), 2))
outer = zipfile.ZipFile('/var/tmp/lid-ds-2021/CVE-2012-2122.zip')
members = {m.rsplit('/', 1)[-1][:-4]: m for m in outer.namelist() if m.endswith('.zip') and not m.startswith('__MACOSX')}
rows = []
for n, r in recs.items():
    if r['split'] == 'test-normal' or r['subset'] != 'development' or n not in z.files: continue
    a = z[n]; ex = r['exploit']; c = a[a[:, 0] > ex]
    fire = c[c[:, ix['top10']] > t]
    rows.append((float(fire[0, 0] - ex) if len(fire) else None, float(a[-1, 0] - ex), n, len(fire), float(c[:, ix['top10']].max()) if len(c) else 0))
rows.sort(key=lambda x: (x[0] is None, x[0]))
lat = [x[0] for x in rows if x[0] is not None]
print('dev attacks', len(rows), 'latency quantiles', np.round(np.percentile(lat, [10, 50, 75, 90, 100]), 1), 'recording seconds after exploit, median', round(float(np.median([x[1] for x in rows])), 1))
for x in rows[:2] + rows[-5:]:
    print('  first firing', x[0], 'recording lasts after exploit', round(x[1], 1), x[2], 'firing windows', x[3], 'max', round(x[4], 1))
late = [x for x in rows if x[0] is not None][-2:]
for lat_, _, n, _, _ in late:
    i = zipfile.ZipFile(io.BytesIO(outer.read(members[n])))
    m = json.loads(i.read(next(k for k in i.namelist() if k.endswith('.json'))))
    print(n, 'exploit entries', len(m['time']['exploit']), 'name', m.get('exploit_name'), 'recording_time', m.get('recording_time'), 'first exploit', m['time']['exploit'][0], 'container roles', [c['role'] for c in m['container']])
    lines = i.read(next(k for k in i.namelist() if k.endswith('.sc'))).decode(errors='replace').splitlines()
    ex = recs[n]['exploit']; target = ex + lat_
    tok = {}
    from collections import Counter
    near = Counter(); before = Counter()
    for l in lines:
        p = l.split(' ', 7)
        if len(p) < 7 or p[6] != '<': continue
        ts = int(p[0]) / 1e9
        tk_ = tk.token(p[5], p[7] if len(p) > 7 else '')
        if target - .5 <= ts <= target: near[tk_] += 1
        elif ts < target - .5: before[tk_] += 1
    print('   tokens in the firing window never seen earlier in this recording:', [k for k in near if k not in before][:15], '| window size', sum(near.values()))
