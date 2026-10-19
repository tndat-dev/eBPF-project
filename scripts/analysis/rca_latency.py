#!/usr/bin/env python3
"""Split RCA preview->case latency: preview_emitted_at -> subscriber saw the decision (cases.created)
-> case written (case JSON created_at); JSON receipt."""
import argparse, glob, json, sqlite3, statistics, time
p = argparse.ArgumentParser(description=__doc__)
p.add_argument('--copy-dir', required=True); p.add_argument('--output', required=True)
a = p.parse_args()
db = sqlite3.connect(f"file:{a.copy_dir}/context.sqlite3?mode=ro", uri=True)
seen = dict(db.execute('select id, created from cases'))
see, build, total = [], [], []
for path in glob.glob(a.copy_dir + '/cases/*.json'):
    t = json.load(open(path)); trig = next(n['trigger'] for n in t['nodes'] if n['kind'] == 'signal')
    if t['case_id'] not in seen or trig.get('preview_emitted_at') is None: continue
    e = float(trig['preview_emitted_at']); s = seen[t['case_id']]
    see.append(s - e); build.append(t['created_at'] - s); total.append(t['created_at'] - e)
q = lambda v: dict(p50=statistics.median(v), p95=sorted(v)[max(0, int(.95 * len(v)) - 1)], n=len(v)) if v else None
r = dict(schema='rca-latency-split-v1', copy_dir=a.copy_dir, preview_to_subscriber_seen=q(see),
         seen_to_case_written=q(build), preview_to_case=q(total), computed_at_unix=time.time())
json.dump(r, open(a.output, 'w'), indent=2); print(json.dumps(r))
