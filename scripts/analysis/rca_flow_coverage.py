#!/usr/bin/env python3
"""Share of RCA cases (modified after --since) that contain sampled flow events, per workload; JSON receipt."""
import argparse, collections, glob, json, os, time
p = argparse.ArgumentParser(description=__doc__)
p.add_argument('--cases', required=True); p.add_argument('--since', type=float, required=True); p.add_argument('--output', required=True)
a = p.parse_args(); total = collections.Counter(); by = collections.defaultdict(lambda: [0, 0])
for path in glob.glob(a.cases + '/*.json'):
    if os.path.getmtime(path) < a.since: continue
    t = json.load(open(path)); trig = next(n['trigger'] for n in t['nodes'] if n['kind'] == 'signal')
    f = bool(t.get('matched_flow_events')); total['cases'] += 1; total['with_flow'] += f
    by[trig['workload_key']][0] += 1; by[trig['workload_key']][1] += f
json.dump(dict(schema='rca-flow-coverage-v1', cases_dir=a.cases, since_unix=a.since, totals=dict(total),
               by_workload={w: dict(cases=n, with_flow=f) for w, (n, f) in sorted(by.items())}, computed_at_unix=time.time()),
          open(a.output, 'w'), indent=2)
print(dict(total))
