#!/usr/bin/env python3
"""Hourly count of matched-worker issues (cadence gaps, loader errors) per node; JSON receipt."""
import argparse, collections, glob, json, time
p = argparse.ArgumentParser(description=__doc__)
p.add_argument('--workers-root', required=True); p.add_argument('--output', required=True)
a = p.parse_args(); out = {}
for node_dir in sorted(glob.glob(a.workers_root + '/*/')):
    per = collections.Counter(); reasons = collections.Counter()
    for path in sorted(glob.glob(node_dir + 'segments/s*/issues.jsonl')):
        for line in open(path):
            d = json.loads(line)
            if d.get('event') == 'resolver_metadata': continue
            per[time.strftime('%Y-%m-%d %H:00 UTC+7', time.gmtime(d['at'] + 7 * 3600))] += 1; reasons[d.get('reason', '?')[:60]] += 1
    out[node_dir.rstrip('/').split('/')[-1]] = dict(hourly=dict(sorted(per.items())), reasons=dict(reasons))
json.dump(dict(schema='matched-worker-issues-v1', workers_root=a.workers_root, nodes=out, computed_at_unix=time.time()),
          open(a.output, 'w'), indent=2)
print(json.dumps({n: v['reasons'] for n, v in out.items()}))
