#!/usr/bin/env python3
"""Installation check of the live rolling calibration (Pulse 5.31): do the live p-values equal an independent rebuild?

For every ``applied`` row of each worker's ``recalibration.jsonl`` (epoch, span [lo, hi)), the calibration is rebuilt
from the run's shared score-buffer hours with the offline pieces only: ``retention.read_buffer`` (eligible windows),
``rolling_recalibration.campaign_spans`` / ``masked`` for the campaign exclusion and ``Recalibrator`` for the p-values.
Then every decision row the worker wrote under that epoch is rescored and compared with what it recorded:
tree_p, support_p and joint_p must be equal (float equality, same arithmetic).

Also reported: whether the three workers swapped the same array sizes for the same hour, and the decision rows per
epoch. Usage: live_recalibration_check.py <run root> --output <json>
"""
import argparse
from collections import Counter, defaultdict
import glob
import gzip
import json
from pathlib import Path

import numpy as np

from sentinel_pulse.attack.rolling_recalibration import campaign_spans, masked
from sentinel_pulse.detector.recalibration import Recalibrator
from sentinel_pulse.pipeline.retention import ELIGIBLE, read_buffer


def rebuild(shared, span, intervals_root):
    data = read_buffer(sorted(str(p) for p in Path(shared).iterdir() if p.is_dir()), *span)
    spans = campaign_spans([Path(intervals_root)]) if intervals_root else []
    tree, support = {}, {}
    for w, a in data.items():
        keep = ((a['flags'] & ELIGIBLE) > 0) & ~masked(a['window_end'], spans)
        tree[w], support[w] = a['tree_score'][keep], a['support_score'][keep]
    return Recalibrator(tree, support, minimum_examples=0)


def decision_rows(worker_root):
    for path in sorted(glob.glob(f'{worker_root}/segments/*/decisions.jsonl*')):
        opener = gzip.open if path.endswith('.gz') else open
        with opener(path, 'rt') as f:
            for line in f:
                if '"calibration_epoch"' in line:
                    row = json.loads(line)
                    if row.get('calibration_epoch') and row.get('status') == 'candidate-raw-score-only':
                        yield row


def check(run_root):
    cfg = json.loads((Path(run_root) / 'CONFIG.json').read_text())
    rc = cfg['recalibration']
    intervals = Path(rc['exclude_intervals']).parent if rc.get('exclude_intervals') else None
    out, sizes = {}, defaultdict(dict)
    for worker in cfg['workers'].values():
        node, root = worker['node_name'], Path(worker['output'])
        applied = {}
        log = root / 'recalibration.jsonl'
        events = Counter()
        for line in (log.read_text().splitlines() if log.exists() else []):
            e = json.loads(line); events[e['event']] += 1
            if e['event'] == 'applied':
                applied[e['epoch']] = e; sizes[e['hour']][node] = e['swapped']
        cals = {}                             # rebuilt lazily, at most two epochs held (rows come in time order)
        def cal(ep):
            if ep not in cals:
                while len(cals) >= 2:
                    cals.pop(min(cals))
                cals[ep] = rebuild(rc['shared'], applied[ep]['span'], intervals)
            return cals[ep]
        n = equal = 0; per_epoch = Counter(); size_ok = True; first_diff = None
        for ep, e in applied.items():
            c = cal(ep)
            for w, (nt, ns) in e['swapped'].items():
                size_ok &= (len(c.tree.get(w, ())), len(c.support.get(w, ()))) == (nt, ns)
        cals.clear()
        for row in decision_rows(root):
            ep = row['calibration_epoch']; per_epoch[ep] += 1
            if ep not in applied or row['workload_key'] not in applied[ep]['swapped']:
                continue                      # workload kept the earlier arrays in that refresh
            got = cal(ep).rewrite(row)
            n += 1
            same = all(got[k] == row[k] for k in ('tree_p', 'support_p')) and got['joint_p'] == row['joint_p']
            equal += same
            if not same and first_diff is None:
                first_diff = dict(workload=row['workload_key'], window_end=row['window_end'], epoch=ep,
                                  live={k: row[k] for k in ('tree_p', 'support_p', 'joint_p')},
                                  rebuilt={k: got[k] for k in ('tree_p', 'support_p', 'joint_p')})
        out[node] = dict(events=dict(events), epochs=sorted(applied), rows_per_epoch=dict(per_epoch), compared=n,
                         equal=equal, agreement=(equal / n if n else None), sizes_match_rebuild=size_ok,
                         first_difference=first_diff)
    same_sizes = {h: len({json.dumps(v, sort_keys=True) for v in by.values()}) == 1 for h, by in sizes.items()}
    return dict(schema='live-recalibration-check-v1', run=cfg['run_id'], workers=out, same_sizes_on_every_worker=same_sizes)


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument('run_root'); ap.add_argument('--output', required=True)
    a = ap.parse_args()
    doc = check(a.run_root)
    Path(a.output).write_text(json.dumps(doc, indent=1, default=lambda x: x.item() if isinstance(x, np.generic) else str(x)))
    print(json.dumps({n: {k: v[k] for k in ('epochs', 'compared', 'agreement', 'sizes_match_rebuild')} for n, v in doc['workers'].items()}))


if __name__ == '__main__':
    main()
