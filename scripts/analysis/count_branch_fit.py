#!/usr/bin/env python3
"""Thresholds of the lidds-ml-v3 count branches (tree, support) on a normal capture of the cluster, for the worker's
``v3_counts`` (sentinel_pulse/detector/v3_policy.py).

Per workload and branch: moment-Gumbel (lidds_ml_v2.gumbel) on the maxima of fixed time blocks of each container over
the validation span, threshold at alpha / 3 (one of three branches). Scores are the frozen candidate's, read from the
workers' decisions.jsonl (status candidate-raw-score-only); the tree score as its logit. The spans and alpha come from
the run's registered protocol.

    python3 count_branch_fit.py --run-root ROOT --validation START END --alpha 0.0002 --block 60 --output T.json
"""
import argparse
from collections import defaultdict
import gzip
import json
import math
from pathlib import Path
import sys

import numpy as np

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
sys.path.insert(0, str(Path(__file__).resolve().parent))
from sentinel_pulse.detector.v3_policy import tree_logit  # noqa: E402
from lidds_ml_v2 import gumbel, threshold  # noqa: E402


def decisions(root):
    for path in sorted(root.glob('workers/*/segments/*/decisions.jsonl*')):
        opener = gzip.open if path.suffix == '.gz' else open
        with opener(path, 'rt') as handle:
            for line in handle:
                d = json.loads(line)
                if d.get('status') == 'candidate-raw-score-only':
                    yield d


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument('--run-root', type=Path, required=True)
    ap.add_argument('--validation', type=float, nargs=2, required=True)
    ap.add_argument('--alpha', type=float, required=True)
    ap.add_argument('--block', type=float, default=60.0)
    ap.add_argument('--minimum-blocks', type=int, default=30)
    ap.add_argument('--output', type=Path, required=True)
    a = ap.parse_args()
    maxima = defaultdict(lambda: defaultdict(lambda: [-math.inf, -math.inf]))
    for d in decisions(a.run_root):
        if not a.validation[0] <= float(d['window_end']) < a.validation[1]:
            continue
        cell = maxima[d['workload_key']][(d['pod_uid'], d['container_name'], math.floor(float(d['window_end']) / a.block))]
        cell[0] = max(cell[0], tree_logit(d['tree_score']))
        cell[1] = max(cell[1], float(d['support_score']))
    out, report = {}, {}
    for key, blocks in sorted(maxima.items()):
        arr = np.asarray(list(blocks.values()), float)
        row = dict(validation_blocks=len(arr))
        if len(arr) >= a.minimum_blocks:
            fits = [gumbel(arr[:, i]) for i in (0, 1)]
            thr = [threshold(f, a.alpha / 3) for f in fits]
            out[key] = dict(tree=thr[0], support=thr[1])
            row.update(tree_gumbel=fits[0], support_gumbel=fits[1], tree=thr[0], support=thr[1],
                       blocks_above=[int((arr[:, i] > thr[i]).sum()) for i in (0, 1)])
        report[key] = row
        print(f"{key:55s} blocks {len(arr):5d} tree {row.get('tree', float('nan')):8.3f} support {row.get('support', float('nan')):8.3f}")
    a.output.write_text(json.dumps(dict(schema='pulse-v3-count-thresholds-v1', run_root=str(a.run_root),
                                        validation=a.validation, alpha=a.alpha, branch_alpha=a.alpha / 3, block=a.block,
                                        workloads=out, report=report), indent=1, sort_keys=True) + '\n')


if __name__ == '__main__':
    main()
