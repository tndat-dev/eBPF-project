#!/usr/bin/env python3
"""Fit the lidds-ml-v3 token branch on a normal capture of the cluster (worker tokens.jsonl), for the worker's
``tokens.models``.

Per workload: the token model (sentinel_pulse/detector/token_model.py, = lidds_ml_tokens.TokenLM) learns every window
of the training span; the threshold is the moment-Gumbel of lidds-ml-v3 fitted not on recording maxima (the cluster
has no recordings) but on the maxima of fixed time blocks of each container over the validation span (design report
section 3), at alpha / 3 (one of three branches). A workload with fewer than --minimum-blocks validation blocks gets no
model. The spans and alpha come from the run's registered protocol; this script only applies them.

    python3 token_branch_fit.py --run-root ROOT --train START END --validation START END --alpha 0.0002 \
        --block 60 --output DIR
"""
import argparse
from collections import defaultdict
import gzip
import hashlib
import json
import math
from pathlib import Path
import sys

import numpy as np

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
sys.path.insert(0, str(Path(__file__).resolve().parent))
from sentinel_pulse.detector.token_model import CountTokenLM  # noqa: E402
from lidds_ml_v2 import gumbel, threshold  # noqa: E402


def token_windows(root):
    for path in sorted(root.glob('workers/*/segments/*/tokens.jsonl*')):
        opener = gzip.open if path.suffix == '.gz' else open
        with opener(path, 'rt') as handle:
            for line in handle:
                yield json.loads(line)


def sha(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument('--run-root', type=Path, required=True)
    ap.add_argument('--train', type=float, nargs=2, required=True)
    ap.add_argument('--validation', type=float, nargs=2, required=True)
    ap.add_argument('--alpha', type=float, required=True, help='system alpha; the token branch gets alpha / 3')
    ap.add_argument('--block', type=float, default=60.0)
    ap.add_argument('--minimum-blocks', type=int, default=30)
    ap.add_argument('--output', type=Path, required=True)
    a = ap.parse_args()
    if not a.train[0] < a.train[1] <= a.validation[0] < a.validation[1]:
        raise SystemExit('spans must be ordered: training before validation')
    a.output.mkdir(parents=True, exist_ok=False)
    models = defaultdict(CountTokenLM)
    trained = defaultdict(int)
    for w in token_windows(a.run_root):
        if a.train[0] <= w['window_end'] < a.train[1]:
            models[w['workload_key']].learn_window(w['grams'])
            trained[w['workload_key']] += 1
    for lm in models.values():
        lm.finalize()
    maxima = defaultdict(dict)                 # workload -> {(pod, container, block): max score}
    for w in token_windows(a.run_root):
        if a.validation[0] <= w['window_end'] < a.validation[1] and w['workload_key'] in models:
            key = (w['pod_uid'], w['container_name'], math.floor(w['window_end'] / a.block))
            s = models[w['workload_key']].window_score(w['grams'])
            got = maxima[w['workload_key']]
            got[key] = max(got.get(key, 0.0), s)
    spec, report = {}, {}
    for key, lm in sorted(models.items()):
        blocks = np.asarray(list(maxima[key].values()), float)
        row = dict(training_windows=trained[key], validation_blocks=len(blocks))
        if len(blocks) >= a.minimum_blocks:
            fit = gumbel(blocks)
            thr = threshold(fit, a.alpha / 3)
            path = a.output / (hashlib.sha256(key.encode()).hexdigest()[:16] + '.lm.json.gz')
            lm.save(path)
            spec[key] = dict(lm=str(path), lm_sha256=sha(path), threshold=thr)
            row.update(gumbel=fit, threshold=thr, validation_block_max=float(blocks.max()),
                       validation_blocks_above=int((blocks > thr).sum()))
        report[key] = row
        print(f"{key:55s} train {row['training_windows']:6d} blocks {row['validation_blocks']:5d} "
              f"thr {row.get('threshold', float('nan')):7.3f} above {row.get('validation_blocks_above', '-')}")
    (a.output / 'MODELS.json').write_text(json.dumps(spec, indent=1, sort_keys=True) + '\n')
    (a.output / 'FIT.json').write_text(json.dumps(dict(schema='pulse-token-branch-fit-v1', run_root=str(a.run_root),
                                                       train=a.train, validation=a.validation, alpha=a.alpha,
                                                       branch_alpha=a.alpha / 3, block=a.block, workloads=report),
                                                  indent=1, sort_keys=True) + '\n')


if __name__ == '__main__':
    main()
