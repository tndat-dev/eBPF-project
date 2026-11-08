#!/usr/bin/env python3
"""Fit the lidds-ml-v3 token branch on a normal capture of the cluster (worker tokens.jsonl), for the worker's
``tokens.models``.

Per workload: the token model (sentinel_pulse/detector/token_model.py, = lidds_ml_tokens.TokenLM) learns every window
of the training span; the threshold is the moment-Gumbel of lidds-ml-v3 fitted not on recording maxima (the cluster
has no recordings) but on the maxima of fixed time blocks of each container over the validation span (design report
section 3), at alpha / 3 (one of three branches). A workload with fewer than --minimum-blocks validation blocks gets no
model. The spans and alpha come from the run's registered protocol; this script only applies them.

    python3 token_branch_fit.py --run-root ROOT --train START END --validation START END --alpha 0.0002 \
        --block 60 --output DIR [--jobs 8 --work /var/tmp/...]
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


def sha(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def split(root, work, lo, hi):
    """One pass over the run: the lines of each workload inside [lo, hi) into their own file (name: sha256 prefix)."""
    handles, names = {}, {}
    for path in sorted(root.glob('workers/*/segments/*/tokens.jsonl*')):
        opener = gzip.open if path.suffix == '.gz' else open
        with opener(path, 'rt') as handle:
            for line in handle:
                w = json.loads(line)
                if not lo <= w['window_end'] < hi:
                    continue
                key = w['workload_key']
                if key not in handles:
                    names[key] = work / (hashlib.sha256(key.encode()).hexdigest()[:16] + '.jsonl')
                    handles[key] = names[key].open('w')
                handles[key].write(line if line.endswith('\n') else line + '\n')
    for h in handles.values():
        h.close()
    return names


def fit_one(job):
    """Learn on the training span, score the validation span, fit the Gumbel; (key, report row, spec entry or None)."""
    key, path, train, validation, alpha, block, minimum, output = job
    lm, trained = CountTokenLM(), 0
    with open(path) as handle:
        for line in handle:
            w = json.loads(line)
            if train[0] <= w['window_end'] < train[1]:
                lm.learn_window(w['grams'])
                trained += 1
    lm.finalize()
    maxima = {}
    with open(path) as handle:
        for line in handle:
            w = json.loads(line)
            if validation[0] <= w['window_end'] < validation[1]:
                cell = (w['pod_uid'], w['container_name'], math.floor(w['window_end'] / block))
                maxima[cell] = max(maxima.get(cell, 0.0), lm.window_score(w['grams']))
    blocks = np.asarray(list(maxima.values()), float)
    row = dict(training_windows=trained, validation_blocks=len(blocks), distinct_contexts=sum(len(level) for level in lm.count))
    if trained == 0 or len(blocks) < minimum:
        return key, row, None
    fit = gumbel(blocks)
    thr = threshold(fit, alpha / 3)
    model = Path(output) / (hashlib.sha256(key.encode()).hexdigest()[:16] + '.lm.json.gz')
    lm.save(model)
    row.update(gumbel=fit, threshold=thr, validation_block_max=float(blocks.max()),
               validation_blocks_above=int((blocks > thr).sum()))
    return key, row, dict(lm=str(model), lm_sha256=sha(model), threshold=thr)


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument('--run-root', type=Path, required=True)
    ap.add_argument('--train', type=float, nargs=2, required=True)
    ap.add_argument('--validation', type=float, nargs=2, required=True)
    ap.add_argument('--alpha', type=float, required=True, help='system alpha; the token branch gets alpha / 3')
    ap.add_argument('--block', type=float, default=60.0)
    ap.add_argument('--minimum-blocks', type=int, default=30)
    ap.add_argument('--output', type=Path, required=True)
    ap.add_argument('--work', type=Path, help='scratch directory for the per-workload split (default OUTPUT/split)')
    ap.add_argument('--jobs', type=int, default=1, help='workloads fitted in parallel')
    a = ap.parse_args()
    if not a.train[0] < a.train[1] <= a.validation[0] < a.validation[1]:
        raise SystemExit('spans must be ordered: training before validation')
    a.output.mkdir(parents=True, exist_ok=False)
    work = a.work or a.output / 'split'
    work.mkdir(parents=True, exist_ok=True)
    names = split(a.run_root, work, a.train[0], a.validation[1])
    jobs = [(k, str(v), a.train, a.validation, a.alpha, a.block, a.minimum_blocks, str(a.output)) for k, v in sorted(names.items())]
    if a.jobs > 1:
        from multiprocessing import Pool
        with Pool(a.jobs) as pool:
            results = pool.map(fit_one, jobs, chunksize=1)
    else:
        results = [fit_one(j) for j in jobs]
    spec, report = {}, {}
    for key, row, entry in results:
        report[key] = row
        if entry:
            spec[key] = entry
        print(f"{key:55s} train {row['training_windows']:7d} blocks {row['validation_blocks']:5d} "
              f"thr {row.get('threshold', float('nan')):7.3f} above {row.get('validation_blocks_above', '-')}", flush=True)
    (a.output / 'MODELS.json').write_text(json.dumps(spec, indent=1, sort_keys=True) + '\n')
    (a.output / 'FIT.json').write_text(json.dumps(dict(schema='pulse-token-branch-fit-v1', run_root=str(a.run_root),
                                                       train=a.train, validation=a.validation, alpha=a.alpha,
                                                       branch_alpha=a.alpha / 3, block=a.block, workloads=report),
                                                  indent=1, sort_keys=True) + '\n')
    for f in work.glob('*.jsonl'):
        f.unlink()
    work.rmdir() if not any(work.iterdir()) else None


if __name__ == '__main__':
    main()
