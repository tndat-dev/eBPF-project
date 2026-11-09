#!/usr/bin/env python3
"""Fit the lidds-ml-v3 token branch on a normal capture of the cluster (worker tokens.jsonl), for the worker's
``tokens.models``.

Per workload: the token model (sentinel_pulse/detector/token_model.py, = lidds_ml_tokens.TokenLM) learns every window
of the training span; the threshold is the moment-Gumbel of lidds-ml-v3 fitted not on recording maxima (the cluster
has no recordings) but on the maxima of fixed time blocks of each container over the validation span (design report
section 3), at alpha / 3 (one of three branches). A workload with fewer than --minimum-blocks validation blocks gets no
model. The spans and alpha come from the run's registered protocol; this script only applies them.

With --folds K the branch is lidds-ml-v4's (sentinel_pulse/protocol/pulse-live-v3-v1-amendment-2.json): the final model
learns training + validation, the two spans together are cut into contiguous chunks of --fold-seconds dealt to K folds
in turn, each chunk is scored by the model of the other folds, and the threshold is the moment-Gumbel of those held-out
block maxima without their top 1 % (rule R4 of lidds_ml_v4.py), at alpha x --share.

    python3 token_branch_fit.py --run-root ROOT --train START END --validation START END --alpha 0.0002 \
        --block 60 --output DIR [--jobs 8 --work /var/tmp/...] [--folds 5 --fold-seconds 1800 --share 0.9]
"""
import argparse
from collections import Counter
import gzip
import hashlib
import json
import math
from pathlib import Path
import sys

import numpy as np

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
sys.path.insert(0, str(Path(__file__).resolve().parent))
from sentinel_pulse.detector.token_model import CountTokenLM, strip  # noqa: E402
from lidds_ml_v2 import gumbel, threshold  # noqa: E402

TOP_DROP = 0.01


def trimmed_gumbel(maxima, drop=TOP_DROP):
    """Moment Gumbel without the top share of the maxima, at least one (rule R4, as lidds_ml_v4.trimmed_gumbel)."""
    x = np.sort(np.asarray(maxima, float))
    return gumbel(x[:max(2, len(x) - max(1, int(round(len(x) * drop))))])


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


def fold_of(window_end, start, seconds, folds):
    """Contiguous chunks of the capture dealt to the folds in turn: a held-out window is far from most learnt windows."""
    return int((window_end - start) // seconds) % folds


def crossfit_one(path, start, end, block, folds, seconds):
    """(final model on every window, held-out block maxima, windows learnt): one parse to count, one to score each fold."""
    grams = [Counter() for _ in range(folds)]
    parts = [open(f'{path}.f{k}', 'w') for k in range(folds)]
    windows = 0
    with open(path) as handle:
        for line in handle:
            w = json.loads(line)
            if start <= w['window_end'] < end:
                k = fold_of(w['window_end'], start, seconds, folds)
                for *gram, c in w['grams']:
                    grams[k][strip(gram)] += int(c)
                parts[k].write(line)
                windows += 1
    for part in parts:
        part.close()
    maxima = {}
    for k in range(folds):
        lm = CountTokenLM()
        for j in range(folds):
            if j != k:
                for gram, c in grams[j].items():
                    lm.learn(gram, c)
        lm.finalize()
        with open(f'{path}.f{k}') as handle:
            for line in handle:
                w = json.loads(line)
                cell = (w['pod_uid'], w['container_name'], math.floor(w['window_end'] / block))
                maxima[cell] = max(maxima.get(cell, 0.0), lm.window_score(w['grams']))
        del lm
        Path(f'{path}.f{k}').unlink()
    final = CountTokenLM()
    for part in grams:
        for gram, c in part.items():
            final.learn(gram, c)
    return final.finalize(), maxima, windows


def fit_crossfit(job):
    """lidds-ml-v4 on the cluster; (key, report row, spec entry or None)."""
    key, path, train, validation, alpha, block, minimum, output, folds, seconds, share = job
    lm, maxima, windows = crossfit_one(path, train[0], validation[1], block, folds, seconds)
    blocks = np.asarray(list(maxima.values()), float)
    row = dict(training_windows=windows, validation_blocks=len(blocks), distinct_contexts=sum(len(level) for level in lm.count))
    if windows == 0 or len(blocks) < minimum:
        return key, row, None
    fit = trimmed_gumbel(blocks)
    thr = threshold(fit, alpha * share)
    model = Path(output) / (hashlib.sha256(key.encode()).hexdigest()[:16] + '.lm.json.gz')
    lm.save(model)
    row.update(gumbel=fit, threshold=thr, validation_block_max=float(blocks.max()),
               validation_blocks_above=int((blocks > thr).sum()))
    return key, row, dict(lm=str(model), lm_sha256=sha(model), threshold=thr)


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
    ap.add_argument('--folds', type=int, default=0, help='cross-fit folds (lidds-ml-v4); 0 = training / validation split')
    ap.add_argument('--fold-seconds', type=float, default=1800.0)
    ap.add_argument('--share', type=float, default=1 / 3, help='share of alpha for this branch')
    a = ap.parse_args()
    if not a.train[0] < a.train[1] <= a.validation[0] < a.validation[1]:
        raise SystemExit('spans must be ordered: training before validation')
    a.output.mkdir(parents=True, exist_ok=False)
    work = a.work or a.output / 'split'
    work.mkdir(parents=True, exist_ok=True)
    names = split(a.run_root, work, a.train[0], a.validation[1])
    jobs = [(k, str(v), a.train, a.validation, a.alpha, a.block, a.minimum_blocks, str(a.output)) for k, v in sorted(names.items())]
    worker = fit_one
    if a.folds:
        jobs = [j + (a.folds, a.fold_seconds, a.share) for j in jobs]
        worker = fit_crossfit
    if a.jobs > 1:
        from multiprocessing import Pool
        with Pool(a.jobs) as pool:
            results = pool.map(worker, jobs, chunksize=1)
    else:
        results = [worker(j) for j in jobs]
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
                                                       branch_alpha=a.alpha * (a.share if a.folds else 1 / 3), block=a.block,
                                                       folds=a.folds, fold_seconds=a.fold_seconds if a.folds else None,
                                                       workloads=report),
                                                  indent=1, sort_keys=True) + '\n')
    for f in work.glob('*.jsonl'):
        f.unlink()
    work.rmdir() if not any(work.iterdir()) else None


if __name__ == '__main__':
    main()
