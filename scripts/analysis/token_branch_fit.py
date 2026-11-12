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
from sentinel_pulse.detector.token_model import CountTokenLM, has_execve, strip  # noqa: E402
from lidds_ml_v2 import gumbel, threshold  # noqa: E402

TOP_DROP = 0.01


def trimmed_gumbel(maxima, drop=TOP_DROP):
    """Moment Gumbel without the top share of the maxima, at least one (rule R4, as lidds_ml_v4.trimmed_gumbel)."""
    x = np.sort(np.asarray(maxima, float))
    return gumbel(x[:max(2, len(x) - max(1, int(round(len(x) * drop))))])


def sha(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


EXCLUDE_BEFORE, EXCLUDE_AFTER = 5.0, 25.0


def trial_spans(campaign):
    """{(pod_uid, container): [(start - 5 s, start + 25 s), ...]} of every campaign interval: a trial's process runs
    15 s from its start; the margins cover the launch through kubectl exec and its exit."""
    out = {}
    for line in (campaign / 'INTERVALS.jsonl').read_text().splitlines():
        if line:
            row = json.loads(line)
            start = float(row['start_at'])
            out.setdefault((row['pod_uid'], row['container_name']), []).append((start - EXCLUDE_BEFORE, start + EXCLUDE_AFTER))
    return out


def split(sources, work):
    """One pass over each run: the lines of each workload into their own file (name: sha256 prefix). sources:
    [(run root, lo, hi, excluded spans per container or None)]; a window is kept when lo <= window_end < hi and it
    lies in no excluded span of its container."""
    handles, names = {}, {}
    for root, lo, hi, excluded in sources:
        for path in sorted(root.glob('workers/*/segments/*/tokens.jsonl*')):
            opener = gzip.open if path.suffix == '.gz' else open
            with opener(path, 'rt') as handle:
                for line in handle:
                    w = json.loads(line)
                    end = w['window_end']
                    if not lo <= end < hi:
                        continue
                    if excluded and any(a <= end < b for a, b in excluded.get((w['pod_uid'], w['container_name']), ())):
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
    key, path, train, validation, alpha, block, minimum, output, folds, seconds, share, *dump = job
    lm, maxima, windows = crossfit_one(path, train[0], validation[1], block, folds, seconds)
    blocks = np.asarray(list(maxima.values()), float)
    if dump and dump[0]:                                   # ml-final-study-v1 part C: the held-out block maxima
        target = Path(dump[0]) / (hashlib.sha256(key.encode()).hexdigest()[:16] + '.maxima.json')
        target.write_text(json.dumps(dict(workload=key, blocks=[[*cell, v] for cell, v in sorted(maxima.items())])))
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


def merge_models(paths):
    """The model of all workloads together: the sum of their counts (protocol lidds-ml-v5)."""
    pool = CountTokenLM()
    for path in paths:
        lm = CountTokenLM.load(Path(path))
        for level, contexts in enumerate(lm.count):
            for context, nexts in contexts.items():
                pool.count[level][context].update(nexts)
        pool.names.update(lm.names)
        for name, tokens in lm.given.items():
            pool.given[name].update(tokens)
        pool.total += lm.total
    return pool.finalize()


POOL_HOLDS = (0.0, 1.0, 2.0)     # the hold and phase seconds of protocol lidds-ml-v5


def fit_pool_threshold(job):
    """Block maxima of the pool score outside each exec hold, moment Gumbel without their top 1 %:
    (key, {hold: fit or None}, {hold: blocks}). One pass serves every hold of the protocol's candidates."""
    key, path, pool_path, start, end, block = job
    pool = CountTokenLM.load(Path(pool_path))
    maxima, last_exec = {h: {} for h in POOL_HOLDS}, {}
    with open(path) as handle:
        for line in handle:
            w = json.loads(line)
            if not start <= w['window_end'] < end:
                continue
            container = (w['pod_uid'], w['container_name'])
            if has_execve(w['grams']):
                last_exec[container] = w['window_end']
            since = w['window_end'] - last_exec.get(container, -math.inf)
            score = pool.window_score(w['grams'])
            cell = container + (math.floor(w['window_end'] / block),)
            for hold in POOL_HOLDS:
                if not hold or since > hold:
                    maxima[hold][cell] = max(maxima[hold].get(cell, 0.0), score)
    fits = {h: (trimmed_gumbel(list(m.values())) if len(m) >= 3 else None) for h, m in maxima.items()}
    return key, fits, {h: len(m) for h, m in maxima.items()}


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
    ap.add_argument('--extra-run', type=Path, help='a finished live run whose normal is learnt too (needs --folds): its '
                    'windows inside --extra-span, outside every campaign interval of their container (-5 s, +25 s)')
    ap.add_argument('--extra-span', type=float, nargs=2, metavar=('START', 'END'))
    ap.add_argument('--pool-level', type=float, help='lidds-ml-v5 gate: level of the pool threshold (needs --folds)')
    ap.add_argument('--exec-hold', type=float, default=1.0, help='lidds-ml-v5 gate: seconds held after an execve')
    ap.add_argument('--dump-maxima', type=Path, help='ml-final-study-v1 part C: write the held-out block maxima per workload here')
    a = ap.parse_args()
    if not a.train[0] < a.train[1] <= a.validation[0] < a.validation[1]:
        raise SystemExit('spans must be ordered: training before validation')
    a.output.mkdir(parents=True, exist_ok=False)
    work = a.work or a.output / 'split'
    work.mkdir(parents=True, exist_ok=True)
    if bool(a.extra_run) != bool(a.extra_span) or (a.extra_run and not a.folds):
        raise SystemExit('--extra-run needs --extra-span and --folds')
    if a.extra_run and not a.validation[1] <= a.extra_span[0] < a.extra_span[1]:
        raise SystemExit('the extra span must follow the capture')
    sources = [(a.run_root, a.train[0], a.validation[1], None)]
    if a.extra_run:
        sources.append((a.extra_run, a.extra_span[0], a.extra_span[1], trial_spans(a.extra_run / 'pulse-development-matrix')))
        a.validation = [a.validation[0], a.extra_span[1]]      # the cross-fit span runs to the end of the extra normal
    names = split(sources, work)
    jobs = [(k, str(v), a.train, a.validation, a.alpha, a.block, a.minimum_blocks, str(a.output)) for k, v in sorted(names.items())]
    worker = fit_one
    if a.folds:
        if a.dump_maxima:
            a.dump_maxima.mkdir(parents=True, exist_ok=True)
        jobs = [j + (a.folds, a.fold_seconds, a.share, str(a.dump_maxima) if a.dump_maxima else None) for j in jobs]
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
    if a.pool_level:
        pool_path = a.output / 'pool.lm.json.gz'
        merge_models([entry['lm'] for entry in spec.values()]).save(pool_path)
        if a.exec_hold not in POOL_HOLDS:
            raise SystemExit(f'--exec-hold must be one of {POOL_HOLDS}')
        pool_jobs = [(k, str(names[k]), str(pool_path), a.train[0], a.validation[1], a.block) for k in sorted(spec)]
        if a.jobs > 1:
            from multiprocessing import Pool
            with Pool(a.jobs) as pool:
                fits = pool.map(fit_pool_threshold, pool_jobs, chunksize=1)
        else:
            fits = [fit_pool_threshold(j) for j in pool_jobs]
        for key, by_hold, blocks in fits:
            spec[key]['pool_threshold'] = threshold(by_hold[a.exec_hold], a.pool_level)
            report[key].update(pool_gumbel={f'{h:g}': fit for h, fit in by_hold.items()},
                               pool_blocks={f'{h:g}': n for h, n in blocks.items()}, pool_threshold=spec[key]['pool_threshold'])
        (a.output / 'GATE.json').write_text(json.dumps(dict(pool=dict(lm=str(pool_path), lm_sha256=sha(pool_path)),
                                                            exec_hold_seconds=a.exec_hold, level=a.pool_level), indent=1) + '\n')
    (a.output / 'MODELS.json').write_text(json.dumps(spec, indent=1, sort_keys=True) + '\n')
    (a.output / 'FIT.json').write_text(json.dumps(dict(schema='pulse-token-branch-fit-v1', run_root=str(a.run_root),
                                                       extra_run=str(a.extra_run) if a.extra_run else None,
                                                       extra_span=a.extra_span,
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
