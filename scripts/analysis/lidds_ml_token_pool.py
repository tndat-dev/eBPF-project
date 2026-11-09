#!/usr/bin/env python3
"""Pool model of lidds-ml-v5 on LID-DS 2021 and CB-DS: the sum of the gram counts of every scenario's training and validation
recordings. Every recording is scored by it; <scenario>.npz holds, per recording (val/<name> for training and validation,
<name> for test), the columns window_end, pool, execve (1 when an event of the window is an execve). Tokens, grams and the
window score are those of lidds_ml_token_crossfit.py. The cluster's pool is token_branch_fit.py --pool-level.

    python3 lidds_ml_token_pool.py --scenario ARCHIVE_DIR NAME [--scenario ...] --work DIR --output DIR [--jobs 6]
"""
import argparse
from collections import Counter
import json
from multiprocessing import Pool
from pathlib import Path
import pickle
import sys
import time

import numpy as np

sys.path.insert(0, str(Path(__file__).resolve().parent))
import lidds_ml_token_crossfit as xf  # noqa: E402

al, tk, v2 = xf.al, xf.tk, xf.v2
POOL = None


def has_execve(grams):
    return any(tk.base_name(g[-1]) == 'execve' for g in grams)


def count_one(job):
    archive, name, work = job
    path = Path(work) / f'{name}.counts.pkl'
    if not path.exists():
        counts = Counter()
        for _, _, blob in v2.split_recordings(archive, {'training', 'validation'}):
            for grams in xf.windows(blob).values():
                counts.update(grams)
        tmp = path.with_suffix('.tmp')
        tmp.write_bytes(pickle.dumps(counts, protocol=pickle.HIGHEST_PROTOCOL))
        tmp.rename(path)
    return str(path)


def matrix(lm, blob):
    per = xf.windows(blob)
    scores = al.score_windows(lm, per)
    return np.asarray([[w, scores[w], float(has_execve(per[w]))] for w in sorted(scores)], float).reshape(-1, 3)


def score_one(job):
    archive, name, output = job
    target = Path(output) / f'{name}.npz'
    if target.exists():
        return name
    out = {}
    for split, rec, blob in v2.split_recordings(archive, {'training', 'validation'}):
        out[f'val/{rec}'] = matrix(POOL, blob)
    for split, rec, blob in v2.split_recordings(archive, {'test-normal', 'test-normal_and_attack'}):
        out[rec] = matrix(POOL, blob)
    np.savez_compressed(target, **out)
    target.with_suffix('.json').write_text(json.dumps(dict(scenario=name, columns=['window_end', 'pool', 'execve'], recordings=len(out))))
    print(f'done {name} {time.strftime("%FT%T", time.gmtime())}', flush=True)
    return name


def main():
    global POOL
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument('--scenario', nargs=2, action='append', required=True, metavar=('DIR', 'NAME'))
    ap.add_argument('--work', type=Path, required=True)
    ap.add_argument('--output', type=Path, required=True)
    ap.add_argument('--jobs', type=int, default=6)
    a = ap.parse_args()
    a.work.mkdir(parents=True, exist_ok=True)
    a.output.mkdir(parents=True, exist_ok=True)
    archives = [(str(Path(d) / f'{n}.zip'), n) for d, n in a.scenario]
    with Pool(a.jobs) as pool:
        paths = pool.map(count_one, [(x, n, str(a.work)) for x, n in archives], chunksize=1)
    print(f'counts done {time.strftime("%FT%T", time.gmtime())}', flush=True)
    lm = xf.WeightedLM()
    for path in paths:
        lm.learn_counts(pickle.loads(Path(path).read_bytes()))
    POOL = lm.finalize() or lm
    with Pool(a.jobs) as pool:      # fork: the workers share the finalized model
        pool.map(score_one, [(x, n, str(a.output)) for x, n in archives], chunksize=1)
    print(f'pool done {time.strftime("%FT%T", time.gmtime())}', flush=True)


if __name__ == '__main__':
    main()
