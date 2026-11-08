#!/usr/bin/env python3
"""Token branch of lidds-ml-v3 with other window statistics: mean of the top k per-event -log p, k in 1, 3, 5, 10, 20.

k = 10 was fixed in lidds-ml-v2 and never varied: a few very surprising events may be diluted by the rest of the top 10.
Both models are scored, from one parse of the grams: `plain` as lidds-ml-v3 (learnt on training; validation recordings as
val/<name>) and `xfit` as lidds_ml_token_crossfit.py (K folds over training + validation; held-out recordings as
val/<name>; test recordings by the model on all of them). Writes OUT/plain/<scenario>.npz and OUT/xfit/<scenario>.npz with
columns window_end, top1, top3, top5, top10, top20. With --alarms only development test recordings are scored.

    python3 lidds_ml_token_topk.py --archives DIR --scenario NAME [--alarms alarms.json.gz] --output OUT [--folds 5]
"""
import argparse
from collections import Counter
import json
import math
from pathlib import Path
import sys
import time

import numpy as np

sys.path.insert(0, str(Path(__file__).resolve().parent))
import lidds_ml_token_crossfit as xf  # noqa: E402

al, tk, v2 = xf.al, xf.tk, xf.v2
TOPS = (1, 3, 5, 10, 20)
COLUMNS = ['window_end'] + [f'top{k}' for k in TOPS]


def score(lm, per):
    rows = []
    for w in sorted(per):
        if not per[w]:
            continue
        nll = sorted((-math.log(lm.prob(g)) for g in per[w]), reverse=True)
        rows.append([w] + [float(np.mean(nll[:k])) for k in TOPS])
    return np.asarray(rows, float).reshape(-1, len(COLUMNS))


def evaluate(archive, folds, wanted):
    counts, split_of = {}, {}
    for split, name, blob in v2.split_recordings(archive, {'training', 'validation'}):
        c = Counter()
        for grams in xf.windows(blob).values():
            c.update(grams)
        counts[name], split_of[name] = c, split
    groups = {}
    for name in counts:
        groups.setdefault(xf.fold_of(name, folds), set()).add(name)
    plain, xfit, meta = {}, {}, {}
    for members in groups.values():
        lm = xf.build(counts, members)
        for split, name, blob in v2.split_recordings(archive, {'training', 'validation'}):
            if name in members:
                xfit[f'val/{name}'] = score(lm, xf.windows(blob))
        del lm
    lm_plain = xf.build(counts, {n for n, s in split_of.items() if s == 'validation'})
    for split, name, blob in v2.split_recordings(archive, {'validation'}):
        plain[f'val/{name}'] = score(lm_plain, xf.windows(blob))
    lm_all = xf.build(counts, set())
    del counts
    for split, name, blob in v2.split_recordings(archive, {'test-normal', 'test-normal_and_attack'}):
        if not wanted(name, split):
            continue
        per = xf.windows(blob)
        plain[name], xfit[name] = score(lm_plain, per), score(lm_all, per)
        meta[name] = dict(split=split, exploit=tk.meta_of(blob))
    return plain, xfit, meta


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument('--archives', type=Path, required=True)
    ap.add_argument('--scenario', required=True)
    ap.add_argument('--alarms', type=Path)
    ap.add_argument('--folds', type=int, default=5)
    ap.add_argument('--output', type=Path, required=True)
    a = ap.parse_args()
    t0 = time.time()
    wanted = al.development_only(a.alarms, a.scenario) if a.alarms else (lambda n, s: True)
    plain, xfit, meta = evaluate(a.archives / f'{a.scenario}.zip', a.folds, wanted)
    for sub, arrays in (('plain', plain), ('xfit', xfit)):
        d = a.output / sub
        d.mkdir(parents=True, exist_ok=True)
        np.savez_compressed(d / f'{a.scenario}.npz', **arrays)
        (d / f'{a.scenario}.json').write_text(json.dumps(dict(scenario=a.scenario, columns=COLUMNS, recordings=meta, seconds=time.time() - t0)))
    print(json.dumps(dict(scenario=a.scenario, plain=len(plain), xfit=len(xfit), seconds=round(time.time() - t0))))


if __name__ == '__main__':
    main()
