#!/usr/bin/env python3
"""Variants of the enriched token alphabet and context order, for development comparison after lidds-ml-v2.

One pass over a scenario archive per variant; a window's score is the mean of the 10 highest per-event negative
log-probabilities, as lidds_ml_tokens.py. Every variant changes one thing from ``base`` (or combines the ones listed):
- path2: two directory levels of an open; size1: log2 byte size without halving; fd: fd type of reads and writes (from
the entry line, file or socket); proc: process name prefix; n3, n5: context order. No metric is computed here.

    python3 lidds_ml_token_variants.py --archives DIR --scenario NAME --output out.npz
"""
import argparse
from collections import defaultdict, deque
import json
import math
from pathlib import Path
import re
import sys
import time

import numpy as np

sys.path.insert(0, str(Path(__file__).resolve().parent))
import lidds_ml_tokens as tk  # noqa: E402

signals, convert, v2 = tk.signals, tk.convert, tk.v2
BASE = dict(levels=1, halve=True, fd=False, proc=False, n=4)
VARIANTS = dict(base=BASE, path2={**BASE, 'levels': 2}, size1={**BASE, 'halve': False}, fd={**BASE, 'fd': True},
                proc={**BASE, 'proc': True}, n3={**BASE, 'n': 3}, n5={**BASE, 'n': 5})
FD_TYPE = re.compile(r'\bfd=-?\d+\(<(\w+)>')


def vtoken(name, args, fd_type, proc, v):
    err = signals.error_of(args)
    head = f'{proc}|' if v['proc'] else ''
    if err is not None:
        return f'{head}{name}!{err}'
    if name in signals.OPENS:
        got = signals.open_path(args)
        if got:
            mode, path = got
            parts = [p for p in path.split('/') if p][:-1][:v['levels']]
            top = ('/' + '/'.join(parts)) if path.startswith('/') and parts else ('/' if path.startswith('/') else 'rel')
            return f"{head}{name}:{'w' if name == 'creat' else mode}:{top}"
    if name in signals.READS or name in signals.WRITES:
        size = signals.byte_count(args)
        if size is not None:
            b = signals.bucket(size)
            fd = f'@{fd_type}' if v['fd'] and fd_type else ''
            return f"{head}{name}{fd}#{b // 2 if v['halve'] else b}"
    return head + name


def variant_windows(lines, v):
    out = defaultdict(list)
    threads = defaultdict(lambda: deque(maxlen=v['n']))
    last_fd = {}
    for line in lines:
        parts = line.split(' ', 7)
        if len(parts) < 7:
            continue
        args = parts[7] if len(parts) > 7 else ''
        if parts[6] == '>':
            if v['fd']:
                m = FD_TYPE.search(args)
                last_fd[parts[4]] = m.group(1) if m else None
            continue
        if parts[6] != '<':
            continue
        try:
            ts = int(parts[0])
        except ValueError:
            continue
        q = threads[parts[4]]
        q.append(vtoken(parts[5], args, last_fd.get(parts[4]), parts[3], v))
        out[signals.window_end(ts)].append(tuple(q))
    return dict(out)






def score_windows(lm, per):
    rows = {}
    for w, grams in per.items():
        nll = sorted((-math.log(lm.prob(g)) for g in grams), reverse=True)[:tk.TOP]
        rows[w] = float(np.mean(nll)) if nll else 0.0
    return rows


def evaluate(archive, names=tuple(VARIANTS)):
    lms = {k: tk.TokenLM(n=VARIANTS[k]['n']) for k in names}
    for _, _, blob in v2.split_recordings(archive, {'training'}):
        lines = convert.recording(blob)[1]
        for k in names:
            for grams in variant_windows(lines, VARIANTS[k]).values():
                lms[k].learn(grams)
    for lm in lms.values():
        lm.finalize()
    out, meta = {}, {}
    for split, name, blob in v2.split_recordings(archive, {'validation', 'test-normal', 'test-normal_and_attack'}):
        lines = convert.recording(blob)[1]
        cols = {k: score_windows(lms[k], variant_windows(lines, VARIANTS[k])) for k in names}
        ends = sorted(set().union(*cols.values()))
        key = f'val/{name}' if split == 'validation' else name
        out[key] = np.asarray([[w] + [cols[k].get(w, 0.0) for k in names] for w in ends], dtype=float).reshape(-1, 1 + len(names))
        if split != 'validation':
            meta[name] = dict(split=split, exploit=tk.meta_of(blob))
    return out, meta


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument('--archives', type=Path, required=True)
    ap.add_argument('--scenario', required=True)
    ap.add_argument('--output', type=Path, required=True)
    a = ap.parse_args()
    t0 = time.time()
    out, meta = evaluate(a.archives / f'{a.scenario}.zip')
    np.savez_compressed(a.output, **out)
    a.output.with_suffix('.json').write_text(json.dumps(dict(scenario=a.scenario, columns=['window_end'] + list(VARIANTS), recordings=meta, seconds=time.time() - t0)))
    print(json.dumps(dict(scenario=a.scenario, seconds=round(time.time() - t0))))


if __name__ == '__main__':
    main()
