#!/usr/bin/env python3
"""Cross-fitted token branch of lidds-ml-v3 (select1f): more normal for the model and for its threshold.

lidds-ml-v3 learns the token model on the training recordings (about 211 per scenario) and fits the Gumbel threshold on
the maxima of the validation recordings (52-60). Here training and validation together (about 270) are split into K
folds by name: every one of them is scored by the model learnt on the other folds (its maximum enters the Gumbel fit, so
the fit has about 270 maxima instead of 60), and the test recordings are scored by the model learnt on all of them.
Tokens, grams, smoothing and the window score are those of lidds_ml_token_alphabets.py / lidds_ml_tokens.py.

Output as lidds_ml_token_alphabets.py: <scenario>.npz (held-out training/validation recordings as val/<name>, test
recordings by name; columns window_end, xfit) and .json. With --alarms only development test recordings are scored
(official not read).

    python3 lidds_ml_token_crossfit.py --archives DIR --scenario NAME [--alarms alarms.json.gz] --output out.npz [--folds 5]
"""
import argparse
from collections import Counter
import hashlib
import json
from pathlib import Path
import sys
import time

import numpy as np

sys.path.insert(0, str(Path(__file__).resolve().parent))
import lidds_ml_token_alphabets as al  # noqa: E402

tk, convert, v2 = al.tk, al.convert, al.v2
ALPHABET = 'select1f'


class WeightedLM(tk.TokenLM):
    """TokenLM fed with gram counts: c occurrences add exactly what c calls of learn() add."""

    def learn_counts(self, counts):
        for g, c in counts.items():
            g = tuple(g[-self.n:])
            w = g[-1]
            for k in range(1, min(self.n, len(g))):
                self.count[k][g[-1 - k:-1]][w] += c
            name = tk.base_name(w)
            self.names[name] += c
            self.given[name][w] += c
            self.total += c


def windows(blob):
    return al.alphabet_windows(convert.recording(blob)[1], (ALPHABET,))[ALPHABET]


def fold_of(name, folds):
    return int(hashlib.sha256(name.encode()).hexdigest(), 16) % folds


def build(counts, skip):
    lm = WeightedLM()
    for name, c in counts.items():
        if name not in skip:
            lm.learn_counts(c)
    lm.finalize()
    return lm


def evaluate(archive, folds, wanted):
    counts = {}
    for split, name, blob in v2.split_recordings(archive, {'training', 'validation'}):
        c = Counter()
        for grams in windows(blob).values():
            c.update(grams)
        counts[name] = c
    groups = {}
    for name in counts:
        groups.setdefault(fold_of(name, folds), set()).add(name)
    out, meta = {}, {}
    for k, members in sorted(groups.items()):          # held-out scores of training + validation
        lm = build(counts, members)
        for split, name, blob in v2.split_recordings(archive, {'training', 'validation'}):
            if name in members:
                sc = al.score_windows(lm, windows(blob))
                ends = sorted(sc)
                out[f'val/{name}'] = np.asarray([[w, sc[w]] for w in ends], float).reshape(-1, 2)
        del lm
    lm = build(counts, set())
    for split, name, blob in v2.split_recordings(archive, {'test-normal', 'test-normal_and_attack'}):
        if not wanted(name, split):
            continue
        sc = al.score_windows(lm, windows(blob))
        ends = sorted(sc)
        out[name] = np.asarray([[w, sc[w]] for w in ends], float).reshape(-1, 2)
        meta[name] = dict(split=split, exploit=tk.meta_of(blob))
    return out, meta, {str(k): len(v) for k, v in groups.items()}


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument('--archives', type=Path, required=True)
    ap.add_argument('--scenario', required=True)
    ap.add_argument('--alarms', type=Path, help='keep development test recordings only; without it every recording (CB-DS)')
    ap.add_argument('--folds', type=int, default=5)
    ap.add_argument('--output', type=Path, required=True)
    a = ap.parse_args()
    t0 = time.time()
    wanted = al.development_only(a.alarms, a.scenario) if a.alarms else (lambda n, s: True)
    out, meta, sizes = evaluate(a.archives / f'{a.scenario}.zip', a.folds, wanted)
    np.savez_compressed(a.output, **out)
    a.output.with_suffix('.json').write_text(json.dumps(dict(scenario=a.scenario, columns=['window_end', 'xfit'],
                                                             folds=sizes, recordings=meta, seconds=time.time() - t0)))
    print(json.dumps(dict(scenario=a.scenario, recordings=len(out), folds=sizes, seconds=round(time.time() - t0))))


if __name__ == '__main__':
    main()
