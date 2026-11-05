#!/usr/bin/env python3
"""Raw branch scores of Pulse's ML on LID-DS / CB-DS, for choosing a decision rule offline (before lidds-ml-v2).

lidds-ml-v1 kept conformal p-values only, whose floor 1/(n+1) erases how far a window lies above the calibration
scores. This runner fits the same branches (lidds_ml_groups.py, fix A off and on) and keeps, for every validation and
test window scored by G0, the raw scores, plus 'surprise mass' statistics of per-event probability models learnt on
the training recordings:

- g2_mass: per-thread 5-gram language model, sum over the window's events of max(0, -log p - log 100);
- g1d_mass, g4d_mass: smoothed multinomials of (mode, directory prefix) of opens and of (syscall, errno) of failures,
  same sum; g1d_unseen, g4d_unseen: the part of it from items never seen in training, the diagnostic of how close the
  statistic is to a novelty rule.

Writes <scenario>.npz: test recordings under their names, validation recordings as val/<name>; columns in COLUMNS.
No decision, selection or metric is computed here. The live warm-up gate (a window is eligible after 10 windows of
history, 5 s) hides the start of a 10-60 s recording, where many exploits fall; ``--all-windows`` lifts it for
training, calibration and scoring. The 3 windows of G0's history still apply.

    python3 lidds_ml_scores.py --converted DIR --archives DIR --scenario NAME --output out.npz
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
import lidds_ml_groups as g  # noqa: E402

v1, v2 = g.v1, g.v2
SURPRISE = math.log(100)            # an event rarer than 1 in 100 starts to count (fixed before any result)
COLUMNS = ['window_end', 'tree_plain', 'tree_fix', 'support', 'g1_plain', 'g1_fix', 'g3_plain', 'g3_fix', 'g4_plain',
           'g4_fix', 'g2_top10', 'g2_mass', 'g1d_mass', 'g1d_unseen', 'g4d_mass', 'g4d_unseen']


class Multinomial:
    """Add-half multinomial over items seen in training, with one shared slot for unseen items."""

    def __init__(self):
        self.count = Counter()

    def learn(self, items):
        self.count.update(items)

    def finalize(self):
        self.total = sum(self.count.values())
        self.den = self.total + 0.5 * (len(self.count) + 1)

    def mass(self, items):
        """(surprise mass of the items, the part from unseen items)."""
        all_, unseen = 0.0, 0.0
        for it in items:
            c = self.count.get(it, 0)
            excess = max(0.0, -math.log((c + 0.5) / self.den) - SURPRISE)
            all_ += excess
            if not c:
                unseen += excess
        return all_, unseen


def lm_mass(lm, grams):
    return sum(max(0.0, -math.log(lm.prob(x)) - SURPRISE) for x in grams)


def file_items(s):
    return [(mode, prefix) for mode, prefix, _ in s['paths']]


def errno_items(s):
    return list(s['errors'].elements())


def read_split(archive, recs, splits, lm, files, errs):
    """{recording: {key: vectors and window statistics}}; the events are dropped after use."""
    out = {}
    for split, name, blob in v2.split_recordings(archive, splits):
        if name not in recs.get(split, {}):
            continue
        raw = v2.raw_windows(blob)
        vec = g.group_vectors(raw, lm)
        for w, s in raw.items():
            v = vec[g.key(w)]
            v['g2_mass'] = lm_mass(lm, s['ngrams'])
            v['g1d'] = files.mass(file_items(s))
            v['g4d'] = errs.mass(errno_items(s))
        out[name] = vec
    return out


def matrix(rows, vec, g0, support, trees):
    """One row per window scored by G0, in COLUMNS order."""
    parts = []
    for ctx, scored, cur, prev, lm_scores, per in g.runs_with_groups(rows, vec):
        dim = g0[False].feature_dim
        cols = [np.asarray([r['window_end'] for r in scored]),
                g0[False].estimator.predict_proba(ctx)[:, 1], g0[True].estimator.predict_proba(ctx)[:, 1],
                support.support_scores(ctx[:, -dim:])]
        for name in g.TREE_GROUPS:
            x = np.concatenate((prev[name], cur[name]), axis=1)
            cols += [trees[name, False].estimator.predict_proba(x)[:, 1], trees[name, True].estimator.predict_proba(x)[:, 1]]
        tail = per[v1.HISTORY:]
        cols += [lm_scores, np.asarray([p.get('g2_mass', 0.0) for p in tail]),
                 np.asarray([p.get('g1d', (0.0, 0.0))[0] for p in tail]), np.asarray([p.get('g1d', (0.0, 0.0))[1] for p in tail]),
                 np.asarray([p.get('g4d', (0.0, 0.0))[0] for p in tail]), np.asarray([p.get('g4d', (0.0, 0.0))[1] for p in tail])]
        parts.append(np.column_stack(cols))
    return np.concatenate(parts) if parts else np.empty((0, len(COLUMNS)))


def evaluate(converted, archive, fix_fraction, all_windows=False):
    recs = {s: v1.recordings(converted / f'{s}.jsonl.gz') for s in v1.SPLITS if (converted / f'{s}.jsonl.gz').exists()}
    if all_windows:                 # no live warm-up gate (history >= 10 windows): a recording lasts 10-60 s
        for split in recs.values():
            for rows in split.values():
                for r in rows:
                    r['eligible_for_normal_review'] = True
    lm, files, errs, raw = g.NgramLM(), Multinomial(), Multinomial(), {}
    for split, name, blob in v2.split_recordings(archive, {'training'}):
        if name in recs.get(split, {}):
            windows = v2.raw_windows(blob)
            raw[name] = g.group_vectors(windows)
            for key, v in raw[name].items():
                lm.learn(v.pop('events'))
            for s in windows.values():
                files.learn(file_items(s)); errs.learn(errno_items(s))
    lm.finalize(); files.finalize(); errs.finalize()
    raw.update(read_split(archive, recs, {s for s in recs if s != 'training'}, lm, files, errs))
    seq = lambda r: [[v1.decode_vector(x) for x in run] for rows in r.values() for run in v1.runs(rows)]
    cur0 = lambda r: np.asarray([v1.decode_vector(x) for rows in r.values() for run in v1.runs(rows) for x in run[v1.HISTORY:]],
                                dtype=np.float32)
    g0 = {}
    for fix in g.FIX_A:
        g0[fix] = g.tree(fix_fraction if fix else 0.0, v1.HISTORY)
        g0[fix].fit_sequences({'train': seq(recs['training']), 'calibration': seq(recs['validation'])})
    support = g.PulseSupportEnsemble(g0[False])
    support.fit_support(cur0(recs['training']), cur0(recs['validation']))
    gseq = {s: g.group_sequences(recs[s], raw) for s in ('training', 'validation')}
    trees = {}
    for name in g.TREE_GROUPS:
        for fix in g.FIX_A:
            trees[name, fix] = g.tree(fix_fraction if fix else 0.0, 1)
            trees[name, fix].fit_sequences({'train': gseq['training'][name], 'calibration': gseq['validation'][name]})
    out, meta = {}, {}
    for name, rows in recs['validation'].items():
        out[f'val/{name}'] = matrix(rows, raw[name], g0, support, trees)
    for split in ('test-normal', 'test-normal_and_attack'):
        for name, rows in recs.get(split, {}).items():
            out[name] = matrix(rows, raw[name], g0, support, trees)
            meta[name] = dict(split=split, exploit=rows[0]['lidds']['exploit_at'])
    return out, meta


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument('--converted', type=Path, required=True)
    ap.add_argument('--archives', type=Path, required=True)
    ap.add_argument('--scenario', required=True)
    ap.add_argument('--fix-a', type=float, default=0.05)
    ap.add_argument('--all-windows', action='store_true', help='train, calibrate and score the first 5 s of a recording too')
    ap.add_argument('--output', type=Path, required=True)
    a = ap.parse_args()
    t0 = time.time()
    out, meta = evaluate(a.converted / a.scenario, a.archives / f'{a.scenario}.zip', a.fix_a, a.all_windows)
    np.savez_compressed(a.output, **out)
    a.output.with_suffix('.json').write_text(json.dumps(dict(scenario=a.scenario, columns=COLUMNS, recordings=meta,
                                                             fix_a_fraction=a.fix_a, all_windows=a.all_windows, seconds=time.time() - t0)))
    print(json.dumps(dict(scenario=a.scenario, seconds=round(time.time() - t0), matrices=len(out))))


if __name__ == '__main__':
    main()
