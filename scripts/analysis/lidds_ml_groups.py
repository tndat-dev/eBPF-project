#!/usr/bin/env python3
"""Pulse's ML with learned branches per information group on LID-DS / CB-DS (protocol lidds-ml-v1).

Per scenario (one workload), every branch is a model fitted on the training recordings' normal windows and turned
into conformal p-values on the validation recordings; no branch uses a fixed 'unseen -> alarm' test:

- G0, the current ML: reference tree (history 3) over the 249 count features and the support interval model;
- G1 file access: opens per window, counted into 64 hashed bins of the 3-level directory prefix, read and write
  apart (128 features, log1p), scored by a reference tree (history 1);
- G2 sequence: a per-thread 5-gram language model of syscall names (Witten-Bell interpolation down to an add-one
  unigram); a window's score is the mean of its 10 highest per-event negative log-probabilities;
- G3 I/O size: read-like and write-like exits per log2 byte bucket (32 features), reference tree (history 1);
- G4 errno: failed exits counted into 32 hashed bins of (syscall, errno), reference tree (history 1).

Fix A (``activate_fraction`` of PulseExtraTrees) is fitted off and on for every tree. Every window scored by G0 gets
all branch p-values; a configuration combines its branches (G0's tree and support plus its groups) by Bonferroni
(min(1, K min p)) or Cauchy, passes when p <= 5 x 0.05/30 and alarms on two consecutive contiguous passes (the
decision of the v1 ML arm). Outcomes are v2 rows per configuration; the p-values are kept (npz).

    python3 lidds_ml_groups.py --converted DIR --archives DIR --scenario NAME --output part.json [--fix-a 0.05]
"""
import argparse
from collections import Counter, defaultdict
import json
import math
from pathlib import Path
import sys
import time
import zlib

import numpy as np

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
sys.path.insert(0, str(Path(__file__).resolve().parent))
import lidds_evaluate as v1  # noqa: E402
import lidds_evaluate_v2 as v2  # noqa: E402
from sentinel_pulse.detector.extended_reference_experiment import PulseExtendedReferenceTree  # noqa: E402
from sentinel_pulse.detector.support_model import PulseSupportEnsemble, pvalues  # noqa: E402

GROUPS = ('g1', 'g2', 'g3', 'g4')
TREE_GROUPS = ('g1', 'g3', 'g4')
DIMS = dict(g1=128, g3=32, g4=32)
LM_N, LM_TOP = 5, 10
GROUP_SETS = (('g0',), ('g0', 'g1'), ('g0', 'g2'), ('g0', 'g1', 'g2'), ('g0', 'g1', 'g2', 'g3'),
              ('g0', 'g1', 'g2', 'g3', 'g4'))
FUSIONS = ('bonferroni', 'cauchy')
FIX_A = (False, True)
PASS = v1.SCALE * v1.ALPHA


def key(t):
    return int(round(float(t) * 2))


def group_vectors(windows, lm=None):
    """{half-second key: {group: vector, 'lm': score or None, 'events': n-grams (only when lm is None)}} from
    signals.recording_signals of one recording; with a fitted lm the events are scored and dropped (memory)."""
    out = {}
    for w, s in windows.items():
        g1 = np.zeros(DIMS['g1'], np.float32)
        for mode, prefix, _ in s['paths']:
            g1[(64 if mode == 'w' else 0) + zlib.crc32(prefix.encode()) % 64] += 1
        g3 = np.zeros(DIMS['g3'], np.float32)
        for (direction, b), n in s['bytes'].items():
            g3[(16 if direction == 'out' else 0) + b] += n
        g4 = np.zeros(DIMS['g4'], np.float32)
        for (name, err), n in s['errors'].items():
            g4[zlib.crc32(f'{name}:{err}'.encode()) % 32] += n
        v = dict(g1=np.log1p(g1), g3=np.log1p(g3), g4=np.log1p(g4))
        if lm is None:
            v['events'] = s['ngrams']
        else:
            v['lm'] = lm.score(s['ngrams'])
        out[key(w)] = v
    return out


class NgramLM:
    """Per-thread syscall-name language model of order LM_N, Witten-Bell interpolation over shorter contexts."""

    def __init__(self, n=LM_N):
        self.n = n
        self.count = [defaultdict(Counter) for _ in range(n)]       # count[k][context of length k][next]
        self.total = 0

    def learn(self, grams):
        for g in grams:
            g = g[-self.n:]
            w = g[-1]
            for k in range(self.n):
                self.count[k][g[-1 - k:-1] if k else ()][w] += 1
            self.total += 1

    def finalize(self):
        """Context totals and type counts (after learning), and an empty memo of probabilities."""
        self.stats = [{h: (sum(c.values()), len(c)) for h, c in level.items()} for level in self.count]
        self.memo = {}

    def prob(self, g):
        g = tuple(g[-self.n:])
        hit = self.memo.get(g)
        if hit is not None:
            return hit
        w = g[-1]
        uni = self.count[0][()]
        p = (uni.get(w, 0) + 1) / (self.total + len(uni) + 1)       # add-one unigram, unknown names allowed
        for k in range(1, self.n):
            h = g[-1 - k:-1]
            st = self.stats[k].get(h)
            if not st:
                continue
            tot, types = st
            p = (self.count[k][h].get(w, 0) + types * p) / (tot + types)
        self.memo[g] = p
        return p

    def score(self, grams):
        if not grams:
            return 0.0
        nll = sorted((-math.log(self.prob(g)) for g in grams), reverse=True)[:LM_TOP]
        return float(np.mean(nll))


def runs_with_groups(rows, gvec):
    """Per contiguous run: (G0 contexts, scored rows, group current/previous matrices, events per scored row)."""
    out = []
    for run in v1.runs(rows):
        ctx, scored = v1.contexts(run)
        if not scored:
            continue
        keys = [key(r['window_end']) for r in run]
        empty = dict(g1=np.zeros(DIMS['g1'], np.float32), g3=np.zeros(DIMS['g3'], np.float32),
                     g4=np.zeros(DIMS['g4'], np.float32), lm=0.0)
        per = [gvec.get(k, empty) for k in keys]
        start = v1.HISTORY
        cur = {g: np.stack([per[i][g] for i in range(start, len(per))]) for g in TREE_GROUPS}
        prev = {g: np.stack([per[i - 1][g] for i in range(start, len(per))]) for g in TREE_GROUPS}
        out.append((ctx, scored, cur, prev, np.asarray([per[i].get('lm', 0.0) for i in range(start, len(per))]), per))
    return out


def group_sequences(recs, gvecs):
    """{group: [ordered group-vector sequence per run]} over the eligible runs of a split (for the history-1 trees)."""
    seqs = {g: [] for g in TREE_GROUPS}
    for name, rows in recs.items():
        for run in v1.runs(rows):
            per = [gvecs[name].get(key(r['window_end'])) for r in run]
            for g in TREE_GROUPS:
                seqs[g].append([p[g] if p else np.zeros(DIMS[g], np.float32) for p in per])
    return seqs


def tree(fix, history):
    return PulseExtendedReferenceTree(history=history, alpha=v1.TREE_ALPHA, random_state=v1.SEED,
                                      activate_fraction=fix)


def cauchy(ps):
    ps = np.clip(np.asarray(ps, dtype=np.float64), 1e-15, 1 - 1e-15)
    t = np.mean(np.tan((0.5 - ps) * np.pi), axis=0)
    return np.clip(0.5 - np.arctan(t) / np.pi, 0, 1)


def combine(branches, fusion):
    if fusion == 'bonferroni':
        return np.minimum(1.0, len(branches) * np.min(branches, axis=0))
    return cauchy(branches)


def config_name(fix, groups, fusion):
    return f"{'+'.join(groups)}|{'fixA' if fix else 'plain'}|{fusion}"


def alarms(scored, p):
    """{window_end: alarm} as v1.ml_alarms: pass and the previous contiguous window passed."""
    out, prev_end, prev_pass = {}, None, False
    for r, x in zip(scored, p):
        ok = x <= PASS
        contiguous = prev_end is not None and .35 <= r['window_end'] - prev_end <= .8
        out[r['window_end']] = bool(ok and prev_pass and contiguous)
        prev_end, prev_pass = r['window_end'], bool(ok)
    return out


def evaluate(scenario, converted, archive, fix_fraction, dev_names=None):
    recs = {s: v1.recordings(converted / f'{s}.jsonl.gz') for s in v1.SPLITS if (converted / f'{s}.jsonl.gz').exists()}
    raw, lm = {}, NgramLM()
    for split, name, blob in v2.split_recordings(archive, {'training'}):    # learn the language model, keep vectors
        if name in recs.get(split, {}):
            raw[name] = group_vectors(v2.raw_windows(blob))
            for v in raw[name].values():
                lm.learn(v.pop('events'))
    lm.finalize()
    others = {s for s in recs if s != 'training'}
    for split, name, blob in v2.split_recordings(archive, others):          # vectors and window scores only
        if name in recs.get(split, {}):
            raw[name] = group_vectors(v2.raw_windows(blob), lm)
    seq = lambda r: [[v1.decode_vector(x) for x in run] for rows in r.values() for run in v1.runs(rows)]
    cur0 = lambda r: np.asarray([v1.decode_vector(x) for rows in r.values() for run in v1.runs(rows) for x in run[v1.HISTORY:]],
                                dtype=np.float32)
    fits = {}
    g0 = {}
    for fix in FIX_A:
        t = tree(fix_fraction if fix else 0.0, v1.HISTORY)
        fits[f'g0_tree_{int(fix)}'] = t.fit_sequences({'train': seq(recs['training']), 'calibration': seq(recs['validation'])})
        g0[fix] = t
    support = PulseSupportEnsemble(g0[False])
    fits['g0_support'] = support.fit_support(cur0(recs['training']), cur0(recs['validation']))
    gseq = {s: group_sequences(recs[s], raw) for s in ('training', 'validation')}
    trees = {}
    for g in TREE_GROUPS:
        for fix in FIX_A:
            t = tree(fix_fraction if fix else 0.0, 1)
            fits[f'{g}_tree_{int(fix)}'] = t.fit_sequences({'train': gseq['training'][g], 'calibration': gseq['validation'][g]})
            trees[g, fix] = t
    cal = []
    for name, rows in recs['validation'].items():
        for _, scored, _, _, lm_scores, _ in runs_with_groups(rows, raw[name]):
            cal.extend(lm_scores)
    lm_cal = np.sort(np.asarray(cal))
    fits['g2_lm'] = dict(order=LM_N, top=LM_TOP, training_events=lm.total, calibration_windows=len(lm_cal))
    names = [n for s in ('test-normal_and_attack',) for n in recs.get(s, {})]
    dev = dev_names if dev_names is not None else v2.development_set(scenario, names)
    outcomes = defaultdict(list)
    kept = {}
    for split in ('test-normal', 'test-normal_and_attack'):
        for name, rows in recs.get(split, {}).items():
            exploit = rows[0]['lidds']['exploit_at']
            subset = 'development' if name in dev else 'official'
            per_cfg = defaultdict(dict)
            stack = []
            for ctx, scored, cur, prev, lm_scores, _ in runs_with_groups(rows, raw[name]):
                tp = {fix: pvalues(g0[fix].estimator.predict_proba(ctx)[:, 1], g0[fix].calibration_scores) for fix in FIX_A}
                sp = pvalues(support.support_scores(ctx[:, -g0[False].feature_dim:]), support.support_calibration)
                gp = {}
                for g in TREE_GROUPS:
                    x = np.concatenate((prev[g], cur[g]), axis=1)
                    for fix in FIX_A:
                        gp[g, fix] = pvalues(trees[g, fix].estimator.predict_proba(x)[:, 1], trees[g, fix].calibration_scores)
                g2p = (len(lm_cal) - np.searchsorted(lm_cal, lm_scores, side='left') + 1.0) / (len(lm_cal) + 1.0)
                for fix in FIX_A:
                    for groups in GROUP_SETS:
                        branches = [tp[fix], sp] + [g2p if g == 'g2' else gp[g, fix] for g in groups if g != 'g0']
                        for fusion in FUSIONS:
                            per_cfg[config_name(fix, groups, fusion)].update(alarms(scored, combine(branches, fusion)))
                stack.append(np.column_stack([[r['window_end'] for r in scored], tp[False], tp[True], sp]
                                             + [gp[g, f] for g in TREE_GROUPS for f in FIX_A] + [g2p]))
            kept[name] = np.concatenate(stack) if stack else np.empty((0, 11))
            for cfg, a in per_cfg.items():
                d, lat, fa = v1.recording_outcome([e for e, x in a.items() if x], exploit)
                outcomes[cfg].append([split, d, lat, fa, len(a), subset, name])
    return dict(scenario=scenario, fits=fits, fix_a_fraction=fix_fraction, development_recordings=sorted(dev)), outcomes, kept


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument('--converted', type=Path, required=True)
    ap.add_argument('--archives', type=Path, required=True)
    ap.add_argument('--scenario', required=True)
    ap.add_argument('--fix-a', type=float, default=0.05)
    ap.add_argument('--output', type=Path, required=True)
    a = ap.parse_args()
    t0 = time.time()
    info, outcomes, kept = evaluate(a.scenario, a.converted / a.scenario, a.archives / f'{a.scenario}.zip', a.fix_a)
    info['seconds'] = time.time() - t0
    info['columns'] = ['window_end', 'g0_tree_plain', 'g0_tree_fixA', 'g0_support'] + \
        [f'{g}_{"fixA" if f else "plain"}' for g in TREE_GROUPS for f in FIX_A] + ['g2_lm']
    info['outcomes'] = dict(outcomes)
    a.output.write_text(json.dumps(info, default=float))
    np.savez_compressed(a.output.with_suffix('.npz'), **kept)
    base = outcomes[config_name(False, ('g0',), 'bonferroni')]
    att = [o for o in base if o[0] == 'test-normal_and_attack']
    print(json.dumps(dict(scenario=a.scenario, seconds=round(info['seconds']), baseline_detected=sum(o[1] for o in att),
                          attacks=len(att))))


if __name__ == '__main__':
    main()
