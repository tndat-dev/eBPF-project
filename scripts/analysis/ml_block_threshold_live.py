#!/usr/bin/env python3
"""Offline check 2 of the token-probe design: can the lidds-ml-v3 threshold rule work on the cluster, where there are
no recordings? Per workload and branch, fit a moment-Gumbel on the maxima of fixed time blocks of each container over
the run's selection span (normal, before the campaign), set the threshold at alpha / 2 (two branches here: the token
branch does not exist on the cluster yet), fire on one window above it. Replay on a finished live run's window table
(tree and support scores as recorded); same metrics as burden_blind_test.py. Reported, nothing is selected here.

    python3 ml_block_threshold_live.py --run name=N,table=T,since=S,campaign=C --selection-end E --calibration C.npz \
        --calibration-table T.npz --output out.json
"""
import argparse
from collections import defaultdict
import json
import math
from pathlib import Path
import sys

import numpy as np

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
sys.path.insert(0, str(Path(__file__).resolve().parent))
import burden_blind_test as bb  # noqa: E402
import burden_levers as bl  # noqa: E402
import lidds_ml_v2 as m  # noqa: E402

ALPHAS = (0.05, 0.02, 0.01, 0.005, 0.002, 0.001, 0.0005)
BLOCKS = (30.0, 60.0, 300.0)


def block_maxima(score, ident, end, sel, block):
    """Maximum score of every (container, block) among the selected rows."""
    key = ident[sel].astype(np.int64) * 10**7 + np.floor(end[sel] / block).astype(np.int64)
    order = np.argsort(key, kind='stable'); k, s = key[order], score[sel][order]
    starts = np.r_[0, np.flatnonzero(k[1:] != k[:-1]) + 1]
    return np.maximum.reduceat(s, starts)


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument('--run', required=True)
    ap.add_argument('--selection-end', type=float, required=True)
    ap.add_argument('--calibration', required=True)
    ap.add_argument('--calibration-table', required=True)
    ap.add_argument('--output', required=True)
    a = ap.parse_args()
    kv = defaultdict(list)
    for part in a.run.split(','):
        k, v = part.split('=', 1)
        kv[k].append(v)
    tree, support = bl.load_calibration(a.calibration)
    classes, _ = bl.calibration_classes(a.calibration_table, tree, support)
    arr, p, trials, info = bl.prepare(kv['table'][0], float(kv['since'][0]), kv['campaign'], tree, support, classes)
    primary = trials.subset(np.isin(trials.rate, bb.PRIMARY_RATES))
    scores = {'tree': m.transform('tree_plain', arr['tree_score']), 'support': np.asarray(arr['support_score'], float)}
    since = float(kv['since'][0])
    fit_rows = (arr['end'] >= since) & (arr['end'] <= a.selection_end) & arr['normal']
    test_normal = arr['normal'] & (arr['end'] > a.selection_end)
    out = dict(schema='pulse-ml-block-threshold-live-v1', run=kv['name'][0], selection=[since, a.selection_end],
               fit_windows=int(fit_rows.sum()), info=info, results=[])
    for block in BLOCKS:
        fits = {}
        for w in np.unique(arr['workload']):
            sel = fit_rows & (arr['workload'] == w)
            if sel.sum() < 50:
                continue
            fits[int(w)] = {b: m.gumbel(block_maxima(scores[b], arr['ident'], arr['end'], sel, block)) for b in scores}
        for alpha in ALPHAS:
            alarm = np.zeros(len(arr['end']), bool)
            for w, f in fits.items():
                sel = arr['workload'] == w
                for b in scores:
                    alarm[sel] |= scores[b][sel] > m.threshold(f[b], alpha / 2)
            # observed block false-alarm rate on normal after the selection span
            fired = block_maxima(alarm.astype(float), arr['ident'], arr['end'], test_normal, block)
            met = bl.metrics(alarm, arr, primary, by_scenario=False)
            out['results'].append(dict(block=block, alpha=alpha, workloads=len(fits), normal_block_fa=float(fired.mean()),
                                       normal_blocks=int(len(fired)), burden_ci=bb.burden_ci(arr, alarm), **met))
            r = out['results'][-1]
            print(f"block {block:5.0f}s alpha {alpha:<7g} block FA {100*r['normal_block_fa']:6.3f}% (design {100*alpha:.3f}%) | attack {r['attack']:.3f} "
                  f"precision {r['precision']:.3f} control {r['control']:.3f} benign {r['benign']:.3f} burden {r['burden']:.2f} p95 {r['p95']}")
    Path(a.output).write_text(json.dumps(out, indent=1, default=float))


if __name__ == '__main__':
    main()
