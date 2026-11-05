#!/usr/bin/env python3
"""The live ML without the replica gate: the owner approved removing it on 01/11 (novel_peer = 0 is a fixed novelty rule).

Recomputes, on the window table of a finished live run, the policy the run alerted with (variant|mode|rule of the
development selection) and the same variant and rule with mode ``none``. Replay of the recorded windows, same metrics as
burden_blind_test.py; nothing is selected here. The row with the gate must reproduce the run's receipt.

    python3 ml_live_no_gate.py --run name=N,table=T,since=S,campaign=C --calibration C.npz --calibration-table T.npz \
        --ml-results burden-levers.json --tier le3s --output out.json
"""
import argparse
from collections import defaultdict
import json
from pathlib import Path
import sys

import numpy as np

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
sys.path.insert(0, str(Path(__file__).resolve().parent))
import burden_blind_test as bb  # noqa: E402
import burden_levers as bl  # noqa: E402


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument('--run', required=True)
    ap.add_argument('--calibration', required=True)
    ap.add_argument('--calibration-table', required=True)
    ap.add_argument('--ml-results', required=True)
    ap.add_argument('--tier', default='le3s')
    ap.add_argument('--output', required=True)
    a = ap.parse_args()
    kv = defaultdict(list)
    for part in a.run.split(','):
        k, v = part.split('=', 1)
        kv[k].append(v)
    variant, mode, rule = json.loads(Path(a.ml_results).read_text())['selection'][a.tier]['choice'].split('|')
    tree, support = bl.load_calibration(a.calibration)
    classes, _ = bl.calibration_classes(a.calibration_table, tree, support)
    arr, p, trials, info = bl.prepare(kv['table'][0], float(kv['since'][0]), kv['campaign'], tree, support, classes)
    primary = trials.subset(np.isin(trials.rate, bb.PRIMARY_RATES))
    out = dict(schema='pulse-ml-live-no-gate-v1', run=kv['name'][0], variant=variant, rule=rule, gate=mode, info=info, arms={})
    for name, m in (('with_gate', mode), ('no_gate', 'none')):
        (_, alarm), = bl.rules(variant, p[variant], arr['alpha'], bl.discount_mask(arr, m), arr['new'], only=rule)
        out['arms'][name] = dict(mode=m, primary=bl.metrics(alarm, arr, primary, by_scenario=True), burden_ci=bb.burden_ci(arr, alarm),
                                 alarm_windows=int(alarm.sum()), windows=int(len(alarm)))
    Path(a.output).write_text(json.dumps(out, indent=1))
    for name, r in out['arms'].items():
        m = r['primary']
        print(name, {k: m[k] for k in ('attack', 'precision', 'control', 'benign', 'burden', 'p50', 'p95')}, r['burden_ci'])


if __name__ == '__main__':
    main()
