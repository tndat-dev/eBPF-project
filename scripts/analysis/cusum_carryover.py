#!/usr/bin/env python3
"""CUSUM carry-over check and choice (protocol stable-selection-v1 amendment 1).

On continuous per-container streams (window tables of burden-reduction-v1; nothing restarts at trial boundaries,
as in the live CusumState), with the refreshed calibration, scores k2of2 alpha x10 (the starting point) and CUSUM
drift 3 / threshold 6 with on_alarm = keep (as frozen, reported only), cap and restart, using the metrics of
burden_levers.py. Then applies the registered rule:

1. a variant (cap, restart) passes when on BOTH runs recall >= 95 %, precision >= 95 %, control <= 5 %, p95 <= 3 s,
   and on pulse-stable-refreshed it is 'better' than k2of2 alpha x10 by the 5.11a criteria (burden >= 10 % lower
   with recall at most 1 point lower, control not higher, p95 at most 0.2 s slower; or p95 >= 0.2 s faster with
   burden not higher);
2. if both pass, the lower max-over-runs burden (within 5 %: cap);
3. if neither passes, the temporal rule reverts to k2of2 alpha x10.
"""
import argparse, json, sys, time
from collections import defaultdict
from pathlib import Path

import numpy as np

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
sys.path.insert(0, str(Path(__file__).resolve().parent))
import burden_levers as bl  # noqa: E402

BLIND = 'pulse-stable-refreshed'
DRIFT, THRESHOLD = 3.0, 6.0


def configs(a, p):
    x = -np.log(np.maximum(p['joint'], 1e-12))
    out = {'k2of2_a10': bl.kofn2(p['joint'] <= a['alpha'] * 10, a['new'])}
    for mode in ('keep', 'cap', 'restart'):
        out[f'cusum_b3_h6_{mode}'] = bl.cusum_alarms(x - DRIFT, a['new'], THRESHOLD, mode)
    return out


def feasible(m):
    return (m['attack'] is not None and m['attack'] >= 0.95 and m['precision'] is not None and m['precision'] >= 0.95
            and m['control'] is not None and m['control'] <= 0.05 and m['p95'] is not None and m['p95'] <= 3.0)


def better(m, ref):
    burden_way = (m['burden'] <= 0.9 * ref['burden'] and m['attack'] >= ref['attack'] - 0.01
                  and m['control'] <= ref['control'] and m['p95'] <= ref['p95'] + 0.2)
    latency_way = m['p95'] <= ref['p95'] - 0.2 and m['burden'] <= ref['burden']
    return burden_way or latency_way


def choose(runs):
    verdict = {}
    for v in ('cusum_b3_h6_cap', 'cusum_b3_h6_restart'):
        checks = {run: feasible(r[v]) for run, r in runs.items()}
        checks['better_than_k2of2_on_' + BLIND] = better(runs[BLIND][v], runs[BLIND]['k2of2_a10'])
        verdict[v] = dict(passes=all(checks.values()), checks=checks,
                          max_burden=max(r[v]['burden'] for r in runs.values()))
    passing = [v for v, c in verdict.items() if c['passes']]
    if not passing:
        return 'k2of2_a10', verdict
    best = min(verdict[v]['max_burden'] for v in passing)
    near = [v for v in passing if verdict[v]['max_burden'] <= best * 1.05]
    return ('cusum_b3_h6_cap' if 'cusum_b3_h6_cap' in near else near[0]), verdict


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument('--run', action='append', required=True, help='name=<n>,table=<npz>,since=<unix>,campaign=<dir>')
    ap.add_argument('--calibration', required=True)
    ap.add_argument('--output', required=True)
    args = ap.parse_args()
    tree, support = bl.load_calibration(args.calibration)
    runs, infos = {}, {}
    for spec in args.run:
        kv = defaultdict(list)
        for part in spec.split(','):
            k, v = part.split('=', 1); kv[k].append(v)
        name = kv['name'][0]
        a, p, trials, info = bl.prepare(kv['table'][0], float(kv['since'][0]), kv['campaign'], tree, support, {})
        runs[name] = {c: bl.metrics(alarm, a, trials, by_scenario=True) for c, alarm in configs(a, p).items()}
        infos[name] = {k: v for k, v in info.items() if k != 'discount_share'}
        print(name, json.dumps({c: {k: round(m[k], 4) if isinstance(m[k], float) else m[k]
                                    for k in ('burden', 'attack', 'precision', 'control', 'benign', 'p95')}
                                for c, m in runs[name].items()}), flush=True)
    choice, verdict = choose(runs)
    result = dict(schema='pulse-cusum-carryover-v1', protocol='sentinel_pulse/protocol/stable-selection-v1-amendment-1.json',
                  evaluation='continuous per-container streams, refreshed calibration', runs=infos, metrics=runs,
                  verdict=verdict, choice=choice, computed_at_unix=time.time())
    Path(args.output).write_text(json.dumps(result, indent=1, default=str))
    print('choice', choice, json.dumps(verdict))


if __name__ == '__main__':
    main()
