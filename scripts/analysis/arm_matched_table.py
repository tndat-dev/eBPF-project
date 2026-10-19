#!/usr/bin/env python3
"""Interpolate each arm's recall / control / benign rate at exact normal-episode budgets from an
arm_budget RESULTS.json (linear in episodes per replica-hour; p95 taken at the loosest grid scale
within budget); JSON receipt. This is the table quoted in SYSCALL_FEATURE_EXPERIMENT_STATUS 5.4/5.5."""
import argparse, json, time
import numpy as np

p = argparse.ArgumentParser(description=__doc__)
p.add_argument('--results', required=True); p.add_argument('--output', required=True)
p.add_argument('--budget', type=float, action='append')
a = p.parse_args()
r = json.load(open(a.results)); budgets = a.budget or [3, 5, 8, 12, 18]
table = {}
for arm, res in r['arms'].items():
    pts = sorted((v['episodes_per_replica_hour'], v['recall'], v['control_positive_rate'],
                  v.get('benign_positive_rate'), v['delay_p95'], float(s)) for s, v in res['scales'].items())
    e = np.array([q[0] for q in pts]); table[arm] = {}
    for b in budgets:
        if b < e[0]: table[arm][f'{b:g}'] = None; continue
        i = max(j for j in range(len(pts)) if pts[j][0] <= b)
        cell = dict(recall=float(np.interp(b, e, [q[1] for q in pts])), control=float(np.interp(b, e, [q[2] for q in pts])),
                    p95_at_grid_scale=pts[i][4], grid_scale=pts[i][5])
        if all(q[3] is not None for q in pts):
            cell['benign'] = float(np.interp(b, e, [q[3] for q in pts])); cell['separation'] = cell['recall'] - cell['benign']
        table[arm][f'{b:g}'] = cell
json.dump(dict(schema='arm-matched-budget-table-v1', results=a.results, budgets=budgets, arms=table,
               computed_at_unix=time.time()), open(a.output, 'w'), indent=2)
print(json.dumps({arm: t.get('5') for arm, t in table.items()})[:1200])
