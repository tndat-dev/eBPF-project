#!/usr/bin/env python3
"""Pareto frontier of the replayed policy grid (Pulse 5.8f item 1, registered 21/10 11:12).

Inputs: one ``confirmation_study attack`` result and the matching ``confirmation_study normal`` results (one per
worker) for one calibration. Per policy: recall, idle-control rate and benign-launch rate with Wilson 95 % CIs
(trial level: these files carry no per-workload attack split), p95 kernel -> preview delay, expected precision, and
alert burden (episodes per scored replica-hour) with a workload-clustered bootstrap CI.

A policy is dominated when another is at least as good on burden, recall, control rate and p95 and strictly better
on one. For the policy under test (``--chosen``) every frontier policy that beats it on some objective is listed with
the paired workload bootstrap of the burden difference and the Wilson intervals of the rate differences' inputs.
"""
import argparse
import json
import math
from pathlib import Path

import numpy as np

REPS = 10000


def wilson(k, n, z=1.96):
    if not n:
        return None
    p = k / n; d = 1 + z * z / n
    c = (p + z * z / (2 * n)) / d; h = z * math.sqrt(p * (1 - p) / n + z * z / (4 * n * n)) / d
    return [max(0.0, c - h), min(1.0, c + h)]


def load(attack_path, normal_paths):
    attack = json.loads(Path(attack_path).read_text())
    normals = [json.loads(Path(p).read_text()) for p in normal_paths]
    hours, episodes = {}, {}
    for n in normals:   # one file per worker; a workload's replicas may sit on several workers
        for w, h in n['scored_hours'].items():
            hours[w] = hours.get(w, 0.0) + h
        for name, pol in n['policies'].items():
            for w, e in pol['episodes'].items():
                episodes.setdefault(name, {}); episodes[name][w] = episodes[name].get(w, 0) + e
    rows = {}
    for name, pol in attack['policies'].items():
        if name not in episodes:
            continue
        cm, benign, delay = pol['confusion_matrix_expected_control_labels'], pol['benign_exec_control'], pol['kernel_to_preview_seconds']
        rows[name] = dict(
            recall=cm['TP'] / (cm['TP'] + cm['FN']), recall_ci=wilson(cm['TP'], cm['TP'] + cm['FN']),
            control=cm['FP'] / (cm['FP'] + cm['TN']), control_ci=wilson(cm['FP'], cm['FP'] + cm['TN']),
            benign=benign['FP'] / (benign['FP'] + benign['TN']), benign_ci=wilson(benign['FP'], benign['FP'] + benign['TN']),
            precision=pol.get('precision_expected'), p95=delay.get('p95'), p50=delay.get('p50'),
            burden=sum(episodes[name].values()) / sum(hours.values()))
    return rows, hours, episodes


def dominated(a, b):
    """True when ``b`` dominates ``a`` (burden, control, p95 lower is better; recall higher is better)."""
    ge = (b['burden'] <= a['burden'] and b['recall'] >= a['recall'] and b['control'] <= a['control'] and b['p95'] <= a['p95'])
    gt = (b['burden'] < a['burden'] or b['recall'] > a['recall'] or b['control'] < a['control'] or b['p95'] < a['p95'])
    return ge and gt


def frontier(rows):
    return sorted(n for n, r in rows.items() if not any(dominated(r, o) for m, o in rows.items() if m != n))


def burden_bootstrap(episodes, hours, names, reps=REPS, seed=20261021):
    """Workload-clustered bootstrap: CI of each policy's burden and of differences to names[0]."""
    workloads = sorted(hours); rng = np.random.default_rng(seed)
    h = np.array([hours[w] for w in workloads])
    e = {n: np.array([episodes[n].get(w, 0) for w in workloads]) for n in names}
    idx = rng.integers(0, len(workloads), size=(reps, len(workloads)))
    hs = h[idx].sum(1)
    rates = {n: e[n][idx].sum(1) / hs for n in names}
    ci = lambda x: [float(np.percentile(x, 2.5)), float(np.percentile(x, 97.5))]
    return ({n: ci(r) for n, r in rates.items()}, {n: ci(rates[n] - rates[names[0]]) for n in names[1:]})


def main():
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument('--attack', required=True); p.add_argument('--normal', action='append', required=True)
    p.add_argument('--chosen', default='k2of2_a10'); p.add_argument('--label', required=True)
    p.add_argument('--output', required=True)
    a = p.parse_args()
    rows, hours, episodes = load(a.attack, a.normal)
    front = frontier(rows)
    c = rows[a.chosen]
    better = [n for n in front if n != a.chosen and (rows[n]['burden'] < c['burden'] or rows[n]['recall'] > c['recall']
                                                     or rows[n]['control'] < c['control'] or rows[n]['p95'] < c['p95'])]
    ci, diff = burden_bootstrap(episodes, hours, [a.chosen, *sorted(rows)])
    for n, r in rows.items():
        r['burden_ci'] = ci[n]
    v2 = {n for n, r in rows.items() if r['recall'] >= .95 and (r['precision'] or 0) >= .95 and r['control'] <= .05 and r['p95'] <= 3.0}
    out = dict(schema='pulse-policy-pareto-v1', label=a.label, attack=a.attack, normal=a.normal, chosen=a.chosen,
               chosen_on_frontier=a.chosen in front, frontier=front,
               frontier_beating_chosen={n: dict(rows[n], burden_diff_ci=diff[n]) for n in better},
               v2_feasible=sorted(v2), v2_feasible_frontier=frontier({n: rows[n] for n in v2}) if v2 else [],
               policies=rows, scored_replica_hours=sum(hours.values()), bootstrap_reps=REPS,
               note='rates: Wilson 95 % CI at trial level; burden: workload-clustered bootstrap; development data')
    Path(a.output).write_text(json.dumps(out, indent=2))
    print(f"{a.label}: chosen {a.chosen} on frontier: {out['chosen_on_frontier']}; frontier {len(front)}/{len(rows)}")
    for n in [a.chosen, *better]:
        r = rows[n]
        print(f"  {n:11s} burden {r['burden']:.2f} {['%.2f' % x for x in r['burden_ci']]} recall {r['recall']:.3f} "
              f"control {r['control']:.3f} benign {r['benign']:.3f} p95 {r['p95']:.2f}"
              + (f" diff {['%+.2f' % x for x in diff[n]]}" if n in diff and n != a.chosen else ''))


if __name__ == '__main__':
    main()
