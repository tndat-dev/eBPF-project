"""Paired, workload-clustered bootstrap CIs for arm-vs-base29 differences at a matched budget.

Protocol v2 asks for paired block-bootstrap confidence intervals instead of treating
overlapping windows or trials as independent. For each budget B every arm uses its own
matched alpha scale (``matched_budget`` of arm_budget RESULTS). Per trial the outcome is
averaged over the three seeds; differences against base29 are paired by trial and the
bootstrap resamples *workloads* with replacement (trials of one workload stay together).

Reported per arm and budget: recall, benign-launch positive rate, idle-control positive rate,
separation (recall - benign rate), their differences to base29, and 95% CIs (two-sided percentile
plus the one-sided 95% lower bound used by the selection rule: recall difference > -3 points).
A campaign without benign-launch controls (pulse-attack-dev) reports the benign columns as None.
"""
from __future__ import annotations

import argparse
from collections import defaultdict
import json
from pathlib import Path
import time

import numpy as np

from ..common import atomic_json
from ..integrity import sha256_file

BASE = 'base29'
REPS = 10000


def load_outcomes(path: Path):
    """(arm, scale) -> trial_key -> dict(workload, kind, detections over seeds, seeds)."""
    table = defaultdict(lambda: defaultdict(lambda: dict(hit=0, n=0)))
    meta = {}
    with path.open() as stream:
        for line in stream:
            r = json.loads(line)
            if r['outcome'] not in ('TP', 'FN', 'FP_expected', 'TN_expected'):
                continue   # unknown intervals carry no label evidence
            cell = table[r['arm'], float(r['scale'])][r['trial_key']]
            cell['hit'] += r['outcome'] in ('TP', 'FP_expected'); cell['n'] += 1
            meta[r['trial_key']] = (r['workload'], r['kind'])
    return table, meta


def per_workload(cells, meta, kind):
    """workload -> (sum of seed-averaged detections, trial count) for one label kind."""
    out = defaultdict(lambda: [0.0, 0])
    for key, cell in cells.items():
        workload, k = meta[key]
        if k == kind and cell['n']:
            out[workload][0] += cell['hit']/cell['n']; out[workload][1] += 1
    return out


def rate(groups, workloads, weights=None):
    hits = sum(groups[w][0]*(1 if weights is None else weights[i]) for i, w in enumerate(workloads) if w in groups)
    count = sum(groups[w][1]*(1 if weights is None else weights[i]) for i, w in enumerate(workloads) if w in groups)
    return hits/count if count else float('nan')


def bootstrap(arm_cells, base_cells, meta, reps=REPS, seed=20261019):
    # Pair on trials scored for both arms so differences are within-trial.
    shared = {k for k in arm_cells if k in base_cells and arm_cells[k]['n'] and base_cells[k]['n']}
    arm = {k: arm_cells[k] for k in shared}; base = {k: base_cells[k] for k in shared}
    groups = {(who, kind): per_workload(cells, meta, kind)
              for who, cells in (('arm', arm), ('base', base)) for kind in ('attack', 'benign', 'expected_normal')}
    workloads = sorted({meta[k][0] for k in shared})
    rng = np.random.default_rng(seed)

    def stats(weights):
        recall = rate(groups['arm', 'attack'], workloads, weights)
        benign = rate(groups['arm', 'benign'], workloads, weights)
        brecall = rate(groups['base', 'attack'], workloads, weights)
        bbenign = rate(groups['base', 'benign'], workloads, weights)
        control = rate(groups['arm', 'expected_normal'], workloads, weights)
        bcontrol = rate(groups['base', 'expected_normal'], workloads, weights)
        return np.array([recall, benign, control, recall - benign, recall - brecall, benign - bbenign,
                         control - bcontrol, (recall - benign) - (brecall - bbenign)])
    point = stats(None)
    draws = np.array([stats(np.bincount(rng.integers(0, len(workloads), len(workloads)), minlength=len(workloads)))
                      for _ in range(reps)])
    names = ('recall', 'benign_rate', 'control_rate', 'separation', 'recall_diff', 'benign_diff', 'control_diff',
             'separation_diff')
    out = {}
    for i, name in enumerate(names):
        col = draws[:, i][np.isfinite(draws[:, i])]
        if not np.isfinite(point[i]) or not len(col):
            out[name] = None   # no trials of that kind (e.g. no benign-launch controls in the campaign)
            continue
        out[name] = dict(point=float(point[i]), ci95=[float(np.percentile(col, 2.5)), float(np.percentile(col, 97.5))],
                         lower95_one_sided=float(np.percentile(col, 5)))
    out['paired_trials'] = len(shared); out['workloads'] = len(workloads)
    return out


def run(budget_dir: Path, output: Path, budgets=None, reps=REPS):
    """``budgets`` default: every budget of the arm_budget run at which base29 has a matched scale."""
    results = json.loads((budget_dir/'RESULTS.json').read_text())
    table, meta = load_outcomes(budget_dir/'TRIAL_OUTCOMES.jsonl')
    if budgets is None:
        budgets = [b for b, picks in results['matched_budget'].items() if (picks or {}).get(BASE)]
    report = {}
    for b in budgets:
        picks = results['matched_budget'].get(b) or {}
        base = picks.get(BASE)
        if not base:
            continue
        base_cells = table[BASE, float(base['alpha_scale'])]
        report[b] = {}
        for arm, pick in picks.items():
            if pick is None:
                continue
            report[b][arm] = dict(alpha_scale=pick['alpha_scale'],
                                  **bootstrap(table[arm, float(pick['alpha_scale'])], base_cells, meta, reps))
            diff = report[b][arm]['recall_diff']
            report[b][arm]['non_inferior_recall'] = diff is not None and diff['lower95_one_sided'] > -0.03
    result = dict(schema='pulse-r4-arm-bootstrap-v1', budget_results=str(budget_dir), reps=reps,
                  cluster='workload', pairing='trial (seed-averaged outcome)', reference=BASE,
                  note='matched budgets use the grid scale with episodes <= B (no interpolation)',
                  budgets=report, inputs={p.name: sha256_file(p) for p in (budget_dir/'RESULTS.json', budget_dir/'TRIAL_OUTCOMES.jsonl')},
                  source_sha256=sha256_file(Path(__file__)), finished_at_unix=time.time())
    atomic_json(output, result)
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument('--budget-dir', type=Path, required=True, help='arm_budget output with TRIAL_OUTCOMES.jsonl')
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--reps', type=int, default=REPS)
    parser.add_argument('--budget', action='append', help='budget key(s); default: all with a base29 match')
    args = parser.parse_args()
    result = run(args.budget_dir, args.output, budgets=args.budget, reps=args.reps)
    for b, arms in result['budgets'].items():
        print('== budget', b)
        key = 'separation' if all(r['separation'] for r in arms.values()) else 'recall'
        for arm, r in sorted(arms.items(), key=lambda kv: -kv[1][key]['point']):
            print(f"  {arm:26s} " + ' '.join(f"{name} {fmt(r[name])}" for name in
                  ('recall', 'benign_rate', 'control_rate', 'recall_diff', 'separation_diff')))


def fmt(stat):
    if stat is None:
        return '-'
    return f"{stat['point']:+.3f}[{stat['ci95'][0]:+.3f},{stat['ci95'][1]:+.3f}]"


if __name__ == '__main__':
    main()
