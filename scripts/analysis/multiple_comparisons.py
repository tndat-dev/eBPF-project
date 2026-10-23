#!/usr/bin/env python3
"""Holm correction over a family of baseline comparisons (G1: "kiểm định nhiều so sánh").

Reads an arm bootstrap (``sentinel_pulse.syscall_study.arm_bootstrap``, which carries a two-sided
percentile-bootstrap p-value per difference to the reference) and treats every candidate x budget x metric as one
family. Holm's step-down procedure controls the family-wise error rate at ``--alpha`` under any dependence between
the tests. A robustness check of conclusions already drawn from 95 % CIs; it selects nothing.

    python3 scripts/analysis/multiple_comparisons.py --bootstrap FRESH-BOOTSTRAP.json \\
        --metric recall_diff --metric separation_diff --output MULTIPLE-COMPARISONS.json
"""
import argparse
import json
from pathlib import Path


def holm(pvalues):
    """Holm-adjusted p-values, in the input order."""
    order = sorted(range(len(pvalues)), key=lambda i: pvalues[i])
    adjusted, running = [0.0] * len(pvalues), 0.0
    for rank, i in enumerate(order):
        running = max(running, min(1.0, (len(pvalues) - rank) * pvalues[i]))
        adjusted[i] = running
    return adjusted


def family(bootstrap, metrics, reference):
    rows = []
    for budget, arms in sorted(bootstrap['budgets'].items(), key=lambda kv: float(kv[0])):
        for arm, r in sorted(arms.items()):
            if arm == reference:
                continue
            for metric in metrics:
                m = r.get(metric)
                if m and m.get('p_two_sided') is not None:
                    rows.append(dict(budget=budget, arm=arm, metric=metric, point=m['point'], ci95=m['ci95'],
                                     p=m['p_two_sided'], ci_excludes_zero=m['ci95'][0] > 0 or m['ci95'][1] < 0))
    return rows


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument('--bootstrap', type=Path, required=True)
    ap.add_argument('--metric', action='append', required=True)
    ap.add_argument('--alpha', type=float, default=0.05)
    ap.add_argument('--output', type=Path, required=True)
    a = ap.parse_args()
    boot = json.loads(a.bootstrap.read_text())
    rows = family(boot, a.metric, boot.get('reference', 'base29'))
    for row, adj in zip(rows, holm([r['p'] for r in rows])):
        row.update(p_holm=adj, significant_holm=adj < a.alpha)
    result = dict(schema='pulse-multiple-comparisons-v1', bootstrap=str(a.bootstrap), reps=boot.get('reps'),
                  method='Holm step-down over every candidate x budget x metric', alpha=a.alpha, tests=len(rows),
                  changed=[r for r in rows if r['ci_excludes_zero'] != r['significant_holm']], rows=rows)
    a.output.write_text(json.dumps(result, indent=1))
    for r in rows:
        print(f"{r['budget']:>5} {r['arm']:13s} {r['metric']:16s} {r['point']:+.3f} p={r['p']:.4f} holm={r['p_holm']:.4f} "
              f"{'*' if r['significant_holm'] else ' '}{'' if r['ci_excludes_zero'] == r['significant_holm'] else '  (CI and Holm disagree)'}")


if __name__ == '__main__':
    main()
