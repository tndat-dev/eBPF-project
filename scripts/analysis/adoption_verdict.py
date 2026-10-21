#!/usr/bin/env python3
"""Adoption rule of protocol baseline-fresh-replication-v1 applied to arm_budget + arm_bootstrap outputs."""
import argparse
import json
from pathlib import Path


def verdict(boot_arm: dict, matched_arm: dict, rule: dict) -> dict:
    r, s = boot_arm['recall_diff'], boot_arm['separation_diff']
    checks = dict(recall=r['point'] >= rule['recall_point_min'] and r['ci95'][0] >= rule['recall_lower_min'],
                  separation=s['point'] >= rule['separation_point_min'] and s['ci95'][0] >= rule['separation_lower_min'],
                  latency=matched_arm.get('delay_p95') is not None and matched_arm['delay_p95'] <= rule['p95_max_seconds'])
    return dict(adopt=all(checks.values()), checks=checks, recall_diff=r, separation_diff=s, delay_p95=matched_arm.get('delay_p95'))


RULE = dict(recall_point_min=0.0, recall_lower_min=-0.01, separation_point_min=0.0, separation_lower_min=-0.05,
            p95_max_seconds=2.0)   # protocol baseline-fresh-replication-v1, adoption_rule


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--bootstrap', required=True); p.add_argument('--budget-results', required=True)
    p.add_argument('--budget', default='1'); p.add_argument('--output', required=True)
    a = p.parse_args()
    boot = json.loads(Path(a.bootstrap).read_text())['budget_results'][a.budget]
    matched = json.loads(Path(a.budget_results).read_text())['matched_budget'][a.budget]
    out = {arm: verdict(boot[arm], matched[arm], RULE) for arm in ('autoencoder', 'tree_ae') if arm in boot and matched.get(arm)}
    adopted = sorted((arm for arm, v in out.items() if v['adopt']), key=lambda arm: -out[arm]['separation_diff']['point'])
    result = dict(schema='pulse-adoption-verdict-v1', budget=a.budget, rule=RULE, candidates=out,
                  next_scorer=adopted[0] if adopted else 'base29')
    Path(a.output).write_text(json.dumps(result, indent=2))
    print(json.dumps(dict(next_scorer=result['next_scorer'], checks={k: v['checks'] for k, v in out.items()})))


if __name__ == '__main__':
    main()
