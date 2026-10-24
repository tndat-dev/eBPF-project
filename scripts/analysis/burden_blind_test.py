#!/usr/bin/env python3
"""Blind test of the burden-reduction-v1 choices on the confirmation run (rule 5), plus the live-burden check.

On the confirmation run's window table (continuous streams, refreshed calibration, Mondrian classes from the
calibration-span table), scores with the metrics of burden_levers.py:

- ``reference``: CUSUM b3/h6 as registered by burden-reduction-v1 (on_alarm=keep);
- ``stable``: the running ML stable rule, CUSUM b3/h6 with on_alarm=cap (stable-selection-v1 amendment 1);
- the choice per latency tier written in BURDEN-LEVERS.json by the development selection.

Rule 5 (registered 22/10 15:34): a choice is adopted only if, on this run, it is feasible (recall >= 95 %,
precision >= 95 %, control <= 5 %, p95 within its tier) and its burden is <= 0.9 x the reference's. The trial
metrics use the primary attack rates (6, 12, 24 per second, the composition of the development runs); every rate is
reported. When the table carries the live ``preview`` column, the burden of what the run actually alerted on and
the window agreement between the live previews and the recomputed rule the run ran (``--live-rule``: ``stable``
by default; ``le3s`` for the run of the adopted replica-discount choice) are reported too.
"""
import argparse, json, sys, time
from collections import defaultdict
from pathlib import Path

import numpy as np

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
sys.path.insert(0, str(Path(__file__).resolve().parent))
import burden_levers as bl  # noqa: E402

PRIMARY_RATES = (6, 12, 24)


def burden_ci(arr, positive, reps=10000, seed=20261022):
    """Workload-clustered bootstrap 95 % CI of episodes per replica-hour (normal span)."""
    pos = positive & arr['normal']
    workloads = np.unique(arr['workload'][arr['normal']])
    ep, hours = [], []
    for w in workloads:
        sel = arr['workload'] == w
        ep.append(bl.episodes(arr['ident'][sel], arr['end'][sel], pos[sel], bl.EPISODE_QUIET))
        hours.append(float(np.sum((arr['end'] - arr['start'])[sel & arr['normal']])) / 3600)
    ep, hours = np.array(ep, float), np.array(hours, float)
    rng = np.random.default_rng(seed)
    idx = rng.integers(0, len(ep), size=(reps, len(ep)))
    boot = ep[idx].sum(1) / hours[idx].sum(1)
    return dict(point=float(ep.sum() / hours.sum()), ci95=[float(np.percentile(boot, 2.5)), float(np.percentile(boot, 97.5))],
                workloads=int(len(ep)), reps=reps)


def adopted(m, ref, tier):
    ok_p95 = bl.TIERS[tier]
    feasible = (m['attack'] is not None and m['attack'] >= 0.95 and m['precision'] is not None and m['precision'] >= 0.95
                and m['control'] is not None and m['control'] <= 0.05 and m['p95'] is not None and ok_p95(m['p95']))
    return dict(feasible=bool(feasible), burden_ratio=m['burden'] / ref['burden'] if ref['burden'] else None,
                adopted=bool(feasible and m['burden'] <= 0.9 * ref['burden']))


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument('--run', required=True, help='name=<n>,table=<npz>,since=<unix>,campaign=<dir>')
    ap.add_argument('--calibration', required=True)
    ap.add_argument('--calibration-table', required=True)
    ap.add_argument('--ml-results', required=True, help='BURDEN-LEVERS.json of the development selection')
    ap.add_argument('--live-rule', default='stable', help='recomputed rule the live previews followed')
    ap.add_argument('--output', required=True)
    a = ap.parse_args()
    kv = defaultdict(list)
    for part in a.run.split(','):
        k, v = part.split('=', 1); kv[k].append(v)
    ml = json.loads(Path(a.ml_results).read_text())
    tree, support = bl.load_calibration(a.calibration)
    classes, checks = bl.calibration_classes(a.calibration_table, tree, support)
    arr, p, trials, info = bl.prepare(kv['table'][0], float(kv['since'][0]), kv['campaign'], tree, support, classes)
    primary = trials.subset(np.isin(trials.rate, PRIMARY_RATES))
    x = -np.log(np.maximum(p['joint'], 1e-12))
    alarms = {'reference': bl.cusum_alarms(x - 3.0, arr['new'], 6.0, 'keep'),
              'stable': bl.cusum_alarms(x - 3.0, arr['new'], 6.0, 'cap')}
    choices = {tier: c['choice'] for tier, c in ml['selection'].items() if c.get('choice') and c.get('proposed')}
    for tier, config in choices.items():
        variant, mode, rule = config.split('|')
        (_, alarm), = bl.rules(variant, p[variant], arr['alpha'], bl.discount_mask(arr, mode), arr['new'], only=rule)
        alarms[tier] = alarm
    metrics = {name: bl.metrics(alarm, arr, primary, by_scenario=True) for name, alarm in alarms.items()}
    by_rate = {name: {f'{r:g}': bl.metrics(alarm, arr, trials.subset(trials.rate == r), by_scenario=False)
                      for r in sorted(set(trials.rate[~np.isnan(trials.rate)].tolist()))} for name, alarm in alarms.items()}
    verdict = {tier: dict(config=config, **adopted(metrics[tier], metrics['reference'], tier),
                          vs_stable_burden_ratio=metrics[tier]['burden'] / metrics['stable']['burden']
                          if metrics['stable']['burden'] else None)
               for tier, config in choices.items()}
    burden_cis = {name: burden_ci(arr, alarm) for name, alarm in alarms.items()}
    live = None
    if 'preview' in arr:
        prev, rule = arr['preview'].astype(bool), alarms[a.live_rule]
        live = dict(burden_live_previews=bl.episodes(arr['ident'], arr['end'], prev & arr['normal'], bl.EPISODE_QUIET) / arr['hours'],
                    live_rule=a.live_rule, window_agreement=float(np.mean(prev == rule)),
                    live_only_windows=int((prev & ~rule).sum()), recomputed_only_windows=int((rule & ~prev).sum()),
                    live_preview_windows=int(prev.sum()), recomputed_windows=int(rule.sum()),
                    burden_live_ci=burden_ci(arr, prev))
        if a.live_rule == 'stable':      # key of the 23/10 receipt
            live['window_agreement_with_recomputed_stable'] = live['window_agreement']
    result = dict(schema='pulse-burden-blind-test-v1', protocol='sentinel_pulse/protocol/burden-reduction-v1.json (rule 5)',
                  run=a.run, ml_results=a.ml_results, calibration_reproduced=checks, run_info=info,
                  primary_rates=list(PRIMARY_RATES), metrics=metrics, by_rate=by_rate, verdict=verdict, live=live,
                  burden_ci=burden_cis,
                  computed_at_unix=time.time())
    Path(a.output).write_text(json.dumps(result, indent=1, default=str))
    print(json.dumps(dict(verdict=verdict, live=live, **{n: {k: metrics[n][k] for k in ('burden', 'attack', 'precision', 'control', 'p95')}
                                                          for n in metrics}), default=str))


if __name__ == '__main__':
    main()
