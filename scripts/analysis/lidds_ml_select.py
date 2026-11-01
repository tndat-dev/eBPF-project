#!/usr/bin/env python3
"""Choose Pulse's ML configuration on LID-DS 2021 development and CB-DS, score LID-DS 2021 official once
(protocol lidds-ml-v1), from lidds_ml_groups.py parts.

Eligible: LID-DS 2021 development precision at the base rate >= 95 %, development latency p95 <= 3 s, development
false-alarm recordings <= 2 %, CB-DS recall >= 95 % with false-alarm recordings <= 2 %. Selected: the highest
development recall; ties to fewer development false alarms, then fewer groups, then without fix A, then Bonferroni.
If no configuration is eligible, the highest development recall among those with development false alarms <= 2 % is
selected and reported as not qualified. Criteria on official (owner, 01/11): recall >= 95 %, precision at the base
rate >= 95 %, latency p95 <= 3 s.

    python3 lidds_ml_select.py --lidds2021 part1.json ... --cbds cbds-part.json --output lidds-ml-v1.json
"""
import argparse
import json
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parent))
import lidds_v3_combine as v3  # noqa: E402

DEV_PRECISION, DEV_P95, DEV_FA, CB_RECALL, CB_FA = 0.95, 3.0, 0.02, 0.95, 0.02
OWN_RECALL, OWN_PRECISION, OWN_P95 = 0.95, 0.95, 3.0
BASELINE = 'g0|plain|bonferroni'


def load_parts(paths):
    """{config: {scenario: {name: (split, detected, latency, false_alarm, subset)}}}."""
    out = {}
    for p in paths:
        d = json.loads(Path(p).read_text())
        for cfg, rows in d['outcomes'].items():
            out.setdefault(cfg, {})[d['scenario']] = {o[6]: (o[0], o[1], o[2], o[3] > 0, o[5]) for o in rows}
    return out


def metrics(per_scenario, part):
    pooled, per = [], {}
    for scenario, rows in per_scenario.items():
        keep = list(v3.subset_of(scenario, rows, part).values())
        per[scenario] = v3.metrics(keep)
        pooled.extend(keep)
    m = v3.metrics(pooled)
    m['detected_within_3s'] = sum(1 for x in pooled if x[0] == 'test-normal_and_attack' and x[2] is not None and x[2] <= 3.0)
    return m, per


def describe(cfg):
    groups, fix, fusion = cfg.split('|')
    return dict(groups=groups.split('+'), fix_a=fix == 'fixA', fusion=fusion)


def rank(r):
    d = describe(r['config'])
    return (-r['development']['detected'], r['development']['false_alarm_recordings'], len(d['groups']),
            d['fix_a'], d['fusion'] != 'bonferroni')


def screen(lidds, cbds):
    out = []
    for cfg in sorted(lidds):
        dev, _ = metrics(lidds[cfg], 'development')
        cb, _ = metrics(cbds[cfg], 'all') if cfg in cbds else (None, None)
        fa_ok = dev['false_alarm_rate'] is not None and dev['false_alarm_rate'] <= DEV_FA
        ok = (fa_ok and (dev['precision_base_rate'] or 0) >= DEV_PRECISION and dev['latency_p95'] is not None
              and dev['latency_p95'] <= DEV_P95 and cb is not None and cb['recall'] >= CB_RECALL
              and cb['false_alarm_rate'] <= CB_FA)
        out.append(dict(config=cfg, eligible=ok, development_fa_ok=fa_ok, development=dev, cbds=cb))
    return out


def select(results):
    eligible = sorted((r for r in results if r['eligible']), key=rank)
    if eligible:
        return eligible[0], True
    fallback = sorted((r for r in results if r['development_fa_ok']), key=rank)
    return (fallback[0] if fallback else None), False


def criteria(m):
    return dict(recall=m['recall'] >= OWN_RECALL, precision_base_rate=(m['precision_base_rate'] or 0) >= OWN_PRECISION,
                latency_p95=m['latency_p95'] is not None and m['latency_p95'] <= OWN_P95)


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument('--lidds2021', nargs='+', required=True)
    ap.add_argument('--cbds', nargs='+', required=True)
    ap.add_argument('--output', type=Path, required=True)
    a = ap.parse_args()
    lidds, cbds = load_parts(a.lidds2021), load_parts(a.cbds)
    results = screen(lidds, cbds)
    chosen, qualified = select(results)
    out = dict(schema='pulse-lidds-ml-v1-selection', protocol='sentinel_pulse/protocol/lidds-ml-v1.json',
               configurations=len(results), eligible=sum(r['eligible'] for r in results), qualified=qualified,
               selected=chosen, screening=results)
    base_off, base_per = metrics(lidds[BASELINE], 'official')
    out['baseline_official'] = dict(config=BASELINE, pooled=base_off, scenarios=base_per)
    if chosen:
        off, per = metrics(lidds[chosen['config']], 'official')
        out['official'] = dict(pooled=off, scenarios=per)
        out['criteria'] = criteria(off)
    a.output.write_text(json.dumps(out, indent=1, default=float))
    brief = lambda m: {k: m[k] for k in ('recall', 'detected', 'false_alarm_rate', 'precision_base_rate',
                                         'latency_p50', 'latency_p95', 'detected_within_3s')}
    print(json.dumps(dict(eligible=out['eligible'], qualified=qualified, selected=chosen and chosen['config'],
                          development=chosen and brief(chosen['development']), cbds=chosen and chosen['cbds'],
                          official=chosen and brief(out['official']['pooled']), criteria=out.get('criteria'),
                          baseline_official=brief(base_off)), indent=1, default=float))


if __name__ == '__main__':
    main()
