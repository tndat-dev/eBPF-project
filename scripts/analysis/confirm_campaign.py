#!/usr/bin/env python3
"""Live campaign result of the confirmation run against its registered expectations (stable-confirmation-v1).

Reads the coordinator's RESULTS.json (live outcomes of the running policy) and the trial files (attack rate,
scenario). Primary expectations are computed on the registered subset of attack rates (6, 12, 24 per second, the
composition of earlier runs); every rate and every scenario is reported too (rates 1 and 3: G4, no expectation).

- recall = TP / (TP + FN); unknown outcomes are left out and counted;
- precision = TP / (TP + idle-control FP), the 1:1 campaign precision used since 5.13a;
- control = idle-control positive rate; benign = benign-launch positive rate;
- p50 / p95 of kernel_to_preview_seconds over detected attacks;
- Wilson 95 % intervals for the rates.

Idle-control positives are also counted per container (workload@node). ``--exclude-container`` drops containers
for a sensitivity analysis decided after seeing data (Pulse 5.24/5.25); its output is marked ``post_hoc`` and never
replaces the registered verdict.
"""
import argparse, glob, json, math, time
from collections import Counter, defaultdict
from pathlib import Path


def wilson(k, n, z=1.959964):
    if not n:
        return None
    p = k / n
    d = 1 + z * z / n
    c = (p + z * z / (2 * n)) / d
    h = z * math.sqrt(p * (1 - p) / n + z * z / (4 * n * n)) / d
    return [max(0.0, c - h), min(1.0, c + h)]


def pct(values, q):
    if not values:
        return None
    v = sorted(values)
    i = (len(v) - 1) * q
    lo, hi = math.floor(i), math.ceil(i)
    return v[lo] + (v[hi] - v[lo]) * (i - lo)


def kind_of(o):
    if o['label'] == 'attack':
        return 'attack'
    return 'benign' if o.get('control_kind') == 'benign_exec' else 'control'


def load(campaign: Path):
    meta = {}
    for path in glob.glob(str(campaign / 'trials' / '*' / 'EVALUATION_INPUT.json')):
        d = json.loads(Path(path).read_text())
        a = d['attack']
        meta[str(a['trial_id']).split(':')[0]] = (a.get('rate_per_second'), a.get('scenario'))
    rows = []
    for o in json.loads((campaign / 'RESULTS.json').read_text())['outcomes']:
        rate, scenario = meta.get(str(o['trial_id']).split(':')[0], (None, None))
        rows.append(dict(kind=kind_of(o), outcome=o['outcome'], delay=o.get('kernel_to_preview_seconds'),
                         rate=rate, scenario=scenario, container=f"{o.get('workload_key')}@{o.get('node_name')}"))
    return rows


def summarize(rows):
    c = Counter((r['kind'], r['outcome']) for r in rows)
    tp, fn = c['attack', 'TP'], c['attack', 'FN']
    fp, tn = c['control', 'FP_expected'], c['control', 'TN_expected']
    bfp, btn = c['benign', 'FP_expected'], c['benign', 'TN_expected']
    delays = [r['delay'] for r in rows if r['kind'] == 'attack' and r['outcome'] == 'TP' and r['delay'] is not None]
    unknown = {k: sum(v for (kk, o), v in c.items() if kk == k and o == 'unknown') for k in ('attack', 'control', 'benign')}
    return dict(TP=tp, FN=fn, control_FP=fp, control_TN=tn, benign_FP=bfp, benign_TN=btn, unknown=unknown,
                recall=tp / (tp + fn) if tp + fn else None, recall_ci=wilson(tp, tp + fn),
                precision=tp / (tp + fp) if tp + fp else None, precision_ci=wilson(tp, tp + fp),
                control=fp / (fp + tn) if fp + tn else None, control_ci=wilson(fp, fp + tn),
                benign=bfp / (bfp + btn) if bfp + btn else None, benign_ci=wilson(bfp, bfp + btn),
                p50=pct(delays, 0.5), p95=pct(delays, 0.95), p99=pct(delays, 0.99), detected_with_delay=len(delays))


def control_fp_by_container(rows):
    c = Counter(r['container'] for r in rows if r['kind'] == 'control' and r['outcome'] == 'FP_expected')
    return dict(sorted(c.items(), key=lambda kv: (-kv[1], kv[0])))


def verdict(s):
    base = (s['precision'] is not None and s['precision'] >= 0.95 and s['recall'] is not None and s['recall'] >= 0.95
            and s['control'] is not None and s['control'] <= 0.05 and s['p95'] is not None)
    tier = None
    if base:
        tier = 'lt2s' if s['p95'] < 2.0 else ('le3s' if s['p95'] <= 3.0 else None)
    return dict(confirmed=tier is not None, tier=tier, precision_ok=s['precision'] is not None and s['precision'] >= 0.95,
                recall_ok=s['recall'] is not None and s['recall'] >= 0.95,
                control_ok=s['control'] is not None and s['control'] <= 0.05)


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument('--campaign', type=Path, required=True)
    ap.add_argument('--primary-rates', default='6,12,24')
    ap.add_argument('--exclude-container', action='append', default=[], metavar='WORKLOAD_KEY@NODE',
                    help='post-hoc sensitivity: leave this container out (repeatable)')
    ap.add_argument('--output', required=True)
    a = ap.parse_args()
    rows = [r for r in load(a.campaign) if r['container'] not in set(a.exclude_container)]
    primary = {int(x) for x in a.primary_rates.split(',')}
    prim = [r for r in rows if r['rate'] in primary]
    by_rate = defaultdict(list); by_scenario = defaultdict(list)
    for r in rows:
        by_rate[r['rate']].append(r)
    for r in prim:
        by_scenario[r['scenario']].append(r)
    p = summarize(prim)
    result = dict(schema='pulse-confirm-campaign-v1', campaign=str(a.campaign), protocol='stable-confirmation-v1 (+ amendment 1)',
                  primary_rates=sorted(primary), primary=p, verdict=verdict(p), all_rates=summarize(rows),
                  by_rate={str(k): summarize(v) for k, v in sorted(by_rate.items(), key=lambda kv: (kv[0] is None, kv[0] or 0))},
                  primary_by_scenario={str(k): summarize(v) for k, v in sorted(by_scenario.items(), key=lambda kv: str(kv[0]))},
                  primary_control_fp_by_container=control_fp_by_container(prim),
                  excluded_containers=sorted(a.exclude_container), post_hoc=bool(a.exclude_container),
                  trials=len(rows), computed_at_unix=time.time())
    Path(a.output).write_text(json.dumps(result, indent=1))
    print(json.dumps(dict(verdict=result['verdict'], primary={k: p[k] for k in ('recall', 'precision', 'control', 'benign', 'p95')},
                          by_rate={k: {m: v[m] for m in ('recall', 'p95')} for k, v in result['by_rate'].items()}), default=str))


if __name__ == '__main__':
    main()
