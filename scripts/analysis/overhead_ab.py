#!/usr/bin/env python3
"""Overhead of the Pulse probe from ``scripts/overhead_ab.sh`` output (protocol overhead-ab-v1).

Per node and syscall mode: median ns/op per condition over the rounds; overhead of ``filtered`` and
``monitored`` relative to ``off`` as the median of the per-round paired ratios, with a percentile bootstrap
95 % CI over rounds (rounds are the unit: conditions rotate within a round). With a second probe build
(``monitored2``, exec-intent-v1 P1) also its overhead against ``off`` and against ``monitored`` (the extra cost of
the second build on the same monitored path).
"""
import argparse
from collections import defaultdict
import json
from pathlib import Path
import random
import statistics


def paired_overhead(rows, condition, reps=10000, seed=7, base='off'):
    """rows: [(round, condition, ns_per_op)] of one node+mode -> (median ratio - 1, [lo, hi]) or None."""
    by_round = defaultdict(dict)
    for r, c, ns in rows:
        by_round[r][c] = ns
    ratios = [v[condition] / v[base] for v in by_round.values() if condition in v and base in v]
    if not ratios:
        return None
    rng = random.Random(seed)
    boots = sorted(statistics.median(rng.choices(ratios, k=len(ratios))) - 1 for _ in range(reps))
    return statistics.median(ratios) - 1, [boots[int(0.025 * reps)], boots[int(0.975 * reps) - 1]], len(ratios)


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('inputs', nargs='+'); p.add_argument('--output', required=True)
    a = p.parse_args()
    data = defaultdict(list)
    for f in a.inputs:
        for line in Path(f).read_text().splitlines():
            d = json.loads(line)
            data[d['node'], d['mode']].append((d['round'], d['condition'], d['ns_per_op']))
    out = {}
    for (node, mode), rows in sorted(data.items()):
        med = {c: statistics.median(ns for _, cc, ns in rows if cc == c) for c in ('off', 'filtered', 'monitored', 'monitored2')
               if any(cc == c for _, cc, _ in rows)}
        res = dict(median_ns_per_op=med)
        for c in ('filtered', 'monitored', 'monitored2'):
            o = paired_overhead(rows, c)
            if o:
                res[f'{c}_overhead'] = dict(relative=o[0], ci95=o[1], rounds=o[2],
                                            added_ns_per_op=med.get(c, 0) - med.get('off', 0))
        o = paired_overhead(rows, 'monitored2', base='monitored')
        if o:
            res['monitored2_vs_monitored'] = dict(relative=o[0], ci95=o[1], rounds=o[2],
                                                  added_ns_per_op=med['monitored2'] - med['monitored'])
        out.setdefault(node, {})[mode] = res
    Path(a.output).write_text(json.dumps(dict(schema='pulse-overhead-ab-v1', protocol='sentinel_pulse/protocol/overhead-ab-v1.json',
                                              nodes=out), indent=1))
    for node, modes in out.items():
        for mode, r in modes.items():
            f, m = r.get('filtered_overhead'), r.get('monitored_overhead')
            print(node, mode, r['median_ns_per_op'], f and round(f['relative'] * 100, 2), m and round(m['relative'] * 100, 2))


if __name__ == '__main__':
    main()
