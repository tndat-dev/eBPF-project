#!/usr/bin/env python3
"""Overhead of the Pulse probe from ``scripts/overhead_ab.sh`` output (protocol overhead-ab-v1).

Per node and syscall mode: median ns/op per condition over the rounds; overhead of ``filtered`` and
``monitored`` relative to ``off`` as the median of the per-round paired ratios, with a percentile bootstrap
95 % CI over rounds (rounds are the unit: conditions rotate within a round). With a second probe build
(``monitored2``, exec-intent-v1 P1) also its overhead against ``off`` and against ``monitored`` (the extra cost of
the second build on the same monitored path). With the token probe (tokB, tokC, tokD, tokD_filtered) also each
token condition against ``monitored``, condition A of reports/Thiết kế probe token Pulse.md.
"""
import argparse
from collections import defaultdict
import json
from pathlib import Path
import random
import statistics

CONDITIONS = ['off', 'filtered', 'monitored', 'monitored2', 'tokB', 'tokC', 'tokD', 'tokD_filtered', 'tokDfx', 'tokDfx_filtered']


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
    p.add_argument('--protocol', default='sentinel_pulse/protocol/overhead-ab-v1.json')
    a = p.parse_args()
    data = defaultdict(list)
    for f in a.inputs:
        for line in Path(f).read_text().splitlines():
            d = json.loads(line)
            data[d['node'], d['mode']].append((d['round'], d['condition'], d['ns_per_op']))
    out = {}
    for (node, mode), rows in sorted(data.items()):
        present = sorted({cc for _, cc, _ in rows}, key=lambda c: (CONDITIONS.index(c) if c in CONDITIONS else 99, c))
        med = {c: statistics.median(ns for _, cc, ns in rows if cc == c) for c in present}
        res = dict(median_ns_per_op=med)
        for c in present[1:] if present and present[0] == 'off' else present:
            o = paired_overhead(rows, c)
            if o:
                res[f'{c}_overhead'] = dict(relative=o[0], ci95=o[1], rounds=o[2],
                                            added_ns_per_op=med.get(c, 0) - med.get('off', 0))
        for c in ('monitored2', 'tokB', 'tokC', 'tokD', 'tokDfx'):   # extra cost over the current probe (condition A)
            o = paired_overhead(rows, c, base='monitored') if c in med and 'monitored' in med else None
            if o:
                res[f'{c}_vs_monitored'] = dict(relative=o[0], ci95=o[1], rounds=o[2],
                                                added_ns_per_op=med[c] - med['monitored'])
        out.setdefault(node, {})[mode] = res
    Path(a.output).write_text(json.dumps(dict(schema='pulse-overhead-ab-v1', protocol=a.protocol,
                                              nodes=out), indent=1))
    for node, modes in out.items():
        for mode, r in modes.items():
            added = {k.replace('_overhead', ''): round(v['added_ns_per_op'], 1) for k, v in r.items() if k.endswith('_overhead')}
            over_a = {k.replace('_vs_monitored', '+'): round(v['added_ns_per_op'], 1) for k, v in r.items() if k.endswith('_vs_monitored')}
            print(node, mode, 'off', round(r['median_ns_per_op'].get('off', 0), 1), 'added ns', added, 'over A', over_a)


if __name__ == '__main__':
    main()
