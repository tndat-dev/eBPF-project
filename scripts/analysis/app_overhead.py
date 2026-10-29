#!/usr/bin/env python3
"""Application latency with and without the Pulse probe from ``scripts/app_overhead_ab.py`` (protocol app-overhead-v1).

Requests are assigned to the block whose [start + settle, end) holds their scheduled time; latency is completion -
scheduled time (open loop). Per round, the probe/off ratio of the block p50/p95/p99 (all requests, and per endpoint);
overhead = median ratio over rounds - 1 with a percentile bootstrap 95 % CI over rounds (10,000 draws).
Standard library only.
"""
import argparse
from collections import defaultdict
import json
from pathlib import Path
import random
import statistics

QUANTILES = (('p50', 0.50), ('p95', 0.95), ('p99', 0.99))


def quantile(xs, q):
    xs = sorted(xs)
    pos = q * (len(xs) - 1); lo = int(pos); hi = min(lo + 1, len(xs) - 1)
    return xs[lo] + (xs[hi] - xs[lo]) * (pos - lo)


def bootstrap_median(values, reps=10000, seed=7):
    rng = random.Random(seed)
    boots = sorted(statistics.median(rng.choices(values, k=len(values))) for _ in range(reps))
    return [boots[int(0.025 * reps)], boots[int(0.975 * reps) - 1]]


def assign(requests, blocks, settle):
    """-> {(round, condition): [request rows]} for requests scheduled in [start + settle, end)."""
    out = defaultdict(list)
    spans = sorted((b['start'] + settle, b['end'], b['round'], b['condition']) for b in blocks)
    for r in requests:
        for lo, hi, rnd, cond in spans:
            if lo <= r['scheduled'] < hi:
                out[rnd, cond].append(r); break
    return out


def paired(by_block, key, metric):
    """key(row) -> group or None; -> {group: dict(overhead, ci, ms, rounds)} for the probe/off ratio of ``metric``."""
    q = dict(QUANTILES)[metric]
    per_round = defaultdict(dict)
    for (rnd, cond), rows in by_block.items():
        groups = defaultdict(list)
        for r in rows:
            g = key(r)
            if g is not None and r['status'] == 200:
                groups[g].append(r['done'] - r['scheduled'])
        for g, lat in groups.items():
            per_round[g].setdefault(rnd, {})[cond] = quantile(lat, q)
    out = {}
    for g, rounds in sorted(per_round.items()):
        pairs = [(v['probe'], v['off']) for v in rounds.values() if 'probe' in v and 'off' in v]
        if not pairs:
            continue
        ratios = [p / o - 1 for p, o in pairs]
        out[g] = dict(overhead=statistics.median(ratios), ci95=bootstrap_median(ratios), rounds=len(pairs),
                      added_ms=statistics.median((p - o) * 1000 for p, o in pairs),
                      off_ms=statistics.median(o * 1000 for _, o in pairs), probe_ms=statistics.median(p * 1000 for p, _ in pairs))
    return out


def pooled(by_block):
    out = {}
    for cond in ('off', 'probe'):
        rows = [r for (_, c), rs in by_block.items() if c == cond for r in rs]
        ok = [r['done'] - r['scheduled'] for r in rows if r['status'] == 200]
        service = [r['done'] - r['sent'] for r in rows if r['status'] == 200]
        out[cond] = dict(requests=len(rows), errors=sum(r['status'] != 200 for r in rows),
                         error_rate=sum(r['status'] != 200 for r in rows) / len(rows) if rows else None,
                         **{m + '_ms': quantile(ok, q) * 1000 for m, q in QUANTILES if ok},
                         service_p95_ms=quantile(service, 0.95) * 1000 if service else None)
    return out


def cpu(blocks):
    """Probe CPU in cores per worker (probe blocks) and node busy cores off vs probe (median over blocks)."""
    probe = defaultdict(list); busy = defaultdict(lambda: defaultdict(list))
    for b in blocks:
        length = b['end'] - b['start']
        for host, n in b['nodes'].items():
            if n['total']:
                busy[host][b['condition']].append(n['busy'] / n['total'])
        for host, ns in (b.get('probe_cpu_ns') or {}).items():
            if ns is not None:
                probe[host].append(ns / 1e9 / length)
    return dict(probe_cores={h: statistics.median(v) for h, v in sorted(probe.items())},
                node_busy_share={h: {c: statistics.median(v) for c, v in sorted(d.items())} for h, d in sorted(busy.items())})


def analyse(requests, events, settle=30.0):
    blocks = [e for e in events if e.get('event') == 'block']
    by_block = assign(requests, blocks, settle)
    overall = {m: paired(by_block, lambda _: 'all', m).get('all') for m, _ in QUANTILES}
    return dict(blocks=len(blocks), rounds=len({b['round'] for b in blocks}), settle_seconds=settle,
                stopped=[e for e in events if e.get('event') in ('stopped', 'refused')],
                pooled=pooled(by_block),
                all_requests={m: v for m, v in overall.items() if v},
                per_endpoint={m: paired(by_block, lambda r: r['endpoint'], m) for m, _ in QUANTILES},
                cpu=cpu(blocks))


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument('run_dir', type=Path); ap.add_argument('--output', type=Path, required=True)
    ap.add_argument('--settle', type=float, default=30.0)
    a = ap.parse_args()
    requests = [json.loads(l) for l in (a.run_dir / 'requests.jsonl').read_text().splitlines()]
    events = [json.loads(l) for l in (a.run_dir / 'blocks.jsonl').read_text().splitlines()]
    doc = dict(schema='app-overhead-v1-result', protocol='sentinel_pulse/protocol/app-overhead-v1.json',
               **analyse(requests, events, a.settle))
    a.output.write_text(json.dumps(doc, indent=1))
    print(json.dumps(doc['all_requests'], indent=1))


if __name__ == '__main__':
    main()
