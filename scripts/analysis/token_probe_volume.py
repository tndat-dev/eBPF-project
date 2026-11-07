#!/usr/bin/env python3
"""Volume and content of the token probe on real pods (loader output of ``make tokens``, ``--tokens grams``).

Reads the loader's stdout (JSON lines) and the resolver's cgroups.json captured at the same time; per workload:
windows, events and distinct grams per window, output bytes; for the node: output bytes per second, drain time, gram
insert and d_path failures, and the most frequent tokens (decoded; directories only as their 20-bit hash, which the
probe does not invert). No decision is made here.

    python3 token_probe_volume.py --loader out.jsonl --cgroups cgroups.json --output volume.json
"""
import argparse
from collections import Counter, defaultdict
import json
from pathlib import Path
import statistics
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
from sentinel_pulse.collector.capture import workload_key  # noqa: E402

TOK_NONE = 0xFFFFFFFF
KINDS = {0: 'name', 1: 'errno', 2: 'size', 3: 'open'}


def decode(t, names):
    if t == TOK_NONE:
        return '_'
    nr, kind, d = t >> 23, (t >> 21) & 3, t & 0x1FFFFF
    n = names.get(nr, str(nr))
    if kind == 0:
        return n
    if kind == 1:
        return f'{n}!{d & 0xFFF}'
    if kind == 2:
        return f'{n}#{d & 0xF}'
    return f"{n}:{'w' if d >> 20 else 'r'}:dir{d & 0xFFFFF:05x}"


def syscall_names():
    try:
        import re
        text = Path('/usr/include/x86_64-linux-gnu/asm/unistd_64.h').read_text()
        return {int(n): s for s, n in re.findall(r'^#define __NR_(\w+)\s+(\d+)$', text, re.M)}
    except OSError:
        return {}


def pct(values, q):
    values = sorted(values)
    return values[min(len(values) - 1, int(q * len(values)))] if values else None


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument('--loader', type=Path, required=True)
    ap.add_argument('--cgroups', type=Path, required=True)
    ap.add_argument('--output', type=Path, required=True)
    a = ap.parse_args()
    meta = json.loads(a.cgroups.read_text())['cgroups']
    names = syscall_names()
    per = defaultdict(lambda: dict(windows=0, events=[], grams=[], bytes=0))
    kinds, tokens, drains = Counter(), Counter(), []
    first = last = None
    total_bytes = token_bytes = 0
    for line in a.loader.read_text().splitlines():
        total_bytes += len(line) + 1
        r = json.loads(line)
        if r['type'] == 'token_drain':
            drains.append(r)
            continue
        if r['type'] != 'token_grams':
            continue
        token_bytes += len(line) + 1
        first = r['window_end'] if first is None else min(first, r['window_end'])
        last = r['window_end'] if last is None else max(last, r['window_end'])
        item = meta.get(str(r['cgroup_id']), {})
        key = workload_key(item) if item else f"cgroup {r['cgroup_id']}"
        w = per[key]
        w['windows'] += 1
        w['events'].append(r['events'])
        w['grams'].append(len(r['grams']))
        w['bytes'] += len(line) + 1
        for *g, c in r['grams']:
            kinds[KINDS[(g[3] >> 21) & 3]] += c
            tokens[decode(g[3], names)] += c
    seconds = (last - first + 0.5) if first is not None else 0
    out = dict(seconds=seconds, loader_bytes=total_bytes, token_line_bytes=token_bytes,
               token_bytes_per_second=token_bytes / seconds if seconds else None,
               drain_seconds=dict(median=statistics.median(d['drain_seconds'] for d in drains) if drains else None,
                                  p95=pct([d['drain_seconds'] for d in drains], .95),
                                  max=max((d['drain_seconds'] for d in drains), default=None)),
               last_drain=drains[-1] if drains else None,
               events_by_kind=dict(kinds), top_tokens=tokens.most_common(40),
               workloads={k: dict(windows=v['windows'], events_median=statistics.median(v['events']),
                                  events_max=max(v['events']), grams_median=statistics.median(v['grams']),
                                  grams_max=max(v['grams']), bytes=v['bytes'])
                          for k, v in sorted(per.items())})
    a.output.write_text(json.dumps(out, indent=1))
    print(json.dumps({k: out[k] for k in ('seconds', 'token_bytes_per_second', 'drain_seconds', 'events_by_kind')}, indent=1))
    for k, v in out['workloads'].items():
        print(f"{k:55s} win {v['windows']:5d} events med {v['events_median']:8.0f} max {v['events_max']:8d} "
              f"grams med {v['grams_median']:6.0f} max {v['grams_max']:6d}")


if __name__ == '__main__':
    main()
