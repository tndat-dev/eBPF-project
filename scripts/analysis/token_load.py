#!/usr/bin/env python3
"""Load of the token probe in a live run: events and distinct grams per window, map occupancy, drops.

Per container and closed 0.5 s window (tokens.jsonl of the declared segments): events (syscall returns of the
container's watched threads, one token and one gram each) and distinct grams (the map entries that window needed).
Per node and window: the sum over containers of both, against the map capacity (pulse_grams, 262,144 entries; about two
windows live at once). Over the whole run, from the loader's token_drain lines (cumulative counters of the probe): grams
counted, map entries drained, inserts that failed because the map was full, directory walks cut short, drain time.

    python3 token_load.py --run-root RUN --output out.json [--segments s00010 s00020 ...]
"""
import argparse
from collections import defaultdict
import json
from pathlib import Path
import sys

import numpy as np

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
from sentinel_pulse.common import open_sealed  # noqa: E402

CAPACITY = 262144
SEGMENTS = ('s00010', 's00020', 's00030', 's00040', 's00045')


def pct(values):
    a = np.asarray(values, float)
    if not len(a):
        return None
    return dict(n=int(len(a)), p50=float(np.percentile(a, 50)), p99=float(np.percentile(a, 99)), max=float(a.max()),
                mean=float(a.mean()))


def windows(seg):
    per_container_events, per_container_grams = [], []
    node = defaultdict(lambda: [0, 0])
    with open_sealed(seg / 'tokens.jsonl') as stream:
        for line in stream:
            if '"token_window"' not in line:
                continue
            row = json.loads(line)
            ev, g = int(row['events']), len(row['grams'])
            per_container_events.append(ev)
            per_container_grams.append(g)
            cell = node[(row['node_name'], row['window'])]
            cell[0] += ev
            cell[1] += g
    return per_container_events, per_container_grams, list(node.values())


def drains(worker):
    """Last cumulative counters and every drain time of one worker, from the token_drain lines of all segments."""
    last, times = None, []
    for seg in sorted((worker / 'segments').iterdir()):
        path = seg / 'features.jsonl'
        if not (path.exists() or path.with_suffix('.jsonl.gz').exists()):
            continue
        with open_sealed(path) as stream:
            for line in stream:
                if not line.startswith('{"type":"token_drain"'):
                    continue
                row = json.loads(line)
                times.append(row['drain_seconds'])
                last = row
    return last, times


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument('--run-root', type=Path, required=True)
    ap.add_argument('--output', type=Path, required=True)
    ap.add_argument('--segments', nargs='+', default=list(SEGMENTS))
    a = ap.parse_args()
    ev, gr, node = [], [], []
    for seg in sorted(p for p in a.run_root.glob('workers/*/segments/*') if p.name in a.segments):
        e, g, n = windows(seg)
        ev += e
        gr += g
        node += n
    doc = dict(schema='token-load-v1', run=str(a.run_root), segments=a.segments, map_capacity=CAPACITY,
               container_window=dict(events=pct(ev), distinct_grams=pct(gr)),
               node_window=dict(events=pct([x[0] for x in node]), distinct_grams=pct([x[1] for x in node]),
                                largest_share_of_capacity=max(x[1] for x in node) / CAPACITY if node else None),
               workers={})
    for worker in sorted(a.run_root.glob('workers/*')):
        last, times = drains(worker)
        if last:
            doc['workers'][worker.name] = dict(grams_cumulative=last['grams_cumulative'], entries_cumulative=last['entries_cumulative'],
                                               insert_fail_cumulative=last['insert_fail_cumulative'],
                                               dir_fail_cumulative=last['dir_fail_cumulative'], drain_seconds=pct(times))
    a.output.write_text(json.dumps(doc, indent=1))
    print(json.dumps(dict(container=doc['container_window'], node=doc['node_window'],
                          drops={k: v['insert_fail_cumulative'] for k, v in doc['workers'].items()})))


if __name__ == '__main__':
    main()
