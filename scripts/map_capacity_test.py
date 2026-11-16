#!/usr/bin/env python3
"""Capacity of the token probe's gram map (protocol map-capacity-v1), on one worker, as root, in an isolated cgroup.

The loader of a token build watches only a new cgroup; testbed/bench/gram_stress runs in it at rising load levels
(threads x calls per second per thread, about one new 4-gram per call). Per level, from the loader's own lines:
achieved calls per second (gram_stress), token events counted in the level's windows, distinct grams per window
(map entries the window needed), failed gram inserts (the map was full), drain time per frame. A level loses events when
its window events fall short of the calls made.

    python3 map_capacity_test.py --build DIR --out DIR [--levels 50000,100000,...] [--threads 8] [--seconds 10]
"""
import argparse
import json
import os
from pathlib import Path
import platform
import statistics
import subprocess
import sys
import time

DEFAULT_LEVELS = (50000, 100000, 200000, 300000, 400000, 600000, 800000, 1200000)


def in_cgroup(cg, argv):
    return subprocess.run(['sh', '-c', f'echo $$ > {cg}/cgroup.procs && exec "$@"', 'sh', *argv],
                          capture_output=True, text=True, check=True)


def summarize(level, run, t0, t1, grams, drains):
    rows = [r for r in grams if t0 + 0.5 <= r['window_end'] <= t1 + 0.5]
    inside = [d for d in drains if t0 <= d['observed_at'] <= t1 + 1.0]
    before = [d for d in drains if d['observed_at'] < t0]
    fail0 = before[-1]['insert_fail_cumulative'] if before else 0
    fail1 = inside[-1]['insert_fail_cumulative'] if inside else fail0
    distinct = [r['distinct'] for r in rows]
    events = sum(r['events'] for r in rows)
    return dict(offered_calls_per_second=level, threads=run['threads'], calls=run['events'],
                achieved_calls_per_second=run['events'] / run['seconds'], windows=len(rows), window_events=events,
                events_lost=max(0, run['events'] - events), failed_inserts=fail1 - fail0,
                distinct_grams_per_window=dict(p50=statistics.median(distinct) if distinct else 0,
                                               max=max(distinct) if distinct else 0),
                drain_seconds=dict(p50=statistics.median(d['drain_seconds'] for d in inside) if inside else None,
                                   max=max(d['drain_seconds'] for d in inside) if inside else None))


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument('--build', type=Path, required=True)
    ap.add_argument('--stress', type=Path, required=True, help='compiled testbed/bench/gram_stress')
    ap.add_argument('--out', type=Path, required=True)
    ap.add_argument('--levels', default=','.join(map(str, DEFAULT_LEVELS)), help='total calls per second, comma-separated')
    ap.add_argument('--threads', type=int, default=8)
    ap.add_argument('--seconds', type=float, default=10.0)
    a = ap.parse_args()
    if os.geteuid() != 0:
        sys.exit('run as root')
    levels = [int(x) for x in a.levels.split(',')]
    a.out.mkdir(parents=True, exist_ok=False)
    cg = Path('/sys/fs/cgroup/pulse-map-capacity')
    cg.mkdir(exist_ok=False)
    cgid = os.stat(cg).st_ino
    (a.out / 'allowed-cgroup').write_text(f'{cgid}\n')
    raw, err = (a.out / 'raw.jsonl').open('w'), (a.out / 'loader.stderr').open('w')
    loader = subprocess.Popen([str(a.build / 'pulse_counter_tokens_loader'), '--object', str(a.build / 'pulse_counter_tokens.bpf.o'),
                               '--allow-cgroup-file', str(a.out / 'allowed-cgroup'), '--interval-ms', '500', '--tokens', 'grams'],
                              stdout=raw, stderr=err)
    spans = []
    try:
        for _ in range(600):
            if 'sentinel-pulse attached' in (a.out / 'loader.stderr').read_text():
                break
            if loader.poll() is not None:
                sys.exit('loader exited: ' + (a.out / 'loader.stderr').read_text())
            time.sleep(0.1)
        time.sleep(1.5)
        for level in levels:
            per_thread = max(64, level // a.threads)
            t0 = time.time()
            out = in_cgroup(cg, [str(a.stress), str(a.threads), str(per_thread), str(a.seconds)])
            t1 = time.time()
            spans.append((level, json.loads(out.stdout), t0, t1))
            time.sleep(3.0)                                  # the level's windows close and are drained
    finally:
        loader.terminate()
        loader.wait(timeout=120)
        raw.close()
        err.close()
        cg.rmdir()
    grams, drains = [], []
    with (a.out / 'raw.jsonl').open() as stream:            # GBs at the top levels: one line at a time, counts only
        for line in stream:
            if line.startswith('{"type":"token_grams"'):
                r = json.loads(line)
                if r['cgroup_id'] == cgid:
                    grams.append(dict(window_end=r['window_end'], events=r['events'], distinct=len(r['grams'])))
            elif line.startswith('{"type":"token_drain"'):
                drains.append(json.loads(line))
    (a.out / 'windows.jsonl').write_text(''.join(json.dumps(r) + '\n' for r in grams))
    (a.out / 'drains.jsonl').write_text(''.join(json.dumps(r) + '\n' for r in drains))
    (a.out / 'raw.jsonl').unlink()
    result = dict(schema='pulse-map-capacity-v1', protocol='sentinel_pulse/protocol/map-capacity-v1.json',
                  kernel=platform.release(), node=platform.node(), cgroup_id=cgid, map_entries=262144,
                  levels=[summarize(level, run, t0, t1, grams, drains) for level, run, t0, t1 in spans])
    (a.out / 'RESULTS.json').write_text(json.dumps(result, indent=2) + '\n')
    for r in result['levels']:
        print(json.dumps({k: r[k] for k in ('offered_calls_per_second', 'achieved_calls_per_second', 'events_lost',
                                           'failed_inserts', 'distinct_grams_per_window', 'drain_seconds')}))


if __name__ == '__main__':
    main()
