"""Binary baseline carried across runs for RCA suspect ranking.

The label review (Pulse 5.20) found that a 90-minute learning phase misses rare periodic tasks: CloudNativePG's
WAL archiving ran for the first time after the baseline froze, so it ranked first as a ``novel_binary``.

``build``: from earlier runs' RCA databases, the binaries each workload executed with a first sighting OUTSIDE
that run's campaign spans (first interval - margin to campaign end + margin). An attack or benign-launch fixture
of an earlier campaign is first seen inside its campaign, so it can never become "known"; a binary first seen in
a campaign and only later in normal is left out too (conservative).

``seed``: inserts them into a new run's database with first_seen = 0, i.e. known before the run, so they score
neither ``novel_binary`` nor ``unknown_binary``. Binaries first seen in the new run are unaffected.
"""
from __future__ import annotations

import argparse
from collections import defaultdict
import hashlib
import json
from pathlib import Path
import sqlite3


def campaign_span(campaign: Path, margin=60.0):
    """First interval start - margin to campaign end + margin. Defined here, not imported from syscall_study: the RCA
    service runs on the system Python without numpy (the 23/10 launch failed on that import)."""
    starts = [float(json.loads(l)['start_at']) for l in (campaign/'INTERVALS.jsonl').read_text().splitlines() if l]
    return min(starts) - margin, float(json.loads((campaign/'TERMINAL.json').read_text())['finished_at_unix']) + margin


def build(runs):
    """runs: [(context.sqlite3 path, [campaign dirs])] -> {workload: sorted binaries}, stats."""
    seen, stats = defaultdict(set), defaultdict(int)
    for db_path, campaigns in runs:
        spans = [campaign_span(Path(c)) for c in campaigns]
        db = sqlite3.connect(f'file:{db_path}?mode=ro', uri=True)
        for workload, binary, first in db.execute('select workload, binary, first_seen from binaries'):
            if any(lo <= first <= hi for lo, hi in spans):
                stats['left_out_first_seen_in_campaign'] += 1
                continue
            seen[workload].add(binary)
            stats['kept'] += 1
        db.close()
    return {w: sorted(b) for w, b in sorted(seen.items())}, dict(stats)


def seed(db, workloads: dict) -> int:
    """Insert seeded binaries as known before the run (first_seen 0); existing rows are kept."""
    before = db.execute('select count(*) from binaries').fetchone()[0]
    db.executemany('insert or ignore into binaries values(?,?,0.0)',
                   [(w, b) for w, binaries in workloads.items() for b in binaries])
    db.commit()
    return db.execute('select count(*) from binaries').fetchone()[0] - before


def main():
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument('--run', action='append', required=True,
                   help='db=<context.sqlite3>,campaign=<dir>[,campaign=<dir>] of an earlier run')
    p.add_argument('--output', type=Path, required=True)
    a = p.parse_args()
    runs = []
    for spec in a.run:
        kv = defaultdict(list)
        for part in spec.split(','):
            k, v = part.split('=', 1); kv[k].append(v)
        runs.append((kv['db'][0], kv['campaign']))
    workloads, stats = build(runs)
    doc = dict(schema='rca-binary-baseline-seed-v1', runs=[dict(db=d, campaigns=c) for d, c in runs],
               rule='first sighting outside the campaign spans (+- 60 s) of its run', stats=stats,
               binaries=sum(map(len, workloads.values())), workloads=workloads)
    a.output.write_text(json.dumps(doc, indent=1))
    print(json.dumps(dict(stats=stats, binaries=doc['binaries'],
                          sha256=hashlib.sha256(a.output.read_bytes()).hexdigest())))


if __name__ == '__main__':
    main()
