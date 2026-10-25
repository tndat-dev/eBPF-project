#!/usr/bin/env python3
"""Live tripwire A1 of a final-system run, from the workers' decisions (protocol final-system-confirmation-v1).

One pass over every worker's decisions.jsonl(.gz):

- ``trials``: per campaign interval, whether a judged window of the trial container inside [start, start + 15 s]
  carries a live tripwire alert, and the end of the first such window (same keys as novel_syscalls.py, so
  rule_comparison.py --tripwire reads it); ``novel`` is None when no window of the interval was judged;
- ``normal``: the live alert windows ending in ``--normal-span`` (rule_comparison.py reads ``normal.alerts``);
- ``agreement`` (with ``--offline``, the novel_syscalls.py --normal-span output on the same run, reference span and
  exec set): judged windows of the normal span whose live alert differs from the offline one, by cause;
- ``frame_lag``: preview_emitted_at - window_end of every decision row, quantiles per worker (shared-writes check).

    python3 live_tripwire.py --workers-root RUN/workers --campaign RUN/pulse-development-matrix \\
        --normal-span SEL_END:CAPTURE_END [--offline tripwire-a1-offline.json] --output live-tripwire.json
"""
import argparse
from array import array
from collections import Counter, defaultdict
import glob
import gzip
import json
from pathlib import Path
import time

import numpy as np


def span(text):
    lo, hi = (float(x) for x in text.split(':'))
    return lo, hi


def decision_files(workers_root):
    for node_dir in sorted(glob.glob(str(workers_root).rstrip('/') + '/*/')):
        for seg in sorted(glob.glob(node_dir + 'segments/s*/')):
            plain, packed = Path(seg)/'decisions.jsonl', Path(seg)/'decisions.jsonl.gz'
            if plain.exists():
                yield Path(node_dir).name, plain
            elif packed.exists():
                yield Path(node_dir).name, packed


def trials_of(campaign):
    out = []
    for path in sorted(glob.glob(str(campaign).rstrip('/') + '/trials/*/EVALUATION_INPUT.json')):
        d = json.loads(Path(path).read_text())
        for label in ('control', 'benign', 'attack'):
            t = d.get(label)
            if t:
                out.append(dict(label=label, scenario=d['attack']['scenario'], trial_id=t.get('trial_id'),
                                ident=(t['node_name'], str(t['pod_uid']), str(t['cgroup_id'])), start=float(t['start_at']),
                                kernel=float(t['kernel_event_at']) if t.get('kernel_event_at') is not None else None))
    return out


def quantiles(values):
    if not len(values):
        return None
    v = np.asarray(values)
    return dict(n=int(len(v)), p50=float(np.percentile(v, 50)), p95=float(np.percentile(v, 95)),
                p99=float(np.percentile(v, 99)), max=float(v.max()))


def scan(workers_root, trials, normal_span):
    by_ident = defaultdict(list)
    for i, t in enumerate(trials):
        by_ident[t['ident']].append(i)
    t_lo = min((t['start'] for t in trials), default=0.0); t_hi = max((t['start'] + 15 for t in trials), default=0.0)
    windows = defaultdict(list)                     # trial index -> [(end, alert)] of judged windows
    alerts, judged_normal, status = [], set(), Counter()
    lag = defaultdict(lambda: array('d'))         # ~13 M rows per worker
    for node, path in decision_files(workers_root):
        with (gzip.open(path, 'rt') if path.suffix == '.gz' else open(path)) as f:
            for line in f:
                row = json.loads(line)
                end = float(row['window_end'])
                if row.get('preview_emitted_at') is not None:
                    lag[node].append(float(row['preview_emitted_at']) - end)
                st = row.get('tripwire_status')
                status[str(st)] += 1
                if st != 'judged':
                    continue
                if t_lo <= end <= t_hi:
                    for i in by_ident.get((row['node_name'], str(row['pod_uid']), str(row['cgroup_id'])), ()):
                        if trials[i]['start'] <= float(row['window_start']) and end <= trials[i]['start'] + 15:
                            windows[i].append((end, bool(row.get('tripwire_alert'))))
                if normal_span[0] <= end <= normal_span[1]:
                    key = (row['node_name'], str(row['pod_uid']), str(row['container_name']), round(end, 3))
                    judged_normal.add(key)
                    if row.get('tripwire_alert'):
                        alerts.append(dict(end=end, node_name=row['node_name'], pod_uid=str(row['pod_uid']),
                                           container_name=row['container_name'], workload=row['workload_key'],
                                           ids=row.get('tripwire_novel_ids')))
    per_trial = []
    for i, t in enumerate(trials):
        w = sorted(windows.get(i, []))
        ends = [e for e, a in w if a]
        per_trial.append(dict(trial_id=t['trial_id'], label=t['label'], scenario=t['scenario'], start=t['start'],
                              kernel=t['kernel'], novel=(bool(ends) if w else None), first_novel_end=ends[0] if ends else None))
    return per_trial, alerts, judged_normal, status, {n: quantiles(v) for n, v in sorted(lag.items())}


def agreement(alerts, judged, offline):
    """Judged normal windows where live and offline disagree; the offline alert list is restricted to judged windows."""
    key = lambda a: (a['node_name'], str(a['pod_uid']), str(a['container_name']), round(float(a['end']), 3))
    live = {key(a) for a in alerts}
    off_all = {key(a) for a in offline['normal']['alerts']}
    off = off_all & judged
    only_live, only_off = live - off, off - live
    return dict(judged_windows=len(judged), live_alert_windows=len(live), offline_alert_windows=len(off),
                offline_alerts_on_windows_not_judged_live=len(off_all - judged),
                live_only=len(only_live), offline_only=len(only_off),
                agreement=1 - (len(only_live) + len(only_off)) / len(judged) if judged else None,
                examples=dict(live_only=sorted(only_live)[:10], offline_only=sorted(only_off)[:10]))


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument('--workers-root', required=True)
    ap.add_argument('--campaign', required=True)
    ap.add_argument('--normal-span', type=span, required=True)
    ap.add_argument('--offline', help='novel_syscalls.py --normal-span output on the same run')
    ap.add_argument('--output', required=True)
    a = ap.parse_args()
    trials = trials_of(a.campaign)
    per_trial, alerts, judged, status, lag = scan(a.workers_root, trials, a.normal_span)
    result = dict(schema='pulse-live-tripwire-v1', protocol='sentinel_pulse/protocol/final-system-confirmation-v1.json',
                  workers_root=a.workers_root, campaign=a.campaign, tripwire_status=dict(status), trials=per_trial,
                  normal=dict(span_unix=list(a.normal_span), windows_judged=len(judged), alert_windows=len(alerts), alerts=alerts),
                  frame_lag_seconds=lag, computed_at_unix=time.time())
    if a.offline:
        result['agreement'] = agreement(alerts, judged, json.loads(Path(a.offline).read_text()))
    Path(a.output).write_text(json.dumps(result, indent=1, default=list))
    print(json.dumps({k: result[k] for k in ('tripwire_status', 'frame_lag_seconds')}, default=str)[:1500])
    if a.offline:
        print(json.dumps({k: v for k, v in result['agreement'].items() if k != 'examples'}))


if __name__ == '__main__':
    main()
