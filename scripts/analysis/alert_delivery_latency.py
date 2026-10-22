#!/usr/bin/env python3
"""Kernel -> recipient latency of Pulse alerts, per delivery path (RCA 5.14), joined trial by trial.

Inputs: the campaign's ``RESULTS.json`` (outcomes with ``kernel_event_at`` and ``first_preview_at`` per attack trial)
and the alert bridge's ``episodes.jsonl`` / ``deliveries.jsonl``. An attack trial is matched to the bridge episode of
the same container (node, pod UID, container) that started inside the trial's 15 s horizon; the delivery time of
that episode on each path (push, pull-fast, pull-default) minus the trial's kernel event time is the latency to the
recipient. A trial whose container already had an episode running when the attack started is reported apart
(``alert_already_active``): its alert reached the recipient before the attack and no new alert was sent.

Only trials that start after ``--since`` count, so that every path was live for every counted trial.
Standard library only (runs on the system Python of .234).
"""
import argparse
from collections import Counter, defaultdict
import json
from pathlib import Path

HORIZON = 15.0
PATHS = ('push', 'pull-fast', 'pull-default')


def quantile(values, q):
    values = sorted(values)
    return values[min(len(values) - 1, int(round(q * (len(values) - 1))))] if values else None


def join(outcomes, episodes, deliveries, since):
    starts = defaultdict(list)
    ended = {e['episode']: e['ended_at'] for e in episodes if e['event'] == 'end'}
    for e in episodes:
        if e['event'] == 'start':
            starts[(e['node'], e['pod_uid'], e['container'])].append(e)
    delivered = {(d['path'], d['episode']): d['received_at'] for d in deliveries}
    rows = []
    for o in outcomes:
        if o.get('label') != 'attack' or float(o['start_at']) < since:
            continue
        key = (o['node_name'], o['pod_uid'], o['container_name'])
        begin, kernel = float(o['start_at']), o.get('kernel_event_at')
        row = dict(trial_id=o['trial_id'], scenario=o.get('scenario'), rate_per_second=o.get('rate_per_second'),
                   outcome=o['outcome'], kernel_to_preview_seconds=o.get('kernel_to_preview_seconds'))
        eps = sorted(starts.get(key, []), key=lambda e: e['preview_emitted_at'])
        active = [e for e in eps if e['preview_emitted_at'] < begin and ended.get(e['episode'], float('inf')) >= begin]
        inside = [e for e in eps if begin <= e['preview_emitted_at'] <= begin + HORIZON]
        if active:
            row['match'] = 'alert_already_active'
        elif not inside:
            row['match'] = 'no_episode'
        else:
            ep = inside[0]
            row.update(match='episode', episode=ep['episode'])
            for path in PATHS:
                at = delivered.get((path, ep['episode']))
                row[f'{path}_kernel_to_recipient_seconds'] = (at - kernel) if at is not None and kernel is not None else None
        rows.append(row)
    return rows


def summarize(rows):
    out = dict(attack_trials=len(rows), outcomes=dict(Counter(r['outcome'] for r in rows)),
               match=dict(Counter(r['match'] for r in rows)),
               kernel_to_preview=dict(p50=quantile([r['kernel_to_preview_seconds'] for r in rows if r['kernel_to_preview_seconds'] is not None], .5),
                                      p95=quantile([r['kernel_to_preview_seconds'] for r in rows if r['kernel_to_preview_seconds'] is not None], .95)))
    for path in PATHS:
        v = [r[f'{path}_kernel_to_recipient_seconds'] for r in rows if r.get(f'{path}_kernel_to_recipient_seconds') is not None]
        out[path] = dict(trials_alerted=len(v), share_of_attack_trials=len(v) / len(rows) if rows else None,
                         p50=quantile(v, .5), p95=quantile(v, .95), max=max(v) if v else None)
    by_rate = defaultdict(list)
    for r in rows:
        by_rate[r['rate_per_second']].append(r)
    out['push_by_rate'] = {str(k): dict(trials=len(v), alerted=sum(r.get('push_kernel_to_recipient_seconds') is not None for r in v),
                                        p95=quantile([r['push_kernel_to_recipient_seconds'] for r in v if r.get('push_kernel_to_recipient_seconds') is not None], .95))
                           for k, v in sorted(by_rate.items(), key=lambda kv: kv[0] or 0)}
    return out


def main():
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument('--results', type=Path, required=True, help='campaign RESULTS.json')
    p.add_argument('--bridge', type=Path, required=True, help='alert bridge output directory')
    p.add_argument('--since', type=float, required=True, help='unix time from which every path was live')
    p.add_argument('--output', type=Path, required=True)
    a = p.parse_args()
    results = json.loads(a.results.read_text())
    outcomes = results['outcomes']
    outcomes = outcomes if isinstance(outcomes, list) else [o for pair in outcomes.values() for o in pair]
    read = lambda name: [json.loads(l) for l in (a.bridge / name).read_text().splitlines() if l]
    rows = join(outcomes, read('episodes.jsonl'), read('deliveries.jsonl'), a.since)
    summary = summarize(rows)
    a.output.write_text(json.dumps(dict(schema='pulse-alert-delivery-latency-v1', since=a.since, summary=summary, trials=rows), indent=1))
    print(json.dumps(summary, indent=1))


if __name__ == '__main__':
    main()
